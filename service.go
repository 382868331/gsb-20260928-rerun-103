package localsecretmaterials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrSecretNotFound        = errors.New("secret not found")
	ErrSecretExists          = errors.New("secret already exists")
	ErrInvalidLease          = errors.New("invalid or unknown lease credential")
	ErrLeaseExpired          = errors.New("lease has expired")
	ErrLeaseRevoked          = errors.New("lease has been revoked")
	ErrMaterialCannotDecrypt = errors.New("material cannot be decrypted: the demo master key that sealed it is no longer available")
	ErrInvalidArgument       = errors.New("invalid argument")
)

type SettleRule string

const (
	// SettleUntilExpiry lets borrows already issued for an old version keep
	// running until their own expiry or explicit revocation.
	SettleUntilExpiry SettleRule = "until_expiry"
	// SettleGracePeriod shortens active old-version borrows during rotation.
	SettleGracePeriod SettleRule = "grace_period"
)

type RotationPolicy struct {
	OldLeases SettleRule
	// GracePeriod is used only when OldLeases is SettleGracePeriod. Zero keeps
	// the existing lease expiry.
	GracePeriod time.Duration
}

type SecretOptions struct {
	Rotation RotationPolicy
}

type Lease struct {
	ID         string
	Token      string
	SecretName string
	VersionID  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

type CheckedOutMaterial struct {
	SecretName string
	VersionID  string
	Plaintext  []byte
	ExpiresAt  time.Time
}

type Service struct {
	mu       sync.Mutex
	store    *Store
	key      MasterKey
	now      func() time.Time
	newToken func() (string, [32]byte, error)
}

// GenerateDemoMasterKey creates a process-local key. It is never written to
// the material store or audit log.
func GenerateDemoMasterKey() (MasterKey, error) {
	return GenerateMasterKey()
}

// OpenDemoService uses the supplied directory for persistent state. A fresh
// key must be supplied for each demo process. After restart, old encrypted
// materials remain, but cannot be decrypted by the replacement key.
func OpenDemoService(ctx context.Context, dir string, key MasterKey) (*Service, error) {
	store, err := OpenStore(ctx, dir)
	if err != nil {
		return nil, err
	}
	return newService(store, key, time.Now), nil
}

func newService(store *Store, key MasterKey, now func() time.Time) *Service {
	return &Service{
		store: store,
		key:   key,
		now:   now,
		newToken: func() (string, [32]byte, error) {
			var secret [32]byte
			if _, err := rand.Read(secret[:]); err != nil {
				return "", [32]byte{}, err
			}
			token := base64.RawURLEncoding.EncodeToString(secret[:])
			return token, sha256.Sum256([]byte(token)), nil
		},
	}
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Close()
}

func (s *Service) CreateSecret(ctx context.Context, name string, plaintext []byte, opts SecretOptions) (string, error) {
	if strings.TrimSpace(name) == "" || len(plaintext) == 0 {
		return "", fmt.Errorf("%w: name and plaintext are required", ErrInvalidArgument)
	}
	if err := validatePolicy(opts.Rotation); err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.store.Materials[name]; ok {
		return "", fmt.Errorf("%w: %s", ErrSecretExists, name)
	}
	version, err := s.sealVersion(1, plaintext)
	if err != nil {
		return "", err
	}
	version.Number = 1
	record := &SecretRecord{
		Name:             name,
		CurrentVersionID: version.ID,
		RotationPolicy:   opts.Rotation,
		Versions:         []*EncryptedVersion{version},
	}
	if err := s.store.SaveSecret(ctx, record); err != nil {
		return "", err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      s.now().UTC(),
		Action:  "secret_created",
		Secret:  name,
		Version: version.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return version.ID, nil
}

func (s *Service) RotateSecret(ctx context.Context, name string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("%w: plaintext is required", ErrInvalidArgument)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.store.Materials[name]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrSecretNotFound, name)
	}
	version, err := s.sealVersion(len(record.Versions)+1, plaintext)
	if err != nil {
		return "", err
	}
	version.Number = len(record.Versions) + 1
	oldVersion := record.CurrentVersionID
	now := s.now()
	record.Versions = append(record.Versions, version)
	record.CurrentVersionID = version.ID

	if record.RotationPolicy.OldLeases == SettleGracePeriod && record.RotationPolicy.GracePeriod > 0 {
		deadline := now.Add(record.RotationPolicy.GracePeriod)
		for _, lease := range s.store.Leases {
			if lease.SecretName == name && lease.VersionID == oldVersion && lease.IsActive(now) && deadline.Before(lease.ExpiresAt) {
				lease.ExpiresAt = deadline
				lease.SettleRule = string(SettleGracePeriod)
				if err := s.store.SaveLease(ctx, lease); err != nil {
					return "", err
				}
			}
		}
	}
	if err := s.store.SaveSecret(ctx, record); err != nil {
		return "", err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:           s.now().UTC(),
		Action:       "secret_rotated",
		Secret:       name,
		Version:      version.ID,
		PriorVersion: oldVersion,
		KeyID:        s.key.ID(),
		Outcome:      "ok",
	})
	return version.ID, nil
}

func (s *Service) Borrow(ctx context.Context, name string, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: ttl must be positive", ErrInvalidArgument)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	record, ok := s.store.Materials[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, name)
	}
	now := s.now()
	token, _, err := s.newToken()
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	lease := &LeaseRecord{
		ID:         "lease_" + hex.EncodeToString(idBytes),
		TokenHash:  hashToken(token),
		SecretName: name,
		VersionID:  record.CurrentVersionID,
		IssuedAt:   now.UTC(),
		ExpiresAt:  now.Add(ttl).UTC(),
	}
	if err := s.store.SaveLease(ctx, lease); err != nil {
		return nil, err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "lease_issued",
		Secret:  name,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return lease.toLease(token), nil
}

func (s *Service) Use(ctx context.Context, token string) (*CheckedOutMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, record, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Outcome: "denied", Reason: err.Error()})
		return nil, err
	}
	encrypted := record.Version(lease.VersionID)
	if encrypted == nil {
		err := fmt.Errorf("%w: version %s is missing", ErrMaterialCannotDecrypt, lease.VersionID)
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: lease.VersionID, LeaseID: lease.ID, Outcome: "denied", Reason: "decryption_key_unavailable"})
		return nil, err
	}
	plaintext, err := s.key.Open(encrypted)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: lease.VersionID, LeaseID: lease.ID, KeyID: s.key.ID(), Outcome: "denied", Reason: "decryption_key_unavailable"})
		if errors.Is(err, ErrWrongMasterKey) {
			return nil, ErrMaterialCannotDecrypt
		}
		return nil, err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "material_use",
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return &CheckedOutMaterial{
		SecretName: lease.SecretName,
		VersionID:  lease.VersionID,
		Plaintext:  plaintext,
		ExpiresAt:  lease.ExpiresAt,
	}, nil
}

// Revoke is idempotent. Repeating it for an already revoked lease does not
// reactivate, extend, or replace the lease.
func (s *Service) Revoke(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, ok := s.store.Leases[hashToken(token)]
	if !ok {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "lease_revoked", Outcome: "denied", Reason: ErrInvalidLease.Error()})
		return ErrInvalidLease
	}
	if lease.RevokedAt.IsZero() {
		lease.RevokedAt = now.UTC()
		if err := s.store.SaveLease(ctx, lease); err != nil {
			return err
		}
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "lease_revoked",
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return nil
}

func (s *Service) AuditEvents(ctx context.Context) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.ReadAudit(ctx)
}

func (s *Service) sealVersion(number int, plaintext []byte) (*EncryptedVersion, error) {
	return s.key.Seal(fmt.Sprintf("v%d", number), plaintext)
}

func (s *Service) activeLease(token string, now time.Time) (*LeaseRecord, *SecretRecord, error) {
	lease, ok := s.store.Leases[hashToken(token)]
	if !ok {
		return nil, nil, ErrInvalidLease
	}
	if !lease.RevokedAt.IsZero() {
		return nil, nil, ErrLeaseRevoked
	}
	if !now.Before(lease.ExpiresAt) {
		return nil, nil, ErrLeaseExpired
	}
	record, ok := s.store.Materials[lease.SecretName]
	if !ok {
		return nil, nil, ErrSecretNotFound
	}
	return lease, record, nil
}

func validatePolicy(policy RotationPolicy) error {
	switch policy.OldLeases {
	case "", SettleUntilExpiry, SettleGracePeriod:
	default:
		return fmt.Errorf("%w: unknown settle rule %q", ErrInvalidArgument, policy.OldLeases)
	}
	if policy.OldLeases == SettleGracePeriod && policy.GracePeriod <= 0 {
		return fmt.Errorf("%w: grace period must be positive", ErrInvalidArgument)
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
