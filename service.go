package localsecretmaterials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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
	ErrLeaseScopeDenied      = errors.New("lease purpose is not authorized for this action")
	ErrLeaseTerminal         = errors.New("lease is permanently settled")
	ErrMaterialCannotDecrypt = errors.New("material cannot be decrypted: the demo master key that sealed it is no longer available")
	ErrInvalidArgument       = errors.New("invalid argument")
	ErrRotationAborted       = errors.New("rotation aborted before lease state changed")
)

// Scope names one operation class a borrow is allowed to perform. A lease can
// only ever act inside the scopes granted at issuance; presenting its token
// for another operation is denied and audited.
type Scope string

const (
	// ScopeReadMaterial allows decrypting the exact version the lease pins.
	ScopeReadMaterial Scope = "material:read"
	// ScopeReadAudit allows reading only the audit events of the same lease.
	ScopeReadAudit Scope = "audit:read"
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
	Purpose    string
	Scopes     []Scope
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// LeaseView is the queryable description of a lease. It never carries the
// bearer token or material plaintext.
type LeaseView struct {
	ID         string
	SecretName string
	VersionID  string
	Purpose    string
	Scopes     []Scope
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Revoked    bool
}

type BorrowOptions struct {
	// Purpose states why the material is borrowed. The same material can have
	// concurrent borrows with different purposes and scopes.
	Purpose string
	Scopes  []Scope
}

type CheckedOutMaterial struct {
	SecretName string
	VersionID  string
	Purpose    string
	Plaintext  []byte
	ExpiresAt  time.Time
}

type Service struct {
	mu       sync.Mutex
	store    *Store
	key      MasterKey
	now      func() time.Time
	newToken func() (string, [32]byte, error)
	// failNextSecretSave is test-only fault injection for rotation recovery.
	failNextSecretSave bool
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
	fresh := cloneJSON(record)
	version, err := s.sealVersion(len(fresh.Versions)+1, plaintext)
	if err != nil {
		return "", err
	}
	version.Number = len(fresh.Versions) + 1
	oldVersion := fresh.CurrentVersionID
	now := s.now()
	fresh.Versions = append(fresh.Versions, version)
	fresh.CurrentVersionID = version.ID

	if s.failNextSecretSave {
		s.failNextSecretSave = false
		s.store.AppendAudit(ctx, AuditEvent{
			At:           now.UTC(),
			Action:       "secret_rotated",
			Secret:       name,
			Version:      oldVersion,
			PriorVersion: oldVersion,
			KeyID:        s.key.ID(),
			Outcome:      "denied",
			Reason:       "persist_failed",
		})
		return "", fmt.Errorf("rotate %s: %w", name, ErrRotationAborted)
	}

	// Persist the new version before touching any existing lease. If this write
	// fails, no lease state is shortened and retries remain possible.
	if err := s.store.SaveSecret(ctx, fresh); err != nil {
		s.store.AppendAudit(ctx, AuditEvent{
			At:      now.UTC(),
			Action:  "secret_rotated",
			Secret:  name,
			Version: oldVersion,
			KeyID:   s.key.ID(),
			Outcome: "denied",
			Reason:  "persist_failed",
		})
		return "", err
	}

	if fresh.RotationPolicy.OldLeases == SettleGracePeriod && fresh.RotationPolicy.GracePeriod > 0 {
		deadline := now.Add(fresh.RotationPolicy.GracePeriod)
		if _, err := s.settleLeaseBatchLocked(ctx, name, oldVersion, deadline, 0, now); err != nil {
			return "", err
		}
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

func (s *Service) Borrow(ctx context.Context, name string, ttl time.Duration, opts ...BorrowOptions) (*Lease, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("%w: ttl must be positive", ErrInvalidArgument)
	}
	var spec BorrowOptions
	if len(opts) > 1 {
		return nil, fmt.Errorf("%w: at most one BorrowOptions value is allowed", ErrInvalidArgument)
	}
	if len(opts) == 1 {
		spec = opts[0]
	}
	spec.Purpose = strings.TrimSpace(spec.Purpose)
	if spec.Purpose == "" {
		return nil, fmt.Errorf("%w: purpose is required", ErrInvalidArgument)
	}
	scopes, err := normalizeScopes(spec.Scopes)
	if err != nil {
		return nil, err
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
		Purpose:    spec.Purpose,
		Scopes:     scopeValues(scopes),
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
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Outcome: "denied", Reason: safeReason(err)})
		return nil, err
	}
	if !leaseHasScope(lease, ScopeReadMaterial) {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: lease.VersionID, LeaseID: lease.ID, Outcome: "denied", Reason: "scope_denied"})
		return nil, ErrLeaseScopeDenied
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
		Purpose:    lease.Purpose,
		Plaintext:  plaintext,
		ExpiresAt:  lease.ExpiresAt,
	}, nil
}

// LeaseInfo exposes only metadata. Callers cannot use the view to obtain the
// pinned version's material, and there is no token to pass to other actions.
func (s *Service) LeaseInfo(ctx context.Context, token string) (*LeaseView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	lease, _, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "lease_query", Outcome: "denied", Reason: safeReason(err)})
		return nil, err
	}
	return lease.toView(), nil
}

// AuditEventsForLease enforces scope at the query boundary: a borrower can
// inspect only its own lease ID. The full audit trail remains service-wide.
func (s *Service) AuditEventsForLease(ctx context.Context, token string) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	lease, _, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "audit_query", Outcome: "denied", Reason: safeReason(err)})
		return nil, err
	}
	if !leaseHasScope(lease, ScopeReadAudit) {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "audit_query", Secret: lease.SecretName, Version: lease.VersionID, LeaseID: lease.ID, Outcome: "denied", Reason: "scope_denied"})
		return nil, ErrLeaseScopeDenied
	}
	events, err := s.store.ReadAudit(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]AuditEvent, 0, len(events))
	for _, event := range events {
		if event.LeaseID == lease.ID {
			filtered = append(filtered, event)
		}
	}
	return filtered, nil
}

// SettleOldLeases revokes or expires active borrows pinned to versions other
// than the current one in deterministic, bounded batches. Already revoked
// borrows are skipped and can never return to active state.
func (s *Service) SettleOldLeases(ctx context.Context, name string, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("%w: batch limit must be positive", ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	return s.settleLeaseBatchLocked(ctx, name, "", now, limit, now)
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

// settleLeaseBatchLocked applies a deterministic upper-bound expiry to active
// leases for oldVersion. versionID == "" matches every non-current version.
// limit <= 0 processes all matching leases; otherwise at most limit leases are
// changed, ordered by lease ID so concurrent batches cannot skip or revive.
func (s *Service) settleLeaseBatchLocked(ctx context.Context, name, versionID string, deadline time.Time, limit int, now time.Time) (int, error) {
	record, ok := s.store.Materials[name]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrSecretNotFound, name)
	}
	var ids []string
	byID := make(map[string]*LeaseRecord)
	for _, lease := range s.store.Leases {
		if lease.SecretName != name || !lease.IsActive(now) {
			continue
		}
		if lease.VersionID == record.CurrentVersionID {
			continue
		}
		if versionID != "" && lease.VersionID != versionID {
			continue
		}
		if !deadline.Before(lease.ExpiresAt) {
			continue
		}
		ids = append(ids, lease.ID)
		byID[lease.ID] = lease
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	changed := 0
	for _, id := range ids {
		lease := byID[id]
		// Reload from the map: an interleaved revoke within this process may
		// have replaced the pointer snapshot. Terminal revocation wins.
		lease = s.store.Leases[lease.TokenHash]
		if lease == nil || !lease.IsActive(now) || !deadline.Before(lease.ExpiresAt) {
			continue
		}
		lease.ExpiresAt = deadline.UTC()
		lease.SettleRule = "batch_settle"
		if err := s.store.SaveLease(ctx, lease); err != nil {
			return changed, err
		}
		changed++
		s.store.AppendAudit(ctx, AuditEvent{
			At:      now.UTC(),
			Action:  "lease_settled",
			Secret:  name,
			Version: lease.VersionID,
			LeaseID: lease.ID,
			KeyID:   s.key.ID(),
			Outcome: "ok",
		})
	}
	return changed, nil
}

func normalizeScopes(values []Scope) ([]Scope, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: at least one access scope is required", ErrInvalidArgument)
	}
	seen := make(map[Scope]bool)
	for _, value := range values {
		switch value {
		case ScopeReadMaterial, ScopeReadAudit:
		default:
			return nil, fmt.Errorf("%w: unknown access scope %q", ErrInvalidArgument, value)
		}
		if seen[value] {
			return nil, fmt.Errorf("%w: duplicate access scope %q", ErrInvalidArgument, value)
		}
		seen[value] = true
	}
	return append([]Scope(nil), values...), nil
}

func leaseHasScope(lease *LeaseRecord, scope Scope) bool {
	for _, value := range lease.Scopes {
		if Scope(value) == scope {
			return true
		}
	}
	return false
}

func scopeValues(scopes []Scope) []string {
	values := make([]string, len(scopes))
	for i, scope := range scopes {
		values[i] = string(scope)
	}
	return values
}

func scopeStrings(values []string) []Scope {
	scopes := make([]Scope, len(values))
	for i, value := range values {
		scopes[i] = Scope(value)
	}
	return scopes
}

func safeReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidLease):
		return ErrInvalidLease.Error()
	case errors.Is(err, ErrLeaseExpired):
		return ErrLeaseExpired.Error()
	case errors.Is(err, ErrLeaseRevoked):
		return ErrLeaseRevoked.Error()
	case errors.Is(err, ErrSecretNotFound):
		return ErrSecretNotFound.Error()
	default:
		return "denied"
	}
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
