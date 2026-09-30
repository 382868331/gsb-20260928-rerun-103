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
	ErrScopeNotAllowed       = errors.New("lease scope does not permit this operation")
	ErrPurposeMismatch       = errors.New("lease purpose does not match the requested material view")
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
	// SettleBatchEnd ends active old-version borrows in explicit batches after rotation.
	SettleBatchEnd SettleRule = "batch_end"
)

// Access scopes carried by a borrow. They bind a lease to a narrow view of
// the material and the service operations it may perform.
const (
	// ScopeMaterialRead allows decrypting the pinned material version.
	ScopeMaterialRead = "material:read"
	// ScopeMetadataView allows reading non-secret material metadata.
	ScopeMetadataView = "metadata:view"
	// ScopeAuditRead allows reading the lease's own audit events.
	ScopeAuditRead = "audit:read"
)

// DefaultPurpose is assigned to leases issued through the simple Borrow API.
const DefaultPurpose = "general"

type RotationPolicy struct {
	OldLeases SettleRule
	// GracePeriod is used only when OldLeases is SettleGracePeriod. Zero keeps
	// the existing lease expiry.
	GracePeriod time.Duration
	// BatchSize is used only when OldLeases is SettleBatchEnd. It bounds how
	// many active old-version borrows EndOldLeaseBatches ends per call.
	BatchSize int
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
	Scopes     []string
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

// MaterialMetadata is the non-secret view exposed to a metadata-scoped borrow.
type MaterialMetadata struct {
	SecretName string
	VersionID  string
	Purpose    string
	ExpiresAt  time.Time
}

// BorrowRequest describes one purpose-bound borrow of a material.
type BorrowRequest struct {
	Purpose string
	Scopes  []string
	TTL     time.Duration
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
	// failSeal forces the next seal operation to fail and then resets itself.
	// Tests use it to drive master key rotation failure recovery.
	failSeal error
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
			}
		}
	}
	if err := s.store.SaveSecret(ctx, record); err != nil {
		return "", err
	}
	if record.RotationPolicy.OldLeases == SettleGracePeriod && record.RotationPolicy.GracePeriod > 0 {
		for _, lease := range s.store.Leases {
			if lease.SecretName == name && lease.SettleRule == string(SettleGracePeriod) && lease.VersionID == oldVersion && lease.RevokedAt.IsZero() {
				if err := s.store.SaveLease(ctx, lease); err != nil {
					return "", err
				}
			}
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

func (s *Service) Borrow(ctx context.Context, name string, ttl time.Duration) (*Lease, error) {
	return s.BorrowFor(ctx, name, BorrowRequest{
		Purpose: DefaultPurpose,
		Scopes:  []string{ScopeMaterialRead, ScopeMetadataView, ScopeAuditRead},
		TTL:     ttl,
	})
}

// BorrowFor issues a lease bound to one stated purpose and an explicit scope
// list. The lease pins the material version current at issue time: it can
// never read another version, and each scope gates a distinct operation.
func (s *Service) BorrowFor(ctx context.Context, name string, req BorrowRequest) (*Lease, error) {
	if req.TTL <= 0 {
		return nil, fmt.Errorf("%w: ttl must be positive", ErrInvalidArgument)
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		return nil, fmt.Errorf("%w: purpose is required", ErrInvalidArgument)
	}
	if strings.ContainsAny(purpose, "\r\n") {
		return nil, fmt.Errorf("%w: purpose must be a single line", ErrInvalidArgument)
	}
	scopes, err := normalizeScopes(req.Scopes)
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
		Purpose:    purpose,
		Scopes:     scopes,
		IssuedAt:   now.UTC(),
		ExpiresAt:  now.Add(req.TTL).UTC(),
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
		Purpose: purpose,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return lease.toLease(token), nil
}

func (s *Service) Use(ctx context.Context, token string) (*CheckedOutMaterial, error) {
	return s.useForPurpose(ctx, token, "")
}

// UseForPurpose checks out plaintext only when the borrow's declared purpose
// matches the caller's requested purpose. A lease for one purpose can never be
// replayed against another purpose's view.
func (s *Service) UseForPurpose(ctx context.Context, token, purpose string) (*CheckedOutMaterial, error) {
	if strings.TrimSpace(purpose) == "" {
		return nil, fmt.Errorf("%w: purpose is required", ErrInvalidArgument)
	}
	return s.useForPurpose(ctx, token, purpose)
}

func (s *Service) useForPurpose(ctx context.Context, token, purpose string) (*CheckedOutMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, record, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Outcome: "denied", Reason: auditReason(err)})
		return nil, err
	}
	if !leaseHasScope(lease, ScopeMaterialRead) {
		s.auditDenied(ctx, now, "material_use", lease, ErrScopeNotAllowed)
		return nil, ErrScopeNotAllowed
	}
	if purpose != "" && lease.Purpose != purpose {
		s.auditDenied(ctx, now, "material_use", lease, ErrPurposeMismatch)
		return nil, ErrPurposeMismatch
	}
	encrypted := record.Version(lease.VersionID)
	if encrypted == nil {
		s.auditDenied(ctx, now, "material_use", lease, ErrMaterialCannotDecrypt)
		return nil, ErrMaterialCannotDecrypt
	}
	plaintext, err := s.key.Open(encrypted)
	if err != nil {
		s.auditDenied(ctx, now, "material_use", lease, ErrMaterialCannotDecrypt)
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
		Purpose: lease.Purpose,
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

// Inspect returns only non-secret metadata. It requires the metadata scope and
// never decrypts material, so a metadata-only borrow cannot turn the view into
// plaintext.
func (s *Service) Inspect(ctx context.Context, token string) (*MaterialMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, _, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_inspect", Outcome: "denied", Reason: auditReason(err)})
		return nil, err
	}
	if !leaseHasScope(lease, ScopeMetadataView) {
		s.auditDenied(ctx, now, "material_inspect", lease, ErrScopeNotAllowed)
		return nil, ErrScopeNotAllowed
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "material_inspect",
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		Purpose: lease.Purpose,
		Outcome: "ok",
	})
	return &MaterialMetadata{
		SecretName: lease.SecretName,
		VersionID:  lease.VersionID,
		Purpose:    lease.Purpose,
		ExpiresAt:  lease.ExpiresAt,
	}, nil
}

// AuditTrail exposes only the calling lease's own events, and only with the
// audit scope. It never includes events for other purposes or leases.
func (s *Service) AuditTrail(ctx context.Context, token string) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, _, err := s.activeLease(token, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "audit_read", Outcome: "denied", Reason: auditReason(err)})
		return nil, err
	}
	if !leaseHasScope(lease, ScopeAuditRead) {
		s.auditDenied(ctx, now, "audit_read", lease, ErrScopeNotAllowed)
		return nil, ErrScopeNotAllowed
	}
	everything, err := s.store.ReadAudit(ctx)
	if err != nil {
		return nil, err
	}
	scoped := make([]AuditEvent, 0, len(everything))
	for _, event := range everything {
		if event.LeaseID == lease.ID {
			scoped = append(scoped, event)
		}
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "audit_read",
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		Purpose: lease.Purpose,
		Outcome: "ok",
	})
	return scoped, nil
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
		Purpose: lease.Purpose,
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

// EndOldLeaseBatch explicitly settles active borrows pinned to a superseded
// version. It ends at most batchSize leases per call, in stable order, so a
// rotation can wind old borrows down batch by batch. Already ended borrows are
// skipped and can never be reactivated by later calls or process restarts.
// It returns the number of borrows ended by this call.
func (s *Service) EndOldLeaseBatch(ctx context.Context, name, oldVersionID string, batchSize int) (int, error) {
	if batchSize <= 0 {
		return 0, fmt.Errorf("%w: batch size must be positive", ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	candidates := make([]*LeaseRecord, 0)
	for _, lease := range s.store.Leases {
		if lease.SecretName == name && lease.VersionID == oldVersionID && lease.IsActive(now) {
			candidates = append(candidates, lease)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ID < candidates[j].ID
	})

	ended := 0
	for _, lease := range candidates {
		if ended >= batchSize {
			break
		}
		// Re-check under the lock: never overwrite an earlier revocation.
		if !lease.RevokedAt.IsZero() || !now.Before(lease.ExpiresAt) {
			continue
		}
		lease.RevokedAt = now.UTC()
		lease.SettleRule = string(SettleBatchEnd)
		if err := s.store.SaveLease(ctx, lease); err != nil {
			return ended, err
		}
		ended++
		s.store.AppendAudit(ctx, AuditEvent{
			At:      now.UTC(),
			Action:  "lease_batch_ended",
			Secret:  lease.SecretName,
			Version: lease.VersionID,
			LeaseID: lease.ID,
			Purpose: lease.Purpose,
			KeyID:   s.key.ID(),
			Outcome: "ok",
		})
	}
	return ended, nil
}

// RotateMasterKey re-seals every stored material version with a fresh
// process-local key. Version IDs and numbers are preserved so existing borrows
// stay pinned to the same material view. All records are rewritten together;
// a sealing failure aborts before any byte is persisted, so a failed rotation
// leaves the store readable under the old key and never revives revoked
// borrows.
func (s *Service) RotateMasterKey(ctx context.Context, newKey MasterKey) (int, error) {
	if newKey.aead == nil {
		return 0, fmt.Errorf("%w: zero master key", ErrWrongMasterKey)
	}
	if newKey.ID() == s.key.ID() {
		return 0, fmt.Errorf("%w: new key is identical to current key", ErrInvalidArgument)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	rotated := make(map[string]*SecretRecord, len(s.store.Materials))
	count := 0
	for name, record := range s.store.Materials {
		next := *record
		next.Versions = make([]*EncryptedVersion, 0, len(record.Versions))
		for _, version := range record.Versions {
			if version.KeyID == newKey.ID() {
				next.Versions = append(next.Versions, version)
				continue
			}
			plaintext, err := s.key.Open(version)
			if err != nil {
				s.store.AppendAudit(ctx, AuditEvent{
					At:      now.UTC(),
					Action:  "master_key_rotated",
					Secret:  name,
					Version: version.ID,
					KeyID:   s.key.ID(),
					Outcome: "denied",
					Reason:  "decryption_key_unavailable",
				})
				return 0, ErrMaterialCannotDecrypt
			}
			if err := s.failNextSeal(); err != nil {
				s.store.AppendAudit(ctx, AuditEvent{
					At:      now.UTC(),
					Action:  "master_key_rotated",
					Secret:  name,
					Version: version.ID,
					KeyID:   s.key.ID(),
					Outcome: "denied",
					Reason:  "seal_failed",
				})
				return 0, err
			}
			sealed, err := newKey.Seal(fmt.Sprintf("v%d-rekey", version.Number), plaintext)
			if err != nil {
				s.store.AppendAudit(ctx, AuditEvent{
					At:      now.UTC(),
					Action:  "master_key_rotated",
					Secret:  name,
					Version: version.ID,
					KeyID:   s.key.ID(),
					Outcome: "denied",
					Reason:  "seal_failed",
				})
				return 0, err
			}
			sealed.ID = version.ID
			sealed.Number = version.Number
			next.Versions = append(next.Versions, sealed)
			count++
		}
		rotated[name] = &next
	}
	if err := s.store.SaveMaterials(ctx, rotated); err != nil {
		return 0, err
	}
	s.key = newKey
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "master_key_rotated",
		KeyID:   newKey.ID(),
		Outcome: "ok",
	})
	return count, nil
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
	case "", SettleUntilExpiry, SettleGracePeriod, SettleBatchEnd:
	default:
		return fmt.Errorf("%w: unknown settle rule %q", ErrInvalidArgument, policy.OldLeases)
	}
	if policy.OldLeases == SettleGracePeriod && policy.GracePeriod <= 0 {
		return fmt.Errorf("%w: grace period must be positive", ErrInvalidArgument)
	}
	if policy.OldLeases == SettleBatchEnd && policy.BatchSize <= 0 {
		return fmt.Errorf("%w: batch size must be positive", ErrInvalidArgument)
	}
	return nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: at least one scope is required", ErrInvalidArgument)
	}
	seen := make(map[string]bool, len(scopes))
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case ScopeMaterialRead, ScopeMetadataView, ScopeAuditRead:
		default:
			return nil, fmt.Errorf("%w: unknown scope %q", ErrInvalidArgument, scope)
		}
		if !seen[scope] {
			seen[scope] = true
			normalized = append(normalized, scope)
		}
	}
	sort.Strings(normalized)
	return normalized, nil
}

func leaseHasScope(lease *LeaseRecord, scope string) bool {
	for _, granted := range lease.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

func (s *Service) auditDenied(ctx context.Context, now time.Time, action string, lease *LeaseRecord, err error) {
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  action,
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		Purpose: lease.Purpose,
		KeyID:   s.key.ID(),
		Outcome: "denied",
		Reason:  auditReason(err),
	})
}

// auditReason maps errors to stable codes so audit lines never embed dynamic
// values such as tokens, purposes supplied by callers, or version strings.
func auditReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidLease):
		return "invalid_lease"
	case errors.Is(err, ErrLeaseExpired):
		return "lease_expired"
	case errors.Is(err, ErrLeaseRevoked):
		return "lease_revoked"
	case errors.Is(err, ErrScopeNotAllowed):
		return "scope_not_allowed"
	case errors.Is(err, ErrPurposeMismatch):
		return "purpose_mismatch"
	case errors.Is(err, ErrSecretNotFound):
		return "secret_not_found"
	case errors.Is(err, ErrMaterialCannotDecrypt):
		return "decryption_key_unavailable"
	default:
		return "denied"
	}
}

func (s *Service) failNextSeal() error {
	if s.failSeal != nil {
		err := s.failSeal
		s.failSeal = nil
		return err
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
