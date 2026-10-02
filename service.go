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
	ErrUpstreamLeaseExpired  = errors.New("an upstream lease has expired")
	ErrUpstreamLeaseRevoked  = errors.New("an upstream lease has been revoked")
	ErrLeaseScopeDenied      = errors.New("lease purpose is not authorized for this action")
	ErrLeaseTerminal         = errors.New("lease is permanently settled")
	ErrDelegationDenied      = errors.New("delegation exceeds upstream authorization")
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
	ID                string
	Token             string
	ParentID          string
	SecretName        string
	VersionID         string
	Purpose           string
	Scopes            []Scope
	AllowsNewVersions bool
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

// LeaseView is the queryable description of a lease. It never carries the
// bearer token or material plaintext.
type LeaseView struct {
	ID                string
	ParentID          string
	SecretName        string
	VersionID         string
	Purpose           string
	Scopes            []Scope
	AllowsNewVersions bool
	IssuedAt          time.Time
	ExpiresAt         time.Time
	Revoked           bool
}

type BorrowOptions struct {
	// Purpose states why the material is borrowed. The same material can have
	// concurrent borrows with different purposes and scopes.
	Purpose           string
	Scopes            []Scope
	AllowsNewVersions bool
}

type DelegateOptions struct {
	Purpose           string
	Scopes            []Scope
	TTL               time.Duration
	AllowsNewVersions bool
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
	if err := s.persistFactsLocked(ctx); err != nil {
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
	if _, err := s.adoptCurrentVersionBatchLocked(ctx, fresh, now); err != nil {
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
	if err := s.persistFactsLocked(ctx); err != nil {
		return "", err
	}
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
		ID:                "lease_" + hex.EncodeToString(idBytes),
		TokenHash:         hashToken(token),
		SecretName:        name,
		VersionID:         record.CurrentVersionID,
		Purpose:           spec.Purpose,
		Scopes:            scopeValues(scopes),
		AllowsNewVersions: spec.AllowsNewVersions,
		IssuedAt:          now.UTC(),
		ExpiresAt:         now.Add(ttl).UTC(),
	}
	if err := s.store.SaveLease(ctx, lease); err != nil {
		return nil, err
	}
	if err := s.persistFactsLocked(ctx); err != nil {
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

// Delegate creates a strictly bounded temporary borrower under parentToken.
// The child purpose, scopes, version access and expiry cannot exceed the
// effective authorization of every upstream lease.
func (s *Service) Delegate(ctx context.Context, parentToken string, opts DelegateOptions) (*Lease, error) {
	opts.Purpose = strings.TrimSpace(opts.Purpose)
	if opts.Purpose == "" {
		return nil, fmt.Errorf("%w: purpose is required", ErrInvalidArgument)
	}
	if opts.TTL <= 0 {
		return nil, fmt.Errorf("%w: ttl must be positive", ErrInvalidArgument)
	}
	scopes, err := normalizeScopes(opts.Scopes)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	parent, record, err := s.authorizedLease(parentToken, now)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "lease_delegated", Outcome: "denied", Reason: safeReason(err)})
		return nil, err
	}
	if !purposeWithin(parent.Purpose, opts.Purpose) {
		err := fmt.Errorf("%w: purpose is outside upstream purpose", ErrDelegationDenied)
		s.appendLeaseDeniedAudit(ctx, "lease_delegated", parent, now, err)
		return nil, err
	}
	if !scopesWithin(scopes, parent.Scopes) {
		err := fmt.Errorf("%w: requested scope is not granted upstream", ErrDelegationDenied)
		s.appendLeaseDeniedAudit(ctx, "lease_delegated", parent, now, err)
		return nil, err
	}
	if opts.AllowsNewVersions && !s.chainAllowsNewVersionsLocked(parent, record) {
		err := fmt.Errorf("%w: new versions are not authorized upstream", ErrDelegationDenied)
		s.appendLeaseDeniedAudit(ctx, "lease_delegated", parent, now, err)
		return nil, err
	}
	childExpiry := now.Add(opts.TTL).UTC()
	if childExpiry.After(parent.ExpiresAt) {
		err := fmt.Errorf("%w: expiry exceeds upstream expiry", ErrDelegationDenied)
		s.appendLeaseDeniedAudit(ctx, "lease_delegated", parent, now, err)
		return nil, err
	}

	token, _, err := s.newToken()
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	versionID := parent.VersionID
	if opts.AllowsNewVersions {
		versionID = record.CurrentVersionID
	}
	child := &LeaseRecord{
		ID:                "lease_" + hex.EncodeToString(idBytes),
		TokenHash:         hashToken(token),
		ParentID:          parent.ID,
		SecretName:        record.Name,
		VersionID:         versionID,
		Purpose:           opts.Purpose,
		Scopes:            scopeValues(scopes),
		AllowsNewVersions: opts.AllowsNewVersions,
		IssuedAt:          now.UTC(),
		ExpiresAt:         childExpiry,
	}
	if err := s.store.SaveLease(ctx, child); err != nil {
		return nil, err
	}
	if err := s.persistFactsLocked(ctx); err != nil {
		return nil, err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:            now.UTC(),
		Action:        "lease_delegated",
		Secret:        record.Name,
		Version:       child.VersionID,
		LeaseID:       child.ID,
		ActorLeaseID:  parent.ID,
		ParentLeaseID: parent.ID,
		KeyID:         s.key.ID(),
		Outcome:       "ok",
	})
	return child.toLease(token), nil
}

func (s *Service) Use(ctx context.Context, token string) (*CheckedOutMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, record, err := s.authorizedLease(token, now)
	if err != nil {
		s.appendTokenDeniedAudit(ctx, "material_use", token, now, err)
		return nil, err
	}
	versionID := s.effectiveVersionIDLocked(lease, record)
	if !leaseHasScope(lease, ScopeReadMaterial) {
		s.appendLeaseDeniedAudit(ctx, "material_use", lease, now, ErrLeaseScopeDenied)
		return nil, ErrLeaseScopeDenied
	}
	encrypted := record.Version(versionID)
	if encrypted == nil {
		err := fmt.Errorf("%w: version %s is missing", ErrMaterialCannotDecrypt, lease.VersionID)
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: versionID, LeaseID: lease.ID, Outcome: "denied", Reason: "decryption_key_unavailable"})
		return nil, err
	}
	plaintext, err := s.key.Open(encrypted)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: versionID, LeaseID: lease.ID, KeyID: s.key.ID(), Outcome: "denied", Reason: "decryption_key_unavailable"})
		if errors.Is(err, ErrWrongMasterKey) {
			return nil, ErrMaterialCannotDecrypt
		}
		return nil, err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "material_use",
		Secret:  lease.SecretName,
		Version: versionID,
		LeaseID: lease.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
	})
	return &CheckedOutMaterial{
		SecretName: lease.SecretName,
		VersionID:  versionID,
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
	lease, record, err := s.authorizedLease(token, now)
	if err != nil {
		s.appendTokenDeniedAudit(ctx, "lease_query", token, now, err)
		return nil, err
	}
	view := lease.toView()
	view.VersionID = s.effectiveVersionIDLocked(lease, record)
	return view, nil
}

// AuditEventsForLease enforces scope at the query boundary: a borrower can
// inspect only its own lease ID. The full audit trail remains service-wide.
func (s *Service) AuditEventsForLease(ctx context.Context, token string) ([]AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	lease, record, err := s.authorizedLease(token, now)
	if err != nil {
		s.appendTokenDeniedAudit(ctx, "audit_query", token, now, err)
		return nil, err
	}
	if !leaseHasScope(lease, ScopeReadAudit) {
		s.appendLeaseDeniedAudit(ctx, "audit_query", lease, now, ErrLeaseScopeDenied)
		return nil, ErrLeaseScopeDenied
	}
	events, err := s.store.ReadAudit(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]AuditEvent, 0, len(events))
	for _, event := range events {
		if event.LeaseID == lease.ID || (record != nil && event.ActorLeaseID == lease.ID) {
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
	changed, err := s.settleLeaseBatchLocked(ctx, name, "", now, limit, now)
	if err != nil {
		return changed, err
	}
	if err := s.persistFactsLocked(ctx); err != nil {
		return changed, err
	}
	return changed, nil
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
	downstream := s.descendantLeasesLocked(lease.ID)
	for _, descendant := range downstream {
		if descendant.RevokedAt.IsZero() {
			descendant.RevokedAt = now.UTC()
			if err := s.store.SaveLease(ctx, descendant); err != nil {
				return err
			}
			s.store.AppendAudit(ctx, AuditEvent{
				At:            now.UTC(),
				Action:        "lease_revoked",
				Secret:        descendant.SecretName,
				Version:       descendant.VersionID,
				LeaseID:       descendant.ID,
				ActorLeaseID:  lease.ID,
				ParentLeaseID: descendant.ParentID,
				KeyID:         s.key.ID(),
				Outcome:       "ok",
				Reason:        "upstream_revoked",
			})
		}
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
	if err := s.persistFactsLocked(ctx); err != nil {
		return err
	}
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

func (s *Service) authorizedLease(token string, now time.Time) (*LeaseRecord, *SecretRecord, error) {
	lease, ok := s.store.Leases[hashToken(token)]
	if !ok {
		return nil, nil, ErrInvalidLease
	}
	if err := s.upstreamLeaseErrorLocked(lease, now); err != nil {
		return nil, nil, err
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

func (s *Service) upstreamLeaseErrorLocked(lease *LeaseRecord, now time.Time) error {
	for parentID := lease.ParentID; parentID != ""; {
		parent := s.leaseByIDLocked(parentID)
		if parent == nil {
			return ErrUpstreamLeaseRevoked
		}
		if !parent.RevokedAt.IsZero() {
			return ErrUpstreamLeaseRevoked
		}
		if !now.Before(parent.ExpiresAt) {
			return ErrUpstreamLeaseExpired
		}
		parentID = parent.ParentID
	}
	return nil
}

func (s *Service) leaseByIDLocked(id string) *LeaseRecord {
	for _, lease := range s.store.Leases {
		if lease.ID == id {
			return lease
		}
	}
	return nil
}

func (s *Service) descendantLeasesLocked(rootID string) []*LeaseRecord {
	childrenByParent := make(map[string][]*LeaseRecord)
	for _, lease := range s.store.Leases {
		if lease.ParentID != "" {
			childrenByParent[lease.ParentID] = append(childrenByParent[lease.ParentID], lease)
		}
	}
	var result []*LeaseRecord
	queue := append([]*LeaseRecord(nil), childrenByParent[rootID]...)
	for len(queue) > 0 {
		lease := queue[0]
		queue = queue[1:]
		result = append(result, lease)
		queue = append(queue, childrenByParent[lease.ID]...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (s *Service) effectiveVersionIDLocked(lease *LeaseRecord, record *SecretRecord) string {
	if lease.AllowsNewVersions && s.chainAllowsNewVersionsLocked(lease, record) {
		return record.CurrentVersionID
	}
	return lease.VersionID
}

func (s *Service) chainAllowsNewVersionsLocked(lease *LeaseRecord, record *SecretRecord) bool {
	for current := lease; current != nil; {
		if !current.AllowsNewVersions {
			return false
		}
		if current.ParentID == "" {
			return true
		}
		current = s.leaseByIDLocked(current.ParentID)
		if current == nil || current.SecretName != record.Name {
			return false
		}
	}
	return false
}

func (s *Service) adoptCurrentVersionBatchLocked(ctx context.Context, record *SecretRecord, now time.Time) (int, error) {
	var ids []string
	for _, lease := range s.store.Leases {
		if lease.SecretName != record.Name || !lease.IsActive(now) || !lease.hasActiveChainLocked(s, now) || !lease.AllowsNewVersions {
			continue
		}
		if !s.chainAllowsNewVersionsLocked(lease, record) || lease.VersionID == record.CurrentVersionID {
			continue
		}
		ids = append(ids, lease.ID)
	}
	sort.Strings(ids)
	changed := 0
	for _, id := range ids {
		lease := s.leaseByIDLocked(id)
		if lease == nil || !lease.IsActive(now) || !lease.hasActiveChainLocked(s, now) || !s.chainAllowsNewVersionsLocked(lease, record) || lease.VersionID == record.CurrentVersionID {
			continue
		}
		previous := lease.VersionID
		lease.VersionID = record.CurrentVersionID
		if err := s.store.SaveLease(ctx, lease); err != nil {
			lease.VersionID = previous
			return changed, err
		}
		changed++
		s.store.AppendAudit(ctx, AuditEvent{
			At:            now.UTC(),
			Action:        "lease_version_adopted",
			Secret:        record.Name,
			Version:       record.CurrentVersionID,
			PriorVersion:  previous,
			LeaseID:       lease.ID,
			ParentLeaseID: lease.ParentID,
			KeyID:         s.key.ID(),
			Outcome:       "ok",
		})
	}
	return changed, nil
}

func purposeWithin(parentPurpose, childPurpose string) bool {
	return childPurpose == parentPurpose || strings.HasPrefix(childPurpose, parentPurpose+"/")
}

func scopesWithin(childScopes []Scope, parentScopes []string) bool {
	for _, scope := range childScopes {
		found := false
		for _, parentScope := range parentScopes {
			if string(scope) == parentScope {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *Service) appendTokenDeniedAudit(ctx context.Context, action, token string, now time.Time, err error) {
	event := AuditEvent{At: now.UTC(), Action: action, Outcome: "denied", Reason: safeReason(err)}
	if lease := s.leaseByTokenHashLocked(hashToken(token)); lease != nil {
		event.Secret = lease.SecretName
		event.Version = lease.VersionID
		event.LeaseID = lease.ID
		if lease.ParentID != "" {
			event.ParentLeaseID = lease.ParentID
		}
	}
	s.store.AppendAudit(ctx, event)
}

func (s *Service) leaseByTokenHashLocked(tokenHash string) *LeaseRecord {
	return s.store.Leases[tokenHash]
}

func (s *Service) appendLeaseDeniedAudit(ctx context.Context, action string, lease *LeaseRecord, now time.Time, err error) {
	event := AuditEvent{
		At:      now.UTC(),
		Action:  action,
		Outcome: "denied",
		Secret:  lease.SecretName,
		Version: lease.VersionID,
		LeaseID: lease.ID,
		Reason:  safeReason(err),
	}
	if lease.ParentID != "" {
		event.ParentLeaseID = lease.ParentID
	}
	s.store.AppendAudit(ctx, event)
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
		if lease.SecretName != name || !lease.IsActive(now) || !lease.hasActiveChainLocked(s, now) {
			continue
		}
		if s.effectiveVersionIDLocked(lease, record) == record.CurrentVersionID {
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

func (r *LeaseRecord) hasActiveChainLocked(s *Service, now time.Time) bool {
	return s.upstreamLeaseErrorLocked(r, now) == nil
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
	case errors.Is(err, ErrUpstreamLeaseExpired):
		return ErrUpstreamLeaseExpired.Error()
	case errors.Is(err, ErrUpstreamLeaseRevoked):
		return ErrUpstreamLeaseRevoked.Error()
	case errors.Is(err, ErrLeaseScopeDenied):
		return "scope_denied"
	case errors.Is(err, ErrDelegationDenied):
		return "delegation_denied"
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
