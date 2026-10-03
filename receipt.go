package localsecretmaterials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	// ErrReceiptInvalid is returned by verification helpers when the receipt
	// or its supporting authorization facts fail any integrity check.
	ErrReceiptInvalid = errors.New("usage receipt failed verification")
)

// ReceiptOptions controls how much business detail a receipt discloses.
type ReceiptOptions struct {
	// PurposeHint is an optional disclosed prefix of the leaf lease purpose.
	// The full purpose only ever appears as a hash inside the receipt, so a
	// borrower can redact the business description down to any prefix. A hint
	// that is not a prefix of the real purpose is rejected at issuance.
	PurposeHint string
}

// LeaseFact is the persisted authorization snapshot of one lease. Facts are
// the service-side record a receipt is verified against; they carry no
// bearer token and no material plaintext.
type LeaseFact struct {
	LeaseID           string    `json:"lease_id"`
	ParentID          string    `json:"parent_id,omitempty"`
	SecretName        string    `json:"secret_name"`
	VersionID         string    `json:"version_id"`
	PriorVersionIDs   []string  `json:"prior_version_ids,omitempty"`
	Purpose           string    `json:"purpose"`
	Scopes            []string  `json:"scopes"`
	AllowsNewVersions bool      `json:"allows_new_versions,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	// GrantedExpiresAt is the expiry fixed at issuance. Grace-period settling
	// only shortens the mutable ExpiresAt, so a receipt can still be judged
	// against the deadline that was in force when the use happened.
	GrantedExpiresAt time.Time `json:"granted_expires_at"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	// PriorFactHashes retains the fact hashes of every earlier state of this
	// lease (version adoption, expiry settling). Offline verification accepts
	// a chain link captured at an earlier use while current-state checks use
	// the latest snapshot.
	PriorFactHashes []string `json:"prior_fact_hashes,omitempty"`
	FactHash        string   `json:"fact_hash"`
}

// VersionFact binds a material version to a digest of its ciphertext. The
// plaintext never appears in facts, receipts, or verification output.
type VersionFact struct {
	VersionID      string `json:"version_id"`
	Number         int    `json:"number"`
	KeyID          string `json:"key_id"`
	MaterialDigest string `json:"material_digest"`
}

// SecretFact is the persisted per-secret authorization anchor.
type SecretFact struct {
	Name             string        `json:"name"`
	CurrentVersionID string        `json:"current_version_id"`
	Versions         []VersionFact `json:"versions"`
}

// AuthorizationFacts is the offline-verifiable record of every authorization
// a receipt can depend on. It is persisted next to the other store files so
// reopening the service keeps issued receipts traceable.
type AuthorizationFacts struct {
	Secrets map[string]*SecretFact `json:"secrets"`
	Leases  map[string]*LeaseFact  `json:"leases"`
	// Usages is the append-only record of uses that actually happened and
	// were issued a receipt. A receipt whose occurrence is absent cannot be
	// confirmed: verification reports inconclusive rather than valid.
	Usages map[string]*UsageFact `json:"usages"`
}

// UsageFact is the immutable record of one specific occurrence: the exact
// object version, leaf lease, purpose, decision, full delegation chain and
// time captured when the service allowed the use. It is the anchor that stops
// an old receipt being rewritten into a use of a different material version
// or spliced together from parallel authorization records. It carries no
// material plaintext and no full business purpose, only their hashes.
type UsageFact struct {
	ReceiptID      string    `json:"receipt_id"`
	SecretName     string    `json:"secret_name"`
	VersionID      string    `json:"version_id"`
	MaterialDigest string    `json:"material_digest"`
	Decision       string    `json:"decision"`
	LeaseID        string    `json:"lease_id"`
	PurposeHash    string    `json:"purpose_hash"`
	Chain          []string  `json:"chain"`
	IssuedAt       time.Time `json:"issued_at"`
	FactHash       string    `json:"fact_hash"`
}

// UsageReceipt proves one specific use matched the complete delegation chain
// at use time. It discloses hashes plus an optional purpose prefix only; the
// full purpose and the material stay out of the receipt.
type UsageReceipt struct {
	ID             string `json:"id"`
	SecretName     string `json:"secret_name"`
	VersionID      string `json:"version_id"`
	MaterialDigest string `json:"material_digest"`
	Decision       string `json:"decision"`
	LeaseID        string `json:"lease_id"`
	PurposeHint    string `json:"purpose_hint,omitempty"`
	// PurposeHash binds the full leaf purpose without disclosing it.
	PurposeHash string `json:"purpose_hash"`
	// UsageHash binds the persisted occurrence record (UsageFact). Without a
	// matching, service-recorded occurrence the receipt proves nothing.
	UsageHash   string    `json:"usage_hash"`
	Chain       []string  `json:"chain"`
	IssuedAt    time.Time `json:"issued_at"`
	ReceiptHash string    `json:"receipt_hash"`
}

// Verification statuses. "inconclusive" means required authorization facts
// are missing, which must never be reported either as illegal or as currently
// usable.
const (
	ReceiptStatusValid        = "valid"
	ReceiptStatusHistorical   = "historical"
	ReceiptStatusInconclusive = "inconclusive"
	ReceiptStatusInvalid      = "invalid"
)

// ReceiptVerification is the outcome of offline receipt verification. It
// distinguishes "the use was legitimate at the time" from "the same lease
// could not be used now", and never contains material plaintext.
type ReceiptVerification struct {
	// Status is one of the ReceiptStatus* constants.
	Status          string `json:"status"`
	Valid           bool   `json:"valid"`
	CurrentlyUsable bool   `json:"currently_usable"`
	Reason          string `json:"reason,omitempty"`
}

// UseWithReceipt performs a normal authorized use and, only when the use is
// allowed, issues a hash-chained receipt covering the full delegation chain.
func (s *Service) UseWithReceipt(ctx context.Context, token string, opts ReceiptOptions) (*CheckedOutMaterial, *UsageReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	lease, record, err := s.authorizedLease(token, now)
	if err != nil {
		s.appendTokenDeniedAudit(ctx, "material_use", token, now, err)
		return nil, nil, err
	}
	versionID := s.effectiveVersionIDLocked(lease, record)
	if !leaseHasScope(lease, ScopeReadMaterial) {
		s.appendLeaseDeniedAudit(ctx, "material_use", lease, now, ErrLeaseScopeDenied)
		return nil, nil, ErrLeaseScopeDenied
	}
	if opts.PurposeHint != "" && !strings.HasPrefix(lease.Purpose, opts.PurposeHint) {
		return nil, nil, fmt.Errorf("%w: purpose hint is not a prefix of the lease purpose", ErrInvalidArgument)
	}
	encrypted := record.Version(versionID)
	if encrypted == nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: versionID, LeaseID: lease.ID, Outcome: "denied", Reason: "decryption_key_unavailable"})
		return nil, nil, fmt.Errorf("%w: version %s is missing", ErrMaterialCannotDecrypt, versionID)
	}
	plaintext, err := s.key.Open(encrypted)
	if err != nil {
		s.store.AppendAudit(ctx, AuditEvent{At: now.UTC(), Action: "material_use", Secret: lease.SecretName, Version: versionID, LeaseID: lease.ID, KeyID: s.key.ID(), Outcome: "denied", Reason: "decryption_key_unavailable"})
		if errors.Is(err, ErrWrongMasterKey) {
			return nil, nil, ErrMaterialCannotDecrypt
		}
		return nil, nil, err
	}

	receipt, err := s.buildReceiptLocked(lease, record, versionID, encrypted, opts.PurposeHint, now)
	if err != nil {
		return nil, nil, err
	}
	if err := s.persistFactsLocked(ctx); err != nil {
		return nil, nil, err
	}
	s.store.AppendAudit(ctx, AuditEvent{
		At:      now.UTC(),
		Action:  "usage_receipt_issued",
		Secret:  lease.SecretName,
		Version: versionID,
		LeaseID: lease.ID,
		KeyID:   s.key.ID(),
		Outcome: "ok",
		Reason:  receipt.ID,
	})
	return &CheckedOutMaterial{
		SecretName: lease.SecretName,
		VersionID:  versionID,
		Purpose:    lease.Purpose,
		Plaintext:  plaintext,
		ExpiresAt:  lease.ExpiresAt,
	}, receipt, nil
}

// AuthorizationFactsSnapshot returns a deep copy of the persisted
// authorization facts so callers can archive or verify receipts offline.
func (s *Service) AuthorizationFactsSnapshot(ctx context.Context) (*AuthorizationFacts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persistFactsLocked(ctx); err != nil {
		return nil, err
	}
	return cloneJSON(s.store.Facts), nil
}

// VerifyReceipt checks a receipt against persisted authorization facts. It is
// a pure function: it needs no service, no master key, and no network, and it
// never sees material plaintext. Any removed delegation layer, substituted
// object, rewritten version, or merged cross-chain permission makes the
// receipt invalid; a required fact being absent is inconclusive.
func VerifyReceipt(receipt *UsageReceipt, facts *AuthorizationFacts, now time.Time) *ReceiptVerification {
	if receipt == nil || facts == nil {
		return inconclusive("missing receipt or facts")
	}
	if receipt.Decision != "allowed" {
		return invalid("receipt decision is not allowed")
	}
	if recomputeReceiptHash(receipt) != receipt.ReceiptHash {
		return invalid("receipt hash mismatch")
	}

	// The receipt must anchor to one specific, service-recorded occurrence.
	// Rewriting any field (version, digest, lease, decision, chain, time) and
	// recomputing the receipt hash does not help: the persisted UsageFact is
	// not rewritten and this binding fails.
	usage := facts.Usages[receipt.ID]
	if usage == nil {
		return inconclusive("the recorded use this receipt claims is not present in authorization facts")
	}
	if recomputeUsageFactHash(usage) != usage.FactHash || usage.ReceiptID != receipt.ID || usage.FactHash != receipt.UsageHash ||
		usage.SecretName != receipt.SecretName || usage.VersionID != receipt.VersionID ||
		usage.MaterialDigest != receipt.MaterialDigest || usage.Decision != receipt.Decision ||
		usage.LeaseID != receipt.LeaseID || usage.PurposeHash != receipt.PurposeHash ||
		!usage.IssuedAt.Equal(receipt.IssuedAt) || !sameStringSlice(usage.Chain, receipt.Chain) {
		return invalid("receipt does not match the single recorded use occurrence")
	}
	secret := facts.Secrets[receipt.SecretName]
	if secret == nil {
		return inconclusive("secret not present in authorization facts")
	}
	var versionFact *VersionFact
	for i := range secret.Versions {
		if secret.Versions[i].VersionID == receipt.VersionID {
			versionFact = &secret.Versions[i]
			break
		}
	}
	if versionFact == nil || versionFact.MaterialDigest != receipt.MaterialDigest {
		return invalid("material digest does not match the pinned version")
	}

	// Rebuild the single delegation chain from the facts, leaf to root. The
	// receipt must match exactly this one chain; permissions from parallel
	// chains cannot be merged in.
	var chain []*LeaseFact
	for id := receipt.LeaseID; id != ""; {
		fact := facts.Leases[id]
		if fact == nil {
			return inconclusive("delegation layer missing from authorization facts")
		}
		if fact.SecretName != receipt.SecretName {
			return invalid("delegation layer belongs to a different secret")
		}
		chain = append(chain, fact)
		for _, seen := range chain[:len(chain)-1] {
			if seen.LeaseID == fact.ParentID {
				return invalid("delegation chain contains a cycle")
			}
		}
		id = fact.ParentID
	}
	if len(chain) != len(receipt.Chain) {
		return invalid("delegation chain length mismatch")
	}
	parentLink := ""
	for i := len(chain) - 1; i >= 0; i-- {
		// The link must match the layer state captured at the recorded use:
		// its current fact hash or a retained prior hash.
		link := ""
		for _, candidate := range append([]string{chain[i].FactHash}, chain[i].PriorFactHashes...) {
			if candidate == "" {
				continue
			}
			if chainLinkHash(candidate, parentLink) == receipt.Chain[i] {
				link = receipt.Chain[i]
				break
			}
		}
		if link != receipt.Chain[i] {
			return invalid("delegation chain link mismatch")
		}
		parentLink = link
	}

	leaf := chain[0]
	if !factHasScope(leaf, ScopeReadMaterial) {
		return invalid("leaf lease lacks material read scope")
	}
	if purposeHashValue(leaf.Purpose) != receipt.PurposeHash {
		return invalid("purpose hash does not match the leaf lease purpose")
	}
	if receipt.PurposeHint != "" && !strings.HasPrefix(leaf.Purpose, receipt.PurposeHint) {
		return invalid("disclosed purpose hint does not match the lease purpose")
	}
	for i := 1; i < len(chain); i++ {
		child, parent := chain[i-1], chain[i]
		if child.ParentID != parent.LeaseID {
			return invalid("delegation chain parent link mismatch")
		}
		if !purposeWithin(parent.Purpose, child.Purpose) {
			return invalid("delegated purpose escapes upstream purpose")
		}
		if !scopesWithin(scopeStrings(child.Scopes), parent.Scopes) {
			return invalid("delegated scope escapes upstream scope")
		}
		if child.ExpiresAt.After(parent.ExpiresAt) {
			return invalid("delegated expiry escapes upstream expiry")
		}
	}

	// The used version must be one the leaf lease actually held at some point:
	// its pinned version or one adopted after rotation. A later version the
	// leaf never adopted, or another secret's version, cannot be substituted.
	if !leaseEverHeldVersion(leaf, receipt.VersionID) {
		return invalid("used version was never authorized for the leaf lease")
	}

	// Legitimacy at the time of the recorded use. GrantedExpiresAt is the
	// deadline fixed at issuance, unaffected by later grace settling.
	for _, fact := range chain {
		if !fact.RevokedAt.IsZero() && fact.RevokedAt.Before(receipt.IssuedAt) {
			return invalid("recorded use happened after a chain revocation")
		}
		issuedExpiry := fact.GrantedExpiresAt
		if issuedExpiry.IsZero() {
			issuedExpiry = fact.ExpiresAt
		}
		if !receipt.IssuedAt.Before(issuedExpiry) {
			return invalid("recorded use happened after a chain expiry")
		}
	}

	verification := &ReceiptVerification{Status: ReceiptStatusValid, Valid: true, CurrentlyUsable: true}
	for _, fact := range chain {
		switch {
		case !fact.RevokedAt.IsZero():
			verification.CurrentlyUsable = false
			verification.Reason = "upstream or leaf lease has since been revoked"
		case !now.Before(fact.ExpiresAt):
			verification.CurrentlyUsable = false
			verification.Reason = "upstream or leaf lease has since expired"
		}
		if !verification.CurrentlyUsable {
			verification.Status = ReceiptStatusHistorical
			return verification
		}
	}
	return verification
}

func invalid(reason string) *ReceiptVerification {
	return &ReceiptVerification{Status: ReceiptStatusInvalid, Reason: reason}
}

func inconclusive(reason string) *ReceiptVerification {
	return &ReceiptVerification{Status: ReceiptStatusInconclusive, Reason: reason}
}

func leaseEverHeldVersion(fact *LeaseFact, versionID string) bool {
	if fact.VersionID == versionID {
		return true
	}
	for _, prior := range fact.PriorVersionIDs {
		if prior == versionID {
			return true
		}
	}
	return false
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Service) buildReceiptLocked(lease *LeaseRecord, record *SecretRecord, versionID string, encrypted *EncryptedVersion, hint string, now time.Time) (*UsageReceipt, error) {
	var chain []*LeaseRecord
	for current := lease; current != nil; {
		chain = append(chain, current)
		if current.ParentID == "" {
			break
		}
		current = s.leaseByIDLocked(current.ParentID)
	}
	links := make([]string, len(chain))
	parentLink := ""
	for i := len(chain) - 1; i >= 0; i-- {
		fact := leaseFactFromRecord(chain[i])
		links[i] = chainLinkHash(fact.FactHash, parentLink)
		parentLink = links[i]
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	receipt := &UsageReceipt{
		ID:             "rcpt_" + hex.EncodeToString(idBytes),
		SecretName:     record.Name,
		VersionID:      versionID,
		MaterialDigest: materialDigest(encrypted),
		Decision:       "allowed",
		LeaseID:        lease.ID,
		PurposeHint:    hint,
		PurposeHash:    purposeHashValue(lease.Purpose),
		Chain:          links,
		IssuedAt:       now.UTC(),
	}
	// Persist the immutable occurrence first, then bind the receipt to it.
	// The verifier re-derives both directions, so the receipt cannot be moved
	// onto another occurrence and the occurrence cannot forge the receipt.
	usage := &UsageFact{
		ReceiptID:      receipt.ID,
		SecretName:     receipt.SecretName,
		VersionID:      receipt.VersionID,
		MaterialDigest: receipt.MaterialDigest,
		Decision:       receipt.Decision,
		LeaseID:        receipt.LeaseID,
		PurposeHash:    receipt.PurposeHash,
		Chain:          append([]string(nil), receipt.Chain...),
		IssuedAt:       receipt.IssuedAt,
	}
	usage.FactHash = recomputeUsageFactHash(usage)
	receipt.UsageHash = usage.FactHash
	receipt.ReceiptHash = recomputeReceiptHash(receipt)
	return receipt, s.store.AppendUsageFact(usage)
}

// persistFactsLocked rewrites the authorization facts file from the current
// store state. Facts are derived data: leases keep their latest snapshot and
// versions keep their ciphertext digests, so reopened processes can still
// trace every fact an earlier receipt depends on.
func (s *Service) persistFactsLocked(ctx context.Context) error {
	facts := &AuthorizationFacts{
		Secrets: make(map[string]*SecretFact),
		Leases:  make(map[string]*LeaseFact),
		Usages:  make(map[string]*UsageFact),
	}
	for name, record := range s.store.Materials {
		secret := &SecretFact{Name: name, CurrentVersionID: record.CurrentVersionID}
		for _, version := range record.Versions {
			secret.Versions = append(secret.Versions, VersionFact{
				VersionID:      version.ID,
				Number:         version.Number,
				KeyID:          version.KeyID,
				MaterialDigest: materialDigest(version),
			})
		}
		sort.Slice(secret.Versions, func(i, j int) bool { return secret.Versions[i].Number < secret.Versions[j].Number })
		facts.Secrets[name] = secret
	}
	for _, lease := range s.store.Leases {
		facts.Leases[lease.ID] = leaseFactFromRecord(lease)
	}
	for id, usage := range s.store.UsageFacts {
		facts.Usages[id] = cloneJSON(usage)
	}
	return s.store.SaveFacts(ctx, facts)
}

func leaseFactFromRecord(lease *LeaseRecord) *LeaseFact {
	fact := &LeaseFact{
		LeaseID:           lease.ID,
		ParentID:          lease.ParentID,
		SecretName:        lease.SecretName,
		VersionID:         lease.VersionID,
		PriorVersionIDs:   append([]string(nil), lease.PriorVersionIDs...),
		Purpose:           lease.Purpose,
		Scopes:            append([]string(nil), lease.Scopes...),
		AllowsNewVersions: lease.AllowsNewVersions,
		IssuedAt:          lease.IssuedAt,
		ExpiresAt:         lease.ExpiresAt,
		GrantedExpiresAt:  lease.GrantedExpiresAt,
		RevokedAt:         lease.RevokedAt,
		PriorFactHashes:   append([]string(nil), lease.PriorFactHashes...),
	}
	fact.FactHash = factHash(fact)
	return fact
}

// purposeHashValue binds the full purpose without disclosing it; a verifier
// can confirm a redacted hint without seeing the business description.
func purposeHashValue(purpose string) string {
	sum := sha256.Sum256([]byte("lease-purpose-v1:" + purpose))
	return hex.EncodeToString(sum[:])
}

// recomputeUsageFactHash binds the immutable occurrence, including the full
// delegation chain captured at use time. It never contains the plaintext or
// the undisclosed purpose text.
func recomputeUsageFactHash(usage *UsageFact) string {
	clone := *usage
	clone.FactHash = ""
	return hashCanonical("usage-fact-v1", &clone)
}

// factHash binds the lease authorization state. Revocation stays outside the
// hash so a then-legitimate receipt keeps verifying while the facts record
// the chain is unusable now. Version adoption and expiry settling produce a
// new hash while the previous one is retained in PriorFactHashes.
func factHash(fact *LeaseFact) string {
	clone := *fact
	clone.FactHash = ""
	clone.RevokedAt = time.Time{}
	clone.PriorFactHashes = nil
	return hashCanonical("lease-fact-v1", &clone)
}

func chainLinkHash(factHashValue, parentLinkHash string) string {
	sum := sha256.Sum256([]byte("chain-link-v1:" + factHashValue + ":" + parentLinkHash))
	return hex.EncodeToString(sum[:])
}

func recomputeReceiptHash(receipt *UsageReceipt) string {
	clone := *receipt
	clone.ReceiptHash = ""
	return hashCanonical("usage-receipt-v1", &clone)
}

func hashCanonical(domain string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte(domain+":"), encoded...))
	return hex.EncodeToString(sum[:])
}

// materialDigest binds a receipt to exactly one encrypted version without
// exposing the plaintext.
func materialDigest(version *EncryptedVersion) string {
	ciphertext, err := base64.StdEncoding.DecodeString(version.CiphertextB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("material-digest-v1:"), ciphertext...))
	return hex.EncodeToString(sum[:])
}

func factHasScope(fact *LeaseFact, scope Scope) bool {
	for _, value := range fact.Scopes {
		if Scope(value) == scope {
			return true
		}
	}
	return false
}
