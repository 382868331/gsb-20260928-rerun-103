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
	Purpose           string    `json:"purpose,omitempty"`
	PurposeHash       string    `json:"purpose_hash"`
	Scopes            []string  `json:"scopes"`
	AllowsNewVersions bool      `json:"allows_new_versions,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
	FactHash          string    `json:"fact_hash"`
}

// ReceiptRecord is the service-side record that one specific use actually
// happened. It pins the exact object version, decision, disclosed purpose,
// and the identity and link hashes of the full delegation chain that
// authorized that single use. A receipt is never self-certifying: without a
// matching record among the verifier's held facts, the use cannot be
// confirmed and verification stays undetermined rather than valid.
type ReceiptRecord struct {
	ReceiptID      string   `json:"receipt_id"`
	SecretName     string   `json:"secret_name"`
	VersionID      string   `json:"version_id"`
	MaterialDigest string   `json:"material_digest"`
	Decision       string   `json:"decision"`
	PurposeHint    string   `json:"purpose_hint,omitempty"`
	LeaseIDs       []string `json:"lease_ids"`
	ChainLinks     []string `json:"chain_links"`
	// PurposeWitnesses[i] vouches, without disclosing any business text, that
	// chain[i-1].Purpose lies within chain[i].Purpose. The service checked the
	// containment at delegation time; a verifier holding hash-only purposes
	// recomputes the witness from the disclosed purpose hashes.
	PurposeWitnesses []string  `json:"purpose_witnesses,omitempty"`
	IssuedAt         time.Time `json:"issued_at"`
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
	Secrets  map[string]*SecretFact    `json:"secrets"`
	Leases   map[string]*LeaseFact     `json:"leases"`
	Receipts map[string]*ReceiptRecord `json:"receipts,omitempty"`
}

// Verification status values. "valid" means the held facts establish that
// exactly this use occurred and was allowed then; "invalid" means the held
// facts contradict the receipt (forgery or splicing); "undetermined" means
// the held facts are insufficient to confirm the use, so it must neither be
// treated as illegal nor claimed currently usable.
const (
	StatusValid        = "valid"
	StatusInvalid      = "invalid"
	StatusUndetermined = "undetermined"
)

// UsageReceipt proves one specific use matched the complete delegation chain
// at use time. It discloses hashes plus an optional purpose prefix only; the
// full purpose and the material stay out of the receipt. The purpose hint is
// a redactable business note: the holder may clear or shorten it before
// showing the receipt, and verification still succeeds as long as the
// remaining hint is a prefix of the hint registered for this use.
type UsageReceipt struct {
	ID             string    `json:"id"`
	SecretName     string    `json:"secret_name"`
	VersionID      string    `json:"version_id"`
	MaterialDigest string    `json:"material_digest"`
	Decision       string    `json:"decision"`
	LeaseID        string    `json:"lease_id"`
	PurposeHint    string    `json:"purpose_hint,omitempty"`
	Chain          []string  `json:"chain"`
	IssuedAt       time.Time `json:"issued_at"`
	ReceiptHash    string    `json:"receipt_hash"`
}

// ReceiptVerification is the outcome of offline receipt verification. It
// distinguishes "the use was legitimate at the time" from "the same lease
// could not be used now", and never contains material plaintext.
type ReceiptVerification struct {
	// Status is one of StatusValid, StatusInvalid, or StatusUndetermined.
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

	receipt, receiptRecord, err := s.buildReceiptLocked(lease, record, versionID, encrypted, opts.PurposeHint, now)
	if err != nil {
		return nil, nil, err
	}
	if s.store.Facts == nil {
		s.store.Facts = &AuthorizationFacts{}
	}
	if s.store.Facts.Receipts == nil {
		s.store.Facts.Receipts = make(map[string]*ReceiptRecord)
	}
	s.store.Facts.Receipts[receipt.ID] = receiptRecord
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
// object, or merged cross-chain permission makes Valid false.
func VerifyReceipt(receipt *UsageReceipt, facts *AuthorizationFacts, now time.Time) *ReceiptVerification {
	undetermined := func(reason string) *ReceiptVerification {
		return &ReceiptVerification{Status: StatusUndetermined, Reason: reason}
	}
	invalid := func(reason string) *ReceiptVerification {
		return &ReceiptVerification{Status: StatusInvalid, Valid: false, Reason: reason}
	}
	if receipt == nil || facts == nil {
		return undetermined("missing receipt or facts")
	}
	if receipt.Decision != "allowed" {
		return invalid("receipt decision is not allowed")
	}
	if recomputeReceiptHash(receipt) != receipt.ReceiptHash {
		return invalid("receipt hash mismatch")
	}

	// A receipt is only a claim. The claim is accepted only when the held
	// facts contain the service-registered record of exactly this use.
	record := facts.Receipts[receipt.ID]
	if record == nil {
		return undetermined("no registered usage event matches this receipt")
	}
	if receipt.SecretName != record.SecretName ||
		receipt.VersionID != record.VersionID ||
		receipt.MaterialDigest != record.MaterialDigest ||
		receipt.Decision != record.Decision ||
		len(record.LeaseIDs) == 0 || receipt.LeaseID != record.LeaseIDs[0] ||
		!receipt.IssuedAt.Equal(record.IssuedAt) ||
		len(receipt.Chain) != len(record.ChainLinks) {
		return invalid("receipt does not match the registered usage event")
	}
	// The purpose hint is a redactable business note, not an immutable usage
	// fact: the holder may clear it or shorten it after issuance. What stays
	// pinned is that whatever hint is still shown must be a prefix of the
	// hint the service registered for this exact use, so a hint cannot be
	// replaced, extended, or spliced in from another receipt.
	if !strings.HasPrefix(record.PurposeHint, receipt.PurposeHint) {
		return invalid("disclosed purpose hint does not match the registered usage event")
	}

	// Rebuild the single delegation chain named by the registered event,
	// leaf to root. Permissions from parallel chains cannot be merged in.
	var chain []*LeaseFact
	for i, id := range record.LeaseIDs {
		fact := facts.Leases[id]
		if fact == nil {
			return undetermined("a required delegation layer is absent from the held facts")
		}
		if fact.SecretName != record.SecretName {
			return invalid("delegation layer belongs to a different secret")
		}
		if i < len(record.LeaseIDs)-1 && fact.ParentID != record.LeaseIDs[i+1] {
			return invalid("delegation chain has been spliced with another lease")
		}
		if i == len(record.LeaseIDs)-1 && fact.ParentID != "" {
			return invalid("delegation chain stops before its root lease")
		}
		chain = append(chain, fact)
	}
	if len(chain) == 0 {
		return invalid("registered usage event carries no delegation chain")
	}

	// The link hashes pin the immutable authorization granted at issuance
	// for every required delegation layer. Recomputing them from the held
	// facts detects swapped layers and cross-receipt splicing even when the
	// facts have since recorded revocation or version adoption.
	parentLink := ""
	for i := len(chain) - 1; i >= 0; i-- {
		link := chainLinkHash(chain[i].FactHash, parentLink)
		if link != record.ChainLinks[i] || link != receipt.Chain[i] {
			return invalid("delegation chain link mismatch")
		}
		parentLink = link
	}

	// Confirm the used object: the version must be a real version of the
	// named secret with the claimed digest, and must be the version this
	// exact chain was authorized for at use time.
	secret := facts.Secrets[record.SecretName]
	if secret == nil {
		return undetermined("the used secret is absent from the held facts")
	}
	var versionFact *VersionFact
	for i := range secret.Versions {
		if secret.Versions[i].VersionID == record.VersionID {
			versionFact = &secret.Versions[i]
			break
		}
	}
	if versionFact == nil {
		return undetermined("the used version is absent from the held facts")
	}
	if versionFact.MaterialDigest != record.MaterialDigest {
		return invalid("material digest does not match the registered version")
	}
	allAdoptNew := true
	for _, fact := range chain {
		if !fact.AllowsNewVersions {
			allAdoptNew = false
		}
	}
	if !allAdoptNew {
		// A pinned chain authorizes exactly the leaf's pinned version, not
		// any later rotated version with an otherwise valid digest.
		if chain[0].VersionID != record.VersionID {
			return invalid("receipt version was not authorized by the pinned lease")
		}
	}

	leaf := chain[0]
	if factHash(leaf) != leaf.FactHash {
		return invalid("leaf lease fact hash does not match its contents")
	}
	if !factHasScope(leaf, ScopeReadMaterial) {
		return invalid("leaf lease lacks material read scope")
	}
	if receipt.PurposeHint != "" {
		if leaf.Purpose == "" {
			// Hash-only facts disclose no business text; the registered event
			// already pins the hint, and issuance guaranteed it was a prefix.
		} else if !strings.HasPrefix(leaf.Purpose, receipt.PurposeHint) {
			return invalid("disclosed purpose hint does not match the lease purpose")
		}
	}
	// Containment checks only run where the held facts disclose the fields.
	// A verifier holding hash-only facts cannot widen a conclusion from them.
	for i := 1; i < len(chain); i++ {
		child, parent := chain[i-1], chain[i]
		if factHash(child) != child.FactHash || factHash(parent) != parent.FactHash {
			return invalid("delegation fact hash does not match its contents")
		}
		if child.Purpose != "" && parent.Purpose != "" && !purposeWithin(parent.Purpose, child.Purpose) {
			return invalid("delegated purpose escapes upstream purpose")
		}
		if child.Purpose == "" || parent.Purpose == "" {
			witnessIndex := i - 1
			if witnessIndex >= len(record.PurposeWitnesses) ||
				purposeWitnessHash(parent.PurposeHash, child.PurposeHash) != record.PurposeWitnesses[witnessIndex] {
				return undetermined("held facts cannot confirm the delegated purpose stays within upstream purpose")
			}
		}
		if !scopesWithin(scopeStrings(child.Scopes), parent.Scopes) {
			return invalid("delegated scope escapes upstream scope")
		}
		if child.ExpiresAt.After(parent.ExpiresAt) {
			return invalid("delegated expiry escapes upstream expiry")
		}
	}
	for _, fact := range chain {
		if record.IssuedAt.Before(fact.IssuedAt) {
			return invalid("receipt predates a delegation layer it depends on")
		}
		if !record.IssuedAt.Before(fact.ExpiresAt) {
			return invalid("receipt was issued while a chain layer was already expired")
		}
	}

	verification := &ReceiptVerification{Status: StatusValid, Valid: true, CurrentlyUsable: true}
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
			return verification
		}
	}
	return verification
}

// RedactFactsForReceipt returns a minimal, verifier-safe subset of facts that
// is still sufficient to verify exactly the given receipt. The full business
// purpose is replaced by its hash on every delegation layer; only the leaf
// purpose backing a receipt's disclosed prefix is retained. No unrelated
// secret, lease, or usage event is included, and no material plaintext ever
// appears. A receipt that is not registered in the facts yields nil.
func RedactFactsForReceipt(facts *AuthorizationFacts, receipt *UsageReceipt) *AuthorizationFacts {
	if facts == nil || receipt == nil {
		return nil
	}
	record := facts.Receipts[receipt.ID]
	if record == nil {
		return nil
	}
	out := &AuthorizationFacts{
		Secrets:  map[string]*SecretFact{},
		Leases:   map[string]*LeaseFact{},
		Receipts: map[string]*ReceiptRecord{record.ReceiptID: cloneJSON(record)},
	}
	if secret := facts.Secrets[record.SecretName]; secret != nil {
		minimal := &SecretFact{Name: secret.Name, CurrentVersionID: secret.CurrentVersionID}
		for i := range secret.Versions {
			if secret.Versions[i].VersionID == record.VersionID {
				minimal.Versions = []VersionFact{secret.Versions[i]}
				break
			}
		}
		out.Secrets[secret.Name] = minimal
	}
	for _, id := range record.LeaseIDs {
		fact := facts.Leases[id]
		if fact == nil {
			continue
		}
		redacted := cloneJSON(fact)
		redacted.Purpose = ""
		out.Leases[id] = redacted
	}
	return out
}

func (s *Service) buildReceiptLocked(lease *LeaseRecord, record *SecretRecord, versionID string, encrypted *EncryptedVersion, hint string, now time.Time) (*UsageReceipt, *ReceiptRecord, error) {
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
		return nil, nil, err
	}
	receipt := &UsageReceipt{
		ID:             "rcpt_" + hex.EncodeToString(idBytes),
		SecretName:     record.Name,
		VersionID:      versionID,
		MaterialDigest: materialDigest(encrypted),
		Decision:       "allowed",
		LeaseID:        lease.ID,
		PurposeHint:    hint,
		Chain:          links,
		IssuedAt:       now.UTC(),
	}
	receipt.ReceiptHash = recomputeReceiptHash(receipt)
	leaseIDs := make([]string, len(chain))
	for i, layer := range chain {
		leaseIDs[i] = layer.ID
	}
	witnesses := make([]string, 0, len(chain)-1)
	for i := 0; i+1 < len(chain); i++ {
		witnesses = append(witnesses, purposeWitnessHash(purposeHash(chain[i+1].Purpose), purposeHash(chain[i].Purpose)))
	}
	registered := &ReceiptRecord{
		ReceiptID:        receipt.ID,
		SecretName:       receipt.SecretName,
		VersionID:        receipt.VersionID,
		MaterialDigest:   receipt.MaterialDigest,
		Decision:         receipt.Decision,
		PurposeHint:      receipt.PurposeHint,
		LeaseIDs:         leaseIDs,
		ChainLinks:       append([]string(nil), links...),
		PurposeWitnesses: witnesses,
		IssuedAt:         receipt.IssuedAt,
	}
	return receipt, registered, nil
}

// persistFactsLocked rewrites the authorization facts file from the current
// store state. Facts are derived data: leases keep their latest snapshot and
// versions keep their ciphertext digests, so reopened processes can still
// trace every fact an earlier receipt depends on.
func (s *Service) persistFactsLocked(ctx context.Context) error {
	facts := &AuthorizationFacts{
		Secrets:  make(map[string]*SecretFact),
		Leases:   make(map[string]*LeaseFact),
		Receipts: s.store.Facts.Receipts,
	}
	if facts.Receipts == nil {
		facts.Receipts = make(map[string]*ReceiptRecord)
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
	return s.store.SaveFacts(ctx, facts)
}

func leaseFactFromRecord(lease *LeaseRecord) *LeaseFact {
	fact := &LeaseFact{
		LeaseID:           lease.ID,
		ParentID:          lease.ParentID,
		SecretName:        lease.SecretName,
		VersionID:         lease.VersionID,
		Purpose:           lease.Purpose,
		PurposeHash:       purposeHash(lease.Purpose),
		Scopes:            append([]string(nil), lease.Scopes...),
		AllowsNewVersions: lease.AllowsNewVersions,
		IssuedAt:          lease.IssuedAt,
		ExpiresAt:         lease.ExpiresAt,
		RevokedAt:         lease.RevokedAt,
	}
	fact.FactHash = factHash(fact)
	return fact
}

// purposeHash binds the full purpose without ever needing to disclose it; a
// verifier holding redacted facts can still compare purposes by hash.
func purposeHash(purpose string) string {
	sum := sha256.Sum256([]byte("lease-purpose-v1:" + purpose))
	return hex.EncodeToString(sum[:])
}

// purposeWitnessHash vouches that childPurpose is within parentPurpose while
// exposing only their hashes. It is generated by the service from the real
// purposes at issuance and verified offline by hash-only verifiers.
func purposeWitnessHash(parentPurposeHashValue, childPurposeHashValue string) string {
	sum := sha256.Sum256([]byte("purpose-containment-v1:" + parentPurposeHashValue + ":" + childPurposeHashValue))
	return hex.EncodeToString(sum[:])
}

// factHash binds the immutable authorization granted at issuance: identity,
// parent, object, purpose hash, scopes, new-version adoption, and lifetime.
// Later state changes (revocation) and in-place new-version adoption stay
// outside the hash so a then-legitimate receipt keeps verifying while the
// facts record that the chain is unusable or on a newer version now. The
// registered usage record independently pins the exact version actually used.
func factHash(fact *LeaseFact) string {
	clone := *fact
	clone.FactHash = ""
	clone.RevokedAt = time.Time{}
	clone.VersionID = ""
	clone.Purpose = ""
	return hashCanonical("lease-fact-v1", &clone)
}

func chainLinkHash(factHashValue, parentLinkHash string) string {
	sum := sha256.Sum256([]byte("chain-link-v1:" + factHashValue + ":" + parentLinkHash))
	return hex.EncodeToString(sum[:])
}

func recomputeReceiptHash(receipt *UsageReceipt) string {
	clone := *receipt
	clone.ReceiptHash = ""
	// PurposeHint is a redactable business note, so it stays outside the
	// self-consistency hash: clearing or shortening it must not invalidate
	// an otherwise legitimate receipt. The registered usage event still
	// pins which hint prefixes may be shown for this use.
	clone.PurposeHint = ""
	return hashCanonical("usage-receipt-v1", &clone)
}

// RecomputeReceiptHash returns the self-consistency hash a receipt must
// carry. It is exported so offline verification tooling can reproduce the
// hash when inspecting or testing tampered receipts; it never makes an
// internally-consistent receipt valid on its own, since validity additionally
// requires the registered usage event among the verifier's facts.
func RecomputeReceiptHash(receipt *UsageReceipt) string {
	return recomputeReceiptHash(receipt)
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
