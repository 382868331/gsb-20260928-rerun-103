package localsecretmaterials

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	// ErrReceiptTampered is returned when a receipt fails offline verification:
	// the signature, the chain digest, or the internal linkage does not hold.
	ErrReceiptTampered = errors.New("usage receipt failed verification")
)

// Receipt decision values recorded as the final decision of one use.
const (
	ReceiptDecisionAllowed = "allowed"
	ReceiptDecisionDenied  = "denied"
)

// ReceiptChainLink commits to one delegation layer exactly as it was recorded
// when the receipt was issued. Purpose may be redacted; PurposeHash always
// commits to it so redaction never weakens verification.
type ReceiptChainLink struct {
	LeaseID     string    `json:"lease_id"`
	ParentID    string    `json:"parent_id,omitempty"`
	SecretName  string    `json:"secret_name"`
	VersionID   string    `json:"version_id"`
	Purpose     string    `json:"purpose,omitempty"`
	PurposeHash string    `json:"purpose_hash"`
	Scopes      []string  `json:"scopes"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	// FactHash commits to the persisted lease record this link relies on, so
	// the authorization facts stay traceable after the process restarts.
	FactHash string `json:"fact_hash"`
}

// UsageReceipt is an offline-verifiable attestation that one material use was
// decided under a complete delegation chain. It never carries material
// plaintext or bearer tokens.
type UsageReceipt struct {
	ID          string             `json:"id"`
	SecretName  string             `json:"secret_name"`
	VersionID   string             `json:"version_id"`
	LeaseID     string             `json:"lease_id"`
	Decision    string             `json:"decision"`
	Reason      string             `json:"reason,omitempty"`
	DecidedAt   time.Time          `json:"decided_at"`
	Chain       []ReceiptChainLink `json:"chain"`
	ChainDigest string             `json:"chain_digest"`
	SignerKeyID string             `json:"signer_key_id"`
	Signature   string             `json:"signature"`
}

// Redacted returns a copy of the receipt with cleartext purposes removed.
// The receipt still verifies: every link keeps its purpose commitment.
func (r *UsageReceipt) Redacted() *UsageReceipt {
	clone := cloneJSON(r)
	for i := range clone.Chain {
		clone.Chain[i].Purpose = ""
	}
	return clone
}

// receiptPayload is the canonical signed body. The signature field itself is
// excluded; JSON field order is fixed by struct order.
type receiptPayload struct {
	ID          string             `json:"id"`
	SecretName  string             `json:"secret_name"`
	VersionID   string             `json:"version_id"`
	LeaseID     string             `json:"lease_id"`
	Decision    string             `json:"decision"`
	Reason      string             `json:"reason,omitempty"`
	DecidedAt   time.Time          `json:"decided_at"`
	Chain       []ReceiptChainLink `json:"chain"`
	ChainDigest string             `json:"chain_digest"`
	SignerKeyID string             `json:"signer_key_id"`
}

func (r *UsageReceipt) payload() receiptPayload {
	// The signed body commits to purposes only through their hashes, so a
	// redacted receipt keeps the same valid signature.
	chain := make([]ReceiptChainLink, len(r.Chain))
	for i, link := range r.Chain {
		link.Purpose = ""
		chain[i] = link
	}
	return receiptPayload{
		ID:          r.ID,
		SecretName:  r.SecretName,
		VersionID:   r.VersionID,
		LeaseID:     r.LeaseID,
		Decision:    r.Decision,
		Reason:      r.Reason,
		DecidedAt:   r.DecidedAt.UTC(),
		Chain:       chain,
		ChainDigest: r.ChainDigest,
		SignerKeyID: r.SignerKeyID,
	}
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func hashHex(parts ...[]byte) string {
	digest := sha256.New()
	for _, part := range parts {
		digest.Write(part)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func purposeCommitment(purpose string) string {
	return hashHex([]byte("receipt-purpose-v1:" + purpose))
}

// leaseFactHash commits to the persisted authorization fact (the lease
// record) so a receipt stays traceable to stored state after restart.
func leaseFactHash(record *LeaseRecord) string {
	encoded, err := canonicalJSON(struct {
		ID                string    `json:"id"`
		ParentID          string    `json:"parent_id,omitempty"`
		SecretName        string    `json:"secret_name"`
		VersionID         string    `json:"version_id"`
		Purpose           string    `json:"purpose"`
		Scopes            []string  `json:"scopes,omitempty"`
		AllowsNewVersions bool      `json:"allows_new_versions,omitempty"`
		IssuedAt          time.Time `json:"issued_at"`
		ExpiresAt         time.Time `json:"expires_at"`
	}{
		ID:                record.ID,
		ParentID:          record.ParentID,
		SecretName:        record.SecretName,
		VersionID:         record.VersionID,
		Purpose:           record.Purpose,
		Scopes:            record.Scopes,
		AllowsNewVersions: record.AllowsNewVersions,
		IssuedAt:          record.IssuedAt.UTC(),
		ExpiresAt:         record.ExpiresAt.UTC(),
	})
	if err != nil {
		return ""
	}
	return hashHex([]byte("receipt-fact-v1:"), encoded)
}

// chainDigest folds the ordered links into one commitment. Cleartext
// purposes are excluded so redacted receipts keep the same digest; the
// purpose commitment stays inside each link. Because each step binds the
// previous digest, dropping or reordering any delegation layer, or splicing
// links from a second chain, changes the final digest.
func chainDigest(links []ReceiptChainLink) (string, error) {
	digest := hashHex([]byte("receipt-chain-v1"))
	for i := range links {
		link := links[i]
		link.Purpose = ""
		encoded, err := canonicalJSON(link)
		if err != nil {
			return "", err
		}
		digest = hashHex([]byte(digest), encoded)
	}
	return digest, nil
}

// VerifyReceipt checks a receipt offline against the service's receipt public
// key. It validates the signature, recomputes the chain digest, and confirms
// the chain is a single continuous delegation path ending at the lease that
// made the decision. It never needs, and never outputs, material plaintext.
func VerifyReceipt(receipt *UsageReceipt, publicKey ed25519.PublicKey) error {
	if receipt == nil {
		return fmt.Errorf("%w: missing receipt", ErrReceiptTampered)
	}
	if len(receipt.Chain) == 0 {
		return fmt.Errorf("%w: empty delegation chain", ErrReceiptTampered)
	}
	if receipt.Decision != ReceiptDecisionAllowed && receipt.Decision != ReceiptDecisionDenied {
		return fmt.Errorf("%w: unknown decision %q", ErrReceiptTampered, receipt.Decision)
	}
	digest, err := chainDigest(receipt.Chain)
	if err != nil {
		return err
	}
	if digest != receipt.ChainDigest {
		return fmt.Errorf("%w: chain digest mismatch", ErrReceiptTampered)
	}
	for i, link := range receipt.Chain {
		if link.LeaseID == "" || link.FactHash == "" || link.PurposeHash == "" {
			return fmt.Errorf("%w: chain link %d is incomplete", ErrReceiptTampered, i)
		}
		if link.Purpose != "" && purposeCommitment(link.Purpose) != link.PurposeHash {
			return fmt.Errorf("%w: purpose does not match its commitment in link %d", ErrReceiptTampered, i)
		}
		if link.SecretName != receipt.SecretName {
			return fmt.Errorf("%w: chain link %d names a different material", ErrReceiptTampered, i)
		}
		if i == 0 {
			if link.ParentID != "" {
				return fmt.Errorf("%w: chain root must not have a parent", ErrReceiptTampered)
			}
			continue
		}
		if link.ParentID != receipt.Chain[i-1].LeaseID {
			return fmt.Errorf("%w: chain link %d does not continue the delegation path", ErrReceiptTampered, i)
		}
		if link.ExpiresAt.After(receipt.Chain[i-1].ExpiresAt) {
			return fmt.Errorf("%w: chain link %d outlives its upstream", ErrReceiptTampered, i)
		}
		if !scopesWithinStrings(link.Scopes, receipt.Chain[i-1].Scopes) {
			return fmt.Errorf("%w: chain link %d exceeds upstream scopes", ErrReceiptTampered, i)
		}
	}
	leaf := receipt.Chain[len(receipt.Chain)-1]
	if leaf.LeaseID != receipt.LeaseID {
		return fmt.Errorf("%w: receipt subject is not the chain leaf", ErrReceiptTampered)
	}
	if leaf.VersionID != receipt.VersionID {
		return fmt.Errorf("%w: receipt version does not match the chain leaf", ErrReceiptTampered)
	}
	payload, err := canonicalJSON(receipt.payload())
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", ErrReceiptTampered)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("%w: signature invalid", ErrReceiptTampered)
	}
	return nil
}

func scopesWithinStrings(child, parent []string) bool {
	granted := make(map[string]bool, len(parent))
	for _, scope := range parent {
		granted[scope] = true
	}
	for _, scope := range child {
		if !granted[scope] {
			return false
		}
	}
	return true
}

// ReceiptFactStatus describes how one authorization fact behind a receipt
// looks in the current persisted state.
type ReceiptFactStatus struct {
	LeaseID         string `json:"lease_id"`
	MatchesStored   bool   `json:"matches_stored"`
	CurrentlyActive bool   `json:"currently_active"`
	Revoked         bool   `json:"revoked"`
	Expired         bool   `json:"expired"`
	UpstreamRevoked bool   `json:"upstream_revoked,omitempty"`
	UpstreamExpired bool   `json:"upstream_expired,omitempty"`
}

// ReceiptTrace is the result of tracing a receipt against persisted state.
type ReceiptTrace struct {
	ReceiptID  string              `json:"receipt_id"`
	Decision   string              `json:"decision"`
	Facts      []ReceiptFactStatus `json:"facts"`
	AllFactsOK bool                `json:"all_facts_ok"`
	// CurrentlyUsable reports whether the same lease could act right now. A
	// receipt can be a legitimate past decision while CurrentlyUsable is
	// false because an upstream was revoked or expired afterwards.
	CurrentlyUsable bool `json:"currently_usable"`
}

// TraceReceipt re-checks the authorization facts a verified receipt depends
// on against the persisted lease store. It distinguishes a decision that was
// legitimate at the time from present unavailability caused by later upstream
// revocation or expiry. It never touches material plaintext.
func (s *Service) TraceReceipt(ctx context.Context, receipt *UsageReceipt) (*ReceiptTrace, error) {
	if receipt == nil {
		return nil, fmt.Errorf("%w: missing receipt", ErrReceiptTampered)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	trace := &ReceiptTrace{
		ReceiptID:  receipt.ID,
		Decision:   receipt.Decision,
		AllFactsOK: true,
	}
	for _, link := range receipt.Chain {
		status := ReceiptFactStatus{LeaseID: link.LeaseID}
		stored := s.leaseByIDLocked(link.LeaseID)
		if stored == nil || leaseFactHash(stored) != link.FactHash {
			status.MatchesStored = false
			trace.AllFactsOK = false
			trace.Facts = append(trace.Facts, status)
			continue
		}
		status.MatchesStored = true
		status.Revoked = !stored.RevokedAt.IsZero()
		status.Expired = !now.Before(stored.ExpiresAt)
		upstreamErr := s.upstreamLeaseErrorLocked(stored, now)
		status.UpstreamRevoked = errors.Is(upstreamErr, ErrUpstreamLeaseRevoked)
		status.UpstreamExpired = errors.Is(upstreamErr, ErrUpstreamLeaseExpired)
		status.CurrentlyActive = stored.IsActive(now) && upstreamErr == nil
		trace.Facts = append(trace.Facts, status)
	}
	if leaf := s.leaseByIDLocked(receipt.LeaseID); leaf != nil {
		trace.CurrentlyUsable = s.leaseCurrentlyUsableLocked(leaf, now)
	}
	return trace, nil
}

func (s *Service) leaseCurrentlyUsableLocked(lease *LeaseRecord, now time.Time) bool {
	if err := s.upstreamLeaseErrorLocked(lease, now); err != nil {
		return false
	}
	return lease.IsActive(now)
}

// buildReceiptLocked assembles and signs a receipt for one decided use. The
// chain is the exact delegation path from the root lease to the using lease;
// parallel authorizations to the same borrower stay separate receipts and can
// never merge into a wider permission.
func (s *Service) buildReceiptLocked(lease *LeaseRecord, versionID, decision, reason string, now time.Time) (*UsageReceipt, error) {
	var path []*LeaseRecord
	for current := lease; current != nil; {
		path = append(path, current)
		if current.ParentID == "" {
			break
		}
		current = s.leaseByIDLocked(current.ParentID)
	}
	if path[len(path)-1].ParentID != "" {
		return nil, fmt.Errorf("%w: incomplete delegation chain", ErrReceiptTampered)
	}
	links := make([]ReceiptChainLink, 0, len(path))
	for i := len(path) - 1; i >= 0; i-- {
		record := path[i]
		scopes := append([]string(nil), record.Scopes...)
		sort.Strings(scopes)
		links = append(links, ReceiptChainLink{
			LeaseID:     record.ID,
			ParentID:    record.ParentID,
			SecretName:  record.SecretName,
			VersionID:   record.VersionID,
			Purpose:     record.Purpose,
			PurposeHash: purposeCommitment(record.Purpose),
			Scopes:      scopes,
			IssuedAt:    record.IssuedAt.UTC(),
			ExpiresAt:   record.ExpiresAt.UTC(),
			FactHash:    leaseFactHash(record),
		})
	}
	// The receipt commits to the version actually used, which may differ from
	// the pinned leaf version when the whole chain allows new versions.
	links[len(links)-1].VersionID = versionID
	digest, err := chainDigest(links)
	if err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	receipt := &UsageReceipt{
		ID:          "rcpt_" + hex.EncodeToString(idBytes),
		SecretName:  lease.SecretName,
		VersionID:   versionID,
		LeaseID:     lease.ID,
		Decision:    decision,
		Reason:      reason,
		DecidedAt:   now.UTC(),
		Chain:       links,
		ChainDigest: digest,
		SignerKeyID: s.store.ReceiptKeyID(),
	}
	payload, err := canonicalJSON(receipt.payload())
	if err != nil {
		return nil, err
	}
	receipt.Signature = hex.EncodeToString(s.store.SignReceipt(payload))
	return receipt, nil
}

// ReceiptPublicKey returns the public half of the persisted receipt signing
// key so anyone can verify receipts offline.
func (s *Service) ReceiptPublicKey() (ed25519.PublicKey, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.ReceiptPublicKey(), s.store.ReceiptKeyID()
}

// DescribeReceipt renders a receipt as text without ever including material
// plaintext or tokens. Redacted purposes show only their commitment prefix.
func DescribeReceipt(receipt *UsageReceipt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "receipt %s: material=%s version=%s decision=%s", receipt.ID, receipt.SecretName, receipt.VersionID, receipt.Decision)
	if receipt.Reason != "" {
		fmt.Fprintf(&b, " reason=%s", receipt.Reason)
	}
	fmt.Fprintf(&b, " at=%s\n", receipt.DecidedAt.UTC().Format(time.RFC3339))
	for i, link := range receipt.Chain {
		purpose := link.Purpose
		if purpose == "" {
			purpose = "<redacted:" + link.PurposeHash[:12] + ">"
		}
		fmt.Fprintf(&b, "  layer %d: lease=%s purpose=%q scopes=%s expires=%s\n",
			i, link.LeaseID, purpose, strings.Join(link.Scopes, ","), link.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return strings.TrimRight(b.String(), "\n")
}
