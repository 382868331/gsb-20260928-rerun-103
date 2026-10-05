package localsecretmaterials

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// StatusConflict marks a verification decision whose receipt depends on
// authorization facts that arrived in mutually contradictory batches. A
// conflicted receipt is neither confirmed nor rejected: the operator must
// resolve which fact batch is authentic. Receipts that do not depend on the
// conflicted facts keep verifying normally.
const StatusConflict = "conflict"

const verificationTaskFile = "verification-task.json"

// FactConflict records that two fact batches disagree about one entity. The
// first-accepted snapshot stays in force; the contradictory arrival is kept
// here as evidence so affected receipts can be named precisely.
type FactConflict struct {
	Kind         string    `json:"kind"` // "lease", "receipt_record", "receipt", or "version"
	ID           string    `json:"id"`
	HeldHash     string    `json:"held_hash"`
	IncomingHash string    `json:"incoming_hash"`
	At           time.Time `json:"at"`
}

// DecisionBasis pins exactly which held facts a decision relied on, so an
// operator reviewing many receipts can see, per receipt, which batch of
// authorization facts produced the conclusion.
type DecisionBasis struct {
	ReceiptRecordHash string            `json:"receipt_record_hash,omitempty"`
	LeaseFactHashes   map[string]string `json:"lease_fact_hashes,omitempty"`
	VersionDigest     string            `json:"version_digest,omitempty"`
	FactsSubsetHash   string            `json:"facts_subset_hash,omitempty"`
}

// VerificationDecision is one appended verification conclusion. Decisions
// are append-only: later fact batches can add new decisions for the same
// receipt, but earlier undetermined or refused conclusions are never
// rewritten.
type VerificationDecision struct {
	Seq             int            `json:"seq"`
	At              time.Time      `json:"at"`
	ReceiptID       string         `json:"receipt_id"`
	Status          string         `json:"status"`
	Valid           bool           `json:"valid"`
	CurrentlyUsable bool           `json:"currently_usable"`
	Reason          string         `json:"reason,omitempty"`
	Basis           *DecisionBasis `json:"basis,omitempty"`
	Conflicts       []FactConflict `json:"conflicts,omitempty"`
}

// VerificationTask is a savable offline verification session. Authorization
// facts and usage receipts arrive in batches, possibly out of order; every
// verification appends a decision together with the exact basis it used.
// The task never sees material plaintext.
type VerificationTask struct {
	ID           string                   `json:"id"`
	CreatedAt    time.Time                `json:"created_at"`
	Facts        *AuthorizationFacts      `json:"facts"`
	Receipts     map[string]*UsageReceipt `json:"receipts"`
	ReceiptOrder []string                 `json:"receipt_order"`
	Decisions    []*VerificationDecision  `json:"decisions"`
	Conflicts    []FactConflict           `json:"conflicts,omitempty"`
	conflicted   map[string]bool
}

// NewVerificationTask starts an empty verification task.
func NewVerificationTask(id string, now time.Time) *VerificationTask {
	return &VerificationTask{
		ID:        id,
		CreatedAt: now.UTC(),
		Facts: &AuthorizationFacts{
			Secrets:  map[string]*SecretFact{},
			Leases:   map[string]*LeaseFact{},
			Receipts: map[string]*ReceiptRecord{},
		},
		Receipts:   map[string]*UsageReceipt{},
		conflicted: map[string]bool{},
	}
}

func (t *VerificationTask) ensureMaps() {
	if t.Facts == nil {
		t.Facts = &AuthorizationFacts{}
	}
	if t.Facts.Secrets == nil {
		t.Facts.Secrets = map[string]*SecretFact{}
	}
	if t.Facts.Leases == nil {
		t.Facts.Leases = map[string]*LeaseFact{}
	}
	if t.Facts.Receipts == nil {
		t.Facts.Receipts = map[string]*ReceiptRecord{}
	}
	if t.Receipts == nil {
		t.Receipts = map[string]*UsageReceipt{}
	}
	if t.conflicted == nil {
		t.conflicted = map[string]bool{}
		for _, c := range t.Conflicts {
			t.conflicted[conflictKey(c.Kind, c.ID)] = true
		}
	}
}

func conflictKey(kind, id string) string { return kind + ":" + id }

// SubmitFacts merges one batch of authorization facts into the task. Batches
// may arrive out of order and may be partial. A later snapshot of the same
// lease (for example one recording a revocation) updates mutable fields, but
// any batch whose immutable content contradicts what the task already holds
// is rejected as a conflict: the held snapshot stays, the contradiction is
// recorded, and receipts depending on the contradicted entity will be
// decided StatusConflict until the operator resolves it.
func (t *VerificationTask) SubmitFacts(facts *AuthorizationFacts, now time.Time) []FactConflict {
	t.ensureMaps()
	if facts == nil {
		return nil
	}
	var newConflicts []FactConflict
	recordConflict := func(kind, id, heldHash, incomingHash string) {
		key := conflictKey(kind, id)
		if t.conflicted[key] {
			return
		}
		t.conflicted[key] = true
		conflict := FactConflict{Kind: kind, ID: id, HeldHash: heldHash, IncomingHash: incomingHash, At: now.UTC()}
		t.Conflicts = append(t.Conflicts, conflict)
		newConflicts = append(newConflicts, conflict)
	}

	for name, secret := range facts.Secrets {
		held := t.Facts.Secrets[name]
		if held == nil {
			t.Facts.Secrets[name] = cloneJSON(secret)
			continue
		}
		held.CurrentVersionID = secret.CurrentVersionID
		for _, version := range secret.Versions {
			found := false
			for i := range held.Versions {
				if held.Versions[i].VersionID == version.VersionID {
					found = true
					heldHash := hashCanonical("version-fact-v1", &held.Versions[i])
					incomingHash := hashCanonical("version-fact-v1", &version)
					if heldHash != incomingHash {
						recordConflict("version", version.VersionID, heldHash, incomingHash)
					}
				}
			}
			if !found {
				held.Versions = append(held.Versions, version)
			}
		}
		sort.Slice(held.Versions, func(i, j int) bool { return held.Versions[i].Number < held.Versions[j].Number })
	}

	for id, lease := range facts.Leases {
		held := t.Facts.Leases[id]
		if held == nil {
			t.Facts.Leases[id] = cloneJSON(lease)
			continue
		}
		heldHash := factHash(held)
		incomingHash := factHash(lease)
		if heldHash != incomingHash {
			recordConflict("lease", id, heldHash, incomingHash)
			continue
		}
		// Same immutable authorization: the newer snapshot may carry mutable
		// state such as a later revocation or an adopted version.
		held.RevokedAt = lease.RevokedAt
		held.VersionID = lease.VersionID
		held.FactHash = lease.FactHash
	}

	for id, event := range facts.Receipts {
		held := t.Facts.Receipts[id]
		if held == nil {
			t.Facts.Receipts[id] = cloneJSON(event)
			continue
		}
		heldHash := hashCanonical("receipt-record-v1", held)
		incomingHash := hashCanonical("receipt-record-v1", event)
		if heldHash != incomingHash {
			recordConflict("receipt_record", id, heldHash, incomingHash)
		}
	}
	return newConflicts
}

// SubmitReceipt registers one arrived receipt. The same receipt arriving
// again (same ID and same self-consistency hash) is a duplicate and does not
// increase the usage count; if the duplicate hides more of the purpose hint,
// the more redacted copy is kept. A different receipt ID is always kept
// separately, even when it stems from the same material version. A receipt
// whose ID matches a held receipt but whose content differs is a conflict.
func (t *VerificationTask) SubmitReceipt(receipt *UsageReceipt, now time.Time) (duplicate bool, conflict *FactConflict) {
	t.ensureMaps()
	if receipt == nil {
		return false, nil
	}
	held, ok := t.Receipts[receipt.ID]
	if !ok {
		t.Receipts[receipt.ID] = cloneJSON(receipt)
		t.ReceiptOrder = append(t.ReceiptOrder, receipt.ID)
		return false, nil
	}
	if held.ReceiptHash != receipt.ReceiptHash {
		key := conflictKey("receipt", receipt.ID)
		if !t.conflicted[key] {
			t.conflicted[key] = true
			c := FactConflict{Kind: "receipt", ID: receipt.ID, HeldHash: held.ReceiptHash, IncomingHash: receipt.ReceiptHash, At: now.UTC()}
			t.Conflicts = append(t.Conflicts, c)
			return false, &c
		}
		return false, nil
	}
	if len(receipt.PurposeHint) < len(held.PurposeHint) {
		held.PurposeHint = receipt.PurposeHint
	}
	return true, nil
}

// UsageCount is the number of distinct receipts the task has seen. Duplicate
// arrivals of the same receipt never increase it.
func (t *VerificationTask) UsageCount() int {
	t.ensureMaps()
	return len(t.ReceiptOrder)
}

// conflictsForReceipt lists recorded conflicts that touch anything the given
// receipt depends on: the receipt itself, its registered usage event, any
// delegation layer, or the used version.
func (t *VerificationTask) conflictsForReceipt(receipt *UsageReceipt) []FactConflict {
	t.ensureMaps()
	if len(t.Conflicts) == 0 || receipt == nil {
		return nil
	}
	relevant := map[string]bool{conflictKey("receipt", receipt.ID): true}
	if record := t.Facts.Receipts[receipt.ID]; record != nil {
		relevant[conflictKey("receipt_record", record.ReceiptID)] = true
		relevant[conflictKey("version", record.VersionID)] = true
		for _, id := range record.LeaseIDs {
			relevant[conflictKey("lease", id)] = true
		}
	}
	var out []FactConflict
	for _, c := range t.Conflicts {
		if relevant[conflictKey(c.Kind, c.ID)] {
			out = append(out, c)
		}
	}
	return out
}

// decisionBasis captures exactly which held facts a decision relied on.
func (t *VerificationTask) decisionBasis(receipt *UsageReceipt) *DecisionBasis {
	basis := &DecisionBasis{LeaseFactHashes: map[string]string{}}
	record := t.Facts.Receipts[receipt.ID]
	if record == nil {
		return basis
	}
	basis.ReceiptRecordHash = hashCanonical("receipt-record-v1", record)
	for _, id := range record.LeaseIDs {
		if fact := t.Facts.Leases[id]; fact != nil {
			basis.LeaseFactHashes[id] = fact.FactHash
		}
	}
	if secret := t.Facts.Secrets[record.SecretName]; secret != nil {
		for i := range secret.Versions {
			if secret.Versions[i].VersionID == record.VersionID {
				basis.VersionDigest = secret.Versions[i].MaterialDigest
			}
		}
	}
	if subset := RedactFactsForReceipt(t.Facts, receipt); subset != nil {
		basis.FactsSubsetHash = hashCanonical("facts-subset-v1", subset)
	}
	return basis
}

// Verify appends a new decision for one receipt. Every call produces a new
// decision; earlier decisions stay in the history untouched, so a later fact
// batch can turn an undetermined receipt valid without erasing the earlier
// undetermined conclusion. A receipt whose dependencies are contradicted by
// conflicting fact batches is decided StatusConflict with the conflicting
// basis named; unrelated receipts keep verifying normally.
func (t *VerificationTask) Verify(receiptID string, now time.Time) *VerificationDecision {
	t.ensureMaps()
	decision := &VerificationDecision{
		Seq:       len(t.Decisions) + 1,
		At:        now.UTC(),
		ReceiptID: receiptID,
	}
	receipt := t.Receipts[receiptID]
	if receipt == nil {
		decision.Status = StatusUndetermined
		decision.Reason = "receipt has not arrived at this task"
		t.Decisions = append(t.Decisions, decision)
		return decision
	}
	if conflicts := t.conflictsForReceipt(receipt); len(conflicts) > 0 {
		decision.Status = StatusConflict
		decision.Reason = "authorization facts for this receipt contradict each other"
		decision.Conflicts = conflicts
		decision.Basis = t.decisionBasis(receipt)
		t.Decisions = append(t.Decisions, decision)
		return decision
	}
	result := VerifyReceipt(receipt, t.Facts, now)
	decision.Status = result.Status
	decision.Valid = result.Valid
	decision.CurrentlyUsable = result.CurrentlyUsable
	decision.Reason = result.Reason
	decision.Basis = t.decisionBasis(receipt)
	t.Decisions = append(t.Decisions, decision)
	return decision
}

// LatestDecisions returns the most recent decision per receipt. The full
// append-only history stays in Decisions.
func (t *VerificationTask) LatestDecisions() map[string]*VerificationDecision {
	latest := map[string]*VerificationDecision{}
	for _, decision := range t.Decisions {
		latest[decision.ReceiptID] = decision
	}
	return latest
}

// Save persists the task so verification can resume after the process
// reopens. The file holds facts, receipts, conflicts, and the append-only
// decision history; it never holds material plaintext.
func (t *VerificationTask) Save(ctx context.Context, dir string) error {
	_ = ctx
	t.ensureMaps()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(dir, verificationTaskFile), t, 0o600)
}

// LoadVerificationTask reopens a previously saved verification task so
// verification can continue where it left off.
func LoadVerificationTask(ctx context.Context, dir string) (*VerificationTask, error) {
	_ = ctx
	task := &VerificationTask{}
	encoded, err := os.ReadFile(filepath.Join(dir, verificationTaskFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(encoded, task); err != nil {
		return nil, err
	}
	task.ensureMaps()
	return task, nil
}

// VerificationPackage is an exportable offline bundle: only the facts the
// selected receipts need, the receipts themselves, and the decisions chosen
// for reproduction. A receiver can reproduce the selected decisions without
// ever seeing material plaintext or unrelated authorizations.
type VerificationPackage struct {
	TaskID     string                  `json:"task_id"`
	ExportedAt time.Time               `json:"exported_at"`
	Facts      *AuthorizationFacts     `json:"facts"`
	Receipts   []*UsageReceipt         `json:"receipts"`
	Decisions  []*VerificationDecision `json:"decisions"`
}

// ExportPackage builds a minimal offline verification package for the
// selected receipts. Facts are reduced per receipt with
// RedactFactsForReceipt, so the package carries no unrelated secret, lease,
// or usage event and no business purpose text. Exporting never mutates the
// task: the task file and in-memory state are byte-identical afterwards.
func (t *VerificationTask) ExportPackage(receiptIDs []string, now time.Time) (*VerificationPackage, error) {
	t.ensureMaps()
	pkg := &VerificationPackage{
		TaskID:     t.ID,
		ExportedAt: now.UTC(),
		Facts: &AuthorizationFacts{
			Secrets:  map[string]*SecretFact{},
			Leases:   map[string]*LeaseFact{},
			Receipts: map[string]*ReceiptRecord{},
		},
	}
	latest := t.LatestDecisions()
	for _, id := range receiptIDs {
		receipt := t.Receipts[id]
		if receipt == nil {
			return nil, fmt.Errorf("%w: receipt %s is not held by this task", ErrInvalidArgument, id)
		}
		pkg.Receipts = append(pkg.Receipts, cloneJSON(receipt))
		if decision := latest[id]; decision != nil {
			pkg.Decisions = append(pkg.Decisions, cloneJSON(decision))
		}
		subset := RedactFactsForReceipt(t.Facts, receipt)
		if subset == nil {
			continue
		}
		for name, secret := range subset.Secrets {
			held := pkg.Facts.Secrets[name]
			if held == nil {
				pkg.Facts.Secrets[name] = secret
				continue
			}
			held.CurrentVersionID = secret.CurrentVersionID
			for _, version := range secret.Versions {
				found := false
				for i := range held.Versions {
					if held.Versions[i].VersionID == version.VersionID {
						found = true
					}
				}
				if !found {
					held.Versions = append(held.Versions, version)
				}
			}
		}
		for leaseID, fact := range subset.Leases {
			pkg.Facts.Leases[leaseID] = fact
		}
		for recordID, record := range subset.Receipts {
			pkg.Facts.Receipts[recordID] = record
		}
	}
	return pkg, nil
}

// PackageReproduction reports whether one exported decision could be
// reproduced from the package facts alone.
type PackageReproduction struct {
	ReceiptID  string `json:"receipt_id"`
	Expected   string `json:"expected_status"`
	Reproduced string `json:"reproduced_status"`
	Matches    bool   `json:"matches"`
}

// VerifyPackage lets a receiver reproduce the exported decisions using only
// the facts inside the package. No service, master key, network, or material
// plaintext is involved.
func VerifyPackage(pkg *VerificationPackage, now time.Time) []PackageReproduction {
	var out []PackageReproduction
	if pkg == nil {
		return out
	}
	receipts := map[string]*UsageReceipt{}
	for _, receipt := range pkg.Receipts {
		receipts[receipt.ID] = receipt
	}
	for _, decision := range pkg.Decisions {
		receipt := receipts[decision.ReceiptID]
		reproduced := StatusUndetermined
		if receipt != nil {
			reproduced = VerifyReceipt(receipt, pkg.Facts, now).Status
		}
		out = append(out, PackageReproduction{
			ReceiptID:  decision.ReceiptID,
			Expected:   decision.Status,
			Reproduced: reproduced,
			Matches:    reproduced == decision.Status,
		})
	}
	return out
}
