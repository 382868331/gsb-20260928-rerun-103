package localsecretmaterials

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// StatusConflict marks a decision whose receipt depends on authorization
// facts that arrived in mutually contradictory batches. It is a task-level
// decision status only; single-shot VerifyReceipt never returns it.
const StatusConflict = "conflict"

var (
	// ErrReceiptMismatch is returned when a receipt ID is submitted again
	// with different content.
	ErrReceiptMismatch = errors.New("receipt id already registered with different content")
	// ErrUnknownReceipt is returned when an export names a receipt the task
	// has never seen.
	ErrUnknownReceipt = errors.New("receipt is not part of the verification task")
	// ErrNoDecision is returned when an export names a receipt that has not
	// been verified yet.
	ErrNoDecision = errors.New("receipt has no verification decision yet")
	// ErrDecisionNotExportable is returned when a decision cannot be
	// reproduced from a minimal fact package (conflicted facts).
	ErrDecisionNotExportable = errors.New("decision cannot be reproduced from a minimal fact package")
)

// FactBatch is one submitted batch of authorization facts and occurrence
// records. Batches accumulate; later batches supplement but never rewrite
// earlier decisions.
type FactBatch struct {
	ID          string              `json:"id"`
	SubmittedAt time.Time           `json:"submitted_at"`
	Facts       *AuthorizationFacts `json:"facts"`
}

// FactConflict names one fact key that two batches disagree about, and the
// batches that contradict each other.
type FactConflict struct {
	Key     string   `json:"key"`
	Batches []string `json:"batches"`
}

// VerificationDecision is one append-only verification outcome for one
// receipt. Supplementing facts appends new decisions; earlier undetermined
// or refused conclusions stay in the task history unchanged.
type VerificationDecision struct {
	Seq             int            `json:"seq"`
	DecidedAt       time.Time      `json:"decided_at"`
	ReceiptID       string         `json:"receipt_id"`
	Status          string         `json:"status"`
	Valid           bool           `json:"valid"`
	CurrentlyUsable bool           `json:"currently_usable"`
	Reason          string         `json:"reason,omitempty"`
	BasisBatches    []string       `json:"basis_batches,omitempty"`
	Missing         []string       `json:"missing,omitempty"`
	Conflicts       []FactConflict `json:"conflicts,omitempty"`
}

// VerificationTask is a persistable offline verification job over many
// historical receipts. The operator submits authorization facts batch by
// batch; every verification run records, per receipt, the conclusion and
// exactly which batches supplied the facts it rests on, or which facts are
// still missing. It never touches material plaintext.
type VerificationTask struct {
	ID           string                   `json:"id"`
	CreatedAt    time.Time                `json:"created_at"`
	Receipts     map[string]*UsageReceipt `json:"receipts"`
	ReceiptOrder []string                 `json:"receipt_order"`
	Batches      []*FactBatch             `json:"batches"`
	Decisions    []*VerificationDecision  `json:"decisions"`
}

// NewVerificationTask creates an empty task with the given operator-chosen ID.
func NewVerificationTask(id string, now time.Time) *VerificationTask {
	return &VerificationTask{
		ID:        id,
		CreatedAt: now.UTC(),
		Receipts:  make(map[string]*UsageReceipt),
	}
}

// LoadVerificationTask reopens a previously saved task so verification can
// continue where it left off.
func LoadVerificationTask(path string) (*VerificationTask, error) {
	var task VerificationTask
	if err := readJSON(path, &task); err != nil {
		return nil, err
	}
	if task.Receipts == nil {
		task.Receipts = make(map[string]*UsageReceipt)
	}
	return &task, nil
}

// Save persists the whole task (receipts, batches, and the full append-only
// decision history) to path.
func (t *VerificationTask) Save(path string) error {
	return writeJSONAtomic(path, t, 0o600)
}

// AddReceipt registers a historical receipt. The same receipt arriving again
// is ignored so one use is never counted twice; different receipts are kept
// separately even when they come from the same material version. The same ID
// with different content is rejected as contradictory.
func (t *VerificationTask) AddReceipt(receipt *UsageReceipt) (bool, error) {
	if receipt == nil || receipt.ID == "" {
		return false, fmt.Errorf("%w: receipt with an id is required", ErrInvalidArgument)
	}
	if existing, ok := t.Receipts[receipt.ID]; ok {
		if hashCanonical("usage-receipt-content-v1", existing) != hashCanonical("usage-receipt-content-v1", receipt) {
			return false, fmt.Errorf("%w: %s", ErrReceiptMismatch, receipt.ID)
		}
		return false, nil
	}
	t.Receipts[receipt.ID] = cloneJSON(receipt)
	t.ReceiptOrder = append(t.ReceiptOrder, receipt.ID)
	return true, nil
}

// SubmitFacts appends one batch of authorization facts and returns its ID.
// Batches may arrive out of order and incomplete; verification merges what
// is held so far and reports what is still missing.
func (t *VerificationTask) SubmitFacts(facts *AuthorizationFacts, now time.Time) (string, error) {
	if facts == nil {
		return "", fmt.Errorf("%w: facts are required", ErrInvalidArgument)
	}
	batch := &FactBatch{
		ID:          fmt.Sprintf("batch-%d", len(t.Batches)+1),
		SubmittedAt: now.UTC(),
		Facts:       cloneJSON(facts),
	}
	t.Batches = append(t.Batches, batch)
	return batch.ID, nil
}

// Verify runs one verification pass over every registered receipt against
// the facts held so far and appends one new decision per receipt. Earlier
// decisions are never modified. It returns the newly appended decisions in
// receipt registration order.
func (t *VerificationTask) Verify(now time.Time) []*VerificationDecision {
	merged := mergeBatches(t.Batches)
	var appended []*VerificationDecision
	for _, id := range t.ReceiptOrder {
		decision := decideReceipt(t.Receipts[id], merged, now)
		decision.Seq = len(t.Decisions) + 1
		t.Decisions = append(t.Decisions, decision)
		appended = append(appended, decision)
	}
	return appended
}

// LatestDecisions returns the most recent decision per receipt.
func (t *VerificationTask) LatestDecisions() map[string]*VerificationDecision {
	latest := make(map[string]*VerificationDecision)
	for _, decision := range t.Decisions {
		latest[decision.ReceiptID] = decision
	}
	return latest
}

// UsageCount counts distinct receipts whose latest decision is valid. A
// receipt that arrived twice is one use; two receipts over the same material
// version are two uses.
func (t *VerificationTask) UsageCount() int {
	count := 0
	for _, decision := range t.LatestDecisions() {
		if decision.Status == StatusValid {
			count++
		}
	}
	return count
}

// mergedFactSet is the union of all submitted batches plus, per fact key,
// the batches that contributed to the merged value and any contradictions.
type mergedFactSet struct {
	facts        *AuthorizationFacts
	contributors map[string][]string
	conflicts    map[string]*FactConflict
}

func (m *mergedFactSet) contribute(key, batchID string) {
	for _, id := range m.contributors[key] {
		if id == batchID {
			return
		}
	}
	m.contributors[key] = append(m.contributors[key], batchID)
}

func (m *mergedFactSet) conflict(key, batchID string) {
	existing, ok := m.conflicts[key]
	if !ok {
		existing = &FactConflict{Key: key, Batches: append([]string(nil), m.contributors[key]...)}
		m.conflicts[key] = existing
	}
	for _, id := range existing.Batches {
		if id == batchID {
			return
		}
	}
	existing.Batches = append(existing.Batches, batchID)
}

// mergeBatches folds every submitted batch into one fact set. Lease facts
// conflict only when the immutable authorization hash differs; revocation
// and version adoption are state updates merged from the latest batch.
// Secrets merge as a union of versions; the same version ID with a different
// digest is a conflict. Registered usage events are immutable, so any
// disagreement about one is a conflict.
func mergeBatches(batches []*FactBatch) *mergedFactSet {
	merged := &mergedFactSet{
		facts: &AuthorizationFacts{
			Secrets:  make(map[string]*SecretFact),
			Leases:   make(map[string]*LeaseFact),
			Receipts: make(map[string]*ReceiptRecord),
		},
		contributors: make(map[string][]string),
		conflicts:    make(map[string]*FactConflict),
	}
	for _, batch := range batches {
		if batch.Facts == nil {
			continue
		}
		for id, record := range batch.Facts.Receipts {
			key := "receipt/" + id
			existing, ok := merged.facts.Receipts[id]
			if !ok {
				merged.facts.Receipts[id] = cloneJSON(record)
				merged.contribute(key, batch.ID)
				continue
			}
			if hashCanonical("receipt-record-v1", existing) != hashCanonical("receipt-record-v1", record) {
				merged.conflict(key, batch.ID)
			}
		}
		for id, fact := range batch.Facts.Leases {
			key := "lease/" + id
			existing, ok := merged.facts.Leases[id]
			if !ok {
				merged.facts.Leases[id] = cloneJSON(fact)
				merged.contribute(key, batch.ID)
				continue
			}
			if existing.FactHash != fact.FactHash {
				merged.conflict(key, batch.ID)
				continue
			}
			if !existing.RevokedAt.Equal(fact.RevokedAt) || existing.VersionID != fact.VersionID {
				merged.facts.Leases[id] = cloneJSON(fact)
				merged.contribute(key, batch.ID)
			}
		}
		for name, secret := range batch.Facts.Secrets {
			key := "secret/" + name
			existing, ok := merged.facts.Secrets[name]
			if !ok {
				merged.facts.Secrets[name] = cloneJSON(secret)
				merged.contribute(key, batch.ID)
				continue
			}
			changed := false
			byID := make(map[string]*VersionFact)
			for i := range existing.Versions {
				byID[existing.Versions[i].VersionID] = &existing.Versions[i]
			}
			for _, version := range secret.Versions {
				held, seen := byID[version.VersionID]
				if !seen {
					existing.Versions = append(existing.Versions, version)
					changed = true
					continue
				}
				if held.MaterialDigest != version.MaterialDigest || held.Number != version.Number || held.KeyID != version.KeyID {
					merged.conflict(key+"/version/"+version.VersionID, batch.ID)
				}
			}
			if existing.CurrentVersionID != secret.CurrentVersionID {
				existing.CurrentVersionID = secret.CurrentVersionID
				changed = true
			}
			if changed {
				merged.contribute(key, batch.ID)
			}
		}
	}
	return merged
}

// decideReceipt produces one decision for one receipt against the merged
// facts. Receipts whose dependencies contradict each other across batches
// are flagged with the conflicting basis; every other receipt keeps
// verifying normally.
func decideReceipt(receipt *UsageReceipt, merged *mergedFactSet, now time.Time) *VerificationDecision {
	decision := &VerificationDecision{ReceiptID: receipt.ID, DecidedAt: now.UTC()}

	deps := []string{"receipt/" + receipt.ID}
	if record := merged.facts.Receipts[receipt.ID]; record != nil {
		for _, id := range record.LeaseIDs {
			deps = append(deps, "lease/"+id)
		}
		deps = append(deps, "secret/"+record.SecretName, "secret/"+record.SecretName+"/version/"+record.VersionID)
	}
	for _, dep := range deps {
		if conflict, ok := merged.conflicts[dep]; ok {
			decision.Conflicts = append(decision.Conflicts, *cloneJSON(conflict))
		}
	}
	if len(decision.Conflicts) > 0 {
		decision.Status = StatusConflict
		decision.Reason = "submitted facts contradict each other for this receipt"
		return decision
	}

	verification, tracker := verifyReceiptTracked(receipt, merged.facts, now, nil)
	decision.Status = verification.Status
	decision.Valid = verification.Valid
	decision.CurrentlyUsable = verification.CurrentlyUsable
	decision.Reason = verification.Reason
	decision.Missing = append([]string(nil), tracker.missing...)
	seen := make(map[string]bool)
	for key := range tracker.used {
		for _, batchID := range merged.contributors[key] {
			if !seen[batchID] {
				seen[batchID] = true
				decision.BasisBatches = append(decision.BasisBatches, batchID)
			}
		}
	}
	sort.Strings(decision.BasisBatches)
	return decision
}

// VerificationPackage is an exportable offline bundle: the selected
// receipts, only the authorization facts those receipts need (purposes as
// hashes, no material plaintext, nothing unrelated), and the recorded
// decisions to reproduce.
type VerificationPackage struct {
	TaskID     string                  `json:"task_id"`
	ExportedAt time.Time               `json:"exported_at"`
	Receipts   []*UsageReceipt         `json:"receipts"`
	Facts      *AuthorizationFacts     `json:"facts"`
	Decisions  []*VerificationDecision `json:"decisions"`
}

// Export builds a minimal offline verification package for the selected
// receipts from the facts held so far. Exporting never modifies the task:
// every value is deep-copied and nothing is persisted.
func (t *VerificationTask) Export(receiptIDs []string, now time.Time) (*VerificationPackage, error) {
	merged := mergeBatches(t.Batches)
	latest := t.LatestDecisions()
	pkg := &VerificationPackage{
		TaskID:     t.ID,
		ExportedAt: now.UTC(),
		Facts: &AuthorizationFacts{
			Secrets:  make(map[string]*SecretFact),
			Leases:   make(map[string]*LeaseFact),
			Receipts: make(map[string]*ReceiptRecord),
		},
	}
	for _, id := range receiptIDs {
		receipt, ok := t.Receipts[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownReceipt, id)
		}
		decision, ok := latest[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNoDecision, id)
		}
		if decision.Status == StatusConflict {
			return nil, fmt.Errorf("%w: receipt %s depends on contradictory facts", ErrDecisionNotExportable, id)
		}
		pkg.Receipts = append(pkg.Receipts, cloneJSON(receipt))
		pkg.Decisions = append(pkg.Decisions, cloneJSON(decision))
		redacted := RedactFactsForReceipt(merged.facts, receipt)
		if redacted == nil {
			continue
		}
		for name, secret := range redacted.Secrets {
			pkg.Facts.Secrets[name] = secret
		}
		for leaseID, fact := range redacted.Leases {
			pkg.Facts.Leases[leaseID] = fact
		}
		for recordID, record := range redacted.Receipts {
			pkg.Facts.Receipts[recordID] = record
		}
	}
	return pkg, nil
}

// Save persists the package so a receiver can verify offline.
func (p *VerificationPackage) Save(path string) error {
	return writeJSONAtomic(path, p, 0o600)
}

// LoadVerificationPackage reopens an exported package.
func LoadVerificationPackage(path string) (*VerificationPackage, error) {
	var pkg VerificationPackage
	if err := readJSON(path, &pkg); err != nil {
		return nil, err
	}
	return &pkg, nil
}

// Reproduce re-verifies every packaged receipt against only the packaged
// facts and confirms each recorded decision comes out the same. The receiver
// needs no service, no master key, and no material plaintext.
func (p *VerificationPackage) Reproduce(now time.Time) ([]*VerificationDecision, error) {
	receipts := make(map[string]*UsageReceipt)
	for _, receipt := range p.Receipts {
		receipts[receipt.ID] = receipt
	}
	var reproduced []*VerificationDecision
	for _, recorded := range p.Decisions {
		receipt, ok := receipts[recorded.ReceiptID]
		if !ok {
			return nil, fmt.Errorf("%w: package lacks receipt %s", ErrDecisionNotExportable, recorded.ReceiptID)
		}
		verification, _ := verifyReceiptTracked(receipt, p.Facts, now, nil)
		if verification.Status != recorded.Status || verification.Valid != recorded.Valid {
			return nil, fmt.Errorf("%w: receipt %s reproduces as %s, recorded decision is %s",
				ErrDecisionNotExportable, recorded.ReceiptID, verification.Status, recorded.Status)
		}
		reproduced = append(reproduced, cloneJSON(recorded))
	}
	return reproduced, nil
}
