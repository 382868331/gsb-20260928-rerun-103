package localsecretmaterials

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// taskFixture builds a service with one secret, a root lease, a delegated
// lease, and two receipts over the same material version.
func taskFixture(t *testing.T) (*Service, *AuthorizationFacts, *UsageReceipt, *UsageReceipt, *Lease) {
	t.Helper()
	ctx := context.Background()
	svc, _ := testService(t)

	if _, err := svc.CreateSecret(ctx, "demo-db", []byte("fictional-password"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	root, err := svc.Borrow(ctx, "demo-db", time.Hour, BorrowOptions{Purpose: "billing", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	delegated, err := svc.Delegate(ctx, root.Token, DelegateOptions{
		Purpose: "billing/monthly-close",
		Scopes:  []Scope{ScopeReadMaterial},
		TTL:     30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, receipt1, err := svc.UseWithReceipt(ctx, delegated.Token, ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		t.Fatal(err)
	}
	_, receipt2, err := svc.UseWithReceipt(ctx, delegated.Token, ReceiptOptions{PurposeHint: "billing/monthly"})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return svc, facts, receipt1, receipt2, root
}

func onlySecrets(facts *AuthorizationFacts) *AuthorizationFacts {
	return &AuthorizationFacts{Secrets: cloneJSON(facts).Secrets, Leases: map[string]*LeaseFact{}, Receipts: map[string]*ReceiptRecord{}}
}

func onlyLeases(facts *AuthorizationFacts) *AuthorizationFacts {
	return &AuthorizationFacts{Secrets: map[string]*SecretFact{}, Leases: cloneJSON(facts).Leases, Receipts: map[string]*ReceiptRecord{}}
}

func onlyReceiptRecords(facts *AuthorizationFacts) *AuthorizationFacts {
	return &AuthorizationFacts{Secrets: map[string]*SecretFact{}, Leases: map[string]*LeaseFact{}, Receipts: cloneJSON(facts).Receipts}
}

func TestVerificationTaskOutOfOrderBatchesAndHistory(t *testing.T) {
	_, facts, receipt1, receipt2, _ := taskFixture(t)
	now := time.Now()
	task := NewVerificationTask("audit-2026-10", now)

	added, err := task.AddReceipt(receipt1)
	if err != nil || !added {
		t.Fatalf("first add = %v, %v", added, err)
	}
	added, err = task.AddReceipt(receipt1)
	if err != nil || added {
		t.Fatalf("duplicate add = %v, %v", added, err)
	}
	tampered := *receipt1
	tampered.Decision = "allowed-unconditionally"
	if _, err := task.AddReceipt(&tampered); !errors.Is(err, ErrReceiptMismatch) {
		t.Fatalf("contradictory duplicate error = %v", err)
	}

	// No facts at all: undetermined, missing basis reported.
	decisions := task.Verify(now)
	if len(decisions) != 1 || decisions[0].Status != StatusUndetermined {
		t.Fatalf("first decisions = %+v", decisions)
	}
	if len(decisions[0].Missing) == 0 || !strings.Contains(decisions[0].Missing[0], "registered usage event") {
		t.Fatalf("missing = %v", decisions[0].Missing)
	}

	// Out-of-order supplements: secrets first, then leases, then records.
	if _, err := task.SubmitFacts(onlySecrets(facts), now); err != nil {
		t.Fatal(err)
	}
	decisions = task.Verify(now)
	if decisions[0].Status != StatusUndetermined {
		t.Fatalf("after secrets batch = %+v", decisions[0])
	}
	if _, err := task.SubmitFacts(onlyLeases(facts), now); err != nil {
		t.Fatal(err)
	}
	decisions = task.Verify(now)
	if decisions[0].Status != StatusUndetermined {
		t.Fatalf("after leases batch = %+v", decisions[0])
	}
	if _, err := task.SubmitFacts(onlyReceiptRecords(facts), now); err != nil {
		t.Fatal(err)
	}
	decisions = task.Verify(now)
	if decisions[0].Status != StatusValid || !decisions[0].Valid || !decisions[0].CurrentlyUsable {
		t.Fatalf("after records batch = %+v", decisions[0])
	}
	for _, batch := range []string{"batch-1", "batch-2", "batch-3"} {
		found := false
		for _, used := range decisions[0].BasisBatches {
			if used == batch {
				found = true
			}
		}
		if !found {
			t.Fatalf("basis %v lacks %s", decisions[0].BasisBatches, batch)
		}
	}

	// Earlier undetermined conclusions are kept, never rewritten.
	if len(task.Decisions) != 4 {
		t.Fatalf("decision history = %d", len(task.Decisions))
	}
	first := task.Decisions[0]
	if first.Status != StatusUndetermined || first.Seq != 1 || len(first.Missing) == 0 {
		t.Fatalf("first decision rewritten: %+v", first)
	}
	if task.UsageCount() != 1 {
		t.Fatalf("usage count = %d", task.UsageCount())
	}

	// A second receipt over the same material version counts separately.
	if receipt2.VersionID != receipt1.VersionID {
		t.Fatalf("expected same version receipts")
	}
	if _, err := task.AddReceipt(receipt2); err != nil {
		t.Fatal(err)
	}
	task.Verify(now)
	if task.UsageCount() != 2 {
		t.Fatalf("usage count with two receipts = %d", task.UsageCount())
	}
}

func TestVerificationTaskHiddenHintStillValid(t *testing.T) {
	_, facts, _, receipt2, _ := taskFixture(t)
	now := time.Now()
	task := NewVerificationTask("hidden-hint", now)

	// The holder hides the business hint entirely before showing the receipt.
	shown := *receipt2
	shown.PurposeHint = ""
	if _, err := task.AddReceipt(&shown); err != nil {
		t.Fatal(err)
	}
	if _, err := task.SubmitFacts(facts, now); err != nil {
		t.Fatal(err)
	}
	decisions := task.Verify(now)
	if decisions[0].Status != StatusValid {
		t.Fatalf("hidden-hint receipt = %+v", decisions[0])
	}
}

func TestVerificationTaskConflictFlagsOnlyAffectedReceipts(t *testing.T) {
	svc, facts, receipt1, receipt2, _ := taskFixture(t)
	ctx := context.Background()
	// A second secret with its own lease and receipt, unaffected by the
	// contradiction.
	if _, err := svc.CreateSecret(ctx, "other", []byte("other-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	otherLease, err := svc.Borrow(ctx, "other", time.Hour, BorrowOptions{Purpose: "audit", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	_, receipt3, err := svc.UseWithReceipt(ctx, otherLease.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err = svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	task := NewVerificationTask("conflict", now)
	for _, receipt := range []*UsageReceipt{receipt1, receipt2, receipt3} {
		if _, err := task.AddReceipt(receipt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := task.SubmitFacts(facts, now); err != nil {
		t.Fatal(err)
	}
	task.Verify(now)

	// A contradictory batch: the leaf lease of receipt1/2 arrives with a
	// different immutable authorization hash.
	contradictory := onlyLeases(facts)
	leaf := contradictory.Leases[receipt1.LeaseID]
	leaf.Scopes = []string{string(ScopeReadAudit)}
	leaf.FactHash = factHash(leaf)
	if _, err := task.SubmitFacts(contradictory, now); err != nil {
		t.Fatal(err)
	}

	decisions := task.Verify(now)
	byID := make(map[string]*VerificationDecision)
	for _, decision := range decisions {
		byID[decision.ReceiptID] = decision
	}
	for _, id := range []string{receipt1.ID, receipt2.ID} {
		decision := byID[id]
		if decision.Status != StatusConflict {
			t.Fatalf("affected receipt = %+v", decision)
		}
		if len(decision.Conflicts) != 1 || decision.Conflicts[0].Key != "lease/"+receipt1.LeaseID {
			t.Fatalf("conflicts = %+v", decision.Conflicts)
		}
		if len(decision.Conflicts[0].Batches) != 2 {
			t.Fatalf("conflict batches = %v", decision.Conflicts[0].Batches)
		}
	}
	if byID[receipt3.ID].Status != StatusValid {
		t.Fatalf("unaffected receipt = %+v", byID[receipt3.ID])
	}

	// A conflicted decision cannot be exported for reproduction.
	if _, err := task.Export([]string{receipt1.ID}, now); !errors.Is(err, ErrDecisionNotExportable) {
		t.Fatalf("export conflicted = %v", err)
	}
}

func TestVerificationTaskRevocationAppendsNewDecision(t *testing.T) {
	svc, facts, receipt1, _, root := taskFixture(t)
	ctx := context.Background()
	now := time.Now()
	task := NewVerificationTask("revocation", now)
	if _, err := task.AddReceipt(receipt1); err != nil {
		t.Fatal(err)
	}
	if _, err := task.SubmitFacts(facts, now); err != nil {
		t.Fatal(err)
	}
	decisions := task.Verify(now)
	if decisions[0].Status != StatusValid || !decisions[0].CurrentlyUsable {
		t.Fatalf("before revocation = %+v", decisions[0])
	}

	// The authorization is revoked afterwards; a new facts batch arrives.
	if err := svc.Revoke(ctx, root.Token); err != nil {
		t.Fatal(err)
	}
	factsAfter, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := task.SubmitFacts(factsAfter, now); err != nil {
		t.Fatal(err)
	}
	decisions = task.Verify(now)
	latest := decisions[0]
	if latest.Status != StatusValid || latest.CurrentlyUsable {
		t.Fatalf("after revocation = %+v", latest)
	}
	if latest.Reason == "" {
		t.Fatalf("expected unusable reason")
	}
	foundRevocationBatch := false
	for _, batch := range latest.BasisBatches {
		if batch == "batch-2" {
			foundRevocationBatch = true
		}
	}
	if !foundRevocationBatch {
		t.Fatalf("basis %v lacks revocation batch", latest.BasisBatches)
	}
	// The earlier decision still says the receipt was usable then.
	if !task.Decisions[0].CurrentlyUsable || task.Decisions[0].Status != StatusValid {
		t.Fatalf("earlier decision rewritten: %+v", task.Decisions[0])
	}
}

func TestVerificationTaskSaveLoadContinues(t *testing.T) {
	_, facts, receipt1, _, _ := taskFixture(t)
	now := time.Now()
	task := NewVerificationTask("reopen", now)
	if _, err := task.AddReceipt(receipt1); err != nil {
		t.Fatal(err)
	}
	if _, err := task.SubmitFacts(onlyReceiptRecords(facts), now); err != nil {
		t.Fatal(err)
	}
	task.Verify(now)

	path := t.TempDir() + "/verification-task.json"
	if err := task.Save(path); err != nil {
		t.Fatal(err)
	}
	reopened, err := LoadVerificationTask(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Decisions) != 1 || len(reopened.Batches) != 1 || len(reopened.Receipts) != 1 {
		t.Fatalf("reopened task = %+v", reopened)
	}
	// Verification continues where the task left off.
	if _, err := reopened.SubmitFacts(facts, now); err != nil {
		t.Fatal(err)
	}
	decisions := reopened.Verify(now)
	if decisions[0].Status != StatusValid {
		t.Fatalf("after reopen = %+v", decisions[0])
	}
	if decisions[0].Seq != 2 {
		t.Fatalf("seq after reopen = %d", decisions[0].Seq)
	}
}

func TestVerificationTaskExportReproducesAndLeavesTaskUntouched(t *testing.T) {
	_, facts, receipt1, receipt2, _ := taskFixture(t)
	now := time.Now()
	task := NewVerificationTask("export", now)
	if _, err := task.AddReceipt(receipt1); err != nil {
		t.Fatal(err)
	}
	// An undetermined receipt: never registered in the held facts.
	unknown := *receipt2
	unknown.ID = "rcpt_00000000000000000000000000000000"
	unknown.ReceiptHash = RecomputeReceiptHash(&unknown)
	if _, err := task.AddReceipt(&unknown); err != nil {
		t.Fatal(err)
	}
	if _, err := task.SubmitFacts(facts, now); err != nil {
		t.Fatal(err)
	}
	task.Verify(now)

	before, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := task.Export([]string{receipt1.ID, unknown.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("export mutated the task")
	}

	// The package carries only the needed facts: purposes are hash-only, no
	// unrelated usage events, no material plaintext fields at all.
	for id, fact := range pkg.Facts.Leases {
		if fact.Purpose != "" {
			t.Fatalf("lease %s discloses purpose", id)
		}
	}
	if len(pkg.Facts.Receipts) != 1 {
		t.Fatalf("package records = %d", len(pkg.Facts.Receipts))
	}
	if len(pkg.Facts.Secrets) != 1 || len(pkg.Facts.Secrets["demo-db"].Versions) != 1 {
		t.Fatalf("package secrets = %+v", pkg.Facts.Secrets)
	}

	path := t.TempDir() + "/package.json"
	if err := pkg.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVerificationPackage(path)
	if err != nil {
		t.Fatal(err)
	}
	reproduced, err := loaded.Reproduce(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(reproduced) != 2 {
		t.Fatalf("reproduced = %d", len(reproduced))
	}
	if reproduced[0].Status != StatusValid || reproduced[1].Status != StatusUndetermined {
		t.Fatalf("reproduced statuses = %s, %s", reproduced[0].Status, reproduced[1].Status)
	}

	if _, err := task.Export([]string{"rcpt_missing"}, now); !errors.Is(err, ErrUnknownReceipt) {
		t.Fatalf("export unknown = %v", err)
	}
}
