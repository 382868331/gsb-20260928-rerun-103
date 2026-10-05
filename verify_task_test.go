package localsecretmaterials

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTaskService(t *testing.T) (*Service, context.Context, *time.Time) {
	t.Helper()
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	return svc, ctx, &now
}

func useOnce(t *testing.T, svc *Service, ctx context.Context, token, hint string) *UsageReceipt {
	t.Helper()
	_, receipt, err := svc.UseWithReceipt(ctx, token, ReceiptOptions{PurposeHint: hint})
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestVerificationTaskOutOfOrderBatches(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	_, child := setupReceiptChain(t, svc, now)
	receipt := useOnce(t, svc, ctx, child.Token, "billing")
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	task := NewVerificationTask("task-1", *now)
	// The receipt arrives before any fact batch.
	if dup, _ := task.SubmitReceipt(receipt, *now); dup {
		t.Fatal("first arrival counted as duplicate")
	}
	first := task.Verify(receipt.ID, *now)
	if first.Status != StatusUndetermined {
		t.Fatalf("before facts status = %s", first.Status)
	}
	// First batch: secrets and leases only, no registered usage event.
	task.SubmitFacts(&AuthorizationFacts{Secrets: facts.Secrets, Leases: facts.Leases}, *now)
	second := task.Verify(receipt.ID, *now)
	if second.Status != StatusUndetermined {
		t.Fatalf("without usage event status = %s", second.Status)
	}
	// Second batch: the registered usage events arrive later.
	task.SubmitFacts(&AuthorizationFacts{Receipts: facts.Receipts}, *now)
	third := task.Verify(receipt.ID, *now)
	if third.Status != StatusValid || !third.Valid {
		t.Fatalf("after full facts status = %s (%s)", third.Status, third.Reason)
	}
	// Earlier conclusions are appended, never rewritten.
	if len(task.Decisions) != 3 {
		t.Fatalf("decisions = %d", len(task.Decisions))
	}
	if task.Decisions[0].Status != StatusUndetermined || task.Decisions[1].Status != StatusUndetermined {
		t.Fatalf("history rewritten: %+v", task.Decisions)
	}
	// The basis names exactly which facts the valid decision used.
	if third.Basis == nil || third.Basis.ReceiptRecordHash == "" || len(third.Basis.LeaseFactHashes) != 2 || third.Basis.VersionDigest == "" {
		t.Fatalf("basis incomplete: %+v", third.Basis)
	}
}

func TestVerificationTaskDeduplicatesReceipts(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	_, child := setupReceiptChain(t, svc, now)
	first := useOnce(t, svc, ctx, child.Token, "billing")
	second := useOnce(t, svc, ctx, child.Token, "billing")

	task := NewVerificationTask("task-dedup", *now)
	if dup, _ := task.SubmitReceipt(first, *now); dup {
		t.Fatal("first arrival is not a duplicate")
	}
	if dup, _ := task.SubmitReceipt(first, *now); !dup {
		t.Fatal("same receipt arriving again must be a duplicate")
	}
	if task.UsageCount() != 1 {
		t.Fatalf("usage count after duplicate = %d", task.UsageCount())
	}
	// A different receipt from the same material version is kept separately.
	if first.VersionID != second.VersionID {
		t.Fatalf("expected same version, got %s vs %s", first.VersionID, second.VersionID)
	}
	if dup, _ := task.SubmitReceipt(second, *now); dup {
		t.Fatal("distinct receipt counted as duplicate")
	}
	if task.UsageCount() != 2 {
		t.Fatalf("usage count = %d", task.UsageCount())
	}
}

func TestVerificationTaskHintHiding(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	_, child := setupReceiptChain(t, svc, now)
	receipt := useOnce(t, svc, ctx, child.Token, "billing")
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	task := NewVerificationTask("task-hint", *now)
	task.SubmitReceipt(receipt, *now)
	// The holder shows the same receipt again with the purpose hint hidden.
	hidden := *receipt
	hidden.PurposeHint = ""
	if dup, _ := task.SubmitReceipt(&hidden, *now); !dup {
		t.Fatal("hidden-hint copy of the same receipt must deduplicate")
	}
	if task.UsageCount() != 1 {
		t.Fatalf("usage count = %d", task.UsageCount())
	}
	if task.Receipts[receipt.ID].PurposeHint != "" {
		t.Fatalf("stored hint = %q", task.Receipts[receipt.ID].PurposeHint)
	}
	task.SubmitFacts(facts, *now)
	decision := task.Verify(receipt.ID, *now)
	if decision.Status != StatusValid {
		t.Fatalf("hidden-hint receipt status = %s (%s)", decision.Status, decision.Reason)
	}
}

func TestVerificationTaskLaterRevocation(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	root, child := setupReceiptChain(t, svc, now)
	receipt := useOnce(t, svc, ctx, child.Token, "billing")
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	task := NewVerificationTask("task-revoke", *now)
	task.SubmitReceipt(receipt, *now)
	task.SubmitFacts(facts, *now)
	before := task.Verify(receipt.ID, *now)
	if !before.Valid || !before.CurrentlyUsable {
		t.Fatalf("before revocation = %+v", before)
	}

	// The authorization is revoked afterwards; a new fact batch arrives.
	if err := svc.Revoke(ctx, root.Token); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if conflicts := task.SubmitFacts(updated, *now); len(conflicts) != 0 {
		t.Fatalf("revocation snapshot must not conflict: %+v", conflicts)
	}
	after := task.Verify(receipt.ID, *now)
	if after.Status != StatusValid || after.CurrentlyUsable {
		t.Fatalf("after revocation = %+v", after)
	}
	// The earlier decision is history and stays usable-at-that-time.
	if !task.Decisions[0].CurrentlyUsable {
		t.Fatal("earlier decision was rewritten")
	}
}

func TestVerificationTaskConflictIsolation(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	root, child := setupReceiptChain(t, svc, now)
	affected := useOnce(t, svc, ctx, child.Token, "billing")

	// A second, independent chain produces an unaffected receipt.
	otherRoot, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "billing", Scopes: []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	unaffected := useOnce(t, svc, ctx, otherRoot.Token, "billing")

	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	task := NewVerificationTask("task-conflict", *now)
	task.SubmitReceipt(affected, *now)
	task.SubmitReceipt(unaffected, *now)
	task.SubmitFacts(facts, *now)

	// A contradictory batch claims a different immutable authorization for
	// the root lease of the first chain.
	forged := cloneJSON(facts)
	lie := forged.Leases[root.ID]
	lie.PurposeHash = purposeHash("marketing")
	lie.FactHash = factHash(lie)
	conflicts := task.SubmitFacts(forged, *now)
	if len(conflicts) != 1 || conflicts[0].Kind != "lease" || conflicts[0].ID != root.ID {
		t.Fatalf("conflicts = %+v", conflicts)
	}

	decision := task.Verify(affected.ID, *now)
	if decision.Status != StatusConflict {
		t.Fatalf("affected receipt status = %s", decision.Status)
	}
	if len(decision.Conflicts) != 1 || decision.Conflicts[0].ID != root.ID {
		t.Fatalf("decision conflicts = %+v", decision.Conflicts)
	}
	other := task.Verify(unaffected.ID, *now)
	if other.Status != StatusValid {
		t.Fatalf("unaffected receipt status = %s (%s)", other.Status, other.Reason)
	}
}

func TestVerificationTaskSaveAndReopen(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	_, child := setupReceiptChain(t, svc, now)
	receipt := useOnce(t, svc, ctx, child.Token, "billing")
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	task := NewVerificationTask("task-persist", *now)
	task.SubmitReceipt(receipt, *now)
	// Save while evidence is still incomplete.
	pending := task.Verify(receipt.ID, *now)
	if pending.Status != StatusUndetermined {
		t.Fatalf("pending status = %s", pending.Status)
	}
	if err := task.Save(ctx, dir); err != nil {
		t.Fatal(err)
	}

	// Reopen and continue: the fact batch arrives after the restart.
	reopened, err := LoadVerificationTask(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.Decisions) != 1 || reopened.UsageCount() != 1 {
		t.Fatalf("reopened state lost: %d decisions, %d uses", len(reopened.Decisions), reopened.UsageCount())
	}
	reopened.SubmitFacts(facts, *now)
	decision := reopened.Verify(receipt.ID, *now)
	if decision.Status != StatusValid || decision.Seq != 2 {
		t.Fatalf("after reopen = %+v", decision)
	}
	if err := reopened.Save(ctx, dir); err != nil {
		t.Fatal(err)
	}
	again, err := LoadVerificationTask(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Decisions) != 2 || again.Decisions[0].Status != StatusUndetermined {
		t.Fatalf("history after reopen = %+v", again.Decisions)
	}
}

func TestVerificationTaskExportPackage(t *testing.T) {
	svc, ctx, now := setupTaskService(t)
	_, child := setupReceiptChain(t, svc, now)
	receipt := useOnce(t, svc, ctx, child.Token, "billing")
	other := useOnce(t, svc, ctx, child.Token, "billing")
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	task := NewVerificationTask("task-export", *now)
	task.SubmitReceipt(receipt, *now)
	task.SubmitReceipt(other, *now)
	task.SubmitFacts(facts, *now)
	decision := task.Verify(receipt.ID, *now)
	if decision.Status != StatusValid {
		t.Fatalf("status = %s", decision.Status)
	}
	if err := task.Save(ctx, dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, verificationTaskFile))
	if err != nil {
		t.Fatal(err)
	}

	pkg, err := task.ExportPackage([]string{receipt.ID}, *now)
	if err != nil {
		t.Fatal(err)
	}
	// Exporting must not change the original task, in memory or on disk.
	after, err := os.ReadFile(filepath.Join(dir, verificationTaskFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("export modified the saved task")
	}
	if task.UsageCount() != 2 || len(task.Decisions) != 1 {
		t.Fatalf("export mutated in-memory task: %d uses, %d decisions", task.UsageCount(), len(task.Decisions))
	}

	// The receiver reproduces the exported decision from the package alone.
	results := VerifyPackage(pkg, *now)
	if len(results) != 1 || !results[0].Matches || results[0].Reproduced != StatusValid {
		t.Fatalf("reproduction = %+v", results)
	}
	// The package carries only the needed facts and no business text.
	if len(pkg.Facts.Receipts) != 1 || len(pkg.Receipts) != 1 {
		t.Fatalf("package leaks unrelated receipts: %+v", pkg.Facts.Receipts)
	}
	encoded, _ := json.Marshal(pkg)
	if strings.Contains(string(encoded), "fictional-material-body") || strings.Contains(string(encoded), "monthly-close") {
		t.Fatalf("package leaks material or purpose: %s", encoded)
	}
	if _, err := task.ExportPackage([]string{"rcpt_missing"}, *now); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing receipt export error = %v", err)
	}
}
