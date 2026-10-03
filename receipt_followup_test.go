package localsecretmaterials

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Rewriting an old receipt onto a later rotated version and recomputing the
// plain hash must no longer turn an old use into a new-version use.
func TestUsageReceiptRejectsRotatedVersionSubstitution(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateSecret(ctx, "vault-token", []byte("fictional-material-body-v2")); err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var newVersion *VersionFact
	for i := range facts.Secrets["vault-token"].Versions {
		v := facts.Secrets["vault-token"].Versions[i]
		if v.VersionID != receipt.VersionID {
			newVersion = &v
		}
	}
	if newVersion == nil {
		t.Fatal("rotated version missing from facts")
	}

	// Rewrite object version and digest to the rotated one, then recompute.
	forged := *receipt
	forged.VersionID = newVersion.VersionID
	forged.MaterialDigest = newVersion.MaterialDigest
	forged.ReceiptHash = recomputeReceiptHash(&forged)
	if result := VerifyReceipt(&forged, facts, now); result.Status != ReceiptStatusInvalid {
		t.Fatalf("version substitution status = %+v", result)
	}

	// Also rewriting the persisted occurrence itself cannot help.
	rewritten := cloneJSON(facts)
	usage := cloneJSON(rewritten.Usages[receipt.ID])
	usage.VersionID = newVersion.VersionID
	usage.MaterialDigest = newVersion.MaterialDigest
	usage.FactHash = recomputeUsageFactHash(usage)
	rewritten.Usages[receipt.ID] = usage
	forged2 := *receipt
	forged2.VersionID = newVersion.VersionID
	forged2.MaterialDigest = newVersion.MaterialDigest
	forged2.UsageHash = usage.FactHash
	forged2.ReceiptHash = recomputeReceiptHash(&forged2)
	if result := VerifyReceipt(&forged2, rewritten, now); result.Status != ReceiptStatusInvalid {
		t.Fatalf("rewritten occurrence status = %+v", result)
	}
}

// Splicing chains from two separately issued receipts cannot assemble wider
// permission; deleting a required delegation layer is invalid, not unknown.
func TestUsageReceiptRejectsCrossReceiptSplice(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "vault-token", []byte("fictional-material-body"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	rootA, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "billing", Scopes: []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "marketing", Scopes: []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	childA, err := svc.Delegate(ctx, rootA.Token, DelegateOptions{
		Purpose: "billing/monthly-close", Scopes: []Scope{ScopeReadMaterial}, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delegate(ctx, rootB.Token, DelegateOptions{
		Purpose: "marketing/campaign", Scopes: []Scope{ScopeReadMaterial}, TTL: 30 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	_, receiptA, err := svc.UseWithReceipt(ctx, childA.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Truncate the required delegation layer and re-anchor at the root.
	truncated := *receiptA
	truncated.LeaseID = rootA.ID
	truncated.Chain = receiptA.Chain[1:]
	truncated.PurposeHash = purposeHashValue(rootA.Purpose)
	truncated.ReceiptHash = recomputeReceiptHash(&truncated)
	if result := VerifyReceipt(&truncated, facts, now); result.Status != ReceiptStatusInvalid {
		t.Fatalf("truncated-chain status = %+v", result)
	}

	// Drop the child lease entirely: evidence is missing, so inconclusive.
	partial := cloneJSON(facts)
	delete(partial.Leases, childA.ID)
	receiptMissingLease := *receiptA
	if result := VerifyReceipt(&receiptMissingLease, partial, now); result.Status != ReceiptStatusInconclusive {
		t.Fatalf("missing-leaf status = %+v", result)
	}
}

// A verifier holding only partial facts reports inconclusive, never illegal
// and never currently usable.
func TestUsageReceiptInconclusiveWhenFactsMissing(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)
	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	noUsage := cloneJSON(facts)
	noUsage.Usages = map[string]*UsageFact{}
	result := VerifyReceipt(receipt, noUsage, now)
	if result.Status != ReceiptStatusInconclusive || result.Valid || result.CurrentlyUsable {
		t.Fatalf("missing occurrence result = %+v", result)
	}

	missingLease := cloneJSON(facts)
	delete(missingLease.Leases, child.ParentID)
	result = VerifyReceipt(receipt, missingLease, now)
	if result.Status != ReceiptStatusInconclusive || result.CurrentlyUsable {
		t.Fatalf("missing upstream lease result = %+v", result)
	}
}

// Adoption of a rotated version keeps the earlier old-version receipt valid,
// a new receipt uses the new version, and the two occurrences cannot swap.
func TestUsageReceiptAdoptedVersionKeepsHistory(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "vault-token", []byte("fictional-material-body"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	root, err := svc.Borrow(ctx, "vault-token", 2*time.Hour, BorrowOptions{
		Purpose: "billing", Scopes: []Scope{ScopeReadMaterial}, AllowsNewVersions: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, oldReceipt, err := svc.UseWithReceipt(ctx, root.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newVersionID, err := svc.RotateSecret(ctx, "vault-token", []byte("fictional-material-body-v2"))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Leases[root.ID].VersionID != newVersionID {
		t.Fatalf("lease did not adopt new version: %s", facts.Leases[root.ID].VersionID)
	}

	now = now.Add(time.Minute)
	_, newReceipt, err := svc.UseWithReceipt(ctx, root.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err = svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if newReceipt.VersionID != newVersionID {
		t.Fatalf("new receipt version = %s", newReceipt.VersionID)
	}
	if result := VerifyReceipt(oldReceipt, facts, now); result.Status != ReceiptStatusValid || !result.CurrentlyUsable {
		t.Fatalf("old-version receipt after adoption = %+v", result)
	}
	if result := VerifyReceipt(newReceipt, facts, now); result.Status != ReceiptStatusValid {
		t.Fatalf("new-version receipt = %+v", result)
	}

	swapped := *newReceipt
	swapped.VersionID = oldReceipt.VersionID
	swapped.MaterialDigest = oldReceipt.MaterialDigest
	swapped.ReceiptHash = recomputeReceiptHash(&swapped)
	if result := VerifyReceipt(&swapped, facts, now); result.Status != ReceiptStatusInvalid {
		t.Fatalf("version-swapped receipt = %+v", result)
	}
}

// Occurrences verify offline after reopen under a different master key, and
// no verification artifact exposes the material.
func TestUsageReceiptOccurrencePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)
	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	key := MustMasterKey(GenerateDemoMasterKey())
	reopened, err := OpenDemoService(ctx, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	facts, err := reopened.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyReceipt(receipt, facts, now)
	if result.Status != ReceiptStatusValid || !result.CurrentlyUsable {
		t.Fatalf("offline verification after reopen = %+v", result)
	}

	encoded, _ := json.Marshal(facts)
	if strings.Contains(string(encoded), "fictional-material-body") {
		t.Fatalf("facts leak material: %s", encoded)
	}
}
