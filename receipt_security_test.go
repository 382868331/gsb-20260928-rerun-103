package localsecretmaterials

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The attack from the task: take a real receipt, swap the material version
// for the later rotated one, recompute the digest and receipt hash, and hope
// offline verification accepts a pinned old-version lease as a new-version
// use. The registered usage record must pin the exact use and reject this.
func TestUsageReceiptVersionSwapRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := svc.RotateSecret(ctx, "vault-token", []byte("fictional-material-body-v2"))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(receipt, facts, now).Valid {
		t.Fatal("original receipt must still verify after rotation")
	}

	var v2Digest string
	for _, version := range facts.Secrets["vault-token"].Versions {
		if version.VersionID == v2 {
			v2Digest = version.MaterialDigest
		}
	}
	forged := *receipt
	forged.VersionID = v2
	forged.MaterialDigest = v2Digest
	forged.ReceiptHash = recomputeReceiptHash(&forged)
	result := VerifyReceipt(&forged, facts, now)
	if result.Status != StatusInvalid || result.Valid {
		t.Fatalf("version-swapped receipt verified: %+v", result)
	}
	if !strings.Contains(result.Reason, "registered usage event") {
		t.Fatalf("unexpected reason: %s", result.Reason)
	}

	// A fully self-consistent fabricated receipt with no registered event is
	// undetermined, never accepted as a legal use.
	fake := *receipt
	fake.ID = "rcpt_0000000000000000000000000000dead"
	fake.ReceiptHash = recomputeReceiptHash(&fake)
	if result := VerifyReceipt(&fake, facts, now); result.Status != StatusUndetermined || result.Valid || result.CurrentlyUsable {
		t.Fatalf("unregistered receipt must stay undetermined: %+v", result)
	}
}

// Cross-receipt splicing: two receipts each legitimate on their own chain
// must not combine into a wider authorization for a single use.
func TestUsageReceiptCrossReceiptSplicingRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "marketing",
		Scopes:  []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, otherReceipt, err := svc.UseWithReceipt(ctx, other.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	spliced := *receipt
	spliced.LeaseID = otherReceipt.LeaseID
	spliced.Chain = otherReceipt.Chain
	spliced.ReceiptHash = recomputeReceiptHash(&spliced)
	if result := VerifyReceipt(&spliced, facts, now); result.Status != StatusInvalid {
		t.Fatalf("cross-receipt splice accepted: %+v", result)
	}

	trimmed := *receipt
	trimmed.Chain = otherReceipt.Chain
	trimmed.ReceiptHash = recomputeReceiptHash(&trimmed)
	if result := VerifyReceipt(&trimmed, facts, now); result.Status != StatusInvalid {
		t.Fatalf("chain length splice accepted: %+v", result)
	}
}

// A verifier with only the minimum disclosed facts can confirm the receipt
// and current usability, and sees neither business purpose text nor material.
func TestUsageReceiptVerifiesWithRedactedFacts(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
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
	redacted := RedactFactsForReceipt(facts, receipt)
	if redacted == nil {
		t.Fatal("redacted facts missing")
	}
	if result := VerifyReceipt(receipt, redacted, now); result.Status != StatusValid || !result.CurrentlyUsable {
		t.Fatalf("receipt must verify on redacted facts: %+v", result)
	}
	encoded, _ := json.Marshal(redacted)
	for _, leaked := range []string{"monthly-close", "fictional-material-body", "fictional-material-body-v2"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("redacted facts leak %q: %s", leaked, encoded)
		}
	}
	if len(redacted.Leases) != len(receipt.Chain) {
		t.Fatalf("redacted facts carry %d leases, want %d", len(redacted.Leases), len(receipt.Chain))
	}
	if len(redacted.Receipts) != 1 {
		t.Fatal("redacted facts must expose exactly the one usage event")
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
	reopenedFacts, err := reopened.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reopenedRedacted := RedactFactsForReceipt(reopenedFacts, receipt)
	if result := VerifyReceipt(receipt, reopenedRedacted, now); !result.Valid {
		t.Fatalf("receipt must verify on redacted facts after reopen: %+v", result)
	}
}

// When the verifier lacks the registered usage event or a required chain
// layer, the answer is undetermined, not illegal and not currently usable.
func TestUsageReceiptMissingEvidenceUndetermined(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delete(facts.Receipts, receipt.ID)
	if result := VerifyReceipt(receipt, facts, now); result.Status != StatusUndetermined || result.Valid || result.CurrentlyUsable {
		t.Fatalf("missing event must be undetermined: %+v", result)
	}

	facts, err = svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	delete(facts.Leases, receipt.LeaseID)
	if result := VerifyReceipt(receipt, facts, now); result.Status != StatusUndetermined {
		t.Fatalf("missing delegation layer must be undetermined: %+v", result)
	}
}

// A chain where every layer explicitly adopts new versions can use a rotated
// version; such a receipt still must match the registered event and cannot be
// freely retargeted to yet another version.
func TestUsageReceiptAdoptedVersionChain(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "vault-token", []byte("fictional-material-body"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	root, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "ops", Scopes: []Scope{ScopeReadMaterial}, AllowsNewVersions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.Delegate(ctx, root.Token, DelegateOptions{
		Purpose: "ops/rollout", Scopes: []Scope{ScopeReadMaterial}, TTL: 30 * time.Minute, AllowsNewVersions: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := svc.RotateSecret(ctx, "vault-token", []byte("fictional-material-body-v2"))
	if err != nil {
		t.Fatal(err)
	}
	checked, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if checked.VersionID != v2 {
		t.Fatalf("adopted use version = %s, want %s", checked.VersionID, v2)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result := VerifyReceipt(receipt, facts, now); result.Status != StatusValid || !result.CurrentlyUsable {
		t.Fatalf("adopted-version receipt must verify: %+v", result)
	}
	if result := VerifyReceipt(receipt, facts, now.Add(2*time.Hour)); result.Status != StatusValid || result.CurrentlyUsable {
		t.Fatalf("expired chain should be valid-then but not usable now: %+v", result)
	}
	fake := *receipt
	fake.ID = "rcpt_0000000000000000000000000000beef"
	fake.ReceiptHash = recomputeReceiptHash(&fake)
	if result := VerifyReceipt(&fake, facts, now); result.Status != StatusUndetermined {
		t.Fatalf("unregistered adopted-version receipt accepted: %+v", result)
	}
}
