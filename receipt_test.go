package localsecretmaterials

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func setupReceiptChain(t *testing.T, svc *Service, now *time.Time) (*Lease, *Lease) {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.CreateSecret(ctx, "vault-token", []byte("fictional-material-body"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	root, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "billing",
		Scopes:  []Scope{ScopeReadMaterial, ScopeReadAudit},
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.Delegate(ctx, root.Token, DelegateOptions{
		Purpose: "billing/monthly-close",
		Scopes:  []Scope{ScopeReadMaterial},
		TTL:     30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, child
}

func TestUsageReceiptVerifiesOffline(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	checked, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		t.Fatal(err)
	}
	if string(checked.Plaintext) != "fictional-material-body" {
		t.Fatalf("plaintext = %q", checked.Plaintext)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyReceipt(receipt, facts, now)
	if !result.Valid || !result.CurrentlyUsable {
		t.Fatalf("verification = %+v", result)
	}
	if len(receipt.Chain) != 2 {
		t.Fatalf("chain length = %d", len(receipt.Chain))
	}

	encoded, _ := json.Marshal(receipt)
	if strings.Contains(string(encoded), "fictional-material-body") || strings.Contains(string(encoded), "monthly-close") {
		t.Fatalf("receipt leaks material or full purpose: %s", encoded)
	}
	factsEncoded, _ := json.Marshal(facts)
	if strings.Contains(string(factsEncoded), "fictional-material-body") {
		t.Fatalf("facts leak material: %s", factsEncoded)
	}
}

func TestUsageReceiptRejectsBadHintAndTampering(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	_, child := setupReceiptChain(t, svc, &now)

	if _, _, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{PurposeHint: "marketing"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad hint error = %v", err)
	}
	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tampered := *receipt
	tampered.Decision = "allowed-after-revoke"
	if VerifyReceipt(&tampered, facts, now).Valid {
		t.Fatal("tampered decision verified")
	}
	tampered = *receipt
	tampered.SecretName = "other-secret"
	if VerifyReceipt(&tampered, facts, now).Valid {
		t.Fatal("substituted secret verified")
	}
	tampered = *receipt
	tampered.VersionID = "ver_deadbeef"
	if VerifyReceipt(&tampered, facts, now).Valid {
		t.Fatal("substituted version verified")
	}
	tampered = *receipt
	tampered.Chain = receipt.Chain[1:]
	if VerifyReceipt(&tampered, facts, now).Valid {
		t.Fatal("removed delegation layer verified")
	}
	tampered = *receipt
	tampered.Chain = []string{receipt.Chain[1], receipt.Chain[0]}
	if VerifyReceipt(&tampered, facts, now).Valid {
		t.Fatal("reordered chain verified")
	}
}

func TestUsageReceiptHintRedactionKeepsValidity(t *testing.T) {
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

	// Full disclosure verifies.
	if result := VerifyReceipt(receipt, facts, now); !result.Valid {
		t.Fatalf("full hint verification = %+v", result)
	}
	// Shortening the business hint to any prefix keeps the receipt valid.
	shortened := *receipt
	shortened.PurposeHint = "bill"
	if result := VerifyReceipt(&shortened, facts, now); !result.Valid {
		t.Fatalf("shortened hint verification = %+v", result)
	}
	// Clearing the hint entirely keeps the receipt valid.
	cleared := *receipt
	cleared.PurposeHint = ""
	if result := VerifyReceipt(&cleared, facts, now); !result.Valid {
		t.Fatalf("cleared hint verification = %+v", result)
	}
	// Redaction also verifies against the minimal redacted fact subset.
	redacted := RedactFactsForReceipt(facts, receipt)
	if result := VerifyReceipt(&cleared, redacted, now); !result.Valid {
		t.Fatalf("cleared hint with redacted facts = %+v", result)
	}
	// A hint that is not a prefix of the registered hint is not redaction.
	forged := *receipt
	forged.PurposeHint = "bills"
	if result := VerifyReceipt(&forged, facts, now); result.Valid || result.Status != StatusInvalid {
		t.Fatalf("forged hint verification = %+v", result)
	}
	// Verification output never carries material plaintext.
	encoded, _ := json.Marshal(VerifyReceipt(receipt, facts, now))
	if strings.Contains(string(encoded), "fictional-material-body") {
		t.Fatalf("verification output leaks material: %s", encoded)
	}
}

func TestUsageReceiptCrossReceiptHintSplicing(t *testing.T) {
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
		Purpose: "audit", Scopes: []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, receiptA, err := svc.UseWithReceipt(ctx, rootA.Token, ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		t.Fatal(err)
	}
	_, receiptB, err := svc.UseWithReceipt(ctx, rootB.Token, ReceiptOptions{PurposeHint: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Splicing receipt B's hint into receipt A is not a redaction of A's
	// registered hint and must be rejected.
	spliced := *receiptA
	spliced.PurposeHint = "audit"
	if result := VerifyReceipt(&spliced, facts, now); result.Valid || result.Status != StatusInvalid {
		t.Fatalf("cross-receipt hint splice = %+v", result)
	}
	// Splicing receipt B's chain into receipt A stays invalid too.
	splicedChain := *receiptA
	splicedChain.Chain = receiptB.Chain
	if result := VerifyReceipt(&splicedChain, facts, now); result.Valid || result.Status != StatusInvalid {
		t.Fatalf("cross-receipt chain splice = %+v", result)
	}
}

func TestUsageReceiptMissingFactsUndetermined(t *testing.T) {
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

	// No registered usage event: undetermined, never valid.
	withoutRecord := cloneJSON(facts)
	delete(withoutRecord.Receipts, receipt.ID)
	if result := VerifyReceipt(receipt, withoutRecord, now); result.Valid || result.Status != StatusUndetermined {
		t.Fatalf("missing usage record = %+v", result)
	}
	// A missing delegation layer: undetermined.
	withoutLease := cloneJSON(facts)
	for id := range withoutLease.Leases {
		delete(withoutLease.Leases, id)
		break
	}
	if result := VerifyReceipt(receipt, withoutLease, now); result.Valid || result.Status != StatusUndetermined {
		t.Fatalf("missing delegation layer = %+v", result)
	}
	// A missing version fact: undetermined.
	withoutVersion := cloneJSON(facts)
	withoutVersion.Secrets[receipt.SecretName].Versions = nil
	if result := VerifyReceipt(receipt, withoutVersion, now); result.Valid || result.Status != StatusUndetermined {
		t.Fatalf("missing version fact = %+v", result)
	}
}

func TestUsageReceiptParallelChainsCannotMerge(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "vault-token", []byte("fictional-material-body"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	// Two parallel authorizations converging on the same operator: chain A
	// can read material, chain B can only read audit.
	rootA, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "billing", Scopes: []Scope{ScopeReadMaterial},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := svc.Borrow(ctx, "vault-token", time.Hour, BorrowOptions{
		Purpose: "billing", Scopes: []Scope{ScopeReadAudit},
	})
	if err != nil {
		t.Fatal(err)
	}
	leafB, err := svc.Delegate(ctx, rootB.Token, DelegateOptions{
		Purpose: "billing/audit-review", Scopes: []Scope{ScopeReadAudit}, TTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.UseWithReceipt(ctx, leafB.Token, ReceiptOptions{}); !errors.Is(err, ErrLeaseScopeDenied) {
		t.Fatalf("audit-only use error = %v", err)
	}
	_, receipt, err := svc.UseWithReceipt(ctx, rootA.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyReceipt(receipt, facts, now).Valid {
		t.Fatal("single-chain receipt should verify")
	}

	// Attacker splices chain B's extra layer under chain A's leaf to claim a
	// wider combined permit.
	merged := *receipt
	merged.Chain = append(append([]string{}, receipt.Chain...), receipt.Chain...)
	if VerifyReceipt(&merged, facts, now).Valid {
		t.Fatal("merged cross-chain receipt verified")
	}
	// Attacker swaps the leaf to chain B's lease while keeping chain A links.
	swapped := *receipt
	swapped.LeaseID = leafB.ID
	if VerifyReceipt(&swapped, facts, now).Valid {
		t.Fatal("leaf-swapped receipt verified")
	}
}

func TestUsageReceiptDistinguishesLaterUpstreamRevocation(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	root, child := setupReceiptChain(t, svc, &now)

	_, receipt, err := svc.UseWithReceipt(ctx, child.Token, ReceiptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, root.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(ctx, child.Token); !errors.Is(err, ErrUpstreamLeaseRevoked) {
		t.Fatalf("post-revoke use error = %v", err)
	}
	facts, err := svc.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyReceipt(receipt, facts, now)
	if !result.Valid {
		t.Fatalf("earlier legitimate use should still verify: %+v", result)
	}
	if result.CurrentlyUsable {
		t.Fatal("revoked chain must report currently unusable")
	}
}

func TestUsageReceiptSurvivesRotationAndReopen(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
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
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen with a fresh process key: decryption of the old version fails,
	// but the receipt's authorization facts remain traceable.
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
	if !result.Valid {
		t.Fatalf("receipt after reopen = %+v", result)
	}
	encoded, _ := json.Marshal(facts)
	for _, leaked := range []string{"fictional-material-body", "fictional-material-body-v2"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("persisted facts leak material: %s", encoded)
		}
	}
}
