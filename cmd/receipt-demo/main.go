// receipt-demo shows offline usage receipts over fictional material:
// parallel authorizations, upstream rotation, and a tampered receipt. It
// never prints material plaintext.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	localsecretmaterials "localsecretmaterials"
)

func main() {
	dir := flag.String("dir", "receipt-demo-data", "directory for fictional local service state")
	flag.Parse()
	ctx := context.Background()

	key, err := localsecretmaterials.GenerateDemoMasterKey()
	if err != nil {
		log.Fatal(err)
	}
	service, err := localsecretmaterials.OpenDemoService(ctx, *dir, key)
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()

	if _, err := service.CreateSecret(ctx, "reporting-token", []byte("fictional-material-body"), localsecretmaterials.SecretOptions{}); err != nil {
		log.Fatal(err)
	}

	// Parallel authorizations converging on one operator.
	readRoot, err := service.Borrow(ctx, "reporting-token", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "billing", Scopes: []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
	})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := service.Borrow(ctx, "reporting-token", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "billing", Scopes: []localsecretmaterials.Scope{localsecretmaterials.ScopeReadAudit},
	}); err != nil {
		log.Fatal(err)
	}
	delegated, err := service.Delegate(ctx, readRoot.Token, localsecretmaterials.DelegateOptions{
		Purpose: "billing/monthly-close",
		Scopes:  []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
		TTL:     30 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}

	// One real use with a redacted receipt: only the purpose prefix is shown.
	material, receipt, err := service.UseWithReceipt(ctx, delegated.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("used version %s (%d fictional bytes, not shown); receipt %s discloses purpose prefix %q only\n",
		material.VersionID, len(material.Plaintext), receipt.ID, receipt.PurposeHint)

	// Upstream rotation: the pinned receipt still verifies afterwards.
	if _, err := service.RotateSecret(ctx, "reporting-token", []byte("fictional-material-body-v2")); err != nil {
		log.Fatal(err)
	}
	fmt.Println("upstream rotated the material to a new version")

	facts, err := service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	report("original receipt after rotation", localsecretmaterials.VerifyReceipt(receipt, facts, time.Now()))

	// Version-rewrite attack: retarget the old receipt at the rotated version
	// and recompute every digest. It must be rejected as invalid because the
	// registered usage event pins the version that was actually used.
	var v2Digest string
	for _, version := range facts.Secrets["reporting-token"].Versions {
		if version.VersionID == material.VersionID {
			continue
		}
		v2Digest = version.MaterialDigest
	}
	swapped := *receipt
	for _, version := range facts.Secrets["reporting-token"].Versions {
		if version.MaterialDigest == v2Digest {
			swapped.VersionID = version.VersionID
		}
	}
	swapped.MaterialDigest = v2Digest
	swapped.ReceiptHash = localsecretmaterials.RecomputeReceiptHash(&swapped)
	report("version-rewritten receipt", localsecretmaterials.VerifyReceipt(&swapped, facts, time.Now()))

	// A different verifier holds only the minimum redacted facts: hashes and
	// one usage event, no business purpose text, no unrelated authorizations.
	redacted := localsecretmaterials.RedactFactsForReceipt(facts, receipt)
	report("receipt on redacted facts only", localsecretmaterials.VerifyReceipt(receipt, redacted, time.Now()))

	// No matching registered usage event: evidence is insufficient, so the
	// answer is undetermined rather than illegal or currently usable.
	unknown := *receipt
	unknown.ID = "rcpt_00000000000000000000000000000000"
	unknown.ReceiptHash = localsecretmaterials.RecomputeReceiptHash(&unknown)
	report("receipt absent from held facts", localsecretmaterials.VerifyReceipt(&unknown, redacted, time.Now()))

	// Tampered receipt: decision flipped, one delegation layer removed.
	tampered := *receipt
	tampered.Decision = "allowed-unconditionally"
	tampered.Chain = receipt.Chain[1:]
	report("tampered receipt", localsecretmaterials.VerifyReceipt(&tampered, facts, time.Now()))

	// Later upstream revocation: then-legitimate, now unusable.
	if err := service.Revoke(ctx, readRoot.Token); err != nil {
		log.Fatal(err)
	}
	facts, err = service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	report("receipt after upstream revocation", localsecretmaterials.VerifyReceipt(receipt, facts, time.Now()))
}

func report(label string, result *localsecretmaterials.ReceiptVerification) {
	reason := result.Reason
	if reason == "" {
		reason = "ok"
	}
	fmt.Printf("%-38s status=%-12s valid_then=%-5v usable_now=%-5v (%s)\n", label+":", result.Status, result.Valid, result.CurrentlyUsable, reason)
}
