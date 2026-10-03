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

	// Rotated-version substitution: rewrite the receipt onto the new version
	// with a recomputed hash. The recorded occurrence is not rewritten, so it
	// is rejected rather than silently becoming a new-version use.
	substituted := *receipt
	for _, version := range facts.Secrets["reporting-token"].Versions {
		if version.VersionID != receipt.VersionID {
			substituted.VersionID = version.VersionID
			substituted.MaterialDigest = version.MaterialDigest
		}
	}
	report("rotated-version substitution", localsecretmaterials.VerifyReceipt(&substituted, facts, time.Now()))

	// Partial disclosure: a verifier given facts with the occurrence withheld
	// must remain undecided, not declare the use illegal or currently usable.
	partial := *facts
	partial.Usages = map[string]*localsecretmaterials.UsageFact{}
	report("occurrence withheld from verifier", localsecretmaterials.VerifyReceipt(receipt, &partial, time.Now()))

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
