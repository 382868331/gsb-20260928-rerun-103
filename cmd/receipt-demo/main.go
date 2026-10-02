// Command receipt-demo exercises usage receipts with fictional material:
// parallel authorizations, upstream rotation, offline verification, and a
// tampered receipt. It never prints material plaintext or tokens.
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

	service, err := localsecretmaterials.OpenDemoService(ctx, *dir, localsecretmaterials.MustMasterKey(localsecretmaterials.GenerateDemoMasterKey()))
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()

	if _, err := service.CreateSecret(ctx, "demo-vault", []byte("fictional-demo-material"), localsecretmaterials.SecretOptions{}); err != nil {
		log.Fatal(err)
	}

	// Parallel authorizations: two independent chains reach borrowers.
	readRoot, err := service.Borrow(ctx, "demo-vault", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose:           "fraud-review",
		Scopes:            []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
		AllowsNewVersions: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	worker, err := service.Delegate(ctx, readRoot.Token, localsecretmaterials.DelegateOptions{
		Purpose:           "fraud-review/case-9",
		Scopes:            []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
		TTL:               30 * time.Minute,
		AllowsNewVersions: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	auditOnly, err := service.Borrow(ctx, "demo-vault", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "audit-only",
		Scopes:  []localsecretmaterials.Scope{localsecretmaterials.ScopeReadAudit},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Upstream rotation: the chain allows new versions, so the receipt commits
	// to the rotated version.
	if _, err := service.RotateSecret(ctx, "demo-vault", []byte("fictional-demo-material-v2")); err != nil {
		log.Fatal(err)
	}

	material, receipt, err := service.UseWithReceipt(ctx, worker.Token)
	if err != nil {
		log.Fatal(err)
	}
	publicKey, keyID := service.ReceiptPublicKey()
	fmt.Printf("checked out %d fictional bytes under version %s\n", len(material.Plaintext), receipt.VersionID)
	fmt.Println(localsecretmaterials.DescribeReceipt(receipt.Redacted()))

	if err := localsecretmaterials.VerifyReceipt(receipt.Redacted(), publicKey); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("offline verification ok (signer %s); business purposes stay redacted\n", keyID)

	// A denied parallel chain gets its own denied receipt; permissions never
	// merge across chains.
	_, deniedReceipt, err := service.UseWithReceipt(ctx, auditOnly.Token)
	if err == nil {
		log.Fatal("audit-only chain unexpectedly read material")
	}
	fmt.Printf("parallel audit-only chain denied as expected: %s\n", localsecretmaterials.DescribeReceipt(deniedReceipt.Redacted()))

	// Tampering: dropping one delegation layer must fail verification.
	tampered := receipt.Redacted()
	tampered.Chain = tampered.Chain[1:]
	if err := localsecretmaterials.VerifyReceipt(tampered, publicKey); err != nil {
		fmt.Printf("tampered receipt (delegation layer removed) rejected: %v\n", err)
	}

	// Late upstream revocation: the recorded decision stays legitimate while
	// the lease becomes unusable now.
	if err := service.Revoke(ctx, readRoot.Token); err != nil {
		log.Fatal(err)
	}
	trace, err := service.TraceReceipt(ctx, receipt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("after upstream revocation: decision=%s facts_ok=%t currently_usable=%t\n",
		trace.Decision, trace.AllFactsOK, trace.CurrentlyUsable)
	fmt.Println("receipts remain verifiable after restart; the signing key persists in", *dir)
}
