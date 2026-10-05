// verify-task-demo shows a persistable offline verification task over many
// historical receipts: out-of-order fact supplements, hidden purpose hints,
// authorization revoked afterwards, reopening the task, and exporting a
// minimal verification package. It never prints material plaintext.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	localsecretmaterials "localsecretmaterials"
)

func main() {
	dir := flag.String("dir", "verify-task-demo-data", "directory for fictional local service state")
	flag.Parse()
	ctx := context.Background()
	now := time.Now()

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
	root, err := service.Borrow(ctx, "reporting-token", 2*time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "billing", Scopes: []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
	})
	if err != nil {
		log.Fatal(err)
	}
	delegated, err := service.Delegate(ctx, root.Token, localsecretmaterials.DelegateOptions{
		Purpose: "billing/monthly-close",
		Scopes:  []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
		TTL:     time.Hour,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Two historical uses of the same material version: two receipts.
	_, receipt1, err := service.UseWithReceipt(ctx, delegated.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		log.Fatal(err)
	}
	_, receipt2, err := service.UseWithReceipt(ctx, delegated.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "billing/monthly"})
	if err != nil {
		log.Fatal(err)
	}
	// The holder hides the business hint of the second receipt entirely.
	shown2 := *receipt2
	shown2.PurposeHint = ""

	task := localsecretmaterials.NewVerificationTask("offline-audit-2026-10", now)
	must(task.AddReceipt(receipt1))
	must(task.AddReceipt(&shown2))
	if added, err := task.AddReceipt(receipt1); err != nil || added {
		log.Fatalf("duplicate receipt should be ignored, got added=%v err=%v", added, err)
	}
	fmt.Printf("registered 2 distinct receipts (a duplicate arrival was ignored)\n")

	fmt.Println("\n-- verify with no facts yet --")
	report(task.Verify(now))

	// Facts arrive out of order: usage records first, then versions, then
	// delegation layers. Each pass keeps its conclusions and its basis.
	facts, err := service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	must2(task.SubmitFacts(&localsecretmaterials.AuthorizationFacts{
		Secrets: map[string]*localsecretmaterials.SecretFact{}, Leases: map[string]*localsecretmaterials.LeaseFact{}, Receipts: facts.Receipts,
	}, now))
	fmt.Println("\n-- batch-1: usage records only (out of order) --")
	report(task.Verify(now))
	must2(task.SubmitFacts(&localsecretmaterials.AuthorizationFacts{
		Secrets: facts.Secrets, Leases: map[string]*localsecretmaterials.LeaseFact{}, Receipts: map[string]*localsecretmaterials.ReceiptRecord{},
	}, now))
	fmt.Println("\n-- batch-2: version digests added --")
	report(task.Verify(now))
	must2(task.SubmitFacts(&localsecretmaterials.AuthorizationFacts{
		Secrets: map[string]*localsecretmaterials.SecretFact{}, Leases: facts.Leases, Receipts: map[string]*localsecretmaterials.ReceiptRecord{},
	}, now))
	fmt.Println("\n-- batch-3: delegation layers added; hidden-hint receipt also verifies --")
	report(task.Verify(now))
	fmt.Printf("distinct verified uses: %d\n", task.UsageCount())

	// The authorization is revoked afterwards; a new batch arrives and only
	// appends new decisions. The old "usable" conclusion stays in history.
	if err := service.Revoke(ctx, root.Token); err != nil {
		log.Fatal(err)
	}
	factsAfter, err := service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	must2(task.SubmitFacts(factsAfter, now))
	fmt.Println("\n-- batch-4: upstream authorization revoked afterwards --")
	report(task.Verify(now))
	fmt.Printf("history keeps %d decisions per receipt; first decision for receipt 1: status=%s usable_now=%v\n",
		len(task.Decisions)/2, task.Decisions[0].Status, task.Decisions[0].CurrentlyUsable)

	// Save, reopen, and continue verifying: history and basis survive.
	taskPath := filepath.Join(*dir, "verification-task.json")
	if err := task.Save(taskPath); err != nil {
		log.Fatal(err)
	}
	reopened, err := localsecretmaterials.LoadVerificationTask(taskPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n-- task reopened from disk; verification continues --")
	report(reopened.Verify(now))

	// Export a minimal package for receipt 1. The task file must not change.
	before := fileDigest(taskPath)
	pkg, err := reopened.Export([]string{receipt1.ID}, now)
	if err != nil {
		log.Fatal(err)
	}
	pkgPath := filepath.Join(*dir, "verification-package.json")
	if err := pkg.Save(pkgPath); err != nil {
		log.Fatal(err)
	}
	after := fileDigest(taskPath)
	fmt.Printf("\nexported package for %s (facts: %d secret, %d leases, %d usage event)\n",
		receipt1.ID, len(pkg.Facts.Secrets), len(pkg.Facts.Leases), len(pkg.Facts.Receipts))
	fmt.Printf("task file unchanged by export: %v\n", before == after)

	loaded, err := localsecretmaterials.LoadVerificationPackage(pkgPath)
	if err != nil {
		log.Fatal(err)
	}
	reproduced, err := loaded.Reproduce(now)
	if err != nil {
		log.Fatal(err)
	}
	for _, decision := range reproduced {
		fmt.Printf("receiver reproduced %s: status=%s (no service, key, or material needed)\n", decision.ReceiptID, decision.Status)
	}
}

func report(decisions []*localsecretmaterials.VerificationDecision) {
	for _, decision := range decisions {
		reason := decision.Reason
		if reason == "" {
			reason = "ok"
		}
		fmt.Printf("  %s seq=%d status=%-12s usable_now=%-5v basis=%v missing=%v (%s)\n",
			decision.ReceiptID, decision.Seq, decision.Status, decision.CurrentlyUsable,
			decision.BasisBatches, decision.Missing, reason)
	}
}

func must(added bool, err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func must2(_ string, err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func fileDigest(path string) string {
	encoded, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
