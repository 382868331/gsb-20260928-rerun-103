// verify-demo shows a savable offline verification task: receipts and
// authorization facts arrive in batches and out of order, every verification
// appends a decision with its basis, duplicates never double-count, a later
// revocation only adds new decisions, conflicting fact batches mark only the
// affected receipts, and an exported package reproduces decisions without
// material plaintext. It never prints material plaintext.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	localsecretmaterials "localsecretmaterials"
)

func main() {
	dir := flag.String("dir", "verify-demo-data", "directory for fictional local service state")
	flag.Parse()
	ctx := context.Background()
	now := time.Now()

	serviceDir := filepath.Join(*dir, "service")
	taskDir := filepath.Join(*dir, "task")

	key, err := localsecretmaterials.GenerateDemoMasterKey()
	if err != nil {
		log.Fatal(err)
	}
	service, err := localsecretmaterials.OpenDemoService(ctx, serviceDir, key)
	if err != nil {
		log.Fatal(err)
	}
	defer service.Close()

	if _, err := service.CreateSecret(ctx, "reporting-token", []byte("fictional-material-body"), localsecretmaterials.SecretOptions{}); err != nil {
		log.Fatal(err)
	}
	root, err := service.Borrow(ctx, "reporting-token", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "billing", Scopes: []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
	})
	if err != nil {
		log.Fatal(err)
	}
	child, err := service.Delegate(ctx, root.Token, localsecretmaterials.DelegateOptions{
		Purpose: "billing/monthly-close",
		Scopes:  []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
		TTL:     30 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	other, err := service.Borrow(ctx, "reporting-token", time.Hour, localsecretmaterials.BorrowOptions{
		Purpose: "audit-trail", Scopes: []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Two distinct uses on one chain (same material version) and one on an
	// independent chain.
	_, receiptA, err := service.UseWithReceipt(ctx, child.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		log.Fatal(err)
	}
	_, receiptB, err := service.UseWithReceipt(ctx, child.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "billing"})
	if err != nil {
		log.Fatal(err)
	}
	_, receiptC, err := service.UseWithReceipt(ctx, other.Token, localsecretmaterials.ReceiptOptions{PurposeHint: "audit"})
	if err != nil {
		log.Fatal(err)
	}
	facts, err := service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}

	task := localsecretmaterials.NewVerificationTask("operator-review-1", now)

	// Out-of-order: receipts arrive before any authorization fact batch, and
	// one receipt arrives twice (the second time with its purpose hint
	// hidden). Usage counting ignores the duplicate.
	task.SubmitReceipt(receiptA, now)
	task.SubmitReceipt(receiptB, now)
	task.SubmitReceipt(receiptC, now)
	hidden := *receiptA
	hidden.PurposeHint = ""
	dup, _ := task.SubmitReceipt(&hidden, now)
	fmt.Printf("receipts arrived: 3 distinct + 1 hidden-hint duplicate (duplicate=%v); usage count = %d\n", dup, task.UsageCount())

	show := func(label string, d *localsecretmaterials.VerificationDecision) {
		fmt.Printf("  decision #%d %-12s status=%s usable-now=%v %s\n", d.Seq, d.ReceiptID[:14]+"...", d.Status, d.CurrentlyUsable, d.Reason)
	}
	fmt.Println("verify before any facts arrive:")
	show("early", task.Verify(receiptA.ID, now))

	// First fact batch: leases and versions only, no registered usage events.
	task.SubmitFacts(&localsecretmaterials.AuthorizationFacts{Secrets: facts.Secrets, Leases: facts.Leases}, now)
	fmt.Println("verify after leases/versions batch (usage events still missing):")
	show("partial", task.Verify(receiptA.ID, now))

	// Second fact batch: the registered usage events catch up.
	task.SubmitFacts(&localsecretmaterials.AuthorizationFacts{Receipts: facts.Receipts}, now)
	fmt.Println("verify after usage-event batch (hidden hint still verifies):")
	show("full", task.Verify(receiptA.ID, now))
	show("full", task.Verify(receiptB.ID, now))
	show("full", task.Verify(receiptC.ID, now))

	// The authorization is revoked afterwards; a new fact batch arrives and
	// only appends new decisions. The earlier ones stay untouched.
	if err := service.Revoke(ctx, root.Token); err != nil {
		log.Fatal(err)
	}
	updated, err := service.AuthorizationFactsSnapshot(ctx)
	if err != nil {
		log.Fatal(err)
	}
	task.SubmitFacts(updated, now)
	fmt.Println("verify after upstream revocation arrived:")
	show("revoked", task.Verify(receiptA.ID, now))
	fmt.Printf("  history for receipt A keeps %d appended decisions; first stays usable-now=%v\n",
		len(task.Decisions), task.Decisions[2].CurrentlyUsable)

	// Save, reopen, and continue verifying in a fresh process state.
	if err := task.Save(ctx, taskDir); err != nil {
		log.Fatal(err)
	}
	reopened, err := localsecretmaterials.LoadVerificationTask(ctx, taskDir)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("task reopened from %s: %d receipts, %d appended decisions\n",
		filepath.Join(taskDir, "verification-task.json"), reopened.UsageCount(), len(reopened.Decisions))
	show("reopened", reopened.Verify(receiptB.ID, now))

	// A contradictory fact batch claims a different immutable authorization
	// for the revoked root lease. Only receipts depending on it are marked.
	forged := *facts
	forgedLeases := map[string]*localsecretmaterials.LeaseFact{}
	for id, fact := range facts.Leases {
		copy := *fact
		if id == root.ID {
			copy.PurposeHash = "0000000000000000000000000000000000000000000000000000000000000000"
		}
		forgedLeases[id] = &copy
	}
	forged.Leases = forgedLeases
	conflicts := reopened.SubmitFacts(&forged, now)
	fmt.Printf("contradictory batch arrived: %d conflict(s) recorded\n", len(conflicts))
	for _, c := range conflicts {
		fmt.Printf("  conflict: %s %s held=%s... incoming=%s...\n", c.Kind, c.ID, c.HeldHash[:12], c.IncomingHash[:12])
	}
	show("conflicted", reopened.Verify(receiptA.ID, now))
	show("unaffected", reopened.Verify(receiptC.ID, now))
	if err := reopened.Save(ctx, taskDir); err != nil {
		log.Fatal(err)
	}

	// Export a minimal offline package for receipt C only. The receiver
	// reproduces the decision without material plaintext, and the export
	// leaves the saved task byte-identical.
	before, err := os.ReadFile(filepath.Join(taskDir, "verification-task.json"))
	if err != nil {
		log.Fatal(err)
	}
	pkg, err := reopened.ExportPackage([]string{receiptC.ID}, now)
	if err != nil {
		log.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(taskDir, "verification-task.json"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("exported package for receipt C: %d fact lease(s), %d usage event(s); saved task unchanged=%v\n",
		len(pkg.Facts.Leases), len(pkg.Facts.Receipts), string(before) == string(after))
	for _, result := range localsecretmaterials.VerifyPackage(pkg, now) {
		fmt.Printf("  receiver reproduces %s: expected=%s reproduced=%s match=%v\n",
			result.ReceiptID[:14]+"...", result.Expected, result.Reproduced, result.Matches)
	}
}
