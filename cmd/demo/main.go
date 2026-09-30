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
	dir := flag.String("dir", "demo-data", "directory for fictional local service state")
	ttl := flag.Duration("ttl", 30*time.Second, "lease TTL")
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

	version, err := service.CreateSecret(ctx, "payment-sandbox", []byte("fictional-api-key-v1"), localsecretmaterials.SecretOptions{
		Rotation: localsecretmaterials.RotationPolicy{
			OldLeases: localsecretmaterials.SettleBatchEnd,
			BatchSize: 1,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	lease, err := service.BorrowFor(ctx, "payment-sandbox", localsecretmaterials.BorrowRequest{
		Purpose: "ops-runbook",
		Scopes:  []string{localsecretmaterials.ScopeMaterialRead, localsecretmaterials.ScopeMetadataView, localsecretmaterials.ScopeAuditRead},
		TTL:     *ttl,
	})
	if err != nil {
		log.Fatal(err)
	}
	material, err := service.UseForPurpose(ctx, lease.Token, "ops-runbook")
	if err != nil {
		log.Fatal(err)
	}
	newVersion, err := service.RotateSecret(ctx, "payment-sandbox", []byte("fictional-api-key-v2"))
	if err != nil {
		log.Fatal(err)
	}
	ended, err := service.EndOldLeaseBatch(ctx, "payment-sandbox", version, 1)
	if err != nil {
		log.Fatal(err)
	}
	rotated, err := service.RotateMasterKey(ctx, localsecretmaterials.MustMasterKey(localsecretmaterials.GenerateDemoMasterKey()))
	if err != nil {
		log.Fatal(err)
	}
	if err := service.Revoke(ctx, lease.Token); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("created %s; checked out %d fictional bytes for %q; rotated to %s\n", version, len(material.Plaintext), lease.Purpose, newVersion)
	fmt.Printf("ended %d old borrow(s); re-sealed %d version(s) with a fresh process key; lease revoked\n", ended, rotated)
	fmt.Println("no plaintext or reusable token is written to public errors or the audit log")
}
