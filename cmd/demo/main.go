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

	version, err := service.CreateSecret(ctx, "payment-sandbox", []byte("fictional-api-key"), localsecretmaterials.SecretOptions{
		Rotation: localsecretmaterials.RotationPolicy{
			OldLeases:   localsecretmaterials.SettleGracePeriod,
			GracePeriod: time.Minute,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	lease, err := service.Borrow(ctx, "payment-sandbox", *ttl, localsecretmaterials.BorrowOptions{
		Purpose: "demo checkout",
		Scopes:  []localsecretmaterials.Scope{localsecretmaterials.ScopeReadMaterial},
	})
	if err != nil {
		log.Fatal(err)
	}
	material, err := service.Use(ctx, lease.Token)
	if err != nil {
		log.Fatal(err)
	}
	if err := service.Revoke(ctx, lease.Token); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("created %s; checked out %d fictional bytes; lease revoked\n", version, len(material.Plaintext))
	fmt.Println("the process-local master key was not saved; restart cannot decrypt this version")
}
