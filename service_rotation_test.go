package localsecretmaterials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBatchEndSettlesOldLeasesInBatches(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	if _, err := svc.CreateSecret(ctx, "batching", []byte(fictionalMaterial+"batch-v1"), SecretOptions{
		Rotation: RotationPolicy{OldLeases: SettleBatchEnd, BatchSize: 2},
	}); err != nil {
		t.Fatal(err)
	}
	tokens := make([]string, 5)
	for i := range tokens {
		lease, err := svc.BorrowFor(ctx, "batching", BorrowRequest{
			Purpose: "worker", Scopes: []string{ScopeMaterialRead}, TTL: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = lease.Token
	}

	oldVersion := svc.store.Materials["batching"].CurrentVersionID
	if _, err := svc.RotateSecret(ctx, "batching", []byte(fictionalMaterial+"batch-v2")); err != nil {
		t.Fatal(err)
	}

	ended, err := svc.EndOldLeaseBatch(ctx, "batching", oldVersion, 2)
	if err != nil || ended != 2 {
		t.Fatalf("first batch = (%d, %v)", ended, err)
	}
	ended, err = svc.EndOldLeaseBatch(ctx, "batching", oldVersion, 2)
	if err != nil || ended != 2 {
		t.Fatalf("second batch = (%d, %v)", ended, err)
	}
	ended, err = svc.EndOldLeaseBatch(ctx, "batching", oldVersion, 2)
	if err != nil || ended != 1 {
		t.Fatalf("final batch = (%d, %v)", ended, err)
	}
	ended, err = svc.EndOldLeaseBatch(ctx, "batching", oldVersion, 2)
	if err != nil || ended != 0 {
		t.Fatalf("empty batch = (%d, %v)", ended, err)
	}

	for _, token := range tokens {
		if _, err := svc.Use(ctx, token); !errors.Is(err, ErrLeaseRevoked) {
			t.Fatalf("old borrow after batch end error = %v", err)
		}
	}
}

func TestBatchEndRestartKeepsRevocations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := MustMasterKey(GenerateDemoMasterKey())
	store, err := OpenStore(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(store, key, time.Now)
	if _, err := svc.CreateSecret(ctx, "r", []byte(fictionalMaterial+"restart"), SecretOptions{
		Rotation: RotationPolicy{OldLeases: SettleBatchEnd, BatchSize: 1},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "r", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldVersion := svc.store.Materials["r"].CurrentVersionID
	if _, err := svc.RotateSecret(ctx, "r", []byte(fictionalMaterial+"restart-v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EndOldLeaseBatch(ctx, "r", oldVersion, 1); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenDemoService(ctx, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Use(ctx, lease.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revival after restart: %v", err)
	}
	// Ending batches again is a stable no-op and must not write a new revocation.
	ended, err := reopened.EndOldLeaseBatch(ctx, "r", oldVersion, 1)
	if err != nil || ended != 0 {
		t.Fatalf("batch after restart = (%d, %v)", ended, err)
	}
}

// Expiry and explicit revocation racing at the same instant always end in one
// stable terminal state; repeated operations never revive the borrow.
func TestExpiryAndRevocationCollision(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	if _, err := svc.CreateSecret(ctx, "race", []byte(fictionalMaterial+"collision"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "race", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var useErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		_, useErr = svc.Use(ctx, lease.Token)
	}()
	revokeErr := svc.Revoke(ctx, lease.Token)
	if revokeErr != nil {
		t.Fatal(revokeErr)
	}
	wg.Wait()
	if useErr != nil && !errors.Is(useErr, ErrLeaseExpired) && !errors.Is(useErr, ErrLeaseRevoked) {
		t.Fatalf("collision error = %v", useErr)
	}

	// Regardless of which terminal state won, the borrow stays dead forever.
	if err := svc.Revoke(ctx, lease.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(ctx, lease.Token); !errors.Is(err, ErrLeaseRevoked) && !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("post-collision use = %v", err)
	}

	encoded, err := os.ReadFile(filepath.Join(dir, auditFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), lease.Token) {
		t.Fatal("collision audit leaked token")
	}
}

func TestMasterKeyRotationFailureRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey := MustMasterKey(GenerateDemoMasterKey())
	store, err := OpenStore(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(store, oldKey, time.Now)
	v1 := []byte(fictionalMaterial + "rekey-v1")
	v2 := []byte(fictionalMaterial + "rekey-v2")
	if _, err := svc.CreateSecret(ctx, "alpha", v1, SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	leaseA, err := svc.Borrow(ctx, "alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateSecret(ctx, "alpha", v2); err != nil {
		t.Fatal(err)
	}
	leaseB, err := svc.Borrow(ctx, "alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, leaseA.Token); err != nil {
		t.Fatal(err)
	}

	// Inject a sealing failure into key rotation. Persistence must not change.
	svc.failSeal = errors.New("injected seal failure")
	newKey := MustMasterKey(GenerateDemoMasterKey())
	if _, err := svc.RotateMasterKey(ctx, newKey); err == nil {
		t.Fatal("expected rotation failure")
	}

	checked, err := svc.Use(ctx, leaseB.Token)
	if err != nil {
		t.Fatalf("old key unusable after failed rotation: %v", err)
	}
	if string(checked.Plaintext) != string(v2) {
		t.Fatalf("material after failed rotation = %q", checked.Plaintext)
	}
	if _, err := svc.Use(ctx, leaseA.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revived after failed rotation: %v", err)
	}

	// Recovery: rotate for real with another fresh key.
	recoveryKey := MustMasterKey(GenerateDemoMasterKey())
	n, err := svc.RotateMasterKey(ctx, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("rotated versions = %d", n)
	}
	checked, err = svc.Use(ctx, leaseB.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(checked.Plaintext) != string(v2) {
		t.Fatalf("material after recovery = %q", checked.Plaintext)
	}
	if _, err := svc.Use(ctx, leaseA.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revived after successful rotation: %v", err)
	}

	// Restart with the recovery key: all versions stay pinned and readable.
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDemoService(ctx, dir, recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Use(ctx, leaseB.Token); err != nil {
		t.Fatalf("reopened with recovery key: %v", err)
	}
	if _, err := reopened.Use(ctx, leaseA.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revived after restart: %v", err)
	}

	assertNoFictionalLeak(t, dir, [][]byte{v1, v2}, []string{leaseA.Token, leaseB.Token})
}
