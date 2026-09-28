package localsecretmaterials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBorrowExpireAndRevoke(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	_, err := svc.CreateSecret(ctx, "demo-db", []byte("fictional-password"), SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "demo-db", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	checked, err := svc.Use(ctx, lease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(checked.Plaintext) != "fictional-password" {
		t.Fatalf("plaintext = %q", checked.Plaintext)
	}

	now = now.Add(2 * time.Minute)
	if _, err := svc.Use(ctx, lease.Token); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired use error = %v", err)
	}

	now = time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	revokable, err := svc.Borrow(ctx, "demo-db", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, revokable.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(ctx, revokable.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revoked use error = %v", err)
	}
	if err := svc.Revoke(ctx, revokable.Token); err != nil {
		t.Fatalf("duplicate revoke = %v", err)
	}
	if _, err := svc.Use(ctx, revokable.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("duplicate revoke changed state: %v", err)
	}

	if _, err := svc.Use(ctx, "not-a-real-token"); !errors.Is(err, ErrInvalidLease) {
		t.Fatalf("invalid token error = %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{materialsFile, leasesFile, auditFile} {
		if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
			t.Fatalf("expected separate store file %s: %v", file, err)
		}
	}
}

func TestRotationSettlesOldLeasesAndIssuesNewVersion(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	_, err := svc.CreateSecret(ctx, "api", []byte("old-fictional-key"), SecretOptions{
		Rotation: RotationPolicy{OldLeases: SettleGracePeriod, GracePeriod: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := svc.Borrow(ctx, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(30 * time.Second)
	newVersion, err := svc.RotateSecret(ctx, "api", []byte("new-fictional-key"))
	if err != nil {
		t.Fatal(err)
	}
	if newVersion == oldLease.VersionID {
		t.Fatal("rotation reused old version")
	}

	newLease, err := svc.Borrow(ctx, "api", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if newLease.VersionID != newVersion {
		t.Fatalf("new lease version = %s, want %s", newLease.VersionID, newVersion)
	}
	newMaterial, err := svc.Use(ctx, newLease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(newMaterial.Plaintext) != "new-fictional-key" {
		t.Fatalf("new material = %q", newMaterial.Plaintext)
	}

	oldMaterial, err := svc.Use(ctx, oldLease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldMaterial.Plaintext) != "old-fictional-key" || oldMaterial.VersionID != oldLease.VersionID {
		t.Fatalf("old lease did not finish by its declared rule: %#v", oldMaterial)
	}

	now = now.Add(61 * time.Second)
	if _, err := svc.Use(ctx, oldLease.Token); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("grace settle error = %v", err)
	}
}

func TestRotationKeepsOldLeaseUntilExpiry(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	_, err := svc.CreateSecret(ctx, "cache", []byte("old-cache-secret"), SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := svc.Borrow(ctx, "cache", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := svc.RotateSecret(ctx, "cache", []byte("new-cache-secret")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(58 * time.Minute)
	checked, err := svc.Use(ctx, oldLease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(checked.Plaintext) != "old-cache-secret" {
		t.Fatalf("old lease material = %q", checked.Plaintext)
	}
	now = now.Add(2 * time.Minute)
	if _, err := svc.Use(ctx, oldLease.Token); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("old lease expiry error = %v", err)
	}
}

func TestRestartWithReplacementDemoKeyCannotReadOldMaterial(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey := MustMasterKey(GenerateDemoMasterKey())
	store, err := OpenStore(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(store, oldKey, time.Now)
	_, err = svc.CreateSecret(ctx, "webhook", []byte("first-fictional-secret"), SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := svc.Borrow(ctx, "webhook", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	newKey := MustMasterKey(GenerateDemoMasterKey())
	restarted, err := OpenDemoService(ctx, dir, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Use(ctx, oldLease.Token); !errors.Is(err, ErrMaterialCannotDecrypt) {
		t.Fatalf("replacement key error = %v", err)
	}
	newVersion, err := restarted.RotateSecret(ctx, "webhook", []byte("second-fictional-secret"))
	if err != nil {
		t.Fatal(err)
	}
	newLease, err := restarted.Borrow(ctx, "webhook", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if newLease.VersionID != newVersion {
		t.Fatalf("new lease = version %s", newLease.VersionID)
	}
	checked, err := restarted.Use(ctx, newLease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(checked.Plaintext) != "second-fictional-secret" {
		t.Fatalf("new material = %q", checked.Plaintext)
	}
}

func TestAuditDoesNotContainPlaintextOrBearerToken(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	plaintext := []byte("do-not-persist-fictional-value")
	_, err := svc.CreateSecret(ctx, "safe", plaintext, SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "safe", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(ctx, lease.Token); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, lease.Token); err != nil {
		t.Fatal(err)
	}

	events, err := svc.AuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events = %d", len(events))
	}
	for _, file := range []string{materialsFile, leasesFile, auditFile} {
		encoded, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), string(plaintext)) {
			t.Fatalf("plaintext leaked into %s", file)
		}
		if file != leasesFile && strings.Contains(string(encoded), lease.Token) {
			t.Fatalf("bearer token leaked into %s", file)
		}
	}
	audit, err := os.ReadFile(filepath.Join(dir, auditFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), lease.Token) {
		t.Fatal("audit contains raw token")
	}
}

func testService(t *testing.T) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	key := MustMasterKey(GenerateDemoMasterKey())
	store, err := OpenStore(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	return newService(store, key, time.Now), dir
}

func setClock(svc *Service, clock *time.Time) {
	svc.now = func() time.Time { return *clock }
}
