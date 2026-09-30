package localsecretmaterials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func borrowOpts(scopes ...Scope) BorrowOptions {
	return BorrowOptions{Purpose: "test purpose", Scopes: scopes}
}

func TestBorrowExpireAndRevoke(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)

	_, err := svc.CreateSecret(ctx, "demo-db", []byte("fictional-password"), SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "demo-db", time.Minute, borrowOpts(ScopeReadMaterial))
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
	revokable, err := svc.Borrow(ctx, "demo-db", time.Minute, borrowOpts(ScopeReadMaterial))
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
	oldLease, err := svc.Borrow(ctx, "api", time.Hour, borrowOpts(ScopeReadMaterial))
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

	newLease, err := svc.Borrow(ctx, "api", time.Hour, borrowOpts(ScopeReadMaterial))
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
	oldLease, err := svc.Borrow(ctx, "cache", time.Hour, borrowOpts(ScopeReadMaterial))
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
	oldLease, err := svc.Borrow(ctx, "webhook", time.Hour, borrowOpts(ScopeReadMaterial))
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
	newLease, err := restarted.Borrow(ctx, "webhook", time.Hour, borrowOpts(ScopeReadMaterial))
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
	lease, err := svc.Borrow(ctx, "safe", time.Minute, borrowOpts(ScopeReadMaterial, ScopeReadAudit))
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

func TestPurposeAndScopesIsolateBorrows(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "doc", []byte("shared-fictional-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	reader, err := svc.Borrow(ctx, "doc", time.Minute, BorrowOptions{Purpose: "read report", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := svc.Borrow(ctx, "doc", time.Minute, BorrowOptions{Purpose: "audit review", Scopes: []Scope{ScopeReadAudit}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(ctx, auditor.Token); !errors.Is(err, ErrLeaseScopeDenied) {
		t.Fatalf("audit-only read = %v", err)
	}
	if _, err := svc.AuditEventsForLease(ctx, reader.Token); !errors.Is(err, ErrLeaseScopeDenied) {
		t.Fatalf("material-only audit query = %v", err)
	}
	if _, err := svc.Borrow(ctx, "doc", time.Minute, BorrowOptions{Purpose: "bad", Scopes: []Scope{Scope("admin:execute")}}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("unknown scope = %v", err)
	}
	info, err := svc.LeaseInfo(ctx, auditor.Token)
	if err != nil {
		t.Fatal(err)
	}
	if info.Purpose != "audit review" || info.VersionID != auditor.VersionID || info.Revoked {
		t.Fatalf("unexpected lease view: %#v", info)
	}
	events, err := svc.AuditEventsForLease(ctx, auditor.Token)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.LeaseID != auditor.ID {
			t.Fatalf("audit exposed lease %s", event.LeaseID)
		}
	}
	checked, err := svc.Use(ctx, reader.Token)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Purpose != "read report" {
		t.Fatalf("purpose = %q", checked.Purpose)
	}
}

func TestPurposeBorrowCannotReadAnotherVersion(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "doc", []byte("v1-fictional"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	v1Lease, err := svc.Borrow(ctx, "doc", time.Hour, BorrowOptions{Purpose: "v1 reader", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	v2, err := svc.RotateSecret(ctx, "doc", []byte("v2-fictional"))
	if err != nil {
		t.Fatal(err)
	}
	v2Lease, err := svc.Borrow(ctx, "doc", time.Hour, BorrowOptions{Purpose: "v2 reader", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := svc.Use(ctx, v1Lease.Token)
	if err != nil || string(checked.Plaintext) != "v1-fictional" {
		t.Fatalf("v1 use = %v %#v", err, checked)
	}
	if checked.VersionID == v2 {
		t.Fatal("old purpose reached new version")
	}
	checked, err = svc.Use(ctx, v2Lease.Token)
	if err != nil || checked.VersionID != v2 || string(checked.Plaintext) != "v2-fictional" {
		t.Fatalf("v2 use = %v %#v", err, checked)
	}
}

func TestBatchSettleEndsOldLeasesAndKeepsRevocationTerminal(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "doc", []byte("v1-fictional"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	leases := make([]*Lease, 4)
	for i := range leases {
		lease, err := svc.Borrow(ctx, "doc", time.Hour, BorrowOptions{Purpose: fmt.Sprintf("reader-%d", i), Scopes: []Scope{ScopeReadMaterial}})
		if err != nil {
			t.Fatal(err)
		}
		leases[i] = lease
	}
	if err := svc.Revoke(ctx, leases[3].Token); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := svc.RotateSecret(ctx, "doc", []byte("v2-fictional")); err != nil {
		t.Fatal(err)
	}
	count, err := svc.SettleOldLeases(ctx, "doc", 2)
	if err != nil || count != 2 {
		t.Fatalf("first batch = %d, %v", count, err)
	}
	count, err = svc.SettleOldLeases(ctx, "doc", 2)
	if err != nil || count != 1 {
		t.Fatalf("second batch = %d, %v", count, err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.Use(ctx, leases[i].Token); !errors.Is(err, ErrLeaseExpired) {
			t.Fatalf("lease %d use after settle = %v", i, err)
		}
	}
	if _, err := svc.Use(ctx, leases[3].Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("revoked lease changed = %v", err)
	}
	if remaining, err := svc.SettleOldLeases(ctx, "doc", 10); err != nil || remaining != 0 {
		t.Fatalf("extra settlement = %d, %v", remaining, err)
	}
}

func TestExpiryAndRevokeCollision(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "race", []byte("collision-fictional"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "race", time.Millisecond, borrowOpts(ScopeReadMaterial))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	var useErr, revokeErr error
	go func() { defer wg.Done(); _, useErr = svc.Use(ctx, lease.Token) }()
	go func() { defer wg.Done(); revokeErr = svc.Revoke(ctx, lease.Token) }()
	wg.Wait()
	if useErr == nil || (!errors.Is(useErr, ErrLeaseExpired) && !errors.Is(useErr, ErrLeaseRevoked)) {
		t.Fatalf("use collision = %v", useErr)
	}
	if revokeErr != nil {
		t.Fatalf("revoke collision = %v", revokeErr)
	}
	if _, err := svc.Use(ctx, lease.Token); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("post-collision use = %v", err)
	}
}

func TestConcurrentUseSamePurpose(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	if _, err := svc.CreateSecret(ctx, "concurrent", []byte("parallel-fictional"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "concurrent", time.Minute, borrowOpts(ScopeReadMaterial))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			checked, err := svc.Use(ctx, lease.Token)
			if err != nil {
				errs <- err
				return
			}
			if string(checked.Plaintext) != "parallel-fictional" {
				errs <- fmt.Errorf("wrong material %q", checked.Plaintext)
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRotationFailureLeavesRecoverableState(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "doc", []byte("v1-fictional"), SecretOptions{
		Rotation: RotationPolicy{OldLeases: SettleGracePeriod, GracePeriod: time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "doc", time.Hour, borrowOpts(ScopeReadMaterial))
	if err != nil {
		t.Fatal(err)
	}
	svc.failNextSecretSave = true
	if _, err := svc.RotateSecret(ctx, "doc", []byte("v2-fictional")); !errors.Is(err, ErrRotationAborted) {
		t.Fatalf("failed rotation = %v", err)
	}
	info, err := svc.LeaseInfo(ctx, lease.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ExpiresAt.Equal(lease.ExpiresAt) {
		t.Fatalf("failed rotation shortened lease: %s vs %s", info.ExpiresAt, lease.ExpiresAt)
	}
	checked, err := svc.Use(ctx, lease.Token)
	if err != nil || string(checked.Plaintext) != "v1-fictional" {
		t.Fatalf("use after failed rotation = %v %#v", err, checked)
	}
	now = now.Add(time.Minute)
	v2, err := svc.RotateSecret(ctx, "doc", []byte("v2-fictional"))
	if err != nil {
		t.Fatal(err)
	}
	newLease, err := svc.Borrow(ctx, "doc", time.Hour, BorrowOptions{Purpose: "recovered", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	if newLease.VersionID != v2 {
		t.Fatalf("recovered lease version = %s", newLease.VersionID)
	}
}

func TestPublicErrorsAndAuditNeverRevealSecrets(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	plaintext := []byte("ultra-secret-fictional-rotation-value")
	if _, err := svc.CreateSecret(ctx, "leaky", []byte("first"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "leaky", time.Minute, BorrowOptions{Purpose: "audit only", Scopes: []Scope{ScopeReadAudit}})
	if err != nil {
		t.Fatal(err)
	}
	publicErrors := []error{}
	_, err = svc.Use(ctx, lease.Token)
	publicErrors = append(publicErrors, err)
	_, err = svc.Use(ctx, lease.Token+"suffix")
	publicErrors = append(publicErrors, err)
	svc.failNextSecretSave = true
	_, err = svc.RotateSecret(ctx, "leaky", plaintext)
	publicErrors = append(publicErrors, err)
	for _, publicErr := range publicErrors {
		if publicErr == nil || strings.Contains(publicErr.Error(), string(plaintext)) || strings.Contains(publicErr.Error(), lease.Token) {
			t.Fatalf("unsafe public error: %v", publicErr)
		}
	}
	events, err := svc.AuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := jsonMarshalEvents(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, string(plaintext)) || strings.Contains(encoded, lease.Token) {
		t.Fatalf("audit leaked sensitive data: %s", encoded)
	}
	for _, file := range []string{materialsFile, leasesFile, auditFile} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), string(plaintext)) {
			t.Fatalf("material plaintext in %s", file)
		}
		if file != leasesFile && strings.Contains(string(data), lease.Token) {
			t.Fatalf("token in %s", file)
		}
	}
}

func jsonMarshalEvents(events []AuditEvent) (string, error) {
	var builder strings.Builder
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return "", err
		}
		builder.Write(encoded)
		builder.WriteByte('\n')
	}
	return builder.String(), nil
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
