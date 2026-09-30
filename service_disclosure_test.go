package localsecretmaterials

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every public error and the whole audit trail must stay free of material
// plaintext, raw bearer tokens, and master key ids that could be reused.
func TestPublicErrorsAndAuditNeverDiscloseSecrets(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	plaintext := []byte(fictionalMaterial + "disclosure")
	if _, err := svc.CreateSecret(ctx, "open", plaintext, SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	lease, err := svc.Borrow(ctx, "open", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var denied []string
	run := func(label string, fn func() error) {
		t.Helper()
		err := fn()
		if err == nil {
			t.Fatalf("%s: expected error", label)
		}
		denied = append(denied, err.Error())
	}
	run("unknown token", func() error { _, e := svc.Use(ctx, "reused-token-never-valid"); return e })
	run("wrong purpose", func() error { _, e := svc.UseForPurpose(ctx, lease.Token, "other-purpose"); return e })
	run("cross scope revoke unknown", func() error { return svc.Revoke(ctx, "reused-token-never-valid") })

	events, err := svc.AuditEvents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		denied = append(denied, event.Action+" "+event.Outcome+" "+event.Reason)
	}

	for _, msg := range denied {
		if strings.Contains(msg, string(plaintext)) {
			t.Fatalf("plaintext disclosed in error/audit: %q", msg)
		}
		if strings.Contains(msg, lease.Token) || strings.Contains(msg, "reused-token-never-valid") {
			t.Fatalf("reusable credential disclosed in error/audit: %q", msg)
		}
	}

	for _, file := range []string{materialsFile, leasesFile, auditFile} {
		encoded, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		if strings.Contains(text, string(plaintext)) {
			t.Fatalf("plaintext in %s", file)
		}
		if file != leasesFile && strings.Contains(text, lease.Token) {
			t.Fatalf("raw token in %s", file)
		}
	}
}
