package localsecretmaterials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const fictionalMaterial = "fictional-purpose-bound-value-"

// Two purpose-bound borrows of the same material stay isolated: each reads
// only its pinned version and declared purpose, and scopes cannot be widened
// by replaying the token against another operation.
func TestPurposeAndScopesIsolateBorrows(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	oldValue := fictionalMaterial + "v1"
	newValue := fictionalMaterial + "v2"
	if _, err := svc.CreateSecret(ctx, "joint", []byte(oldValue), SecretOptions{}); err != nil {
		t.Fatal(err)
	}

	reporting, err := svc.BorrowFor(ctx, "joint", BorrowRequest{
		Purpose: "incident-report",
		Scopes:  []string{ScopeMaterialRead, ScopeMetadataView, ScopeAuditRead},
		TTL:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadataOnly, err := svc.BorrowFor(ctx, "joint", BorrowRequest{
		Purpose: "catalog-sync",
		Scopes:  []string{ScopeMetadataView},
		TTL:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Rotation produces a second version; the early borrow stays pinned to v1.
	newVersion, err := svc.RotateSecret(ctx, "joint", []byte(newValue))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := svc.BorrowFor(ctx, "joint", BorrowRequest{
		Purpose: "deploy",
		Scopes:  []string{ScopeMaterialRead},
		TTL:     time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if deployment.VersionID != newVersion {
		t.Fatalf("new borrow pinned to %s, want %s", deployment.VersionID, newVersion)
	}

	// Purpose check: the incident-report token cannot check out for deploy.
	if _, err := svc.UseForPurpose(ctx, reporting.Token, "deploy"); !errors.Is(err, ErrPurposeMismatch) {
		t.Fatalf("cross-purpose use error = %v", err)
	}
	oldChecked, err := svc.UseForPurpose(ctx, reporting.Token, "incident-report")
	if err != nil {
		t.Fatal(err)
	}
	if string(oldChecked.Plaintext) != oldValue || oldChecked.VersionID != reporting.VersionID {
		t.Fatalf("reporting borrow read %q@%s", oldChecked.Plaintext, oldChecked.VersionID)
	}

	// Version pinning: old purpose cannot read the rotated version.
	if oldChecked.VersionID == newVersion {
		t.Fatal("old borrow followed rotation to the new version")
	}

	// Scope isolation: metadata-only borrow cannot read plaintext or audit.
	if _, err := svc.Use(ctx, metadataOnly.Token); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("metadata borrow read material: %v", err)
	}
	if _, err := svc.AuditTrail(ctx, metadataOnly.Token); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("metadata borrow read audit: %v", err)
	}
	meta, err := svc.Inspect(ctx, metadataOnly.Token)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Purpose != "catalog-sync" || meta.VersionID != metadataOnly.VersionID {
		t.Fatalf("metadata = %#v", meta)
	}

	// Read-only borrow cannot inspect or read its audit trail.
	if _, err := svc.Inspect(ctx, deployment.Token); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("material borrow inspected: %v", err)
	}
	if _, err := svc.AuditTrail(ctx, deployment.Token); !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("material borrow read audit: %v", err)
	}

	// Scoped audit trail exposes only that lease's own events.
	trail, err := svc.AuditTrail(ctx, reporting.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) == 0 {
		t.Fatal("expected own audit events")
	}
	for _, event := range trail {
		if event.LeaseID != reporting.ID {
			t.Fatalf("scoped audit leaked lease %s", event.LeaseID)
		}
	}

	assertNoFictionalLeak(t, dir, [][]byte{[]byte(oldValue), []byte(newValue)}, []string{reporting.Token, metadataOnly.Token, deployment.Token})
}

func TestInvalidBorrowRequestsRejected(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	if _, err := svc.CreateSecret(ctx, "m", []byte(fictionalMaterial+"x"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	cases := []BorrowRequest{
		{Purpose: "", Scopes: []string{ScopeMaterialRead}, TTL: time.Minute},
		{Purpose: "bad\npurpose", Scopes: []string{ScopeMaterialRead}, TTL: time.Minute},
		{Purpose: "p", Scopes: nil, TTL: time.Minute},
		{Purpose: "p", Scopes: []string{"admin:all"}, TTL: time.Minute},
		{Purpose: "p", Scopes: []string{ScopeMaterialRead}, TTL: 0},
	}
	for i, req := range cases {
		if _, err := svc.BorrowFor(ctx, "m", req); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

// Concurrent checkouts of distinct borrows all succeed independently and
// never corrupt lease state or leak across lease boundaries.
func TestConcurrentPurposeBorrows(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	value := []byte(fictionalMaterial + "concurrent")
	if _, err := svc.CreateSecret(ctx, "busy", value, SecretOptions{}); err != nil {
		t.Fatal(err)
	}

	const workers = 24
	tokens := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lease, err := svc.BorrowFor(ctx, "busy", BorrowRequest{
				Purpose: fmt.Sprintf("worker-%d", i),
				Scopes:  []string{ScopeMaterialRead, ScopeAuditRead},
				TTL:     time.Minute,
			})
			if err != nil {
				t.Errorf("borrow %d: %v", i, err)
				return
			}
			tokens <- lease.Token
		}(i)
	}
	wg.Wait()
	close(tokens)

	wg = sync.WaitGroup{}
	seen := sync.Map{}
	for token := range tokens {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			checked, err := svc.Use(ctx, token)
			if err != nil {
				t.Errorf("use: %v", err)
				return
			}
			if string(checked.Plaintext) != string(value) {
				t.Errorf("material = %q", checked.Plaintext)
			}
			trail, err := svc.AuditTrail(ctx, token)
			if err != nil {
				t.Errorf("audit: %v", err)
				return
			}
			for _, event := range trail {
				if event.Action == "material_use" && event.Outcome != "ok" {
					t.Errorf("denied event in own trail: %#v", event)
				}
			}
			if checked.VersionID == "" {
				t.Error("empty version")
			}
			seen.Store(checked.VersionID, true)
		}(token)
	}
	wg.Wait()

	assertNoFictionalLeak(t, dir, [][]byte{value}, nil)
}

func assertNoFictionalLeak(t *testing.T, dir string, plaintexts [][]byte, tokens []string) {
	t.Helper()
	for _, file := range []string{materialsFile, leasesFile, auditFile} {
		encoded, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, plaintext := range plaintexts {
			if strings.Contains(string(encoded), string(plaintext)) {
				t.Fatalf("plaintext leaked into %s", file)
			}
		}
		if file == leasesFile {
			continue
		}
		for _, token := range tokens {
			if token != "" && strings.Contains(string(encoded), token) {
				t.Fatalf("bearer token leaked into %s", file)
			}
		}
	}
}
