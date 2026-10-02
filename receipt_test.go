package localsecretmaterials

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// borrowChain issues root -> mid -> leaf leases for name and returns them.
func borrowChain(t *testing.T, ctx context.Context, svc *Service, name string, allowsNew bool) (*Lease, *Lease, *Lease) {
	t.Helper()
	root, err := svc.Borrow(ctx, name, time.Hour, BorrowOptions{
		Purpose:           "fraud-review",
		Scopes:            []Scope{ScopeReadMaterial, ScopeReadAudit},
		AllowsNewVersions: allowsNew,
	})
	if err != nil {
		t.Fatal(err)
	}
	mid, err := svc.Delegate(ctx, root.Token, DelegateOptions{
		Purpose:           "fraud-review/case-7",
		Scopes:            []Scope{ScopeReadMaterial},
		TTL:               30 * time.Minute,
		AllowsNewVersions: allowsNew,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := svc.Delegate(ctx, mid.Token, DelegateOptions{
		Purpose:           "fraud-review/case-7",
		Scopes:            []Scope{ScopeReadMaterial},
		TTL:               10 * time.Minute,
		AllowsNewVersions: allowsNew,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, mid, leaf
}

func TestReceiptVerifiesOfflineAndSurvivesRedaction(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	if _, err := svc.CreateSecret(ctx, "vault", []byte("fictional-vault-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	_, _, leaf := borrowChain(t, ctx, svc, "vault", false)

	material, receipt, err := svc.UseWithReceipt(ctx, leaf.Token)
	if err != nil {
		t.Fatal(err)
	}
	if material == nil || receipt == nil {
		t.Fatal("expected material and receipt")
	}
	if receipt.Decision != ReceiptDecisionAllowed {
		t.Fatalf("decision = %s", receipt.Decision)
	}
	if len(receipt.Chain) != 3 {
		t.Fatalf("chain layers = %d", len(receipt.Chain))
	}
	if receipt.LeaseID != leaf.ID {
		t.Fatalf("receipt subject = %s, want %s", receipt.LeaseID, leaf.ID)
	}

	publicKey, keyID := svc.ReceiptPublicKey()
	if receipt.SignerKeyID != keyID {
		t.Fatalf("signer = %s, want %s", receipt.SignerKeyID, keyID)
	}
	if err := VerifyReceipt(receipt, publicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Redacted receipts disclose only purpose commitments and still verify.
	redacted := receipt.Redacted()
	for _, link := range redacted.Chain {
		if link.Purpose != "" {
			t.Fatal("redaction left a cleartext purpose")
		}
	}
	if err := VerifyReceipt(redacted, publicKey); err != nil {
		t.Fatalf("verify redacted: %v", err)
	}
	description := DescribeReceipt(redacted)
	if strings.Contains(description, "fraud-review") {
		t.Fatal("redacted description leaks the business purpose")
	}
	if strings.Contains(description, "fictional-vault-material") {
		t.Fatal("description leaks material plaintext")
	}
}

func TestReceiptRejectsTampering(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	if _, err := svc.CreateSecret(ctx, "vault", []byte("fictional-vault-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	_, _, leaf := borrowChain(t, ctx, svc, "vault", false)
	_, receipt, err := svc.UseWithReceipt(ctx, leaf.Token)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := svc.ReceiptPublicKey()

	cases := map[string]func(*UsageReceipt){
		"drop a delegation layer": func(r *UsageReceipt) {
			r.Chain = append(r.Chain[:1], r.Chain[2:]...)
		},
		"swap the used version": func(r *UsageReceipt) {
			r.VersionID = "ver_attacker"
		},
		"swap the use subject": func(r *UsageReceipt) {
			r.LeaseID = "lease_attacker"
		},
		"swap the material": func(r *UsageReceipt) {
			r.SecretName = "other-material"
		},
		"rewrite the decision": func(r *UsageReceipt) {
			r.Decision = ReceiptDecisionDenied
		},
		"forge a purpose": func(r *UsageReceipt) {
			r.Chain[0].Purpose = "attacker-purpose"
		},
		"widen leaf scopes": func(r *UsageReceipt) {
			r.Chain[len(r.Chain)-1].Scopes = append(r.Chain[len(r.Chain)-1].Scopes, string(ScopeReadAudit))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := cloneJSON(receipt)
			mutate(tampered)
			if err := VerifyReceipt(tampered, publicKey); !errors.Is(err, ErrReceiptTampered) {
				t.Fatalf("tampered receipt verified: %v", err)
			}
		})
	}
}

func TestReceiptChainsCannotBeSpliced(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	if _, err := svc.CreateSecret(ctx, "vault", []byte("fictional-vault-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	// Two parallel authorizations reach the same borrower with incompatible
	// permissions: chain A allows reading material, chain B only the audit.
	leaseA, err := svc.Borrow(ctx, "vault", time.Hour, BorrowOptions{Purpose: "read-path", Scopes: []Scope{ScopeReadMaterial}})
	if err != nil {
		t.Fatal(err)
	}
	leafA, err := svc.Delegate(ctx, leaseA.Token, DelegateOptions{Purpose: "read-path/run", Scopes: []Scope{ScopeReadMaterial}, TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	leaseB, err := svc.Borrow(ctx, "vault", time.Hour, BorrowOptions{Purpose: "audit-path", Scopes: []Scope{ScopeReadAudit}})
	if err != nil {
		t.Fatal(err)
	}
	leafB, err := svc.Delegate(ctx, leaseB.Token, DelegateOptions{Purpose: "audit-path/run", Scopes: []Scope{ScopeReadAudit}, TTL: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	_, receiptA, err := svc.UseWithReceipt(ctx, leafA.Token)
	if err != nil {
		t.Fatal(err)
	}
	_, deniedB, err := svc.UseWithReceipt(ctx, leafB.Token)
	if !errors.Is(err, ErrLeaseScopeDenied) {
		t.Fatalf("audit-only use error = %v", err)
	}
	if deniedB == nil || deniedB.Decision != ReceiptDecisionDenied {
		t.Fatalf("denied receipt = %+v", deniedB)
	}
	publicKey, _ := svc.ReceiptPublicKey()
	if err := VerifyReceipt(deniedB, publicKey); err != nil {
		t.Fatalf("denied receipt must still verify: %v", err)
	}

	// Splice: take the audit-capable root of chain B and the material-reading
	// leaf of chain A to fake one wider permission. The chain digest, the
	// linkage, and the signature all refuse it.
	spliced := cloneJSON(receiptA)
	spliced.Chain = []ReceiptChainLink{deniedB.Chain[0], receiptA.Chain[1]}
	if err := VerifyReceipt(spliced, publicKey); !errors.Is(err, ErrReceiptTampered) {
		t.Fatalf("spliced receipt verified: %v", err)
	}
	// Recomputing the digest cannot save the splice: the signature is over
	// the original chain and the leaf scopes exceed the spliced root.
	spliced2 := cloneJSON(receiptA)
	spliced2.Chain = []ReceiptChainLink{deniedB.Chain[0], receiptA.Chain[1]}
	digest, err := chainDigest(spliced2.Chain)
	if err != nil {
		t.Fatal(err)
	}
	spliced2.ChainDigest = digest
	if err := VerifyReceipt(spliced2, publicKey); !errors.Is(err, ErrReceiptTampered) {
		t.Fatalf("re-digested splice verified: %v", err)
	}
}

func TestReceiptCommitsToRotatedVersion(t *testing.T) {
	ctx := context.Background()
	svc, _ := testService(t)
	first, err := svc.CreateSecret(ctx, "vault", []byte("fictional-v1"), SecretOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, leaf := borrowChain(t, ctx, svc, "vault", true)
	second, err := svc.RotateSecret(ctx, "vault", []byte("fictional-v2"))
	if err != nil {
		t.Fatal(err)
	}
	material, receipt, err := svc.UseWithReceipt(ctx, leaf.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(material.Plaintext) != "fictional-v2" {
		t.Fatalf("plaintext = %q", material.Plaintext)
	}
	if receipt.VersionID != second || receipt.VersionID == first {
		t.Fatalf("receipt version = %s, want rotated %s", receipt.VersionID, second)
	}
	publicKey, _ := svc.ReceiptPublicKey()
	if err := VerifyReceipt(receipt, publicKey); err != nil {
		t.Fatalf("verify rotated receipt: %v", err)
	}
}

func TestReceiptTraceDistinguishesLateUpstreamRevocation(t *testing.T) {
	ctx := context.Background()
	svc, dir := testService(t)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	setClock(svc, &now)
	if _, err := svc.CreateSecret(ctx, "vault", []byte("fictional-vault-material"), SecretOptions{}); err != nil {
		t.Fatal(err)
	}
	root, _, leaf := borrowChain(t, ctx, svc, "vault", false)

	_, receipt, err := svc.UseWithReceipt(ctx, leaf.Token)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := svc.TraceReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !trace.AllFactsOK || !trace.CurrentlyUsable {
		t.Fatalf("fresh trace = %+v", trace)
	}

	// Later the upstream is revoked. The past decision stays legitimate; the
	// trace explains why the same lease is unusable now.
	if err := svc.Revoke(ctx, root.Token); err != nil {
		t.Fatal(err)
	}
	trace, err = svc.TraceReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !trace.AllFactsOK {
		t.Fatalf("facts must still match stored records: %+v", trace)
	}
	if trace.CurrentlyUsable {
		t.Fatal("lease must not be usable after upstream revocation")
	}
	if trace.Decision != ReceiptDecisionAllowed {
		t.Fatalf("recorded decision = %s", trace.Decision)
	}
	var sawUpstreamRevoked bool
	for _, fact := range trace.Facts {
		if fact.UpstreamRevoked || (fact.LeaseID == root.ID && fact.Revoked) {
			sawUpstreamRevoked = true
		}
	}
	if !sawUpstreamRevoked {
		t.Fatalf("trace does not explain the revocation: %+v", trace.Facts)
	}

	// Restart with a fresh master key: receipts still verify offline and the
	// authorization facts behind them remain traceable.
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenDemoService(ctx, dir, MustMasterKey(GenerateDemoMasterKey()))
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	publicKey, keyID := restarted.ReceiptPublicKey()
	if receipt.SignerKeyID != keyID {
		t.Fatalf("signing key changed across restart: %s -> %s", receipt.SignerKeyID, keyID)
	}
	if err := VerifyReceipt(receipt, publicKey); err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
	trace, err = restarted.TraceReceipt(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !trace.AllFactsOK || trace.CurrentlyUsable {
		t.Fatalf("post-restart trace = %+v", trace)
	}
}
