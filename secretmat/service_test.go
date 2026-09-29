package secretmat

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestService 用临时主密钥与可操控时钟建立服务。
// 材料全部为虚构随机字节，不涉及任何真实密钥。
func newTestService(t *testing.T, dir string, key []byte, clock *time.Time) *Service {
	t.Helper()
	audit, err := OpenAuditLog(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := Open(filepath.Join(dir, "store"), key, audit)
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return *clock }
	return svc
}

func fakeMaterial(t *testing.T, label string) []byte {
	t.Helper()
	// 虚构材料：仅为演示生成的随机字节，绝非用户真实密钥。
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		t.Fatal(err)
	}
	return append([]byte("fake-"+label+":"), m...)
}

func TestBorrowUseAndExpiry(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	mat := fakeMaterial(t, "db")
	if err := svc.CreateSecret("db", mat); err != nil {
		t.Fatal(err)
	}
	tok, err := svc.Borrow("db", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Use(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mat) {
		t.Fatal("取回的材料与存入不一致")
	}
	// 到期后不再有效
	clock = clock.Add(2 * time.Minute)
	if _, err := svc.Use(tok); !errors.Is(err, ErrBorrowExpired) {
		t.Fatalf("期望 ErrBorrowExpired，得到 %v", err)
	}
	st, _ := svc.BorrowStatus(tok)
	if st != "expired" {
		t.Fatalf("期望 expired，得到 %s", st)
	}
}

func TestRevokeAndDoubleRevoke(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	svc.CreateSecret("api", fakeMaterial(t, "api"))
	tok, _ := svc.Borrow("api", time.Hour)
	if err := svc.Revoke(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Use(tok); !errors.Is(err, ErrBorrowRevoked) {
		t.Fatalf("撤销后期望 ErrBorrowRevoked，得到 %v", err)
	}
	// 重复撤销：明确报错而不是静默成功
	if err := svc.Revoke(tok); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("期望 ErrAlreadyRevoked，得到 %v", err)
	}
}

func TestRestartPersistsState(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	mat := fakeMaterial(t, "cache")
	svc.CreateSecret("cache", mat)
	tok, _ := svc.Borrow("cache", time.Hour)

	// 模拟重启：同一主密钥重新打开
	svc2 := newTestService(t, dir, key, &clock)
	got, err := svc2.Use(tok)
	if err != nil {
		t.Fatalf("重启后借用应仍有效: %v", err)
	}
	if !bytes.Equal(got, mat) {
		t.Fatal("重启后材料不一致")
	}
}

func TestLostMasterKeyCannotDecrypt(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	svc.CreateSecret("vault", fakeMaterial(t, "vault"))

	// 主密钥丢失（演示密钥仅临时存在于内存），换新密钥重开必须失败
	other, _ := GenerateMasterKey()
	audit, _ := OpenAuditLog(filepath.Join(dir, "audit.log"))
	if _, err := Open(filepath.Join(dir, "store"), other, audit); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("期望 ErrUndecryptable，得到 %v", err)
	}
}

func TestRotationDrainOld(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	old := fakeMaterial(t, "v1")
	newMat := fakeMaterial(t, "v2")
	svc.CreateSecret("tls", old)
	oldTok, _ := svc.Borrow("tls", time.Hour)
	if _, err := svc.Rotate("tls", newMat, DrainOld); err != nil {
		t.Fatal(err)
	}
	// 旧借用按 drain 规则收尾：到期前仍可用旧版本
	got, err := svc.Use(oldTok)
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("drain 期间旧借用应可用旧版本: %v", err)
	}
	// 新借用使用新版本
	newTok, _ := svc.Borrow("tls", time.Hour)
	got, err = svc.Use(newTok)
	if err != nil || !bytes.Equal(got, newMat) {
		t.Fatalf("新借用应使用新版本: %v", err)
	}
	// 旧借用到期后失效
	clock = clock.Add(2 * time.Hour)
	if _, err := svc.Use(oldTok); !errors.Is(err, ErrBorrowExpired) {
		t.Fatalf("期望 ErrBorrowExpired，得到 %v", err)
	}
}

func TestRotationRevokeOld(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	svc.CreateSecret("sign", fakeMaterial(t, "v1"))
	oldTok, _ := svc.Borrow("sign", time.Hour)
	svc.Rotate("sign", fakeMaterial(t, "v2"), RevokeOld)
	if _, err := svc.Use(oldTok); !errors.Is(err, ErrBorrowRevoked) {
		t.Fatalf("revoke 策略下旧借用应立即失效: %v", err)
	}
}

func TestAuditContainsNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	key, _ := GenerateMasterKey()
	clock := time.Now()
	svc := newTestService(t, dir, key, &clock)
	mat := fakeMaterial(t, "audit")
	svc.CreateSecret("audit", mat)
	tok, _ := svc.Borrow("audit", time.Hour)
	svc.Use(tok)
	svc.Revoke(tok)
	svc.Revoke(tok) // 重复撤销也会留痕

	raw, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, mat) {
		t.Fatal("审计记录中不得出现材料明文")
	}
	if strings.Contains(string(raw), tok) {
		t.Fatal("审计记录中不得出现凭据本身（只存哈希）")
	}
	// 状态文件同样不含明文
	storeRaw, _ := os.ReadFile(filepath.Join(dir, "store", "state.json"))
	if bytes.Contains(storeRaw, mat) {
		t.Fatal("存储文件中不得出现材料明文")
	}
}

func TestInvalidMasterKeyLength(t *testing.T) {
	if _, err := Open(t.TempDir(), []byte("short"), nil); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("期望 ErrInvalidMasterKey，得到 %v", err)
	}
}
