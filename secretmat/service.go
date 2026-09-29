package secretmat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const stateFile = "state.json"

// GenerateMasterKey 生成演示用的临时主密钥（32 字节）。
// 它不写入磁盘；进程退出或密钥被丢弃后，已加密材料无法恢复。
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("secretmat: 生成主密钥失败: %w", err)
	}
	return key, nil
}

type state struct {
	Secrets map[string][]Version `json:"secrets"`
	Borrows map[string]*Borrow   `json:"borrows"` // key: tokenHash
}

// Service 是本地秘密材料服务。
type Service struct {
	mu    sync.Mutex
	gcm   cipher.AEAD
	dir   string
	audit *AuditLog
	now   func() time.Time
	st    state
}

// Open 打开（或创建）位于 dir 的服务。masterKey 必须是此前加密材料时
// 使用的同一把临时主密钥；若不匹配，加载已有材料时返回 ErrUndecryptable。
func Open(dir string, masterKey []byte, audit *AuditLog) (*Service, error) {
	if len(masterKey) != 32 {
		return nil, ErrInvalidMasterKey
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Service{
		gcm:   gcm,
		dir:   dir,
		audit: audit,
		now:   time.Now,
		st: state{
			Secrets: map[string][]Version{},
			Borrows: map[string]*Borrow{},
		},
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load 读取持久化状态并验证主密钥可解密所有版本。
func (s *Service) load() error {
	data, err := os.ReadFile(filepath.Join(s.dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.st); err != nil {
		return fmt.Errorf("secretmat: 状态文件损坏: %w", err)
	}
	for id, versions := range s.st.Secrets {
		for _, v := range versions {
			if _, err := s.open(id, v.Ciphertext); err != nil {
				return ErrUndecryptable
			}
		}
	}
	return nil
}

func (s *Service) saveLocked() error {
	data, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, stateFile))
}

func (s *Service) seal(secretID string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plaintext, []byte(secretID)), nil
}

func (s *Service) open(secretID string, ciphertext []byte) ([]byte, error) {
	n := s.gcm.NonceSize()
	if len(ciphertext) < n {
		return nil, ErrUndecryptable
	}
	plain, err := s.gcm.Open(nil, ciphertext[:n], ciphertext[n:], []byte(secretID))
	if err != nil {
		return nil, ErrUndecryptable
	}
	return plain, nil
}

// CreateSecret 以初始材料创建秘密（版本 1）。material 必须是虚构材料，
// 不得传入用户真实密钥。
func (s *Service) CreateSecret(secretID string, material []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Secrets[secretID]; ok {
		return fmt.Errorf("secretmat: 秘密 %q 已存在", secretID)
	}
	ct, err := s.seal(secretID, material)
	if err != nil {
		return err
	}
	s.st.Secrets[secretID] = []Version{{Number: 1, Ciphertext: ct, CreatedAt: s.now()}}
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.audit.Record(Event{Type: EventCreate, SecretID: secretID, Version: 1, At: s.now()})
	return nil
}

// Rotate 轮换秘密：旧版本按 policy 声明的规则收尾，新版本立即生效。
// DrainOld 下旧借用保留至到期；RevokeOld 下旧借用立即撤销。
func (s *Service) Rotate(secretID string, newMaterial []byte, policy RotationPolicy) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.st.Secrets[secretID]
	if !ok {
		return 0, ErrSecretNotFound
	}
	now := s.now()
	old := versions[len(versions)-1]
	old.RetiredAt = &now
	old.Policy = policy
	versions[len(versions)-1] = old

	ct, err := s.seal(secretID, newMaterial)
	if err != nil {
		return 0, err
	}
	next := old.Number + 1
	s.st.Secrets[secretID] = append(versions, Version{Number: next, Ciphertext: ct, CreatedAt: now})

	if policy == RevokeOld {
		for _, b := range s.st.Borrows {
			if b.SecretID == secretID && b.Version == old.Number && b.Status(now) == "active" {
				b.RevokedAt = &now
				s.audit.Record(Event{Type: EventRevoke, SecretID: secretID, Version: b.Version, TokenHash: b.TokenHash, Note: "rotation", At: now})
			}
		}
	}
	if err := s.saveLocked(); err != nil {
		return 0, err
	}
	s.audit.Record(Event{Type: EventRotate, SecretID: secretID, Version: next, Note: string(policy), At: now})
	return next, nil
}

// Borrow 签发短期借用凭据，绑定当前最新版本。返回的凭据仅此一次可见，
// 服务内部只保存其哈希。
func (s *Service) Borrow(secretID string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.st.Secrets[secretID]
	if !ok {
		return "", ErrSecretNotFound
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	now := s.now()
	cur := versions[len(versions)-1]
	b := &Borrow{
		TokenHash: hashToken(token),
		SecretID:  secretID,
		Version:   cur.Number,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	s.st.Borrows[b.TokenHash] = b
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	s.audit.Record(Event{Type: EventBorrow, SecretID: secretID, Version: cur.Number, TokenHash: b.TokenHash, At: now})
	return token, nil
}

// Use 校验借用凭据并返回材料明文。过期或已撤销的凭据返回错误。
func (s *Service) Use(token string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.st.Borrows[hashToken(token)]
	if !ok {
		return nil, ErrBorrowNotFound
	}
	now := s.now()
	switch b.Status(now) {
	case "revoked":
		s.audit.Record(Event{Type: EventUseDenied, SecretID: b.SecretID, Version: b.Version, TokenHash: b.TokenHash, Note: "revoked", At: now})
		return nil, ErrBorrowRevoked
	case "expired":
		s.audit.Record(Event{Type: EventUseDenied, SecretID: b.SecretID, Version: b.Version, TokenHash: b.TokenHash, Note: "expired", At: now})
		return nil, ErrBorrowExpired
	}
	var v *Version
	for i := range s.st.Secrets[b.SecretID] {
		if s.st.Secrets[b.SecretID][i].Number == b.Version {
			v = &s.st.Secrets[b.SecretID][i]
		}
	}
	if v == nil {
		return nil, ErrSecretNotFound
	}
	plain, err := s.open(b.SecretID, v.Ciphertext)
	if err != nil {
		return nil, err
	}
	s.audit.Record(Event{Type: EventUse, SecretID: b.SecretID, Version: b.Version, TokenHash: b.TokenHash, At: now})
	return plain, nil
}

// Revoke 主动撤销借用。重复撤销返回 ErrAlreadyRevoked。
func (s *Service) Revoke(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.st.Borrows[hashToken(token)]
	if !ok {
		return ErrBorrowNotFound
	}
	if b.RevokedAt != nil {
		s.audit.Record(Event{Type: EventRevokeDenied, SecretID: b.SecretID, Version: b.Version, TokenHash: b.TokenHash, Note: "already revoked", At: s.now()})
		return ErrAlreadyRevoked
	}
	now := s.now()
	b.RevokedAt = &now
	if err := s.saveLocked(); err != nil {
		return err
	}
	s.audit.Record(Event{Type: EventRevoke, SecretID: b.SecretID, Version: b.Version, TokenHash: b.TokenHash, At: now})
	return nil
}

// BorrowStatus 返回凭据当前状态（active / expired / revoked），便于调用方排查。
func (s *Service) BorrowStatus(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.st.Borrows[hashToken(token)]
	if !ok {
		return "", ErrBorrowNotFound
	}
	return b.Status(s.now()), nil
}

// Versions 返回秘密的版本号列表（升序），不暴露材料。
func (s *Service) Versions(secretID string) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions, ok := s.st.Secrets[secretID]
	if !ok {
		return nil, ErrSecretNotFound
	}
	out := make([]int, 0, len(versions))
	for _, v := range versions {
		out = append(out, v.Number)
	}
	sort.Ints(out)
	return out, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
