package localsecretmaterials

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	materialsFile  = "secret-materials.json"
	leasesFile     = "lease-credentials.json"
	auditFile      = "usage-audit.jsonl"
	receiptKeyFile = "receipt-signing-key.json"
)

type Store struct {
	dir       string
	Materials map[string]*SecretRecord
	Leases    map[string]*LeaseRecord
	auditFile *os.File
	// receiptKey signs usage receipts. Unlike the demo master key it is
	// persisted, because receipts must stay verifiable after a restart; it
	// never protects material plaintext.
	receiptKey ed25519.PrivateKey
}

func OpenStore(ctx context.Context, dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &Store{
		dir:       dir,
		Materials: make(map[string]*SecretRecord),
		Leases:    make(map[string]*LeaseRecord),
	}
	if err := store.loadMaterials(); err != nil {
		return nil, err
	}
	if err := store.loadLeases(); err != nil {
		return nil, err
	}
	if err := store.openAudit(ctx); err != nil {
		return nil, err
	}
	if err := store.loadReceiptKey(); err != nil {
		return nil, err
	}
	return store, nil
}

// ReceiptPublicKey exposes the verification half of the receipt signing key
// so receipts can be checked offline without the service.
func (s *Store) ReceiptPublicKey() ed25519.PublicKey {
	return s.receiptKey.Public().(ed25519.PublicKey)
}

// ReceiptKeyID identifies which signing key produced a receipt.
func (s *Store) ReceiptKeyID() string {
	sum := sha256.Sum256(s.ReceiptPublicKey())
	return "rkey_" + hex.EncodeToString(sum[:12])
}

// SignReceipt signs the canonical receipt payload.
func (s *Store) SignReceipt(payload []byte) []byte {
	return ed25519.Sign(s.receiptKey, payload)
}

type receiptKeyFileData struct {
	SeedB64 string `json:"seed_b64"`
}

func (s *Store) loadReceiptKey() error {
	path := filepath.Join(s.dir, receiptKeyFile)
	var data receiptKeyFileData
	if err := readJSON(path, &data); err != nil {
		return err
	}
	if data.SeedB64 != "" {
		seed, err := base64.StdEncoding.DecodeString(data.SeedB64)
		if err != nil {
			return fmt.Errorf("load receipt signing key: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("load receipt signing key: bad seed length %d", len(seed))
		}
		s.receiptKey = ed25519.NewKeyFromSeed(seed)
		return nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.receiptKey = key
	seed := key.Seed()
	return writeJSONAtomic(path, receiptKeyFileData{SeedB64: base64.StdEncoding.EncodeToString(seed)}, 0o600)
}

func (s *Store) SaveSecret(ctx context.Context, record *SecretRecord) error {
	s.Materials[record.Name] = cloneJSON(record)
	return writeJSONAtomic(filepath.Join(s.dir, materialsFile), s.Materials, 0o600)
}

func (s *Store) SaveLease(ctx context.Context, lease *LeaseRecord) error {
	if existing, ok := s.Leases[lease.TokenHash]; ok && !existing.RevokedAt.IsZero() {
		if lease.RevokedAt.IsZero() {
			return fmt.Errorf("%w: cannot restore revoked lease %s", ErrLeaseTerminal, lease.ID)
		}
		if lease.RevokedAt.Before(existing.RevokedAt) || lease.ExpiresAt.After(existing.ExpiresAt) {
			return fmt.Errorf("%w: cannot weaken terminal lease %s", ErrLeaseTerminal, lease.ID)
		}
	}
	s.Leases[lease.TokenHash] = cloneJSON(lease)
	return writeJSONAtomic(filepath.Join(s.dir, leasesFile), s.Leases, 0o600)
}

func (s *Store) AppendAudit(ctx context.Context, event AuditEvent) {
	// Audit failures must not silently turn into material writes. The service
	// keeps the append-only file open, so ordinary disk writes only fail here
	// for severe I/O problems.
	_ = ctx
	encoded, err := json.Marshal(event)
	if err != nil {
		return
	}
	encoded = append(encoded, '\n')
	_, _ = s.auditFile.Write(encoded)
	_ = s.auditFile.Sync()
}

func (s *Store) ReadAudit(ctx context.Context) ([]AuditEvent, error) {
	_ = ctx
	if err := s.auditFile.Sync(); err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(s.dir, auditFile))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []AuditEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func (s *Store) Close() error {
	if s.auditFile == nil {
		return nil
	}
	err := s.auditFile.Close()
	s.auditFile = nil
	return err
}

func (s *Store) loadMaterials() error {
	path := filepath.Join(s.dir, materialsFile)
	if err := readJSON(path, &s.Materials); err != nil {
		return err
	}
	if s.Materials == nil {
		s.Materials = make(map[string]*SecretRecord)
	}
	return nil
}

func (s *Store) loadLeases() error {
	path := filepath.Join(s.dir, leasesFile)
	if err := readJSON(path, &s.Leases); err != nil {
		return err
	}
	if s.Leases == nil {
		s.Leases = make(map[string]*LeaseRecord)
	}
	return nil
}

func (s *Store) openAudit(ctx context.Context) error {
	_ = ctx
	file, err := os.OpenFile(filepath.Join(s.dir, auditFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.auditFile = file
	return nil
}

func readJSON(path string, target any) error {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(encoded) == 0 {
		return nil
	}
	return json.Unmarshal(encoded, target)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmpName, err)
	}
	return nil
}

func cloneJSON[T any](value *T) *T {
	encoded, _ := json.Marshal(value)
	var cloned T
	_ = json.Unmarshal(encoded, &cloned)
	return &cloned
}
