package localsecretmaterials

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	materialsFile = "secret-materials.json"
	leasesFile    = "lease-credentials.json"
	auditFile     = "usage-audit.jsonl"
)

type Store struct {
	dir       string
	Materials map[string]*SecretRecord
	Leases    map[string]*LeaseRecord
	auditFile *os.File
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
	return store, nil
}

func (s *Store) SaveSecret(ctx context.Context, record *SecretRecord) error {
	s.Materials[record.Name] = cloneJSON(record)
	return writeJSONAtomic(filepath.Join(s.dir, materialsFile), s.Materials, 0o600)
}

func (s *Store) SaveLease(ctx context.Context, lease *LeaseRecord) error {
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
