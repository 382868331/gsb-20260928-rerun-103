package secretmat

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// EventType 是审计事件类型。
type EventType string

const (
	EventCreate       EventType = "create"
	EventRotate       EventType = "rotate"
	EventBorrow       EventType = "borrow"
	EventUse          EventType = "use"
	EventUseDenied    EventType = "use_denied"
	EventRevoke       EventType = "revoke"
	EventRevokeDenied EventType = "revoke_denied"
)

// Event 是一条使用记录。只含标识符、版本号与凭据哈希，绝不包含材料明文。
type Event struct {
	Type      EventType `json:"type"`
	SecretID  string    `json:"secret_id"`
	Version   int       `json:"version,omitempty"`
	TokenHash string    `json:"token_hash,omitempty"`
	Note      string    `json:"note,omitempty"`
	At        time.Time `json:"at"`
}

// AuditLog 是追加式使用记录，与秘密存储分开存放。
type AuditLog struct {
	mu   sync.Mutex
	path string
}

// OpenAuditLog 打开（或创建）位于 path 的审计日志。
func OpenAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{path: path}, f.Close()
}

// Record 追加一条事件。
func (a *AuditLog) Record(e Event) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", data)
}

// Events 读取全部事件，供检查与测试。
func (a *AuditLog) Events() ([]Event, error) {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("secretmat: 审计记录损坏: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
