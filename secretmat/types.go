// Package secretmat 提供本地秘密材料服务：对虚构秘密材料做版本管理、
// 短期借用与轮换。存储与使用记录（审计）分离，审计中不出现明文。
//
// 设计约束：
//   - 主密钥仅在演示时临时生成（GenerateMasterKey），不持久化；
//     丢失后已加密材料明确无法解密（Open 返回 ErrUndecryptable）。
//   - 用户的真实密钥不参与：服务只接受调用方传入的虚构材料字节。
//   - 借用凭据到期或主动撤销后不再有效。
package secretmat

import (
	"errors"
	"time"
)

// RotationPolicy 声明轮换期间旧版本借用的收尾规则。
type RotationPolicy string

const (
	// DrainOld 旧版本上已发出的借用继续有效直至各自到期，新借用使用新版本。
	DrainOld RotationPolicy = "drain"
	// RevokeOld 轮换立即撤销旧版本上所有未结束的借用。
	RevokeOld RotationPolicy = "revoke"
)

var (
	ErrSecretNotFound   = errors.New("secretmat: 秘密不存在")
	ErrBorrowNotFound   = errors.New("secretmat: 借用不存在")
	ErrBorrowExpired    = errors.New("secretmat: 借用已过期")
	ErrBorrowRevoked    = errors.New("secretmat: 借用已撤销")
	ErrAlreadyRevoked   = errors.New("secretmat: 借用已被撤销，不可重复撤销")
	ErrUndecryptable    = errors.New("secretmat: 主密钥不匹配，材料无法解密")
	ErrInvalidMasterKey = errors.New("secretmat: 主密钥长度必须为 32 字节")
	ErrInvalidTTL       = errors.New("secretmat: 借用时长必须为正")
)

// Version 是秘密材料的一个版本，仅存密文。
type Version struct {
	Number     int            `json:"number"`
	Ciphertext []byte         `json:"ciphertext"` // AES-GCM 密文（含 nonce）
	CreatedAt  time.Time      `json:"created_at"`
	RetiredAt  *time.Time     `json:"retired_at,omitempty"`
	Policy     RotationPolicy `json:"policy,omitempty"` // 被轮换时声明的收尾规则
}

// Borrow 是一次短期借用记录。
type Borrow struct {
	TokenHash string     `json:"token_hash"` // 凭据的 SHA-256，不存凭据本身
	SecretID  string     `json:"secret_id"`
	Version   int        `json:"version"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Status 返回借用在 now 时刻的状态：active / expired / revoked。
func (b *Borrow) Status(now time.Time) string {
	switch {
	case b.RevokedAt != nil:
		return "revoked"
	case !now.Before(b.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}
