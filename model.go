package localsecretmaterials

import "time"

type SecretRecord struct {
	Name             string              `json:"name"`
	CurrentVersionID string              `json:"current_version_id"`
	RotationPolicy   RotationPolicy      `json:"rotation_policy"`
	Versions         []*EncryptedVersion `json:"versions"`
}

func (r *SecretRecord) Version(id string) *EncryptedVersion {
	for _, version := range r.Versions {
		if version.ID == id {
			return version
		}
	}
	return nil
}

type LeaseRecord struct {
	ID         string    `json:"id"`
	TokenHash  string    `json:"token_hash"`
	SecretName string    `json:"secret_name"`
	VersionID  string    `json:"version_id"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	SettleRule string    `json:"settle_rule,omitempty"`
}

func (r *LeaseRecord) IsActive(now time.Time) bool {
	return r.RevokedAt.IsZero() && now.Before(r.ExpiresAt)
}

func (r *LeaseRecord) toLease(token string) *Lease {
	return &Lease{
		ID:         r.ID,
		Token:      token,
		SecretName: r.SecretName,
		VersionID:  r.VersionID,
		IssuedAt:   r.IssuedAt,
		ExpiresAt:  r.ExpiresAt,
	}
}

type AuditEvent struct {
	At           time.Time `json:"at"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome"`
	Secret       string    `json:"secret,omitempty"`
	Version      string    `json:"version,omitempty"`
	PriorVersion string    `json:"prior_version,omitempty"`
	LeaseID      string    `json:"lease_id,omitempty"`
	KeyID        string    `json:"key_id,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}
