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
	ID                string    `json:"id"`
	TokenHash         string    `json:"token_hash"`
	ParentID          string    `json:"parent_id,omitempty"`
	SecretName        string    `json:"secret_name"`
	VersionID         string    `json:"version_id"`
	Purpose           string    `json:"purpose"`
	Scopes            []string  `json:"scopes,omitempty"`
	AllowsNewVersions bool      `json:"allows_new_versions,omitempty"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	// GrantedExpiresAt is fixed at issuance; grace settling only shortens
	// ExpiresAt. Zero on records created before receipts existed.
	GrantedExpiresAt time.Time `json:"granted_expires_at,omitempty"`
	RevokedAt        time.Time `json:"revoked_at,omitempty"`
	SettleRule       string    `json:"settle_rule,omitempty"`
	// PriorVersionIDs records versions this lease held before rotation-driven
	// adoption, so an earlier receipt still binds to a version once held.
	PriorVersionIDs []string `json:"prior_version_ids,omitempty"`
	// PriorFactHashes retains the fact hashes of earlier lease states.
	PriorFactHashes []string `json:"prior_fact_hashes,omitempty"`
}

// snapshotFactForHistory records the lease's current fact hash before a
// version-adoption or expiry-settling change mutates it.
func (r *LeaseRecord) snapshotFactForHistory() {
	current := leaseFactFromRecord(r).FactHash
	for _, prior := range r.PriorFactHashes {
		if prior == current {
			return
		}
	}
	r.PriorFactHashes = append(r.PriorFactHashes, current)
}

// recordPriorVersion remembers a version the lease is leaving during
// rotation-driven adoption.
func (r *LeaseRecord) recordPriorVersion(versionID string) {
	for _, prior := range r.PriorVersionIDs {
		if prior == versionID {
			return
		}
	}
	r.PriorVersionIDs = append(r.PriorVersionIDs, versionID)
}

func (r *LeaseRecord) IsActive(now time.Time) bool {
	return r.RevokedAt.IsZero() && now.Before(r.ExpiresAt)
}

func (r *LeaseRecord) toLease(token string) *Lease {
	return &Lease{
		ID:                r.ID,
		Token:             token,
		ParentID:          r.ParentID,
		SecretName:        r.SecretName,
		VersionID:         r.VersionID,
		Purpose:           r.Purpose,
		Scopes:            append([]Scope(nil), scopeStrings(r.Scopes)...),
		AllowsNewVersions: r.AllowsNewVersions,
		IssuedAt:          r.IssuedAt,
		ExpiresAt:         r.ExpiresAt,
	}
}
func (r *LeaseRecord) toView() *LeaseView {
	scopes := make([]Scope, len(r.Scopes))
	for i, value := range r.Scopes {
		scopes[i] = Scope(value)
	}
	return &LeaseView{
		ID:                r.ID,
		ParentID:          r.ParentID,
		SecretName:        r.SecretName,
		VersionID:         r.VersionID,
		Purpose:           r.Purpose,
		Scopes:            scopes,
		AllowsNewVersions: r.AllowsNewVersions,
		IssuedAt:          r.IssuedAt,
		ExpiresAt:         r.ExpiresAt,
		Revoked:           !r.RevokedAt.IsZero(),
	}
}

type AuditEvent struct {
	At            time.Time `json:"at"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	Secret        string    `json:"secret,omitempty"`
	Version       string    `json:"version,omitempty"`
	PriorVersion  string    `json:"prior_version,omitempty"`
	LeaseID       string    `json:"lease_id,omitempty"`
	ActorLeaseID  string    `json:"actor_lease_id,omitempty"`
	ParentLeaseID string    `json:"parent_lease_id,omitempty"`
	KeyID         string    `json:"key_id,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}
