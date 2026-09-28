package localsecretmaterials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var ErrWrongMasterKey = errors.New("wrong master key for encrypted material")

// MasterKey is deliberately scoped to this in-memory process. Persisting it
// next to the encrypted fictional material would defeat the demo's warning.
type MasterKey struct {
	id   string
	aead cipher.AEAD
}

type EncryptedVersion struct {
	ID            string `json:"id"`
	Number        int    `json:"number"`
	KeyID         string `json:"key_id"`
	NonceB64      string `json:"nonce_b64"`
	CiphertextB64 string `json:"ciphertext_b64"`
}

func GenerateMasterKey() (MasterKey, error) {
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return MasterKey{}, err
	}
	block, err := aes.NewCipher(raw[:])
	if err != nil {
		return MasterKey{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return MasterKey{}, err
	}
	keyIDBytes := sha256.Sum256(append([]byte("local-materials-key-id-v1:"), raw[:]...))
	return MasterKey{id: hex.EncodeToString(keyIDBytes[:12]), aead: aead}, nil
}

func MustMasterKey(key MasterKey, err error) MasterKey {
	if err != nil {
		panic(err)
	}
	return key
}

func (k MasterKey) ID() string {
	return k.id
}

func (k MasterKey) Seal(versionLabel string, plaintext []byte) (*EncryptedVersion, error) {
	if k.aead == nil {
		return nil, fmt.Errorf("%w: zero master key", ErrWrongMasterKey)
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	idDigest := sha256.Sum256([]byte("local-materials-version-v1:" + k.id + ":" + versionLabel + ":" + hex.EncodeToString(nonce)))
	ciphertext := k.aead.Seal(nil, nonce, plaintext, []byte("local-secret-materials"))
	return &EncryptedVersion{
		ID:            "ver_" + hex.EncodeToString(idDigest[:12]),
		Number:        0,
		KeyID:         k.id,
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func (k MasterKey) Open(version *EncryptedVersion) ([]byte, error) {
	if version.KeyID != k.id {
		return nil, fmt.Errorf("%w: stored key %s, current key %s", ErrWrongMasterKey, version.KeyID, k.id)
	}
	nonce, err := base64.StdEncoding.DecodeString(version.NonceB64)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(version.CiphertextB64)
	if err != nil {
		return nil, err
	}
	plaintext, err := k.aead.Open(nil, nonce, ciphertext, []byte("local-secret-materials"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrongMasterKey, err)
	}
	return plaintext, nil
}
