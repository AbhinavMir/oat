package vault

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic   = "OAT1"
	saltLen = 16
	keyLen  = 32
)

type argonParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

func defaultArgon() argonParams {
	return argonParams{Time: 3, Memory: 64 * 1024, Threads: 4}
}

func deriveKEK(password string, salt []byte, p argonParams) []byte {
	return argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
}

func validArgon(p argonParams) error {
	if p.Time < 1 || p.Threads < 1 || p.Memory < 8*uint32(p.Threads) {
		return errors.New("invalid argon parameters")
	}
	return nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func seal(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func unseal(key, box []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(box) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := box[:aead.NonceSize()], box[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}
