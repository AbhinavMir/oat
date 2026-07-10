package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const keyringService = "oat"

// keyringUser ties the cached key to a specific vault directory, so separate
// vaults (a demo vault, a second machine profile) never share one slot.
func keyringUser(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return "vault-key:" + hex.EncodeToString(sum[:8])
}

func keyringGet(dir string) ([]byte, bool) {
	s, err := keyring.Get(keyringService, keyringUser(dir))
	if err != nil {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != keyLen {
		return nil, false
	}
	return b, true
}

func keyringSet(dir string, dk []byte) {
	_ = keyring.Set(keyringService, keyringUser(dir), base64.StdEncoding.EncodeToString(dk))
}

func keyringClear(dir string) {
	_ = keyring.Delete(keyringService, keyringUser(dir))
}
