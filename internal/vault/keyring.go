package vault

import (
	"encoding/base64"

	"github.com/zalando/go-keyring"
)

const (
	keyringService = "oat"
	keyringUser    = "vault-key"
)

func keyringGet() ([]byte, bool) {
	s, err := keyring.Get(keyringService, keyringUser)
	if err != nil {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != keyLen {
		return nil, false
	}
	return b, true
}

func keyringSet(dk []byte) {
	_ = keyring.Set(keyringService, keyringUser, base64.StdEncoding.EncodeToString(dk))
}

func keyringClear() {
	_ = keyring.Delete(keyringService, keyringUser)
}
