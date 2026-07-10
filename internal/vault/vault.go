package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Account struct {
	Domain    string    `json:"domain"`
	Username  string    `json:"username"`
	Secret    string    `json:"secret"`
	Digits    int       `json:"digits"`
	Period    int       `json:"period"`
	Algorithm string    `json:"algorithm"`
	Added     time.Time `json:"added"`
}

type Vault struct {
	Accounts []Account
	Access   Access

	dk      []byte
	dir     string
	salt    []byte
	wrapped []byte
	argon   argonParams
}

type fileFormat struct {
	Magic      string      `json:"magic"`
	Salt       []byte      `json:"salt"`
	Argon      argonParams `json:"argon"`
	WrappedKey []byte      `json:"wrappedKey"`
	Content    []byte      `json:"content"`
}

func Dir() (string, error) {
	if d := os.Getenv("OAT_DIR"); d != "" {
		return d, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "oat"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "oat"), nil
}

func vaultPath(dir string) string {
	return filepath.Join(dir, "vault.enc")
}

// Exists reports whether a vault has already been created on this machine.
func Exists() bool {
	dir, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(vaultPath(dir))
	return err == nil
}

// Open loads the vault, creating it on first run. askNew and askUnlock supply
// passwords; either may be nil to disable that path.
func Open(askNew, askUnlock func() (string, error)) (*Vault, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(vaultPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return create(dir, askNew)
	} else if err != nil {
		return nil, err
	}

	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("vault file is corrupt: %w", err)
	}
	if f.Magic != magic {
		return nil, errors.New("not an oat vault")
	}
	if err := validArgon(f.Argon); err != nil {
		return nil, fmt.Errorf("vault file is corrupt: %w", err)
	}

	v := &Vault{dir: dir, salt: f.Salt, wrapped: f.WrappedKey, argon: f.Argon}

	if dk, ok := keyringGet(dir); ok {
		if content, err := unseal(dk, f.Content); err == nil {
			v.dk = dk
			v.load(content)
			v.Access = checkAccess(dir, dk, raw)
			return v, nil
		}
	}

	if askUnlock == nil {
		return nil, errors.New("vault is locked and no password source is available")
	}
	pw, err := askUnlock()
	if err != nil {
		return nil, err
	}
	dk, err := unseal(deriveKEK(pw, f.Salt, f.Argon), f.WrappedKey)
	if err != nil {
		return nil, errors.New("wrong password")
	}
	content, err := unseal(dk, f.Content)
	if err != nil {
		return nil, errors.New("vault could not be decrypted")
	}
	v.dk = dk
	v.load(content)
	keyringSet(dir, dk)
	v.Access = checkAccess(dir, dk, raw)
	return v, nil
}

func create(dir string, askNew func() (string, error)) (*Vault, error) {
	if askNew == nil {
		return nil, errors.New("no vault exists and no password source is available")
	}
	pw, err := askNew()
	if err != nil {
		return nil, err
	}
	salt, err := randomBytes(saltLen)
	if err != nil {
		return nil, err
	}
	dk, err := randomBytes(keyLen)
	if err != nil {
		return nil, err
	}
	argon := defaultArgon()
	wrapped, err := seal(deriveKEK(pw, salt, argon), dk)
	if err != nil {
		return nil, err
	}
	v := &Vault{dir: dir, dk: dk, salt: salt, wrapped: wrapped, argon: argon}
	if err := v.save(); err != nil {
		return nil, err
	}
	keyringSet(dir, dk)
	return v, nil
}

func (v *Vault) load(content []byte) {
	v.Accounts = nil
	if len(content) > 0 {
		_ = json.Unmarshal(content, &v.Accounts)
	}
}

func (v *Vault) save() error {
	content, err := json.Marshal(v.Accounts)
	if err != nil {
		return err
	}
	box, err := seal(v.dk, content)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(fileFormat{
		Magic:      magic,
		Salt:       v.salt,
		Argon:      v.argon,
		WrappedKey: v.wrapped,
		Content:    box,
	}, "", "  ")
	if err != nil {
		return err
	}

	path := vaultPath(v.dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	mtime := time.Now().UnixNano()
	if info, err := os.Stat(path); err == nil {
		mtime = info.ModTime().UnixNano()
	}
	// The freshly written file is now the trusted baseline.
	v.Access = Access{}
	return writeMeta(v.dir, v.dk, raw, mtime)
}

func (v *Vault) Add(a Account) error {
	if a.Digits == 0 {
		a.Digits = 6
	}
	if a.Period == 0 {
		a.Period = 30
	}
	if a.Algorithm == "" {
		a.Algorithm = "SHA1"
	}
	a.Added = time.Now()
	v.Accounts = append(v.Accounts, a)
	return v.save()
}

func (v *Vault) RemoveAt(i int) error {
	if i < 0 || i >= len(v.Accounts) {
		return errors.New("no such account")
	}
	v.Accounts = append(v.Accounts[:i], v.Accounts[i+1:]...)
	return v.save()
}

// Find returns indexes of accounts whose domain or username contains query.
func (v *Vault) Find(query string) []int {
	query = strings.ToLower(strings.TrimSpace(query))
	var out []int
	for i, a := range v.Accounts {
		if query == "" ||
			strings.Contains(strings.ToLower(a.Domain), query) ||
			strings.Contains(strings.ToLower(a.Username), query) {
			out = append(out, i)
		}
	}
	return out
}
