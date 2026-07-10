package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// meta records what the vault file looked like the last time oat wrote it,
// authenticated with an HMAC keyed by the data key. Only oat knows the data
// key, so nothing else can forge a matching record after editing the file.
type meta struct {
	SHA256 []byte `json:"sha256"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	HMAC   []byte `json:"hmac"`
}

// Access describes an out-of-band change to the vault file detected on open.
type Access struct {
	Detected bool
	Reason   string
}

func metaPath(dir string) string {
	return filepath.Join(dir, "meta.json")
}

func metaMAC(dk []byte, m meta) []byte {
	mac := hmac.New(sha256.New, dk)
	mac.Write(m.SHA256)
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(m.Size))
	binary.BigEndian.PutUint64(b[8:16], uint64(m.MTime))
	mac.Write(b[:])
	return mac.Sum(nil)
}

func writeMeta(dir string, dk, fileBytes []byte, mtime int64) error {
	sum := sha256.Sum256(fileBytes)
	m := meta{SHA256: sum[:], Size: int64(len(fileBytes)), MTime: mtime}
	m.HMAC = metaMAC(dk, m)
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := metaPath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func checkAccess(dir string, dk, fileBytes []byte) Access {
	raw, err := os.ReadFile(metaPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return Access{Detected: true, Reason: "integrity record is missing"}
	} else if err != nil {
		return Access{Detected: true, Reason: "integrity record unreadable"}
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return Access{Detected: true, Reason: "integrity record corrupt"}
	}
	if !hmac.Equal(m.HMAC, metaMAC(dk, m)) {
		return Access{Detected: true, Reason: "integrity record was tampered with"}
	}
	sum := sha256.Sum256(fileBytes)
	if !hmac.Equal(m.SHA256, sum[:]) {
		return Access{Detected: true, Reason: "vault was modified outside oat"}
	}
	return Access{}
}
