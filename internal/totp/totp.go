package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Params struct {
	Secret    string
	Digits    int
	Period    int
	Algorithm string
}

func (p Params) withDefaults() Params {
	if p.Digits < 1 || p.Digits > 10 {
		p.Digits = 6
	}
	if p.Period < 1 {
		p.Period = 30
	}
	if p.Algorithm == "" {
		p.Algorithm = "SHA1"
	}
	return p
}

func Code(p Params, t time.Time) (string, error) {
	p = p.withDefaults()
	key, err := decodeSecret(p.Secret)
	if err != nil {
		return "", err
	}
	h, err := hashFor(p.Algorithm)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / uint64(p.Period)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(h, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code := uint64(value) % pow10(p.Digits)
	return fmt.Sprintf("%0*d", p.Digits, code), nil
}

func Remaining(p Params, t time.Time) int {
	p = p.withDefaults()
	return p.Period - int(t.Unix()%int64(p.Period))
}

// Parse accepts either a raw base32 secret or a full otpauth:// URI and
// returns the params plus any issuer/account it could recover from a URI.
func Parse(raw string) (params Params, issuer, account string, err error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return parseURI(raw)
	}
	p := Params{Secret: normalize(raw)}.withDefaults()
	if _, err := decodeSecret(p.Secret); err != nil {
		return Params{}, "", "", errors.New("not a valid base32 secret")
	}
	return p, "", "", nil
}

func parseURI(raw string) (Params, string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Params{}, "", "", err
	}
	if strings.ToLower(u.Host) != "totp" {
		return Params{}, "", "", errors.New("only totp uris are supported")
	}
	q := u.Query()
	p := Params{
		Secret:    normalize(q.Get("secret")),
		Algorithm: strings.ToUpper(q.Get("algorithm")),
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 10 {
			return Params{}, "", "", errors.New("uri has invalid digits")
		}
		p.Digits = n
	}
	if pr := q.Get("period"); pr != "" {
		n, err := strconv.Atoi(pr)
		if err != nil || n < 1 {
			return Params{}, "", "", errors.New("uri has invalid period")
		}
		p.Period = n
	}
	p = p.withDefaults()
	if _, err := decodeSecret(p.Secret); err != nil {
		return Params{}, "", "", errors.New("uri has no valid secret")
	}

	issuer := q.Get("issuer")
	account := strings.TrimPrefix(u.Path, "/")
	if i := strings.Index(account, ":"); i >= 0 {
		if issuer == "" {
			issuer = account[:i]
		}
		account = account[i+1:]
	}
	return p, issuer, account, nil
}

func decodeSecret(secret string) ([]byte, error) {
	s := normalize(secret)
	if s == "" {
		return nil, errors.New("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func normalize(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s)
	return s
}

func hashFor(algo string) (func() hash.Hash, error) {
	switch strings.ToUpper(algo) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q", algo)
}

func pow10(n int) uint64 {
	r := uint64(1)
	for i := 0; i < n; i++ {
		r *= 10
	}
	return r
}
