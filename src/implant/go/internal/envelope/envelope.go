// Package envelope seals and opens the R1 contact body: AES-256-GCM under
// the per-artifact key the build baked, base64-wrapped, each direction
// under its own purpose tag so neither side's ciphertext replays as the
// other (the wire reference, extending/implants.md).
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// The purpose tags: one per direction and arm, so a sealed body from one
// context never verifies in another.
const (
	EnrollAAD          = "rod-envelope-v1"
	ContactRequestAAD  = "rod-contact-v1"
	ContactResponseAAD = "rod-contact-response-v1"
)

// Key is the baked envelope key split into its wire halves: the 16-byte
// key id and the 32-byte AES-256 key, packed in that order in the baked
// profile's base64 envelopeKey value.
type Key struct {
	ID  [16]byte
	AES [32]byte
}

// ParseBakedKey decodes the profile's envelopeKey: standard base64 of
// keyId(16) || key(32).
func ParseBakedKey(baked string) (Key, error) {
	var k Key
	raw, err := base64.StdEncoding.DecodeString(baked)
	if err != nil {
		return k, fmt.Errorf("envelope key is not base64: %w", err)
	}
	if len(raw) != 16+32 {
		return k, fmt.Errorf("envelope key packs keyId(16)||key(32), got %d bytes", len(raw))
	}
	copy(k.ID[:], raw[:16])
	copy(k.AES[:], raw[16:])
	return k, nil
}

// SealContactBody produces the wire body: base64(R1 || keyId || nonce ||
// ciphertext || tag), the opaque-string shape the routes carry.
func SealContactBody(plaintext, aad string, key Key) ([]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	block, err := aes.NewCipher(key.AES[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce[:], []byte(plaintext), []byte(aad))
	body := make([]byte, 0, 2+16+12+len(sealed))
	body = append(body, 'R', '1')
	body = append(body, key.ID[:]...)
	body = append(body, nonce[:]...)
	body = append(body, sealed...)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(body)))
	base64.StdEncoding.Encode(encoded, body)
	return encoded, nil
}

// OpenContactBody verifies and opens what SealContactBody produced; any
// mismatch (wrong key, tampered bytes, foreign shape) is an error and the
// caller drops the whole cycle.
func OpenContactBody(body []byte, aad string, key Key) ([]byte, error) {
	packed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("body is not base64: %w", err)
	}
	if len(packed) < 2+16+12+16 || packed[0] != 'R' || packed[1] != '1' {
		return nil, fmt.Errorf("body is not an R1 envelope")
	}
	if string(packed[2:18]) != string(key.ID[:]) {
		return nil, fmt.Errorf("body names a different key id")
	}
	block, err := aes.NewCipher(key.AES[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, packed[18:30], packed[30:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("body did not verify: %w", err)
	}
	return plain, nil
}
