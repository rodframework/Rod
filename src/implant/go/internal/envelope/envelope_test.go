package envelope

import (
	"encoding/base64"
	"testing"
)

func TestContactBodyRoundTrip(t *testing.T) {
	key := Key{}
	for i := range key.ID {
		key.ID[i] = byte(i)
	}
	for i := range key.AES {
		key.AES[i] = byte(200 - i)
	}
	plain := "counter-and-frames"

	sealed, err := SealContactBody(plain, ContactRequestAAD, key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(sealed)); err != nil || string(decoded[:2]) != "R1" {
		t.Fatalf("sealed body should be the base64 of R1||..., got %q", sealed[:8])
	}
	opened, err := OpenContactBody(sealed, ContactRequestAAD, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(opened) != plain {
		t.Fatalf("round trip changed the plaintext")
	}
}

func TestWrongPurposeTagDoesNotVerify(t *testing.T) {
	key := Key{}
	sealed, err := SealContactBody("plain", ContactRequestAAD, key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := OpenContactBody(sealed, ContactResponseAAD, key); err == nil {
		t.Fatal("a request-sealed body must not verify under the response tag")
	}
}

func TestWrongKeyDoesNotVerify(t *testing.T) {
	key := Key{}
	key.AES = [32]byte{1, 2, 3}
	sealed, err := SealContactBody("plain", EnrollAAD, key)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	key.AES[0] = 9
	if _, err := OpenContactBody(sealed, EnrollAAD, key); err == nil {
		t.Fatal("a body sealed under one key must not open under another")
	}
}

func TestParseBakedKeyRejectsShortInput(t *testing.T) {
	if _, err := ParseBakedKey("AAAA"); err == nil {
		t.Fatal("a packed key shorter than keyId(16)||key(32) must be refused")
	}
}
