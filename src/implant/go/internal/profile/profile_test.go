package profile

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func bake(t *testing.T, m map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestDecodeReadsTheContractKeys(t *testing.T) {
	p, err := Decode(bake(t, map[string]any{
		"enrollURL":          "https://front.example/enroll",
		"fallbackEnrollURLs": []string{"https://backup.example/enroll"},
		"mode":               "poll",
		"killDate":           "2030-01-01T00:00:00Z",
		"sleep":              "45s",
		"jitter":             "5s",
		"enrollPath":         "/enroll",
		"requestTimeout":     "20s",
		"envelope":           "aesgcm",
		"contactEnvelope":    "aesgcm",
		"envelopeKey":        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4=",
		"token":              "secret",
		"verbs":              "shell.exec,file.pull",
		"unknownFutureKey":   struct{}{},
	}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.EnrollURL != "https://front.example/enroll" || p.Token != "secret" {
		t.Fatalf("core keys decoded wrong: %+v", p)
	}
	if p.SleepSeconds != 45 || p.JitterSeconds != 5 {
		t.Fatalf("cadence decoded wrong: %v/%v", p.SleepSeconds, p.JitterSeconds)
	}
	if len(p.Verbs) != 2 || p.Verbs[1] != "file.pull" {
		t.Fatalf("verbs decoded wrong: %v", p.Verbs)
	}
	if p.TlsTrust != "pinned" {
		t.Fatalf("an absent tlsTrust defaults to pinned, got %q", p.TlsTrust)
	}
	if len(p.FallbackEnrollURLs) != 1 {
		t.Fatalf("fallback walk decoded wrong: %v", p.FallbackEnrollURLs)
	}
}

func TestEmptyProfileRefuses(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("an unbaked profile must refuse to decode")
	}
}

func TestEnrollWalkAppliesThePath(t *testing.T) {
	p, err := Decode(bake(t, map[string]any{
		"enrollURL":          "http://front.example/custom",
		"enrollPath":         "/x",
		"fallbackEnrollURLs": []string{"http://backup.example", "tcp://10.0.0.9:443"},
	}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	walk := p.EnrollWalk()
	if len(walk) != 3 {
		t.Fatalf("the walk carries every front, got %d", len(walk))
	}
	if walk[0] != "http://front.example/x" {
		t.Fatalf("the path replaces the URL's own, got %q", walk[0])
	}
	if walk[1] != "http://backup.example/x" {
		t.Fatalf("a bare authority gains the path, got %q", walk[1])
	}
	if walk[2] != "tcp://10.0.0.9:443" {
		t.Fatalf("the socket family's dial data stands, got %q", walk[2])
	}
}

func TestKillDatePassed(t *testing.T) {
	p, err := Decode(bake(t, map[string]any{"killDate": "2000-01-01T00:00:00Z"}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !p.KillDatePassed(time.Now()) {
		t.Fatal("a past kill date must report passed")
	}
	p, _ = Decode(bake(t, map[string]any{}))
	if p.KillDatePassed(time.Now()) {
		t.Fatal("an empty kill date is the open-ended shape")
	}
}
