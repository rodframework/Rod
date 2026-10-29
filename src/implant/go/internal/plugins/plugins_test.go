package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"rodimplant/internal/wire"
)

// stubLibrary answers every exchange from a fixed table -- the registry's
// test seam, the in-process equivalent of a load the platform loader
// performed.
type stubLibrary struct {
	name  string
	verbs []string
	abi   uint32
	run   func(index uint32, arguments string) RunStatus
}

func (s *stubLibrary) Abi() (uint32, error) { return s.abi, nil }
func (s *stubLibrary) Name() string         { return s.name }
func (s *stubLibrary) VerbCount() uint32    { return uint32(len(s.verbs)) }
func (s *stubLibrary) VerbName(index uint32) (string, bool) {
	if int(index) >= len(s.verbs) {
		return "", false
	}
	return s.verbs[index], true
}
func (s *stubLibrary) Run(index uint32, arguments string) RunStatus {
	if s.run != nil {
		return s.run(index, arguments)
	}
	return RunStatus{Kind: RunSucceeded, Output: "stub"}
}

// install puts a stub-loaded entry into the registry the way a successful
// Load would, routes and all -- the replaced entry's routes drop with it.
func (r *Registry) install(name string, verbs []string, library Library) {
	entry := &moduleEntry{name: name, verbs: verbs, library: library}
	kept := r.modules[:0]
	for _, held := range r.modules {
		if held.name == name {
			for verb, routed := range r.routes {
				if routed.module == held {
					delete(r.routes, verb)
				}
			}
			continue
		}
		kept = append(kept, held)
	}
	r.modules = append(kept, entry)
	for index, verb := range verbs {
		r.routes[verb] = route{module: entry, index: uint32(index)}
	}
}

func hexSHA(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func TestValidateHandleGrammar(t *testing.T) {
	for _, handle := range []string{"", strings.Repeat("a", 65), "bad name", "bad/name", "naïve"} {
		if err := validateHandle(handle); err == nil {
			t.Fatalf("'%s' must fail the handle grammar", handle)
		}
	}
	for _, handle := range []string{"conform", "hostenum-2", "mod_1.0", strings.Repeat("a", 64)} {
		if err := validateHandle(handle); err != nil {
			t.Fatalf("'%s' is a valid handle: %v", handle, err)
		}
	}
}

func TestValidateVerbGuards(t *testing.T) {
	reserved := map[string]bool{"shell.exec": true, "module.load": true}
	for _, verb := range []string{"noslash", ".action", "namespace.", "shell.exec", "module.load"} {
		if err := validateVerb(verb, reserved); err == nil {
			t.Fatalf("'%s' must fail the verb guards", verb)
		}
	}
	if err := validateVerb("conform.plugin", reserved); err != nil {
		t.Fatalf("a namespaced unreserved verb passes: %v", err)
	}
}

func TestVerifySHA256IsCaseInsensitive(t *testing.T) {
	sum := hexSHA([]byte("payload"))
	if err := verifySHA256([]byte("payload"), strings.ToUpper(sum)); err != nil {
		t.Fatalf("the hash token matches case-insensitively: %v", err)
	}
	err := verifySHA256([]byte("other"), sum)
	if err == nil || !strings.Contains(err.Error(), "payload hash mismatch: expected") {
		t.Fatalf("a mismatched hash is refused, got %v", err)
	}
}

func TestLoadRejectsBadHandlesAndHashes(t *testing.T) {
	r := New([]string{"shell.exec"})
	payload := []byte("module bytes")
	sum := hexSHA(payload)
	if _, err := r.Load("bad handle", payload, sum); err == nil ||
		!strings.Contains(err.Error(), "module.load expects '<name>'") {
		t.Fatalf("the handle grammar is enforced, got %v", err)
	}
	if _, err := r.Load("conform", payload, "deadbeef"); err == nil ||
		!strings.Contains(err.Error(), "payload hash mismatch") {
		t.Fatalf("the payload hash is enforced, got %v", err)
	}
}

func TestStubRegistryLifecycle(t *testing.T) {
	r := New([]string{"shell.exec", "file.pull"})
	if r.List() != "no modules loaded" {
		t.Fatal("the empty registry lists so")
	}
	r.install("conform", []string{"conform.plugin", "conform.artifact"}, &stubLibrary{name: "conform"})
	if verbs := r.AdvertisedVerbs(); len(verbs) != 2 || verbs[0] != "conform.artifact" || verbs[1] != "conform.plugin" {
		t.Fatalf("the registered verbs advertise (sorted), got %v", verbs)
	}
	if r.List() != "conform: conform.plugin, conform.artifact" {
		t.Fatalf("module.list names the module and its verbs, got %q", r.List())
	}
	outcome, output, artifact, ok := r.Dispatch("conform.plugin", "marker")
	if !ok || outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED || output != "stub" || artifact != nil {
		t.Fatalf("a routed dispatch runs the module, got %v %q %v %v", ok, output, artifact, outcome)
	}
	if _, _, _, ok := r.Dispatch("shell.exec", ""); ok {
		t.Fatal("a reserved verb never routes to a module")
	}
	report, err := r.Unload("conform")
	if err != nil || report != "module conform unloaded (conform.plugin, conform.artifact; library unload is best-effort)" {
		t.Fatalf("unload reports the retraction, got %q %v", report, err)
	}
	if _, err := r.Unload("conform"); err == nil ||
		!strings.Contains(err.Error(), "module.load has no module named conform") {
		t.Fatalf("unloading a missing module names it, got %v", err)
	}
	if verbs := r.AdvertisedVerbs(); len(verbs) != 0 {
		t.Fatal("unload drops the routes")
	}
}

func TestSameNameLoadReplacesAndDropsRoutes(t *testing.T) {
	r := New(nil)
	r.install("conform", []string{"conform.plugin", "conform.old"}, &stubLibrary{name: "conform"})
	r.install("conform", []string{"conform.plugin"}, &stubLibrary{name: "conform"})
	if _, _, _, ok := r.Dispatch("conform.old", ""); ok {
		t.Fatal("a verb the replacement does not carry stops routing")
	}
	if _, _, _, ok := r.Dispatch("conform.plugin", ""); !ok {
		t.Fatal("the carried verb keeps routing")
	}
	if r.List() != "conform: conform.plugin" {
		t.Fatalf("one module survives the same-name replace, got %q", r.List())
	}
}
