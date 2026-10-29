// The module registry (architecture.md Sec 5.4): the loaded modules and the
// verb routes they registered, one instance living in the session across
// every reconnect. Registrations are run-state -- a restarted implant
// re-advertises without them, and the operator re-loads what is still
// needed. The load guards and report lines mirror the Rust reference's
// registry (src/implant/rust/src/plugins.rs); the two hosts answer
// module.list with the same lines.
package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"rodimplant/internal/wire"
)

// AbiVersion is the loader ABI this build hosts; version 2 added the
// artifact return.
const AbiVersion uint32 = 2

// Artifact is the bulk data a module verb produced -- the named bytes that
// flow to the artifact store through the session's exfil arm.
type Artifact struct {
	Name        string
	ContentType string
	Data        []byte
}

// RunKind is the three-way outcome of one module verb run.
type RunKind int

const (
	// RunSucceeded: the module answered OK, output and artifact in hand.
	RunSucceeded RunKind = iota
	// RunFailed: the module answered FAILED; its output is the cause.
	RunFailed
	// RunError: the exchange itself went wrong; the output names why.
	RunError
)

// RunStatus is one module verb run's outcome.
type RunStatus struct {
	Kind     RunKind
	Output   string
	Artifact *Artifact
}

// Library is one loaded module: the loader-facing surface the registry
// drives. The lifecycle is the reference's: discovery (abi, name, verb
// table) once at load, then a run per dispatch.
type Library interface {
	// Abi answers the module's protocol version, or the refusal cause.
	Abi() (uint32, error)
	// Name is the module's declared name; empty lets the registry fall
	// back to the task handle.
	Name() string
	VerbCount() uint32
	// VerbName names verb `index`, reporting false when the module holds
	// no such row.
	VerbName(index uint32) (string, bool)
	Run(index uint32, arguments string) RunStatus
}

type route struct {
	module *moduleEntry
	index  uint32
}

type moduleEntry struct {
	name    string
	verbs   []string
	library Library
}

// Registry is the run's plugin table. The mutex guards the tables only:
// dispatch runs outside it so a long module run never blocks the
// registry's own reads.
type Registry struct {
	mu       sync.Mutex
	modules  []*moduleEntry
	routes   map[string]route
	reserved map[string]bool
}

// New builds an empty registry. The reserved set names the verbs a module
// cannot own -- the compiled handlers and the module family itself -- the
// "stays compiled" guard.
func New(reserved []string) *Registry {
	set := make(map[string]bool, len(reserved))
	for _, verb := range reserved {
		set[verb] = true
	}
	return &Registry{routes: map[string]route{}, reserved: set}
}

// Load loads one module: verifies the handle and the staged payload's
// integrity, asks the platform loader for a library, checks the ABI, reads
// the verb table, and registers the routes the guards admit. It answers the
// load report the operator reads on the task.
func (r *Registry) Load(handle string, bytes []byte, expectedSHA256 string) (string, error) {
	if err := validateHandle(handle); err != nil {
		return "", err
	}
	if err := verifySHA256(bytes, expectedSHA256); err != nil {
		return "", err
	}
	library, err := loadLibrary(handle, bytes)
	if err != nil {
		return "", err
	}
	reported, err := library.Abi()
	if err != nil {
		return "", err
	}
	if reported != AbiVersion {
		return "", fmt.Errorf("module reports ABI %d and this build loads %d", reported, AbiVersion)
	}
	name := registryName(handle, library.Name())
	count := library.VerbCount()
	verbs := make([]string, 0, count)
	for index := uint32(0); index < count; index++ {
		verb, ok := library.VerbName(index)
		if !ok {
			return "", fmt.Errorf("module did not name verb %d", index)
		}
		if err := validateVerb(verb, r.reserved); err != nil {
			return "", err
		}
		verbs = append(verbs, verb)
	}
	if len(verbs) == 0 {
		return "", fmt.Errorf("module %s registers no verbs", name)
	}
	entry := &moduleEntry{name: name, verbs: verbs, library: library}

	r.mu.Lock()
	defer r.mu.Unlock()
	// A same-name load replaces the module it names: its routes drop with
	// it, and any verb the new module does not carry stops routing -- the
	// honest answer to "load the fixed version".
	kept := r.modules[:0]
	for _, held := range r.modules {
		if held.name == entry.name {
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
	return fmt.Sprintf("module %s loaded: %s; advertised at the next contact", entry.name, strings.Join(verbs, ", ")), nil
}

// Unload retracts one module -- best-effort by construction: the routes drop
// immediately, and the library dies with its fd (a run mid-execution may
// still fail its next exchange; the report line says as much).
func (r *Registry) Unload(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	position := -1
	for i, held := range r.modules {
		if held.name == name {
			position = i
			break
		}
	}
	if position < 0 {
		return "", fmt.Errorf("module.load has no module named %s", name)
	}
	entry := r.modules[position]
	r.modules = append(r.modules[:position], r.modules[position+1:]...)
	for verb, held := range r.routes {
		if held.module == entry {
			delete(r.routes, verb)
		}
	}
	if closer, ok := entry.library.(interface{ Close() }); ok {
		closer.Close()
	}
	return fmt.Sprintf("module %s unloaded (%s; library unload is best-effort)", name, strings.Join(entry.verbs, ", ")), nil
}

// List answers the loaded modules and their verbs, one line each -- what
// module.list reports.
func (r *Registry) List() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.modules) == 0 {
		return "no modules loaded"
	}
	lines := make([]string, 0, len(r.modules))
	for _, module := range r.modules {
		lines = append(lines, fmt.Sprintf("%s: %s", module.name, strings.Join(module.verbs, ", ")))
	}
	return strings.Join(lines, "\n")
}

// Dispatch runs one verb on the module that registered it. The second
// return is false when no route holds the verb. The run happens outside the
// table lock: a long module run must not block the registry's reads.
func (r *Registry) Dispatch(verb, arguments string) (wire.TaskOutcome, string, *Artifact, bool) {
	r.mu.Lock()
	held, ok := r.routes[verb]
	r.mu.Unlock()
	if !ok {
		return 0, "", nil, false
	}
	status := held.module.library.Run(held.index, arguments)
	switch status.Kind {
	case RunSucceeded:
		return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, status.Output, status.Artifact, true
	default:
		// Failed carries the module's own cause; Error names the fault
		// in the verb's voice, the same prefix a compiled refusal gets.
		output := status.Output
		if status.Kind == RunError {
			output = fmt.Sprintf("%s: %s", verb, status.Output)
		}
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, output, nil, true
	}
}

// AdvertisedVerbs answers every verb the loaded modules registered -- the
// advertisement widening source, read at every handshake.
func (r *Registry) AdvertisedVerbs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	verbs := make([]string, 0, len(r.routes))
	for verb := range r.routes {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	return verbs
}

// registryName picks the key the routes and module.list report: the
// module's own declared name, with the task's handle honored when the
// module declares none (an empty name would be ununloadable).
func registryName(handle, declared string) string {
	if strings.TrimSpace(declared) == "" {
		return handle
	}
	return declared
}

// validateHandle enforces the module handle grammar: non-empty, 64 bytes at
// most, ASCII letters, digits, dot, dash, underscore.
func validateHandle(handle string) error {
	valid := handle != "" && len(handle) <= 64
	for _, c := range handle {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			valid = false
			break
		}
	}
	if !valid {
		return fmt.Errorf("module.load expects '<name>' (ascii letters, digits, dot, dash, underscore; 64 bytes at most): '%s'", handle)
	}
	return nil
}

// validateVerb enforces the load guards (architecture.md Sec 5.4): the
// namespace grammar and the one domain a module cannot own here -- the
// compiled set. The reference implant also guards the channel machinery;
// this build carries no channel surface, so there is nothing to guard.
func validateVerb(verb string, reserved map[string]bool) error {
	namespace, action, found := strings.Cut(verb, ".")
	if !found || namespace == "" || action == "" {
		return fmt.Errorf("module verb '%s' is not a namespaced verb (namespace.action)", verb)
	}
	if reserved[verb] {
		return fmt.Errorf("module verb '%s' is compiled into this artifact and stays compiled", verb)
	}
	return nil
}

// verifySHA256 checks the staged payload against the hex token the signed
// task carried, case-insensitively.
func verifySHA256(bytes []byte, expected string) error {
	sum := sha256.Sum256(bytes)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("module.load: payload hash mismatch: expected %s, received %s", expected, actual)
	}
	return nil
}
