//go:build linux

package plugins

import (
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"

	"rodimplant/internal/wire"
)

// The loader's real-exec tests turn this test binary into the module: the
// loader stages os.Executable()'s bytes in a memfd, execs them, and the
// child -- seeing the same environment -- re-enters TestMain and serves the
// stdio protocol instead of running the tests. ROD_TEST_MODULE picks the
// dialect: "1" speaks protocol 2, "legacy" answers protocol 1.
func TestMain(m *testing.M) {
	dialect := os.Getenv("ROD_TEST_MODULE")
	if dialect == "" {
		os.Exit(m.Run())
	}
	version := ProtocolVersion
	if dialect == "legacy" {
		version = 1
	}
	serveModule(os.Stdin, os.Stdout, version)
	os.Exit(0)
}

// serveModule answers request frames until stdin ends -- the module half of
// the contract the loader under test speaks.
func serveModule(stdin io.Reader, stdout io.Writer, version byte) {
	var head [9]byte
	for {
		if _, err := io.ReadFull(stdin, head[:]); err != nil {
			return
		}
		op := head[0]
		arg := binary.LittleEndian.Uint32(head[1:5])
		size := binary.LittleEndian.Uint32(head[5:9])
		if size > MaxPayload {
			return
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(stdin, payload); err != nil {
			return
		}
		status, body, artifact := moduleAnswer(op, arg, payload)
		stdout.Write(answerFrame(version, status, body, artifact))
	}
}

// moduleAnswer is the fixture's verb table: three verbs covering the three
// run shapes a module can answer -- plain output, artifact return, and a
// failure with a cause.
func moduleAnswer(op byte, arg uint32, payload []byte) (byte, []byte, []byte) {
	status, body, artifact := StatusOK, []byte{}, artifactSection("", "", nil)
	verbs := map[uint32]string{0: "stub.echo", 1: "stub.artifact", 2: "stub.fail"}
	switch op {
	case OpPing:
	case OpName:
		body = []byte("go-test-module")
	case OpCount:
		body = make([]byte, 4)
		binary.LittleEndian.PutUint32(body, 3)
	case OpVerbName:
		if name, ok := verbs[arg]; ok {
			body = []byte(name)
		} else {
			status = StatusBadReq
		}
	case OpRun:
		switch arg {
		case 0:
			body = append([]byte("echo:"), payload...)
		case 1:
			body = []byte("the artifact run")
			artifact = artifactSection("stub.bin", "application/octet-stream", payload)
		case 2:
			status = StatusFailed
			body = []byte("refused by the module")
		default:
			status = StatusBadReq
		}
	default:
		status = StatusBadReq
	}
	return status, body, artifact
}

func selfBytes(t *testing.T) []byte {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatalf("the test binary has no path: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the test binary: %v", err)
	}
	return data
}

func reservedVerbs() []string {
	return []string{"shell.exec", "file.pull", "module.load", "module.unload", "module.list"}
}

func TestExecLoaderLoadsAndRunsAModule(t *testing.T) {
	os.Setenv("ROD_TEST_MODULE", "1")
	t.Cleanup(func() { os.Unsetenv("ROD_TEST_MODULE") })
	bytes := selfBytes(t)

	registry := New(reservedVerbs())
	report, err := registry.Load("gotest", bytes, hexSHA(bytes))
	if err != nil {
		t.Fatalf("the fixture loads through the memfd exec: %v", err)
	}
	want := "module go-test-module loaded: stub.echo, stub.artifact, stub.fail; advertised at the next contact"
	if report != want {
		t.Fatalf("the load report names the module and its verbs:\n got %q\nwant %q", report, want)
	}
	if verbs := registry.AdvertisedVerbs(); strings.Join(verbs, ",") != "stub.artifact,stub.echo,stub.fail" {
		t.Fatalf("the module's verbs advertise, got %v", verbs)
	}

	outcome, output, artifact, ok := registry.Dispatch("stub.echo", "marker")
	if !ok || outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED || output != "echo:marker" || artifact != nil {
		t.Fatalf("the marker verb echoes through a fresh process, got %v %q %v", ok, output, artifact)
	}
	outcome, output, artifact, ok = registry.Dispatch("stub.artifact", "payload-bytes")
	if !ok || outcome != wire.TaskOutcome_TASK_OUTCOME_SUCCEEDED || output != "the artifact run" {
		t.Fatalf("the artifact verb answers, got %v %q", ok, output)
	}
	if artifact == nil || artifact.Name != "stub.bin" ||
		artifact.ContentType != "application/octet-stream" ||
		string(artifact.Data) != "payload-bytes" {
		t.Fatalf("the artifact run returns verbatim, got %+v", artifact)
	}
	outcome, output, _, ok = registry.Dispatch("stub.fail", "ignored")
	if !ok || outcome != wire.TaskOutcome_TASK_OUTCOME_FAILED || output != "refused by the module" {
		t.Fatalf("the module's own failure carries its cause, got %v %q", ok, output)
	}

	unloaded, err := registry.Unload("go-test-module")
	if err != nil || unloaded != "module go-test-module unloaded (stub.echo, stub.artifact, stub.fail; library unload is best-effort)" {
		t.Fatalf("unload retracts the module, got %q %v", unloaded, err)
	}
}

func TestExecLoaderRefusesAForeignProtocol(t *testing.T) {
	os.Setenv("ROD_TEST_MODULE", "legacy")
	t.Cleanup(func() { os.Unsetenv("ROD_TEST_MODULE") })
	bytes := selfBytes(t)

	_, err := New(reservedVerbs()).Load("gotest", bytes, hexSHA(bytes))
	if err == nil || !strings.Contains(err.Error(), "the bytes are not a loadable module") ||
		!strings.Contains(err.Error(), "module speaks protocol 1 and this build speaks 2") {
		t.Fatalf("a module answering another protocol is refused by name, got %v", err)
	}
}

func TestExecLoaderRefusesGarbageBytes(t *testing.T) {
	payload := []byte("these are not a program")
	_, err := New(reservedVerbs()).Load("gotest", payload, hexSHA(payload))
	if err == nil || !strings.Contains(err.Error(), "the bytes are not a loadable module") {
		t.Fatalf("bytes that cannot exec are refused as unloadable, got %v", err)
	}
}
