//go:build linux

// The Linux module shape (architecture.md Sec 5.4): the bytes stage in a
// memfd and the loader execs them through the anonymous fd -- the memfd
// carried as the child's inherited descriptor and exec'd by its
// /proc/self/fd path, Go's equivalent of the reference implant's
// execveat(AT_EMPTY_PATH) (os/exec has no pre-exec hook to issue that
// syscall instead). Nothing lands on the filesystem at any step: the
// /proc/self/fd path resolves the anonymous fd, it does not name a file.
// The string grammar rides stdio as length-prefixed frames, one fresh
// process per exchange, so a module that dies cannot take the implant with
// it and the shape carries no libc coupling.
package plugins

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// mfdCloexec is memfd_create's MFD_CLOEXEC flag: the fd closes in every
// child that does not ask for it explicitly.
const mfdCloexec uintptr = 0x0001

// execLibrary is one exec'd module: the memfd holding its bytes. Every
// exchange spawns a fresh process off the fd; the fd dies with the library,
// which is the unload's best-effort other half.
type execLibrary struct {
	file *os.File
}

// loadLibrary stages the bytes in a memfd and defers execution to each
// exchange. The fd is close-on-exec: ordinary children (a shell.exec, say)
// never inherit the module -- only the module child's own dup does.
func loadLibrary(handle string, bytes []byte) (Library, error) {
	fd, err := memfdCreate()
	if err != nil {
		return nil, fmt.Errorf("module.load: memfd_create: %w", err)
	}
	file := os.NewFile(uintptr(fd), "rod-module")
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("module.load: memfd_create: bad descriptor")
	}
	written := 0
	for written < len(bytes) {
		count, err := syscall.Write(fd, bytes[written:])
		if count <= 0 || err != nil {
			file.Close()
			if err == nil {
				err = syscall.EIO
			}
			return nil, fmt.Errorf("module.load: staging the bytes: %w", err)
		}
		written += count
	}
	return &execLibrary{file: file}, nil
}

// Close drops the memfd -- the best-effort unload half.
func (l *execLibrary) Close() { l.file.Close() }

// exchange runs one request/response round over a fresh module process:
// exec the memfd, write the frame, read the answer (payload plus the
// artifact section), reap.
func (l *execLibrary) exchange(op byte, arg uint32, payload []byte) (byte, []byte, *Artifact, error) {
	// The argv names the module, not the /proc path it exec'd; ExtraFiles
	// hands the memfd over as the child's descriptor 3 (0 through 2 are
	// the pipes).
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = []string{"rod-module"}
	cmd.ExtraFiles = []*os.File{l.file}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("exec the staged module: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("exec the staged module: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return 0, nil, nil, fmt.Errorf("exec the staged module: %w", err)
	}
	frame := appendRequest(make([]byte, 0, 9+len(payload)), op, arg, payload)
	if _, err := stdin.Write(frame); err != nil {
		return 0, nil, nil, fmt.Errorf("writing the request: %w", err)
	}
	// Close the input either way: the module answers the request it
	// holds, then exits at the end of stream.
	stdin.Close()
	status, body, artifact, err := readAnswer(stdout)
	if err != nil {
		cmd.Wait()
		return 0, nil, nil, err
	}
	if err := cmd.Wait(); err != nil {
		return 0, nil, nil, fmt.Errorf("the module process failed: %w", err)
	}
	return status, body, artifact, nil
}

func (l *execLibrary) Abi() (uint32, error) {
	status, body, _, err := l.exchange(OpPing, 0, nil)
	switch {
	case err != nil:
		return 0, fmt.Errorf("module.load: the bytes are not a loadable module: %v", err)
	case status != StatusOK:
		return 0, fmt.Errorf("module.load: the module's own ping answered status %d: %s", status, lossyString(body))
	default:
		return uint32(ProtocolVersion), nil
	}
}

func (l *execLibrary) Name() string {
	if _, body, _, err := l.exchange(OpName, 0, nil); err == nil {
		return lossyString(body)
	}
	return ""
}

func (l *execLibrary) VerbCount() uint32 {
	if _, body, _, err := l.exchange(OpCount, 0, nil); err == nil && len(body) == 4 {
		return binary.LittleEndian.Uint32(body)
	}
	return 0
}

func (l *execLibrary) VerbName(index uint32) (string, bool) {
	_, body, _, err := l.exchange(OpVerbName, index, nil)
	if err != nil {
		return "", false
	}
	name := lossyString(body)
	if name == "" {
		return "", false
	}
	return name, true
}

func (l *execLibrary) Run(index uint32, arguments string) RunStatus {
	status, body, artifact, err := l.exchange(OpRun, index, []byte(arguments))
	switch {
	case err != nil:
		return RunStatus{Kind: RunError, Output: fmt.Sprintf("the module process failed: %v", err)}
	case status == StatusOK:
		return RunStatus{Kind: RunSucceeded, Output: lossyString(body), Artifact: artifact}
	case status == StatusFailed:
		return RunStatus{Kind: RunFailed, Output: lossyString(body)}
	case status == StatusBadReq:
		return RunStatus{Kind: RunError, Output: "the module no longer holds that verb index"}
	case status == StatusPanicked:
		return RunStatus{Kind: RunError, Output: fmt.Sprintf("module handler panicked: %s", lossyString(body))}
	default:
		return RunStatus{Kind: RunError, Output: fmt.Sprintf("module answered status %d: %s", status, lossyString(body))}
	}
}

// LoaderCapabilities answers the loader ABIs this build hosts -- the
// handshake advertisement rows the runtime requirement gate reads.
func LoaderCapabilities() []string {
	return []string{"plugin-loader/exec-v1"}
}

// memfdCreate opens one anonymous in-memory file, close-on-exec. The trap
// number is the kernel ABI's per-arch constant (stable since Linux 3.17):
// the stdlib syscall package's frozen constant table predates the call.
func memfdCreate() (int, error) {
	trap := uintptr(0)
	switch runtime.GOARCH {
	case "amd64":
		trap = 319
	case "arm64":
		trap = 279
	case "arm":
		trap = 384
	case "386":
		trap = 385
	default:
		return -1, syscall.ENOSYS
	}
	name := []byte("rod-module\x00")
	fd, _, errno := syscall.Syscall(trap, uintptr(unsafe.Pointer(&name[0])), mfdCloexec, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
