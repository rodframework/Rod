package plugins

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// answerFrame renders one response frame the way a module writes it:
// header, payload, then the artifact section.
func answerFrame(version, status byte, payload []byte, artifact []byte) []byte {
	frame := make([]byte, 0, 6+len(payload)+len(artifact))
	var head [6]byte
	head[0] = version
	head[1] = status
	binary.LittleEndian.PutUint32(head[2:6], uint32(len(payload)))
	frame = append(frame, head[:]...)
	frame = append(frame, payload...)
	return append(frame, artifact...)
}

// artifactSection renders the artifact run's three length-prefixed fields;
// a nil artifact renders the absent run's zero name length.
func artifactSection(name, contentType string, data []byte) []byte {
	field := func(value []byte) []byte {
		var size [4]byte
		binary.LittleEndian.PutUint32(size[:], uint32(len(value)))
		return append(size[:], value...)
	}
	section := field([]byte(name))
	if name == "" {
		return section
	}
	section = append(section, field([]byte(contentType))...)
	return append(section, field(data)...)
}

func TestRequestFrameLayout(t *testing.T) {
	frame := appendRequest(nil, OpRun, 7, []byte("args"))
	if len(frame) != 9+4 {
		t.Fatalf("the frame is nine header bytes plus the payload, got %d", len(frame))
	}
	if frame[0] != OpRun {
		t.Fatal("the first byte is the op")
	}
	if arg := binary.LittleEndian.Uint32(frame[1:5]); arg != 7 {
		t.Fatalf("the u32 argument is little-endian, got %d", arg)
	}
	if size := binary.LittleEndian.Uint32(frame[5:9]); size != 4 {
		t.Fatalf("the payload length is little-endian, got %d", size)
	}
}

func TestReadAnswerParsesFrameAndArtifact(t *testing.T) {
	answer := answerFrame(ProtocolVersion, StatusOK, []byte("ran"),
		artifactSection("conform.bin", "application/octet-stream", []byte{1, 2, 3}))
	status, body, artifact, err := readAnswer(bytes.NewReader(answer))
	if err != nil {
		t.Fatalf("a well-formed answer parses: %v", err)
	}
	if status != StatusOK || string(body) != "ran" {
		t.Fatal("the status and payload round trip")
	}
	if artifact == nil || artifact.Name != "conform.bin" ||
		artifact.ContentType != "application/octet-stream" ||
		!bytes.Equal(artifact.Data, []byte{1, 2, 3}) {
		t.Fatalf("the artifact section round trips, got %+v", artifact)
	}
}

func TestReadAnswerWithoutArtifact(t *testing.T) {
	answer := answerFrame(ProtocolVersion, StatusFailed, []byte("cause"), artifactSection("", "", nil))
	_, _, artifact, err := readAnswer(bytes.NewReader(answer))
	if err != nil {
		t.Fatalf("the absent artifact is the zero name length, not an error: %v", err)
	}
	if artifact != nil {
		t.Fatal("a zero name length marks the absent run")
	}
}

func TestReadAnswerRefusesTheWrongProtocol(t *testing.T) {
	answer := answerFrame(ProtocolVersion, StatusOK, nil, nil)
	answer[0] = 1
	_, _, _, err := readAnswer(bytes.NewReader(answer))
	if err == nil || !strings.Contains(err.Error(), "module speaks protocol 1 and this build speaks 2") {
		t.Fatalf("a foreign protocol version is refused by name, got %v", err)
	}
}

func TestReadAnswerRefusesOverBudgetPayloads(t *testing.T) {
	var head [6]byte
	head[0] = ProtocolVersion
	head[1] = StatusOK
	binary.LittleEndian.PutUint32(head[2:6], MaxPayload+1)
	_, _, _, err := readAnswer(bytes.NewReader(head[:]))
	if err == nil || !strings.Contains(err.Error(), "exceeds the exchange budget") {
		t.Fatalf("an over-budget answer is refused, got %v", err)
	}
}

func TestReadArtifactSectionRefusesOverBudgetFields(t *testing.T) {
	var len [4]byte
	binary.LittleEndian.PutUint32(len[:], MaxPayload+1)
	_, err := readArtifactSection(bytes.NewReader(len[:]))
	if err == nil || !strings.Contains(err.Error(), "the module's artifact name exceeds the exchange budget") {
		t.Fatalf("an over-budget artifact field is refused with the budget named, got %v", err)
	}
}

func TestReadArtifactSectionEndsEarly(t *testing.T) {
	_, err := readArtifactSection(bytes.NewReader([]byte{1, 0, 0}))
	if err == nil || !strings.Contains(err.Error(), "the module's artifact section ended early") {
		t.Fatalf("a truncated section is refused, got %v", err)
	}
}
