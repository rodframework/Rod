package wire

import (
	"bytes"
	"testing"
)

func TestFrameSequenceRoundTrip(t *testing.T) {
	frames := []*Frame{
		{Payload: []byte{}, Kind: FrameKind_FRAME_KIND_UNSPECIFIED},
		{Payload: []byte{0x01, 0x02}, Kind: FrameKind_FRAME_KIND_TASK_RESULT},
		{Payload: bytes.Repeat([]byte{0xaa}, 70000), Kind: FrameKind_FRAME_KIND_EXFIL_CHUNK},
	}
	parsed, err := ParseFrames(EncodeFrames(frames))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != len(frames) {
		t.Fatalf("got %d frames, want %d", len(parsed), len(frames))
	}
	for i := range frames {
		if parsed[i].Kind != frames[i].Kind || !bytes.Equal(parsed[i].Payload, frames[i].Payload) {
			t.Fatalf("frame %d changed across the codec", i)
		}
	}
}

func TestTruncatedBodyIsAWholeFailure(t *testing.T) {
	encoded := EncodeFrames([]*Frame{{Payload: []byte{1, 2, 3}}})
	if _, err := ParseFrames(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("a truncated frame body must fail the whole parse")
	}
	if _, err := ParseFrames([]byte{0x7f}); err == nil {
		t.Fatal("a dangling length prefix must fail the whole parse")
	}
}
