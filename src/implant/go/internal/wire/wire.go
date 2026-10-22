// Package wire carries the rod.v1 frames: the generated protobuf messages
// plus the delimited-sequence codec every contact body uses -- one
// uvarint byte length ahead of each serialized Frame, the canonical
// delimited-stream shape every protobuf runtime ships.
package wire

import (
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// EncodeFrames serializes frames as the delimited sequence a contact body
// carries: uvarint(len) || Frame bytes, repeated.
func EncodeFrames(frames []*Frame) []byte {
	var out []byte
	var prefix [binary.MaxVarintLen64]byte
	for _, frame := range frames {
		payload, err := proto.Marshal(frame)
		if err != nil {
			continue
		}
		n := binary.PutUvarint(prefix[:], uint64(len(payload)))
		out = append(out, prefix[:n]...)
		out = append(out, payload...)
	}
	return out
}

// ParseFrames decodes the delimited sequence. A malformed stream is a
// whole-body failure: the caller drops the cycle rather than acting on a
// partial read.
func ParseFrames(body []byte) ([]*Frame, error) {
	var frames []*Frame
	for len(body) > 0 {
		length, n := binary.Uvarint(body)
		if n <= 0 {
			return nil, fmt.Errorf("malformed frame length prefix")
		}
		body = body[n:]
		if uint64(len(body)) < length {
			return nil, fmt.Errorf("truncated frame body")
		}
		var frame Frame
		if err := proto.Unmarshal(body[:length], &frame); err != nil {
			return nil, fmt.Errorf("unparseable frame: %w", err)
		}
		frames = append(frames, &frame)
		body = body[length:]
	}
	return frames, nil
}
