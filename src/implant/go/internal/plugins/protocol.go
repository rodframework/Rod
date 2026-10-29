// Package plugins holds the implant-side module registry and the exec-v1
// loader (architecture.md Sec 5.4): module.load stages a module's bytes, the
// loader turns them into a dispatchable verb table, and the session widens
// its advertisement with the verbs that registered. The stdio protocol here
// is the mirror of the Rust plugin-sdk's protocol module -- the two hosts
// share the contract, not a dependency.
package plugins

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// ProtocolVersion is the stdio protocol this build speaks; version 2 added
// the artifact section every response frame carries after its payload.
const ProtocolVersion byte = 2

// MaxPayload bounds every length-prefixed field of an exchange: request
// payloads, response payloads, and each artifact section field alike.
const MaxPayload = 64 << 20

// The request frame's operation byte.
const (
	OpPing     byte = 0
	OpName     byte = 1
	OpCount    byte = 2
	OpVerbName byte = 3
	OpRun      byte = 4
)

// The response frame's status byte.
const (
	StatusOK       byte = 0
	StatusFailed   byte = 1
	StatusBadReq   byte = 2
	StatusPanicked byte = 3
)

// appendRequest renders one request frame: the op, the u32 argument, and the
// length-prefixed payload, all little-endian -- nine header bytes before the
// payload bytes.
func appendRequest(frame []byte, op byte, arg uint32, payload []byte) []byte {
	var head [9]byte
	head[0] = op
	binary.LittleEndian.PutUint32(head[1:5], arg)
	binary.LittleEndian.PutUint32(head[5:9], uint32(len(payload)))
	frame = append(frame, head[:]...)
	return append(frame, payload...)
}

// readAnswer reads one response frame: the six-byte header (version, status,
// little-endian length), the payload, and the artifact section that follows
// every protocol 2 answer.
func readAnswer(r io.Reader) (status byte, body []byte, artifact *Artifact, err error) {
	var head [6]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, nil, fmt.Errorf("the module did not answer the protocol: %w", err)
	}
	if head[0] != ProtocolVersion {
		return 0, nil, nil, fmt.Errorf("module speaks protocol %d and this build speaks %d", head[0], ProtocolVersion)
	}
	size := binary.LittleEndian.Uint32(head[2:6])
	if size > MaxPayload {
		return 0, nil, nil, fmt.Errorf("the module's %d-byte answer exceeds the exchange budget", size)
	}
	body = make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, nil, fmt.Errorf("the module's answer ended early: %w", err)
	}
	artifact, err = readArtifactSection(r)
	if err != nil {
		return 0, nil, nil, err
	}
	return head[1], body, artifact, nil
}

// readArtifactSection reads the artifact run every protocol 2 response
// carries after its payload: three length-prefixed fields (name, content
// type, bytes), a zero name length marking the absent run.
func readArtifactSection(r io.Reader) (*Artifact, error) {
	section := func(budget string) ([]byte, error) {
		var len [4]byte
		if _, err := io.ReadFull(r, len[:]); err != nil {
			return nil, fmt.Errorf("the module's artifact section ended early: %w", err)
		}
		size := binary.LittleEndian.Uint32(len[:])
		if size > MaxPayload {
			return nil, fmt.Errorf("the module's artifact %s exceeds the exchange budget", budget)
		}
		field := make([]byte, size)
		if _, err := io.ReadFull(r, field); err != nil {
			return nil, fmt.Errorf("the module's artifact section ended early: %w", err)
		}
		return field, nil
	}
	name, err := section("name")
	if err != nil {
		return nil, err
	}
	if len(name) == 0 {
		return nil, nil
	}
	contentType, err := section("content type")
	if err != nil {
		return nil, err
	}
	data, err := section("bytes")
	if err != nil {
		return nil, err
	}
	return &Artifact{
		Name:        lossyString(name),
		ContentType: lossyString(contentType),
		Data:        data,
	}, nil
}

// lossyString renders module-supplied text the way the protocol treats it:
// invalid UTF-8 becomes replacement characters, never a failure.
func lossyString(bytes []byte) string {
	return strings.ToValidUTF8(string(bytes), "\uFFFD")
}
