#!/usr/bin/env bash
# Regenerates src/implant/go/internal/wire/rodv1.pb.go from the wire
# contract's proto source of truth, src/teamserver/Rod.Protocol/protos/
# rod.proto. The Go tree is the only stack carrying checked-in generated
# wire code: the .NET half compiles the proto at build time (Grpc.Tools)
# and the Rust half at crate build time (prost in build.rs), so this
# script is how the Go copy follows a rod.proto change.
#
# Byte-stable against the checked-in file under the pinned tools:
# protoc 3.19.6 and protoc-gen-go v1.36.11 (the go.mod pin). A run that
# shows a git diff under these versions means the proto itself changed
# -- review the diff as contract surface (docs/extending/implants.md,
# evolution rules).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
protos="$root/src/teamserver/Rod.Protocol/protos"
wire_dir="$root/src/implant/go/internal/wire"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing tool: $1 ($2)" >&2
        exit 1
    }
}
need protoc "the proto compiler; the pinned version is 3.19.6"

# protoc finds the plugin through PATH; when it is not there, the go
# toolchain's own bin directory (go env GOPATH /bin) is the standard
# place `go install` put it.
plugin="$(command -v protoc-gen-go || true)"
if [ -z "$plugin" ]; then
    candidate="$(go env GOPATH 2>/dev/null || echo "$HOME/go")/bin/protoc-gen-go"
    [ -x "$candidate" ] && plugin="$candidate"
fi
if [ -z "$plugin" ]; then
    echo "missing tool: protoc-gen-go (google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11)" >&2
    exit 1
fi
export PATH="$(dirname "$plugin"):$PATH"

echo "protoc $(protoc --version), $(protoc-gen-go --version)"

# Generate into a scratch dir and move the result in, so the wire
# package never momentarily carries both rod.pb.go and rodv1.pb.go.
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

(cd "$protos" && protoc \
    --go_out="$out" \
    --go_opt=paths=source_relative \
    --go_opt=Mrod.proto=rodimplant/internal/wire \
    rod.proto)

mv "$out/rod.pb.go" "$wire_dir/rodv1.pb.go"
echo "regenerated $wire_dir/rodv1.pb.go"
