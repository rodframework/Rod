package main

import _ "embed"

// The profile file's compile-time embed (architecture.md Sec 5.1, Sec
// 15.2): rod.profile.json at the module root is the file contract every
// build unit stages -- the same bytes for every language, no per-unit
// parsing. The checked-in stub is empty, so a dev checkout builds and runs
// from ROD_* environment variables; the build unit overwrites the file in
// its staging copy, and the artifact embeds the profile verbatim. An empty
// embed refuses to run, exactly like the Rust reference's unbaked stub.
//
//go:embed rod.profile.json
var Profile string
