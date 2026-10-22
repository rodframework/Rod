package main

// The baked-profile stub. The Go build unit overwrites this file in its
// staging copy with the per-artifact profile (architecture.md Sec 5.1):
// base64url JSON, the same keys every build unit emits. The checked-in
// stub stays empty -- an unbaked binary refuses to run, exactly like the
// Rust reference's unbaked stub.
const Profile = ""
