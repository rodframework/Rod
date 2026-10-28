// The profile file's compile-time embed (architecture.md Sec 5.1, Sec
// 15.2): rod.profile.json at the crate root is the file contract every
// build unit stages -- the same bytes for every language, no per-unit
// parsing. The checked-in stub is empty, so a dev checkout compiles and
// runs from ROD_* environment variables; the build unit overwrites the
// file in its staging copy, and the artifact embeds the profile verbatim.
pub const PROFILE: &str = include_str!("../rod.profile.json");
