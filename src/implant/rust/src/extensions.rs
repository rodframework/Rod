//! The build-time extension overlay (architecture.md Sec 5.3, ADR-022):
//! the registry table the rod-rust build unit generates from the build
//! request's extension list. An extension is a package compiled into the
//! artifact -- the implant-native tier, with the implant's own internals
//! in reach -- and this file is the only seam between the two: the build
//! unit stages each extension's sources under
//! `src/extensions/extensions_impl/` and rewrites this file to dispatch
//! its verbs.
//!
//! The default (checked-in) table is empty -- an artifact built with no
//! extensions compiles this file as-is and answers no extension verbs. The
//! build unit's generated replacement carries the same shape: a const verb
//! table the session's advertisement intersects with the baked profile, and
//! a dispatch function handing each verb to its crate.

use crate::handlers::HandlerOutput;

/// The verbs this artifact's compiled-in extensions register. The session
/// widens its advertisement with these beside the compiled core verbs, so
/// the server gates tasking on what the artifact actually carries.
pub const EXTENSION_VERBS: &[&str] = &[];

/// Dispatches one verb to the extension crate that owns it, or None when no
/// extension holds the verb. The compiled table answers first and the
/// runtime plugin table second (architecture.md Sec 5.3): a compiled-in
/// extension outranks everything loadable, exactly the way the core verbs
/// do.
pub fn dispatch(_verb: &str, _arguments: &str) -> Option<HandlerOutput> {
    None
}
