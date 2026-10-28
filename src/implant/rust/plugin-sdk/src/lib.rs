//! The authoring surface for Rod implant-side plugin modules
//! (architecture.md Sec 5.4). A module is normal Rust code against one
//! trait: implement [`Plugin`], register [`macro@rod_plugin`] for the
//! Windows cdylib shape (the extern "C" shims the manual PE map
//! resolves), and call [`serve`] from a `main` for the Linux executable
//! shape (the stdio loop the loader execs). One source, two artifacts.
//!
//! The seam's whole contract is the task grammar's own -- a verb name and
//! an opaque argument string in, an outcome and an output string back,
//! and since ABI 2 an optional artifact out ([`VerbOutput`]: a named,
//! typed byte run the session uploads through the exfil arm exactly like
//! a compiled handler's) -- so a module verb reads on the operator
//! console exactly like a compiled one. The domain is the stateless long
//! tail; a plugin cannot own a live channel or a carriage, and the
//! loader refuses verbs the artifact already compiles.
//!
//! # Writing a module
//!
//! (The example is `ignore`-marked only because this host's rustdoc pairs
//! with a mismatched rustc build; `tests/shims.rs` compiles and runs the
//! same code.)
//!
//! ```ignore
//! use rod_plugin_sdk::{rod_plugin, Plugin, Verb, VerbOutput};
//!
//! pub struct HostEnum;
//!
//! impl Plugin for HostEnum {
//!     fn name(&self) -> &'static str {
//!         "hostenum"
//!     }
//!     fn verbs(&self) -> Vec<Verb> {
//!         vec![
//!             Verb::new("recon.hostenum", hostenum),
//!             Verb::with_artifact("collect.dumpline", dumpline),
//!         ]
//!     }
//! }
//!
//! fn hostenum(arguments: &str) -> Result<String, String> {
//!     // One JSON finding per line, the recon output grammar the topology
//!     // view parses (extending/tradecraft.md).
//!     Ok(format!("{{\"host\":\"{arguments}\"}}"))
//! }
//!
//! fn dumpline(arguments: &str) -> Result<VerbOutput, String> {
//!     Ok(VerbOutput::artifact(
//!         "dump.bin",
//!         "application/octet-stream",
//!         arguments.as_bytes().to_vec(),
//!         "collected the dump",
//!     ))
//! }
//!
//! rod_plugin!(HostEnum);
//! ```
//!
//! One module source builds both delivery shapes. The Windows cdylib:
//! `crate-type = ["cdylib"]` plus `rod_plugin!`. The Linux executable:
//! a `[[bin]]` whose `main` calls [`serve`] over the same plugin (the
//! lib target needs `crate-type = ["cdylib", "rlib"]` so the bin can
//! link it) -- build it against a musl triple for a static module that
//! runs from any artifact. Deliver the artifact's bytes as a
//! `module.load` task's content either way. Panics are fenced: the
//! Windows shim catches and reports; on Linux the process edge is the
//! fence, and an aborted module merely reads as a dead child.

/// The C-ABI version this SDK speaks. The loader refuses a module whose
/// `rod_plugin_abi` answer it does not recognize, whole and named, so an
/// ABI change is a version bump here and a matching loader, never a
/// silent mismatch.
///
/// ABI 2 adds the artifact return: `rod_plugin_run` grows a
/// [`RodArtifact`] out parameter and the stdio response frame grows its
/// artifact section. A module built against ABI 1 is refused by a
/// loader that speaks 2, whole and named.
pub const ABI_VERSION: u32 = 2;

pub mod protocol;

/// A length-delimited byte string crossing the C ABI. Not a NUL-terminated
/// C string: the task grammar's arguments and outputs are opaque bytes and
/// cannot ride one.
///
/// Allocation discipline: a `RodStr` a module returns is module memory,
/// and the host returns it through the `rod_plugin_free` export the macro
/// emits -- the host never frees module memory itself.
#[repr(C)]
pub struct RodStr {
    /// The first byte. Read-only when the host built the string (a verb's
    /// arguments); owned when the module built it (a name or output).
    pub ptr: *mut u8,
    /// The byte count.
    pub len: usize,
}

impl RodStr {
    /// The empty string, the shape a shim returns when it has nothing to
    /// say (an out-of-range index, a caught panic).
    pub fn empty() -> RodStr {
        RodStr {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Borrows a slice as a read-only argument string. The host builds
    /// these; a module only reads them.
    pub fn from_slice(bytes: &[u8]) -> RodStr {
        RodStr {
            ptr: bytes.as_ptr() as *mut u8,
            len: bytes.len(),
        }
    }

    /// Copies a string into freshly allocated module memory, the shape the
    /// name and output shims return and the host frees through
    /// `rod_plugin_free`.
    pub fn to_owned_str(text: &str) -> RodStr {
        let bytes: Vec<u8> = text.as_bytes().to_vec();
        RodStr::from_vec(bytes)
    }

    /// Takes ownership of a vector, keeping its allocation as the string's
    /// storage.
    pub fn from_vec(bytes: Vec<u8>) -> RodStr {
        let len = bytes.len();
        let ptr = bytes.as_ptr() as *mut u8;
        std::mem::forget(bytes);
        RodStr { ptr, len }
    }

    /// The string as a byte slice, if the pointer/length pair is valid.
    ///
    /// # Safety
    /// The caller must only read strings the pointer of which it received
    /// from the other side of the boundary and not retain the slice past
    /// the free.
    pub unsafe fn as_slice(&self) -> Option<&[u8]> {
        if self.ptr.is_null() {
            return if self.len == 0 { Some(&[][..]) } else { None };
        }
        Some(unsafe { std::slice::from_raw_parts(self.ptr, self.len) })
    }
}

/// A run's optional artifact as it crosses the C ABI: three module-owned
/// strings the host copies out and returns through `rod_plugin_free`.
/// The shape ABI 2 adds to `rod_plugin_run`; a null `name` pointer is the
/// absent artifact, the only null the shape emits.
#[repr(C)]
pub struct RodArtifact {
    /// The artifact's logical name (a filename the operator reads).
    pub name: RodStr,
    /// The MIME hint (the panel routing the type names).
    pub content_type: RodStr,
    /// The bytes themselves.
    pub data: RodStr,
}

impl RodArtifact {
    /// The absent artifact: a null name is the marker the host reads.
    pub fn none() -> RodArtifact {
        RodArtifact {
            name: RodStr::empty(),
            content_type: RodStr::empty(),
            data: RodStr::empty(),
        }
    }
}

/// One artifact a verb returns: the logical name, the MIME hint, and the
/// bytes -- the same triple a compiled handler's artifact run carries,
/// handed to the session's upload arm as-is.
pub struct VerbArtifact {
    pub name: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

/// A verb run's whole answer: the output text the task transcript reads,
/// plus the optional artifact the session uploads. Builders keep the
/// common shapes one line ([`VerbOutput::text`],
/// [`VerbOutput::artifact`]).
pub struct VerbOutput {
    pub text: String,
    pub artifact: Option<VerbArtifact>,
}

impl VerbOutput {
    /// A text-only answer, the shape every ABI 1 verb spoke.
    pub fn text<S: Into<String>>(text: S) -> VerbOutput {
        VerbOutput {
            text: text.into(),
            artifact: None,
        }
    }

    /// An artifact answer: the run's byte upload plus the line the
    /// transcript reads beside it.
    pub fn artifact<N: Into<String>, C: Into<String>>(
        name: N,
        content_type: C,
        data: Vec<u8>,
        text: &str,
    ) -> VerbOutput {
        VerbOutput {
            text: text.to_string(),
            artifact: Some(VerbArtifact {
                name: name.into(),
                content_type: content_type.into(),
                data,
            }),
        }
    }
}

impl From<String> for VerbOutput {
    fn from(text: String) -> VerbOutput {
        VerbOutput::text(text)
    }
}

impl From<&str> for VerbOutput {
    fn from(text: &str) -> VerbOutput {
        VerbOutput::text(text)
    }
}

/// The text-only handler shape: the opaque argument string in, the output
/// string out. `Ok` is success, `Err` carries the failure the operator
/// reads on the task -- the same shape the compiled handlers speak.
pub type VerbFn = fn(&str) -> Result<String, String>;

/// The artifact-capable handler shape (ABI 2): the same grammar with
/// [`VerbOutput`] out, so a module can hand the session a byte run the
/// exfil arm uploads. Register with [`Verb::with_artifact`].
pub type ArtifactFn = fn(&str) -> Result<VerbOutput, String>;

/// A verb's handler as a callable the panic fences capture: an enum of
/// the two fn-pointer shapes, `Copy` and unwind-safe by construction.
/// [`Verb::handler`] hands it out; the shims and `serve` fence a call to
/// it rather than fencing the table.
#[derive(Clone, Copy)]
pub enum HandlerCall {
    Text(VerbFn),
    Artifact(ArtifactFn),
}

impl HandlerCall {
    /// Runs the handler over the argument string, flattening the text
    /// shape onto [`VerbOutput`] so both shapes answer one type.
    pub fn run(&self, arguments: &str) -> Result<VerbOutput, String> {
        match self {
            HandlerCall::Text(run) => run(arguments).map(VerbOutput::text),
            HandlerCall::Artifact(run) => run(arguments),
        }
    }
}

enum Handler {
    Text(VerbFn),
    Artifact(ArtifactFn),
}

/// A verb registration: its namespaced name and its handler -- the plain
/// string shape ([`Verb::new`]) or the artifact-capable one
/// ([`Verb::with_artifact`]). Both ride the same table, the same ABI, and
/// the same wire.
pub struct Verb {
    /// The verb, `namespace.action` -- the grammar every Rod verb
    /// follows. The loader refuses a name without a namespace.
    pub name: &'static str,
    run: Handler,
}

impl Verb {
    pub fn new(name: &'static str, run: VerbFn) -> Verb {
        Verb {
            name,
            run: Handler::Text(run),
        }
    }

    pub fn with_artifact(name: &'static str, run: ArtifactFn) -> Verb {
        Verb {
            name,
            run: Handler::Artifact(run),
        }
    }

    /// The handler as the callable the fences capture. Public because
    /// [`macro@rod_plugin`] expands in the module's crate, not here.
    pub fn handler(&self) -> HandlerCall {
        match &self.run {
            Handler::Text(run) => HandlerCall::Text(*run),
            Handler::Artifact(run) => HandlerCall::Artifact(*run),
        }
    }
}

/// A plugin module: a name and the verbs it brings. One implementation
/// per module, handed to [`macro@rod_plugin`] (the Windows shape) and
/// [`serve`] (the Linux shape).
pub trait Plugin {
    /// The module's self-declared name. Short and lowercase -- it is the
    /// handle `module.list` reports and `module.unload` retracts.
    fn name(&self) -> &'static str;

    /// The verbs this module registers. Collected once, at init.
    fn verbs(&self) -> Vec<Verb>;
}

/// The Linux module shape's entry point (architecture.md Sec 5.4): answer
/// the loader's stdio protocol until stdin ends. A module's `main` is
/// exactly `rod_plugin_sdk::serve(MyPlugin);` -- the loop holds the verb
/// table, fences panics (a panicking handler answers a `PANICKED`
/// status rather than dying mid-frame), and keeps the process
/// exchange-per-request so the host can exec a fresh process per verb
/// dispatch.
pub fn serve<P: Plugin>(plugin: P) {
    let verbs = plugin.verbs();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    while let Some(request) = protocol::read_request(&mut input) {
        let response = answer(&plugin, &verbs, request);
        if protocol::write_response(&mut output, response.0, &response.1, response.2.as_ref())
            .is_err()
        {
            return; // the host went away; nothing to serve
        }
    }
}

// One request to one (status, payload, artifact) triple. Everything the
// loader can ask -- liveness, the name, the table, a run -- answers
// through here, so the loop above stays transport and this stays
// semantics.
fn answer<P: Plugin>(
    plugin: &P,
    verbs: &[Verb],
    request: protocol::Request,
) -> (u8, Vec<u8>, Option<VerbArtifact>) {
    use protocol::{op, status};
    match request.op {
        op::PING => (status::OK, Vec::new(), None),
        op::NAME => (status::OK, plugin.name().as_bytes().to_vec(), None),
        op::COUNT => (
            status::OK,
            (verbs.len() as u32).to_le_bytes().to_vec(),
            None,
        ),
        op::VERB_NAME => match verbs.get(request.arg as usize) {
            Some(verb) => (status::OK, verb.name.as_bytes().to_vec(), None),
            None => (status::BAD_REQUEST, Vec::new(), None),
        },
        op::RUN => match verbs.get(request.arg as usize) {
            None => (status::BAD_REQUEST, Vec::new(), None),
            Some(verb) => {
                let arguments = String::from_utf8_lossy(&request.payload).into_owned();
                let name = verb.name;
                let call = verb.handler();
                // The panic fence: a handler must not die mid-frame, so the
                // loop answers a PANICKED status instead. An abort build
                // turns this off -- the process edge is the backstop, the
                // host reads a dead child and fails the task. The captured
                // callable is a pair of fn pointers, unwind-safe by
                // construction.
                match std::panic::catch_unwind(move || call.run(&arguments)) {
                    Ok(Ok(output)) => {
                        let VerbOutput { text, artifact } = output;
                        (status::OK, text.into_bytes(), artifact)
                    }
                    Ok(Err(cause)) => (status::FAILED, cause.into_bytes(), None),
                    Err(panic) => {
                        let message = panic
                            .downcast_ref::<&str>()
                            .map(|text| text.to_string())
                            .or_else(|| panic.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "module handler panicked".to_string());
                        (
                            status::PANICKED,
                            format!("{name}: {message}").into_bytes(),
                            None,
                        )
                    }
                }
            }
        },
        _ => (status::BAD_REQUEST, Vec::new(), None),
    }
}

/// Emits the extern "C" shim a Rod loader resolves (architecture.md Sec
/// 5.4): `rod_plugin_abi`, `rod_plugin_name`, `rod_plugin_init`,
/// `rod_plugin_verb_name`, `rod_plugin_run`, and `rod_plugin_free`.
/// Call once per cdylib, at the crate root, naming the [`Plugin`]
/// implementation.
///
/// The verb table is built on init and cached for the process's life --
/// plugin verbs are load-time registrations, not per-call discoveries.
#[macro_export]
macro_rules! rod_plugin {
    ($plugin:ident) => {
        fn __rod_plugin_table() -> Vec<$crate::Verb> {
            let plugin = $plugin;
            plugin.verbs()
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_abi() -> u32 {
            $crate::ABI_VERSION
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_name() -> $crate::RodStr {
            let plugin = $plugin;
            $crate::RodStr::to_owned_str(plugin.name())
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_init() -> u32 {
            let table = __rod_plugin_table();
            let count = table.len() as u32;
            __rod_verbs(Some(table));
            count
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_verb_name(index: u32) -> $crate::RodStr {
            let table = __rod_verbs(None);
            match table.get(index as usize) {
                Some(verb) => $crate::RodStr::to_owned_str(verb.name),
                None => $crate::RodStr::empty(),
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_run(
            index: u32,
            arguments: $crate::RodStr,
            out: &mut $crate::RodStr,
            artifact: &mut $crate::RodArtifact,
        ) -> i32 {
            let table = __rod_verbs(None);
            let Some(verb) = table.get(index as usize) else {
                *out = $crate::RodStr::empty();
                *artifact = $crate::RodArtifact::none();
                return -1;
            };
            let name = verb.name;
            let call = verb.handler();
            // Panic fence: a module handler must never unwind into the
            // host, so the shim catches and reports. The unwind shape is
            // part of the contract -- building with panic = "abort" turns
            // this fence off. The captured callable is a pair of fn
            // pointers, unwind-safe by construction.
            match std::panic::catch_unwind(move || {
                let text = unsafe { arguments.as_slice() }
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                    .unwrap_or_default();
                call.run(&text)
            }) {
                Ok(Ok(output)) => {
                    let $crate::VerbOutput {
                        text,
                        artifact: run,
                    } = output;
                    *out = $crate::RodStr::to_owned_str(&text);
                    match run {
                        None => *artifact = $crate::RodArtifact::none(),
                        Some(run) => {
                            *artifact = $crate::RodArtifact {
                                name: $crate::RodStr::to_owned_str(&run.name),
                                content_type: $crate::RodStr::to_owned_str(&run.content_type),
                                data: $crate::RodStr::from_vec(run.data),
                            };
                        }
                    }
                    0
                }
                Ok(Err(cause)) => {
                    *out = $crate::RodStr::to_owned_str(&cause);
                    *artifact = $crate::RodArtifact::none();
                    1
                }
                Err(panic) => {
                    let message = panic
                        .downcast_ref::<&str>()
                        .map(|text| text.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "module handler panicked".to_string());
                    *out = $crate::RodStr::to_owned_str(&format!(
                        "{name}: module handler panicked: {message}"
                    ));
                    *artifact = $crate::RodArtifact::none();
                    -2
                }
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn rod_plugin_free(ptr: *mut u8, len: usize) {
            if ptr.is_null() {
                return;
            }
            // The allocation discipline's other half: a RodStr this module
            // returned was a leaked Vec, and the free rebuilds and drops
            // it in the allocator that made it.
            unsafe { drop(Vec::from_raw_parts(ptr, len, len)) };
        }

        // The process-lifetime verb table. Init fills it (Some); the
        // per-call shims read it (None). A OnceLock rather than static
        // mut: the loader may call init from any thread it owns.
        fn __rod_verbs(fill: Option<Vec<$crate::Verb>>) -> &'static [$crate::Verb] {
            use std::sync::OnceLock;
            static TABLE: OnceLock<Vec<$crate::Verb>> = OnceLock::new();
            if let Some(fill) = fill {
                let _ = TABLE.set(fill);
            }
            match TABLE.get() {
                Some(table) => table.as_slice(),
                None => &[],
            }
        }
    };
}
