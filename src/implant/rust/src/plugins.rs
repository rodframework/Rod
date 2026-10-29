//! The implant-side plugin seam (architecture.md Sec 5.4): C-ABI capability
//! modules loaded on demand over the staged task channel. The registry
//! here is the implant-side twin of the server's capability registry -- a
//! verb arrives by `module.load`, its routes join the dispatch table, and
//! the advertised set widens so the next contact reports them.
//!
//! The domain is the stateless long tail. Guards hold the line the design
//! draws: a module cannot register a verb the artifact compiles (the
//! compiled arm would shadow it forever) nor a channel verb (a plugin
//! cannot own a live channel or a carriage), and verb names must follow
//! the `namespace.action` grammar every Rod verb follows.
//!
//! The loader shapes are the design's loading contracts (architecture.md
//! Sec 5.4): Linux stages the bytes in a memfd and execs the module
//! through `/proc/self/fd` -- the loader tier's own mechanism -- one
//! process per verb dispatch over a stdio protocol, uniform across
//! static musl and dynamic builds alike; Windows maps the PE by hand
//! and, beside it, loads COFF objects -- the BOF corpus's coff-v1
//! shape, a Beacon-compatible host table standing in for imports. macOS
//! and the android leg keep the family compiled but dormant: neither
//! floor carries the anonymous-fd exec the memfd shape is. The registry
//! itself is platform-blind behind the Library trait.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::channel;
use crate::handlers::{self, ArtifactRun, HandlerOutput, Outcome};

/// The module ABI version the loader speaks; the mirror of
/// `rod_plugin_sdk::ABI_VERSION` (the Windows extern family) and of its
/// `PROTOCOL_VERSION` (the Linux stdio frames) -- one number, two shapes.
/// The crates share the contract, not a dependency: the implant defines
/// its own copy the way every implant language would.
///
/// ABI 2 adds the artifact return: `rod_plugin_run` grows its artifact out
/// parameter and the stdio response frame grows its artifact section, so
/// a module verb can hand the session a byte run the exfil arm uploads
/// exactly like a compiled handler's.
const ABI_VERSION: u32 = 2;

/// A length-delimited byte string as it crosses the Windows boundary --
/// the shape `rod-plugin-sdk`'s `RodStr` defines. Not NUL-terminated: task
/// arguments are opaque bytes and cannot ride a C string. The Linux
/// protocol frames carry the same bytes length-prefixed instead.
#[cfg(windows)]
#[repr(C)]
struct AbiStr {
    ptr: *mut u8,
    len: usize,
}

#[cfg(windows)]
impl AbiStr {
    fn empty() -> AbiStr {
        AbiStr {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }

    fn from_slice(bytes: &[u8]) -> AbiStr {
        AbiStr {
            ptr: bytes.as_ptr() as *mut u8,
            len: bytes.len(),
        }
    }

    /// The string as lossy text, for copying out before the free. A null
    /// pointer is the empty string -- the only null the SDK's shapes emit.
    unsafe fn as_text(&self) -> String {
        if self.ptr.is_null() || self.len == 0 {
            return String::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// The buffer's raw bytes, for the artifact data's own copy-out --
    /// bytes cannot ride the lossy text reader.
    unsafe fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// One run's outcome as the shim reports it: success or failure with the
/// module's output string -- success carrying the optional artifact run
/// the session uploads (ABI 2) -- or a shim error (an unknown index, a
/// fenced panic) carrying the cause. Only the platform loaders construct
/// these; the dormant seams' refusals never do (the cfg_attr silences the
/// dead-code lint there alone).
#[cfg_attr(any(target_os = "android", target_os = "macos"), allow(dead_code))]
enum RunStatus {
    Succeeded(String, Option<ArtifactRun>),
    Failed(String),
    Error(String),
}

/// One loaded module's library half: the platform handle behind the entry
/// family. A trait, not a struct, so the registry's guards and dispatch
/// are unit-testable without a dynamic loader in the loop.
trait Library: Send {
    /// The ABI version the module reports, or the cause it could not
    /// answer (bytes that are not a module, a dead process, a protocol
    /// mismatch). A loader that does not recognize the version refuses
    /// the module whole.
    fn abi(&self) -> Result<u32, String>;

    /// The module's self-declared name.
    fn name(&self) -> String;

    /// Construct the verb table and answer its size. Called once, at load.
    fn verb_count(&self) -> u32;

    /// The verb name at an index, or None past the table's end.
    fn verb_name(&self, index: u32) -> Option<String>;

    /// Execute one verb under the shared string grammar.
    fn run(&self, index: u32, arguments: &str) -> RunStatus;
}

/// A registered route: the module that owns the verb and its index in the
/// module's table. Last registration wins -- a later module's route for a
/// verb replaces the earlier one's.
pub(crate) struct Route {
    module: Arc<ModuleEntry>,
    index: u32,
}

pub(crate) struct ModuleEntry {
    name: String,
    verbs: Vec<String>,
    library: Mutex<Option<Box<dyn Library>>>,
}

impl ModuleEntry {
    fn new(name: String, verbs: Vec<String>, library: Box<dyn Library>) -> ModuleEntry {
        ModuleEntry {
            name,
            verbs,
            library: Mutex::new(Some(library)),
        }
    }

    /// The crate's test seam: an entry over a stub library that answers
    /// every run with the verb's name. Session-layer tests install one to
    /// pin the advertisement widening without a platform loader.
    #[cfg(test)]
    pub(crate) fn new_for_test(name: &str, verbs: &[&str]) -> ModuleEntry {
        struct StubLibrary {
            name: &'static str,
        }
        impl Library for StubLibrary {
            fn abi(&self) -> Result<u32, String> {
                Ok(ABI_VERSION)
            }
            fn name(&self) -> String {
                self.name.into()
            }
            fn verb_count(&self) -> u32 {
                0
            }
            fn verb_name(&self, _index: u32) -> Option<String> {
                None
            }
            fn run(&self, _index: u32, _arguments: &str) -> RunStatus {
                RunStatus::Succeeded("stub".into(), None)
            }
        }
        ModuleEntry::new(
            name.into(),
            verbs.iter().map(|verb| verb.to_string()).collect(),
            Box::new(StubLibrary {
                name: Box::leak(name.to_string().into_boxed_str()),
            }),
        )
    }
}

impl Drop for ModuleEntry {
    fn drop(&mut self) {
        // Best-effort made exact where it can be: the library dies when
        // the last Arc goes away, so a dispatch still running keeps its
        // module alive and the unload lands the moment it ends.
        drop(self.library.get_mut().expect("library lock").take());
    }
}

/// The run's plugin table: the loaded modules and the verb routes they
/// registered. One instance lives in the session and survives every
/// reconnect and walk step, the way the cadence does -- but not a process
/// restart: registrations are run-state, and a restarted implant
/// re-advertises without them (the operator re-loads what is still
/// needed).
pub struct Plugins {
    inner: Mutex<Inner>,
}

struct Inner {
    modules: Vec<Arc<ModuleEntry>>,
    routes: HashMap<String, Route>,
}

impl Plugins {
    pub fn new() -> Plugins {
        Plugins {
            inner: Mutex::new(Inner {
                modules: Vec::new(),
                routes: HashMap::new(),
            }),
        }
    }

    /// Loads one module: verifies the handle and the staged payload's
    /// integrity, asks the platform loader for a library, checks the ABI,
    /// reads the verb table, and registers the routes the guards admit.
    /// Answers the load report the operator reads on the task.
    pub fn load(
        &self,
        handle: &str,
        bytes: &[u8],
        expected_sha256: &str,
    ) -> Result<String, String> {
        validate_handle(handle)?;
        verify_sha256(bytes, expected_sha256)?;
        let library = load_library(handle, bytes)?;
        let reported = library.abi()?;
        if reported != ABI_VERSION {
            return Err(format!(
                "module reports ABI {reported} and this build loads {ABI_VERSION}"
            ));
        }
        let declared = library.name();
        let name = registry_name(handle, &declared);
        let count = library.verb_count();
        let mut verbs = Vec::new();
        for index in 0..count {
            let verb = library
                .verb_name(index)
                .ok_or_else(|| format!("module did not name verb {index}"))?;
            validate_verb(&verb)?;
            verbs.push(verb);
        }
        if verbs.is_empty() {
            return Err(format!("module {name} registers no verbs"));
        }
        let entry = Arc::new(ModuleEntry::new(name, verbs.clone(), library));

        let mut inner = self.inner.lock().expect("plugin table");
        // A same-name load replaces the module it names: its routes drop
        // with it, and any verb the new module does not carry stops
        // routing -- the honest answer to "load the fixed version".
        inner.modules.retain(|held| held.name != entry.name);
        inner.modules.push(Arc::clone(&entry));
        for (index, verb) in verbs.iter().enumerate() {
            inner.routes.insert(
                verb.clone(),
                Route {
                    module: Arc::clone(&entry),
                    index: index as u32,
                },
            );
        }
        Ok(format!(
            "module {} loaded: {}; advertised at the next contact",
            entry.name,
            verbs.join(", ")
        ))
    }

    /// Retracts one module -- best-effort by construction: the routes drop
    /// immediately, and the library dies when the last dispatch holding it
    /// ends (a handler mid-execution finishes).
    pub fn unload(&self, name: &str) -> Result<String, String> {
        let mut inner = self.inner.lock().expect("plugin table");
        let Some(position) = inner.modules.iter().position(|held| held.name == name) else {
            return Err(format!("module.load has no module named {name}"));
        };
        let entry = inner.modules.remove(position);
        inner
            .routes
            .retain(|_, route| !Arc::ptr_eq(&route.module, &entry));
        Ok(format!(
            "module {name} unloaded ({}; library unload is best-effort)",
            entry.verbs.join(", ")
        ))
    }

    /// The loaded modules and their verbs, one line each -- what
    /// `module.list` reports.
    pub fn list(&self) -> String {
        let inner = self.inner.lock().expect("plugin table");
        if inner.modules.is_empty() {
            return "no modules loaded".into();
        }
        let mut lines = Vec::new();
        for module in &inner.modules {
            lines.push(format!("{}: {}", module.name, module.verbs.join(", ")));
        }
        lines.join("\n")
    }

    /// Dispatches one verb to the module that registered it, or None when
    /// no route holds the verb. Runs outside the table lock: a long
    /// handler must not block the registry's own reads, and the Arc keeps
    /// the module alive for the run's duration however the table mutates.
    /// The answer is the same HandlerOutput a compiled handler produces,
    /// artifact run included.
    pub fn dispatch(&self, verb: &str, arguments: &str) -> Option<HandlerOutput> {
        let (module, index) = {
            let inner = self.inner.lock().expect("plugin table");
            inner
                .routes
                .get(verb)
                .map(|route| (Arc::clone(&route.module), route.index))?
        };
        let guard = module.library.lock().expect("library lock");
        let library = guard.as_ref()?;
        Some(match library.run(index, arguments) {
            RunStatus::Succeeded(output, artifact) => HandlerOutput {
                outcome: Outcome::Succeeded,
                output,
                artifact,
            },
            RunStatus::Failed(output) => HandlerOutput {
                outcome: Outcome::Failed,
                output,
                artifact: None,
            },
            RunStatus::Error(cause) => HandlerOutput::fail(format!("{verb}: {cause}")),
        })
    }

    /// Every verb the loaded modules registered -- the advertisement
    /// widening source, read after each load.
    pub fn advertised_verbs(&self) -> Vec<String> {
        let inner = self.inner.lock().expect("plugin table");
        inner.routes.keys().cloned().collect()
    }

    /// The registry's test seam: installs an entry the guards would admit,
    /// the in-process equivalent of a `module.load` the platform loader
    /// performed.
    #[cfg(test)]
    pub(crate) fn install(&self, entry: ModuleEntry) {
        let name = entry.name.clone();
        let verbs = entry.verbs.clone();
        let entry = Arc::new(entry);
        let mut inner = self.inner.lock().expect("plugin table");
        inner.modules.retain(|held| held.name != name);
        inner.modules.push(Arc::clone(&entry));
        for (index, verb) in verbs.iter().enumerate() {
            inner.routes.insert(
                verb.clone(),
                Route {
                    module: Arc::clone(&entry),
                    index: index as u32,
                },
            );
        }
    }
}

// The registry key the routes and module.list report: the module's own
// declared name, with the task's handle honored when the module declares
// none (an empty name would be ununloadable).
fn registry_name(handle: &str, declared: &str) -> String {
    if declared.trim().is_empty() {
        handle.to_string()
    } else {
        declared.to_string()
    }
}

fn validate_handle(handle: &str) -> Result<(), String> {
    let valid = !handle.is_empty()
        && handle.len() <= 64
        && handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "module.load expects '<name>' (ascii letters, digits, dot, dash, underscore; 64 bytes at most): '{handle}'"
        ))
    }
}

/// The load guards (architecture.md Sec 5.4): the namespace grammar, and
/// the two domains a module cannot own -- the compiled set and the
/// channel machinery.
fn validate_verb(verb: &str) -> Result<(), String> {
    let Some((namespace, action)) = verb.split_once('.') else {
        return Err(format!(
            "module verb '{verb}' is not a namespaced verb (namespace.action)"
        ));
    };
    if namespace.is_empty() || action.is_empty() {
        return Err(format!(
            "module verb '{verb}' is not a namespaced verb (namespace.action)"
        ));
    }
    if channel::is_channel_verb(verb) {
        return Err(format!(
            "module verb '{verb}' is a channel verb: a plugin cannot own a live channel"
        ));
    }
    if handlers::COMPILED_VERBS.contains(&verb) {
        return Err(format!(
            "module verb '{verb}' is compiled into this artifact and stays compiled"
        ));
    }
    Ok(())
}

fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(format!(
            "module.load: payload hash mismatch: expected {expected}, received {actual}"
        ))
    }
}

// --- The platform loaders ---------------------------------------------------

#[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
fn load_library(_handle: &str, bytes: &[u8]) -> Result<Box<dyn Library>, String> {
    executed::ExecLibrary::load(bytes)
}

// Two floors keep the module family compiled-but-dormant (architecture.md
// Sec 12.2): the android leg -- bionic below API 30 carries no
// memfd_create symbol to link against, and the untrusted_app SELinux
// domain denies exec of anonymous fds -- and macOS, whose kernel carries
// neither memfd_create nor an exec-from-fd path to stage bytes on. The
// seam refuses with the fact rather than failing at load or linking an
// artifact that cannot open on the floor the leg targets.
#[cfg(any(target_os = "android", target_os = "macos"))]
fn load_library(_handle: &str, _bytes: &[u8]) -> Result<Box<dyn Library>, String> {
    #[cfg(target_os = "android")]
    const FLOOR: &str = "the Android leg (no anonymous-fd exec under the app domain)";
    #[cfg(target_os = "macos")]
    const FLOOR: &str = "the macOS leg (no anonymous-fd exec on the kernel)";

    Err(format!(
        "module.load: the module family is dormant on {FLOOR}"
    ))
}

// The format picks the loader on the Windows floor: a PE announces
// itself with MZ, and everything else reaches for the COFF object
// loader, whose parse refuses what it cannot bind by name. The handle
// rides along for the loaders that name their verbs from it.
#[cfg(windows)]
fn load_library(handle: &str, bytes: &[u8]) -> Result<Box<dyn Library>, String> {
    if bytes.starts_with(b"MZ") {
        pe::PeLibrary::load(bytes)
    } else {
        coff::CoffLibrary::load(handle, bytes)
    }
}

// --- Linux: the memfd + exec loader -------------------------------------------

#[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
mod executed {
    //! The Linux module shape (architecture.md Sec 5.4): the bytes stage in
    //! a memfd and the loader execs them through the anonymous fd --
    //! `execveat(AT_EMPTY_PATH)`, the loader tier's own syscall (Sec 6), no
    //! `/proc` path in sight -- with the string grammar spoken over stdio
    //! as length-prefixed request/response frames. One process per
    //! exchange; a verb dispatch is a fresh child, so a module that dies
    //! cannot take the implant with it, and the shape carries no libc
    //! coupling: the static musl artifact loads modules exactly like any
    //! other.

    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::{ArtifactRun, Library, RunStatus};

    /// The protocol's version and operations, the mirror of
    /// rod-plugin-sdk's `protocol` module: the crates share the contract,
    /// not a dependency. Protocol 2 adds the artifact section every
    /// response frame carries after its payload.
    const PROTOCOL_VERSION: u8 = 2;
    const MAX_PAYLOAD: u32 = 64 << 20;

    mod op {
        pub const PING: u8 = 0;
        pub const NAME: u8 = 1;
        pub const COUNT: u8 = 2;
        pub const VERB_NAME: u8 = 3;
        pub const RUN: u8 = 4;
    }

    mod status {
        pub const OK: u8 = 0;
        pub const FAILED: u8 = 1;
        pub const BAD_REQUEST: u8 = 2;
        pub const PANICKED: u8 = 3;
    }

    /// One exec'd module: the memfd holding its bytes. Every exchange
    /// spawns a fresh process off the fd; the fd dies with the library,
    /// which is the unload's best-effort other half.
    pub struct ExecLibrary {
        fd: i32,
    }

    // The fd is a plain kernel handle; spawning children from it is
    // thread-safe.
    unsafe impl Send for ExecLibrary {}

    impl ExecLibrary {
        /// Stages the bytes in a memfd -- nothing lands on the filesystem
        /// at any step -- and defers execution to each exchange. The fd is
        /// close-on-exec: the exec that consumes it is `execveat` itself,
        /// and no other child (a shell.exec, say) inherits the module.
        pub fn load(bytes: &[u8]) -> Result<Box<dyn Library>, String> {
            let name = c"rod-module";
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            if fd < 0 {
                return Err(format!(
                    "module.load: memfd_create: errno {}",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                ));
            }
            let mut written = 0usize;
            while written < bytes.len() {
                let count = unsafe {
                    libc::write(
                        fd,
                        bytes[written..].as_ptr() as *const libc::c_void,
                        bytes.len() - written,
                    )
                };
                if count <= 0 {
                    unsafe { libc::close(fd) };
                    return Err(format!(
                        "module.load: staging the bytes: errno {}",
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                    ));
                }
                written += count as usize;
            }
            Ok(Box::new(ExecLibrary { fd }))
        }

        /// One request/response exchange over a fresh process: exec the
        /// memfd, write the frame, read the answer (payload plus the
        /// artifact section protocol 2 appends to every response), reap.
        fn exchange(
            &self,
            op: u8,
            arg: u32,
            payload: &[u8],
        ) -> Result<(u8, Vec<u8>, Option<ArtifactRun>), String> {
            let mut child = self
                .spawn_module()
                .map_err(|err| format!("execveat the staged module: {err}"))?;

            let mut frame = Vec::with_capacity(9 + payload.len());
            frame.push(op);
            frame.extend_from_slice(&arg.to_le_bytes());
            frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            frame.extend_from_slice(payload);
            let Some(mut stdin) = child.stdin.take() else {
                return Err("the module process took no stdin".into());
            };
            let write = stdin.write_all(&frame).and_then(|()| stdin.flush());
            // Close the input either way: serve() answers the request it
            // holds, then exits at the end of stream.
            drop(stdin);
            write.map_err(|err| format!("writing the request: {err}"))?;

            let Some(mut stdout) = child.stdout.take() else {
                return Err("the module process gave no stdout".into());
            };
            let mut header = [0u8; 6];
            stdout
                .read_exact(&mut header)
                .map_err(|err| format!("the module did not answer the protocol: {err}"))?;
            if header[0] != PROTOCOL_VERSION {
                return Err(format!(
                    "module speaks protocol {} and this build speaks {PROTOCOL_VERSION}",
                    header[0]
                ));
            }
            let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
            if len > MAX_PAYLOAD {
                return Err(format!(
                    "the module's {len}-byte answer exceeds the exchange budget"
                ));
            }
            let mut body = vec![0u8; len as usize];
            stdout
                .read_exact(&mut body)
                .map_err(|err| format!("the module's answer ended early: {err}"))?;
            let artifact = read_artifact_section(&mut stdout)?;
            let _ = child.wait();
            Ok((header[1], body, artifact))
        }
    }

    /// Everything `execveat` points at, built before the fork: the
    /// pre-exec closure may only read stable addresses and issue the
    /// syscall (the async-signal-safe discipline `pre_exec` demands), so
    /// the argv and envp arrays exist up front and the closure is a
    /// function call on the whole struct. The function boundary is
    /// load-bearing: edition-2021 closures capture disjoint fields, and a
    /// bare array of raw pointers is not `Send` however the owning struct
    /// is declared.
    struct Spawn {
        empty: CString,
        // Ownership anchors: argv and envp point into these allocations,
        // which is a read the borrow checker cannot see.
        #[allow(dead_code)]
        argv0: CString,
        argv: [*const std::ffi::c_char; 2],
        #[allow(dead_code)]
        env: Vec<CString>,
        envp: Vec<*const std::ffi::c_char>,
        fd: i32,
    }

    // The pointers are into the struct's own heap allocations and the fd
    // is a plain kernel handle; both ride the fork safely.
    unsafe impl Send for Spawn {}
    unsafe impl Sync for Spawn {}

    impl Spawn {
        /// Snapshots the environment the module should see -- the
        /// implant's own, the same inheritance a compiled handler's child
        /// gets, and recon data in its own right (USER, PATH, HOSTNAME).
        fn new(fd: i32) -> Spawn {
            let argv0 = CString::new("rod-module").expect("no NUL in the argv");
            let argv = [argv0.as_ptr(), std::ptr::null()];
            let env: Vec<CString> = std::env::vars_os()
                .filter_map(|(name, value)| {
                    let mut pair = name;
                    pair.push("=");
                    pair.push(value);
                    // An interior NUL cannot ride a C string; an
                    // environment entry carrying one is dropped, not fatal.
                    CString::new(pair.into_vec()).ok()
                })
                .collect();
            let mut envp: Vec<*const std::ffi::c_char> =
                env.iter().map(|entry| entry.as_ptr()).collect();
            envp.push(std::ptr::null());
            Spawn {
                empty: CString::new("").expect("no NUL in the empty path"),
                argv0,
                argv,
                env,
                envp,
                fd,
            }
        }
    }

    // The only step between fork and exec: hand the anonymous fd to the
    // kernel as the new image. Returning at all means the exec failed.
    // Routed through the raw syscall number rather than libc's typed
    // wrapper: the musl bindings carry SYS_execveat but no execveat
    // function, and one path serves both libcs.
    fn exec_module(spawn: &Spawn) -> std::io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_execveat,
                spawn.fd,
                spawn.empty.as_ptr(),
                spawn.argv.as_ptr() as *const libc::c_char,
                spawn.envp.as_ptr() as *const libc::c_char,
                libc::AT_EMPTY_PATH,
            ) as libc::c_int
        };
        debug_assert!(result != 0, "execveat returned without exec'ing");
        Err(std::io::Error::last_os_error())
    }

    impl ExecLibrary {
        /// Spawns one module process off the staged fd. The program string
        /// never runs -- the pre-exec closure has already replaced the
        /// image by the time std's own exec would act -- and the module
        /// inherits the implant's environment through the prepared envp.
        fn spawn_module(&self) -> Result<std::process::Child, std::io::Error> {
            let spawn = Spawn::new(self.fd);
            let mut command = Command::new("rod-module");
            unsafe {
                command
                    .pre_exec(move || exec_module(&spawn))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped());
            }
            command.spawn()
        }
    }

    impl Drop for ExecLibrary {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    /// Reads the artifact section every protocol 2 response carries after
    /// its payload: three length-prefixed strings, the zero name length
    /// marking the absent run. The mirror of the SDK writer, byte for
    /// byte.
    fn read_artifact_section<R: std::io::Read>(
        reader: &mut R,
    ) -> Result<Option<ArtifactRun>, String> {
        fn section<R: std::io::Read>(reader: &mut R, budget: &str) -> Result<Vec<u8>, String> {
            let mut len = [0u8; 4];
            reader
                .read_exact(&mut len)
                .map_err(|err| format!("the module's artifact section ended early: {err}"))?;
            let len = u32::from_le_bytes(len);
            if len > MAX_PAYLOAD {
                return Err(format!(
                    "the module's artifact {budget} exceeds the exchange budget"
                ));
            }
            let mut bytes = vec![0u8; len as usize];
            reader
                .read_exact(&mut bytes)
                .map_err(|err| format!("the module's artifact section ended early: {err}"))?;
            Ok(bytes)
        }

        let name = section(reader, "name")?;
        if name.is_empty() {
            return Ok(None);
        }
        let content_type = section(reader, "content type")?;
        let data = section(reader, "bytes")?;
        Ok(Some(ArtifactRun {
            name: String::from_utf8_lossy(&name).into_owned(),
            content_type: String::from_utf8_lossy(&content_type).into_owned(),
            data,
        }))
    }

    // Test reach-throughs: the parser and the budget are private to the
    // loader, and the tests pin the byte layout against hand-built frames.
    #[cfg(test)]
    pub(crate) fn read_artifact_section_for_test<R: std::io::Read>(
        reader: &mut R,
    ) -> Result<Option<ArtifactRun>, String> {
        read_artifact_section(reader)
    }

    #[cfg(test)]
    pub(crate) const MAX_PAYLOAD_FOR_TEST: u32 = MAX_PAYLOAD;

    impl Library for ExecLibrary {
        fn abi(&self) -> Result<u32, String> {
            match self.exchange(op::PING, 0, &[]) {
                Ok((status::OK, _, _)) => Ok(PROTOCOL_VERSION as u32),
                Ok((other, text, _)) => Err(format!(
                    "module.load: the module's own ping answered status {other}: {}",
                    String::from_utf8_lossy(&text)
                )),
                Err(cause) => Err(format!(
                    "module.load: the bytes are not a loadable module: {cause}"
                )),
            }
        }

        fn name(&self) -> String {
            self.exchange(op::NAME, 0, &[])
                .map(|(_, body, _)| String::from_utf8_lossy(&body).into_owned())
                .unwrap_or_default()
        }

        fn verb_count(&self) -> u32 {
            self.exchange(op::COUNT, 0, &[])
                .ok()
                .and_then(|(_, body, _)| {
                    let bytes: [u8; 4] = body.as_slice().try_into().ok()?;
                    Some(u32::from_le_bytes(bytes))
                })
                .unwrap_or(0)
        }

        fn verb_name(&self, index: u32) -> Option<String> {
            let body = self.exchange(op::VERB_NAME, index, &[]).ok()?.1;
            let name = String::from_utf8_lossy(&body).into_owned();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }

        fn run(&self, index: u32, arguments: &str) -> RunStatus {
            match self.exchange(op::RUN, index, arguments.as_bytes()) {
                Ok((status::OK, body, artifact)) => {
                    RunStatus::Succeeded(String::from_utf8_lossy(&body).into_owned(), artifact)
                }
                Ok((status::FAILED, body, _)) => {
                    RunStatus::Failed(String::from_utf8_lossy(&body).into_owned())
                }
                Ok((status::BAD_REQUEST, _, _)) => {
                    RunStatus::Error("the module no longer holds that verb index".into())
                }
                Ok((status::PANICKED, body, _)) => RunStatus::Error(format!(
                    "module handler panicked: {}",
                    String::from_utf8_lossy(&body)
                )),
                Ok((other, body, _)) => RunStatus::Error(format!(
                    "module answered status {other}: {}",
                    String::from_utf8_lossy(&body)
                )),
                Err(cause) => RunStatus::Error(format!("the module process failed: {cause}")),
            }
        }
    }
}

// --- Windows: the manual PE map ----------------------------------------------

// The third shape, beside the map: the COFF object loader (coff-v1).
// Compiled for the Windows floor and for the test builds -- its parse
// and relocation core is host-blind, and the tests are the loader's
// conformance until a lane runs the rig against a Windows implant.
#[cfg(any(windows, test))]
mod coff;

#[cfg(windows)]
mod pe {
    //! The manual PE map (architecture.md Sec 5.4): `LoadLibrary` wants a
    //! path and the seam keeps modules off disk, so the loader maps the
    //! image itself -- allocate, copy sections, apply base relocations,
    //! resolve imports against the system DLLs, give the image its TLS
    //! block on the loading thread, call the entry, then walk the export
    //! table for the entry family.
    //!
    //! Scope note: the TLS handling covers the loading thread -- the
    //! reference implant dispatches every one-shot verb on the run loop
    //! thread that loads, so module TLS access stays inside it by
    //! construction. A host that dispatches module verbs off other threads
    //! would need the TEB-wide patch the platform loader owns; that is
    //! the rehearsal boundary to check on a Windows guest.

    use std::collections::HashMap;
    use std::ffi::CString;

    use windows_sys::Win32::Foundation::{BOOL, HINSTANCE};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };
    // The one DllMain reason the map calls; a local constant beats a
    // windows-sys feature for a value the ABI froze decades ago.
    const DLL_PROCESS_ATTACH: u32 = 1;

    use super::{AbiStr, ArtifactRun, Library, RunStatus};

    type AbiFn = unsafe extern "C" fn() -> u32;
    type NameFn = unsafe extern "C" fn() -> AbiStr;
    type InitFn = unsafe extern "C" fn() -> u32;
    type VerbNameFn = unsafe extern "C" fn(u32) -> AbiStr;
    type RunFn = unsafe extern "C" fn(u32, AbiStr, *mut AbiStr, *mut AbiArtifact) -> i32;
    type FreeFn = unsafe extern "C" fn(*mut u8, usize);

    /// A run's optional artifact as `rod_plugin_run`'s ABI 2 out parameter
    /// carries it: three module-owned strings freed through the module's
    /// own export, the mirror of the SDK's `RodArtifact`.
    #[repr(C)]
    struct AbiArtifact {
        name: AbiStr,
        content_type: AbiStr,
        data: AbiStr,
    }

    impl AbiArtifact {
        fn none() -> AbiArtifact {
            AbiArtifact {
                name: AbiStr::empty(),
                content_type: AbiStr::empty(),
                data: AbiStr::empty(),
            }
        }
    }

    /// One manually mapped image: the allocation plus the resolved export
    /// addresses. The unload posture is the map's own best-effort: routes
    /// drop, and the allocation lives on -- a mapped image has no platform
    /// refcount to retire against, and freeing pages under code a handler
    /// still holds is worse than the leak.
    pub struct PeLibrary {
        base: *mut u8,
        exports: HashMap<String, usize>,
    }

    unsafe impl Send for PeLibrary {}

    impl PeLibrary {
        pub fn load(bytes: &[u8]) -> Result<Box<dyn Library>, String> {
            let image = parse(bytes)?;
            unsafe { Self::map(&image) }
        }

        unsafe fn map(image: &PeImage) -> Result<Box<dyn Library>, String> {
            let base = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    image.size_of_image as usize,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            } as *mut u8;
            if base.is_null() {
                return Err("module.load: the image allocation failed".into());
            }
            // Headers, then each section at its virtual address.
            unsafe {
                std::ptr::copy_nonoverlapping(image.bytes.as_ptr(), base, image.headers_len);
            }
            for section in &image.sections {
                if section.raw_size == 0 {
                    continue;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        image.bytes.as_ptr().add(section.raw_offset),
                        base.add(section.virtual_address),
                        section.raw_size,
                    );
                }
            }
            let delta = (base as usize).wrapping_sub(image.image_base as usize);
            unsafe { relocate(base, image, delta)? };
            unsafe { resolve_imports(base, image)? };
            unsafe { give_tls(base, image)? };
            if image.entry_point != 0 {
                unsafe {
                    let entry: unsafe extern "C" fn(
                        HINSTANCE,
                        u32,
                        *mut core::ffi::c_void,
                    ) -> BOOL = std::mem::transmute(base.add(image.entry_point));
                    entry(base as HINSTANCE, DLL_PROCESS_ATTACH, std::ptr::null_mut());
                }
            }
            let exports = unsafe { export_table(base, image)? };
            Ok(Box::new(PeLibrary { base, exports }))
        }

        fn entry<Entry: Copy>(&self, name: &str) -> Result<Entry, String> {
            let address = self
                .exports
                .get(name)
                .copied()
                .ok_or_else(|| format!("module does not export {name}"))?;
            Ok(unsafe { std::mem::transmute_copy(&(base_add(self.base, address))) })
        }

        fn read_owned(&self, string: AbiStr) -> String {
            let text = unsafe { string.as_text() };
            self.free_string(string);
            text
        }

        /// Copies a module-owned byte buffer out and returns it through the
        /// module's free -- the artifact data's own discipline, since bytes
        /// cannot ride the lossy text reader.
        fn read_bytes(&self, string: AbiStr) -> Vec<u8> {
            let bytes = unsafe { string.as_bytes() }.to_vec();
            self.free_string(string);
            bytes
        }

        /// Copies an artifact run out, freeing every buffer it rode; a null
        /// name is the absent run.
        fn read_artifact(&self, artifact: AbiArtifact) -> Option<ArtifactRun> {
            if artifact.name.ptr.is_null() {
                self.free_string(artifact.content_type);
                self.free_string(artifact.data);
                return None;
            }
            let name = self.read_owned(artifact.name);
            let content_type = self.read_owned(artifact.content_type);
            let data = self.read_bytes(artifact.data);
            Some(ArtifactRun {
                name,
                content_type,
                data,
            })
        }

        /// Returns module-allocated memory through the export the module
        /// ships for it; the host never frees module memory itself.
        fn free_string(&self, string: AbiStr) {
            if string.ptr.is_null() || string.len == 0 {
                return;
            }
            let Ok(free) = self.entry::<FreeFn>("rod_plugin_free") else {
                return;
            };
            unsafe { free(string.ptr, string.len) };
        }

        /// Drains an artifact the failure statuses leave behind: a module
        /// that errored may still have filled buffers, and every
        /// module-owned byte goes back through the module's own free.
        fn free_artifact_buffers(&self, artifact: AbiArtifact) {
            self.free_string(artifact.name);
            self.free_string(artifact.content_type);
            self.free_string(artifact.data);
        }
    }

    // The image's export addresses are RVAs into the mapped image.
    fn base_add(base: *mut u8, rva: usize) -> usize {
        unsafe { base.add(rva) as usize }
    }

    impl Library for PeLibrary {
        fn abi(&self) -> Result<u32, String> {
            let abi: AbiFn = self.entry("rod_plugin_abi")?;
            Ok(unsafe { abi() })
        }

        fn name(&self) -> String {
            let Ok(name) = self.entry::<NameFn>("rod_plugin_name") else {
                return String::new();
            };
            self.read_owned(unsafe { name() })
        }

        fn verb_count(&self) -> u32 {
            let Ok(init) = self.entry::<InitFn>("rod_plugin_init") else {
                return 0;
            };
            unsafe { init() }
        }

        fn verb_name(&self, index: u32) -> Option<String> {
            let verb_name = self.entry::<VerbNameFn>("rod_plugin_verb_name").ok()?;
            let name = self.read_owned(unsafe { verb_name(index) });
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        }

        fn run(&self, index: u32, arguments: &str) -> RunStatus {
            let Ok(run) = self.entry::<RunFn>("rod_plugin_run") else {
                return RunStatus::Error("module does not export rod_plugin_run".into());
            };
            let args = AbiStr::from_slice(arguments.as_bytes());
            let mut out = AbiStr::empty();
            let mut artifact = AbiArtifact::none();
            let status = unsafe { run(index, args, &mut out, &mut artifact) };
            let text = self.read_owned(out);
            match status {
                0 => RunStatus::Succeeded(text, self.read_artifact(artifact)),
                1 => {
                    self.free_artifact_buffers(artifact);
                    RunStatus::Failed(text)
                }
                other => {
                    self.free_artifact_buffers(artifact);
                    RunStatus::Error(format!("shim status {other}: {text}"))
                }
            }
        }
    }

    // The parsed image: everything the mapper reads, bounds-checked once.
    struct PeImage {
        bytes: Vec<u8>,
        headers_len: usize,
        image_base: u64,
        size_of_image: u32,
        entry_point: usize,
        sections: Vec<PeSection>,
        reloc_rva: u32,
        reloc_size: u32,
        import_rva: u32,
        import_size: u32,
        export_rva: u32,
        export_size: u32,
        tls_rva: u32,
        tls_size: u32,
    }

    struct PeSection {
        virtual_address: usize,
        raw_offset: usize,
        raw_size: usize,
    }

    fn read_u16(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    fn read_u32(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn read_u64(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    fn parse(bytes: &[u8]) -> Result<PeImage, String> {
        let bad = |what: &str| format!("module.load: not a loadable PE image: {what}");
        if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
            return Err(bad("no DOS header"));
        }
        let pe_offset = read_u32(bytes, 0x3c) as usize;
        if pe_offset + 24 + 240 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(bad("no PE header"));
        }
        let machine = read_u16(bytes, pe_offset + 4);
        if machine != 0x8664 && machine != 0x14c {
            return Err(bad("unsupported machine"));
        }
        let section_count = read_u16(bytes, pe_offset + 6) as usize;
        let optional_size = read_u16(bytes, pe_offset + 20) as usize;
        let optional = pe_offset + 24;
        let magic = read_u16(bytes, optional);
        let (image_base, data_directory): (u64, usize) = if magic == 0x20b {
            (read_u64(bytes, optional + 24), optional + 112)
        } else {
            (read_u32(bytes, optional + 28) as u64, optional + 96)
        };
        let entry_point = read_u32(bytes, optional + 16) as usize;
        let size_of_image = read_u32(bytes, optional + 56);
        let headers_len = read_u32(bytes, optional + 60) as usize;
        if data_directory + 16 * 8 > bytes.len() {
            return Err(bad("truncated data directories"));
        }
        let directory = |index: usize| -> (u32, u32) {
            (
                read_u32(bytes, data_directory + index * 8),
                read_u32(bytes, data_directory + index * 8 + 4),
            )
        };
        let (reloc_rva, reloc_size) = directory(5);
        let (import_rva, import_size) = directory(1);
        let (export_rva, export_size) = directory(0);
        let (tls_rva, tls_size) = directory(9);

        // Every field the map turns into a pointer or a length is bounds-
        // checked here, before any allocation: module bytes are operator-
        // input, and a malformed table must fail the load, never walk off
        // the image. An absent directory (rva and size both zero) passes;
        // a present one must sit inside the image.
        if size_of_image == 0 {
            return Err(bad("the image declares no size"));
        }
        if headers_len == 0 || headers_len > bytes.len() || headers_len > size_of_image as usize {
            return Err(bad("the headers length sits outside the file or the image"));
        }
        if entry_point >= size_of_image as usize {
            return Err(bad("the entry point runs past the image"));
        }
        let inside_image = |rva: u32, size: u32| {
            (rva == 0 && size == 0)
                || (rva as usize)
                    .checked_add(size as usize)
                    .is_some_and(|end| end <= size_of_image as usize)
        };
        if !inside_image(reloc_rva, reloc_size)
            || !inside_image(import_rva, import_size)
            || !inside_image(export_rva, export_size)
            || !inside_image(tls_rva, tls_size)
        {
            return Err(bad("a data directory runs past the image"));
        }

        let sections_at = optional + optional_size;
        if sections_at + section_count * 40 > bytes.len() {
            return Err(bad("truncated section table"));
        }
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let at = sections_at + index * 40;
            let virtual_address = read_u32(bytes, at + 12) as usize;
            let raw_size = read_u32(bytes, at + 16) as usize;
            let raw_offset = read_u32(bytes, at + 20) as usize;
            if raw_offset
                .checked_add(raw_size)
                .is_none_or(|end| end > bytes.len())
            {
                return Err(bad("a section runs past the file"));
            }
            if virtual_address
                .checked_add(raw_size)
                .is_none_or(|end| end > size_of_image as usize)
            {
                return Err(bad("a section runs past the image"));
            }
            sections.push(PeSection {
                virtual_address,
                raw_offset,
                raw_size,
            });
        }
        Ok(PeImage {
            bytes: bytes.to_vec(),
            headers_len,
            image_base,
            size_of_image,
            entry_point,
            sections,
            reloc_rva,
            reloc_size,
            import_rva,
            import_size,
            export_rva,
            export_size,
            tls_rva,
            tls_size,
        })
    }

    // Unaligned reads off the mapped image -- the PE structures carry no
    // alignment promise at arbitrary RVAs.
    unsafe fn peek_u32(at: *mut u8) -> u32 {
        unsafe { (at as *const u32).read_unaligned() }
    }

    unsafe fn peek_u16(at: *mut u8) -> u16 {
        unsafe { (at as *const u16).read_unaligned() }
    }

    unsafe fn peek_u64(at: *mut u8) -> u64 {
        unsafe { (at as *const u64).read_unaligned() }
    }

    // A pointer-width read: the TLS directory's field widths follow the
    // image's own PE32/PE32+ shape, so its walks route through here.
    unsafe fn peek_usize(at: *mut u8) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            (unsafe { peek_u64(at) }) as usize
        }
        #[cfg(target_arch = "x86")]
        {
            (unsafe { peek_u32(at) }) as usize
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
        {
            let _ = at;
            unreachable!("the TLS map serves the x86 shapes alone")
        }
    }

    unsafe fn poke_u32(at: *mut u8, value: u32) {
        unsafe { (at as *mut u32).write_unaligned(value) };
    }

    unsafe fn poke_u64(at: *mut u8, value: u64) {
        unsafe { (at as *mut u64).write_unaligned(value) };
    }

    unsafe fn relocate(base: *mut u8, image: &PeImage, delta: usize) -> Result<(), String> {
        if delta == 0 || image.reloc_size == 0 {
            return Ok(());
        }
        let mut offset = 0usize;
        while offset + 8 <= image.reloc_size as usize {
            let block = base.add(image.reloc_rva as usize + offset);
            // Block layout: the page's base RVA, then the block's own size,
            // then the 2-byte entries. Each entry's 12-bit offset is
            // relative to the page base, so the slot it names lives at
            // base + page RVA + offset -- not inside the block itself.
            let page_rva = unsafe { peek_u32(block) } as usize;
            let block_size = unsafe { peek_u32(block.add(4)) } as usize;
            if block_size < 8 || block_size > image.reloc_size as usize - offset {
                return Err("module.load: malformed relocation table".into());
            }
            let count = (block_size - 8) / 2;
            for entry in 0..count {
                let word = unsafe { peek_u16(block.add(8 + entry * 2)) };
                let kind = word >> 12;
                let at = (word & 0xfff) as usize;
                match kind {
                    0 => {} // pad
                    width @ (3 | 10) => {
                        // The slot the entry names must land inside the
                        // image: the table itself is module bytes, so a
                        // hostile or corrupt entry is refused, not trusted
                        // to point somewhere loadable.
                        let slot_width = if width == 3 { 4 } else { 8 };
                        let Some(slot) = page_rva.checked_add(at) else {
                            return Err("module.load: malformed relocation table".into());
                        };
                        if slot + slot_width > image.size_of_image as usize {
                            return Err("module.load: a relocation slot runs past the image".into());
                        }
                        unsafe {
                            let slot = base.add(slot);
                            if width == 3 {
                                // HIGHLOW: a 32-bit VA.
                                poke_u32(slot, peek_u32(slot).wrapping_add(delta as u32));
                            } else {
                                // DIR64: a 64-bit VA.
                                poke_u64(slot, peek_u64(slot).wrapping_add(delta as u64));
                            }
                        }
                    }
                    other => {
                        return Err(format!("module.load: unsupported relocation type {other}"))
                    }
                }
            }
            offset += block_size;
        }
        Ok(())
    }

    unsafe fn resolve_imports(base: *mut u8, image: &PeImage) -> Result<(), String> {
        if image.import_rva == 0 && image.import_size == 0 {
            return Ok(());
        }
        let image_size = image.size_of_image as usize;
        let mut offset = 0usize;
        loop {
            // The descriptor and both tables it names are module bytes:
            // each walk step is bounds-checked against the image rather
            // than trusted to terminate on a null name.
            if image.import_rva as usize + offset + 20 > image_size {
                return Err("module.load: the import table runs past the image".into());
            }
            let descriptor = base.add(image.import_rva as usize + offset);
            let name_rva = unsafe { peek_u32(descriptor.add(12)) };
            if name_rva == 0 {
                return Ok(());
            }
            if name_rva as usize >= image_size {
                return Err("module.load: an import name runs past the image".into());
            }
            let dll = unsafe { c_string_at(base.add(name_rva as usize), base.add(image_size)) };
            let dll =
                CString::new(dll).map_err(|_| "module.load: a bad import name".to_string())?;
            let library = unsafe { LoadLibraryA(dll.as_ptr().cast()) };
            if library.is_null() {
                return Err(format!("module.load: import {dll:?} did not resolve"));
            }
            let first_thunk = unsafe { peek_u32(descriptor.add(16)) } as usize;
            let original = unsafe { peek_u32(descriptor) } as usize;
            let lookup_table = if original != 0 { original } else { first_thunk };
            let mut slot = 0usize;
            loop {
                if lookup_table + slot * 8 + 8 > image_size
                    || first_thunk + slot * 8 + 8 > image_size
                {
                    return Err("module.load: an import table runs past the image".into());
                }
                let value = unsafe { peek_u64(base.add(lookup_table + slot * 8)) };
                if value == 0 {
                    break;
                }
                let address = if value & (1 << 63) != 0 {
                    let ordinal = (value & 0xffff) as usize;
                    unsafe { GetProcAddress(library, ordinal as *const u8) }
                } else {
                    if value as usize >= image_size {
                        return Err("module.load: an import hint/name runs past the image".into());
                    }
                    let name = base.add(value as usize + 2);
                    unsafe { GetProcAddress(library, name) }
                };
                let Some(address) = address else {
                    return Err(format!(
                        "module.load: an import from {dll:?} did not resolve"
                    ));
                };
                unsafe { poke_u64(base.add(first_thunk + slot * 8), address as usize as u64) };
                slot += 1;
            }
            offset += 20;
        }
    }

    /// Gives the image its TLS block on the loading thread: copy the
    /// template into a fresh block, take a slot in the thread's native-TLS
    /// array (growing the array when the loader left no room), write the
    /// slot's index into the image's index variable, and run the
    /// callbacks. The loading-thread scope is the documented constraint
    /// above.
    unsafe fn give_tls(base: *mut u8, image: &PeImage) -> Result<(), String> {
        // The directory's own width: PE32+ carries 8-byte VAs and a
        // 40-byte directory, PE32 4-byte VAs and 24 bytes -- the x86 TLS
        // array insertion below is the other half of that leg's support.
        let width = std::mem::size_of::<usize>();
        if image.tls_rva == 0 || image.tls_size < (4 * width + 8) as u32 {
            return Ok(());
        }
        let directory = base.add(image.tls_rva as usize);
        // The directory's fields are VAs, and relocation ran before this:
        // each one was fixuped to the mapped base, so they are live
        // pointers here -- reducing them against image_base (or rebasing
        // them) computes an address twice and lands off the image.
        // They are module bytes all the same: each one must point inside
        // the mapped image before anything dereferences or copies it.
        let image_start = base as usize;
        let image_end = image_start + image.size_of_image as usize;
        let in_image = |address: usize| address >= image_start && address < image_end;
        let start = unsafe { peek_usize(directory) };
        let end = unsafe { peek_usize(directory.add(width)) };
        let index_address = unsafe { peek_usize(directory.add(2 * width)) } as *mut u8;
        let callbacks = unsafe { peek_usize(directory.add(3 * width)) };
        let zero_fill = unsafe { peek_u32(directory.add(4 * width)) } as usize;
        let template_len = end.saturating_sub(start);
        let block_len = template_len.saturating_add(zero_fill);
        if block_len == 0 {
            return Ok(());
        }
        if template_len > 0 && !(in_image(start) && end >= start && in_image(end)) {
            return Err("module.load: the TLS template sits outside the image".into());
        }
        if !index_address.is_null() && !in_image(index_address as usize) {
            return Err("module.load: the TLS index variable sits outside the image".into());
        }
        if callbacks != 0 && !in_image(callbacks) {
            return Err("module.load: the TLS callbacks sit outside the image".into());
        }
        let block = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                block_len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut u8;
        if block.is_null() {
            return Err("module.load: the TLS block allocation failed".into());
        }
        if template_len > 0 {
            unsafe { std::ptr::copy_nonoverlapping(start as *const u8, block, template_len) };
        }
        let index = unsafe { tls_array_insert(block)? };
        unsafe { poke_u32(index_address, index) };
        if callbacks != 0 {
            let mut at = callbacks as *mut u8;
            loop {
                let callback = unsafe { peek_usize(at) };
                if callback == 0 {
                    break;
                }
                let run: unsafe extern "C" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void) =
                    unsafe { std::mem::transmute(callback) };
                unsafe { run(base as *mut _, DLL_PROCESS_ATTACH, std::ptr::null_mut()) };
                at = at.add(width);
            }
        }
        Ok(())
    }

    /// Puts the TLS block into the current thread's native-TLS array and
    /// answers the slot's index, growing the array when the process
    /// loader's allocation left no room. The reference implant loads and
    /// dispatches on the one run-loop thread, so the one array this
    /// touches is the only one that matters.
    #[cfg(target_arch = "x86_64")]
    unsafe fn tls_array_insert(block: *mut u8) -> Result<u32, String> {
        // The array's element count is not stored anywhere readable; the
        // platform loader allocates one pointer per image with TLS plus a
        // surplus, and 64 slots is the classic bound it never undercuts.
        // A busy first array grows into a fresh one the TEB then names.
        const CAPACITY: usize = 64;
        let array: *mut *mut u8;
        unsafe { std::arch::asm!("mov {array}, gs:[0x58]", array = out(reg) array) };
        unsafe {
            for index in 0..CAPACITY {
                if (*array.add(index)).is_null() {
                    *array.add(index) = block;
                    return Ok(index as u32);
                }
            }
        }
        let grown = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                (CAPACITY + 1) * std::mem::size_of::<*mut u8>(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut *mut u8;
        if grown.is_null() {
            return Err("module.load: the TLS array growth failed".into());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(array, grown, CAPACITY);
            *grown.add(CAPACITY) = block;
            std::arch::asm!(
                "mov gs:[0x58], {grown}",
                grown = in(reg) grown,
                options(nostack)
            );
        }
        Ok(CAPACITY as u32)
    }

    #[cfg(target_arch = "x86")]
    unsafe fn tls_array_insert(block: *mut u8) -> Result<u32, String> {
        const CAPACITY: usize = 64;
        let array: *mut *mut u8;
        unsafe { std::arch::asm!("mov {array}, fs:[0x2C]", array = out(reg) array) };
        unsafe {
            for index in 0..CAPACITY {
                if (*array.add(index)).is_null() {
                    *array.add(index) = block;
                    return Ok(index as u32);
                }
            }
        }
        let grown = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                (CAPACITY + 1) * std::mem::size_of::<*mut u8>(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        } as *mut *mut u8;
        if grown.is_null() {
            return Err("module.load: the TLS array growth failed".into());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(array, grown, CAPACITY);
            *grown.add(CAPACITY) = block;
            std::arch::asm!("mov fs:[0x2C], {grown}", grown = in(reg) grown);
        }
        Ok(CAPACITY as u32)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    unsafe fn tls_array_insert(_block: *mut u8) -> Result<u32, String> {
        Err("module.load: this Windows architecture carries no TLS map".into())
    }

    // Walks a NUL-terminated string with a hard stop at the image end: a
    // module whose bytes hold no terminator must not walk the walk past the
    // allocation.
    unsafe fn c_string_at(at: *mut u8, end: *mut u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut walk = at;
        unsafe {
            while walk < end && *walk != 0 {
                bytes.push(*walk);
                walk = walk.add(1);
            }
        }
        bytes
    }

    unsafe fn export_table(
        base: *mut u8,
        image: &PeImage,
    ) -> Result<HashMap<String, usize>, String> {
        if image.export_rva == 0 || image.export_size == 0 {
            return Err("module.load: the image exports nothing".into());
        }
        let image_size = image.size_of_image as usize;
        let directory = base.add(image.export_rva as usize);
        let names_count = unsafe { peek_u32(directory.add(24)) } as usize;
        let functions_rva = unsafe { peek_u32(directory.add(28)) } as usize;
        let names_rva = unsafe { peek_u32(directory.add(32)) } as usize;
        let ordinals_rva = unsafe { peek_u32(directory.add(36)) } as usize;
        // The three arrays the directory names are module bytes: their
        // extents are bounds-checked before the walk, and each row's own
        // values (a name RVA, an ordinal) are checked where they are used.
        if names_rva
            .checked_add(names_count * 4)
            .is_none_or(|end| end > image_size)
            || ordinals_rva
                .checked_add(names_count * 2)
                .is_none_or(|end| end > image_size)
        {
            return Err("module.load: the export arrays run past the image".into());
        }
        let mut exports = HashMap::new();
        for index in 0..names_count {
            let name_rva = unsafe { peek_u32(base.add(names_rva + index * 4)) } as usize;
            if name_rva >= image_size {
                continue;
            }
            let name = unsafe { c_string_at(base.add(name_rva), base.add(image_size)) };
            let Ok(name) = String::from_utf8(name) else {
                continue;
            };
            if !name.starts_with("rod_plugin_") {
                continue;
            }
            let ordinal = unsafe { peek_u16(base.add(ordinals_rva + index * 2)) } as usize;
            let Some(function) = (functions_rva + ordinal * 4)
                .checked_add(4)
                .filter(|end| *end <= image_size)
            else {
                continue;
            };
            let function = unsafe { peek_u32(base.add(function)) } as usize;
            exports.insert(name, function);
        }
        if exports.is_empty() {
            return Err("module.load: the image exports no rod_plugin entry".into());
        }
        Ok(exports)
    }

    #[cfg(test)]
    fn zeroed_image(size: u32) -> PeImage {
        PeImage {
            bytes: Vec::new(),
            headers_len: 0,
            image_base: 0x140_000_000,
            size_of_image: size,
            entry_point: 0,
            sections: Vec::new(),
            reloc_rva: 0,
            reloc_size: 0,
            import_rva: 0,
            import_size: 0,
            export_rva: 0,
            export_size: 0,
            tls_rva: 0,
            tls_size: 0,
        }
    }

    #[cfg(test)]
    #[test]
    fn relocate_walks_page_blocks_like_mingw_writes_them() {
        // One block covering page 0x1000 with a single DIR64 entry at page
        // offset 0x40. The walker must take the block's size from the
        // second dword -- the first is the page RVA, which on a real image
        // dwarfs the directory and reads as malformed -- and land the fixup
        // on the covered page, not inside the relocation directory.
        let mut mapped = vec![0u8; 0x2000];
        let base = mapped.as_mut_ptr();
        let mut image = zeroed_image(0x2000);
        image.reloc_rva = 0x1800;
        image.reloc_size = 0x10;
        let directory = unsafe { base.add(0x1800) };
        unsafe {
            poke_u32(directory, 0x1000); // page RVA
            poke_u32(directory.add(4), 0x10); // block size
            (directory.add(8) as *mut u16).write_unaligned((10 << 12) | 0x40); // DIR64 at +0x40
            poke_u64(base.add(0x1040), 0x140_001_040); // the VA to fix up
        }
        let delta = (base as usize).wrapping_sub(0x140_000_000);
        unsafe { relocate(base, &image, delta) }.expect("the walk succeeds");
        assert_eq!(
            unsafe { peek_u64(base.add(0x1040)) },
            0x140_001_040u64.wrapping_add(delta as u64)
        );
        assert_eq!(
            unsafe { peek_u64(base.add(0x1808)) },
            (10 << 12) | 0x40,
            "the entry itself must not be treated as a fixup slot"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-process stand-in library: fixed name and verbs, behavior by
    /// table. Everything the registry does around a library is testable
    /// without a platform loader.
    struct FakeLibrary {
        name: &'static str,
        verbs: Vec<&'static str>,
        fail: bool,
        panicked: std::sync::atomic::AtomicBool,
    }

    impl FakeLibrary {
        fn of(name: &'static str, verbs: &[&'static str]) -> FakeLibrary {
            FakeLibrary {
                name,
                verbs: verbs.to_vec(),
                fail: false,
                panicked: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl Library for FakeLibrary {
        fn abi(&self) -> Result<u32, String> {
            Ok(ABI_VERSION)
        }
        fn name(&self) -> String {
            self.name.into()
        }
        fn verb_count(&self) -> u32 {
            self.verbs.len() as u32
        }
        fn verb_name(&self, index: u32) -> Option<String> {
            self.verbs.get(index as usize).map(|verb| verb.to_string())
        }
        fn run(&self, index: u32, arguments: &str) -> RunStatus {
            if self.panicked.load(std::sync::atomic::Ordering::SeqCst) {
                return RunStatus::Error("shim status -2: module handler panicked".into());
            }
            let verb = self.verbs[index as usize];
            if self.fail {
                RunStatus::Failed(format!("{verb} refused: {arguments}"))
            } else {
                RunStatus::Succeeded(format!("{verb} ran: {arguments}"), None)
            }
        }
    }

    fn installed(name: &'static str, verbs: &[&'static str]) -> Plugins {
        let plugins = Plugins::new();
        let entry = ModuleEntry::new(
            name.into(),
            verbs.iter().map(|verb| verb.to_string()).collect(),
            Box::new(FakeLibrary::of(name, verbs)),
        );
        plugins.install(entry);
        plugins
    }

    #[test]
    fn module_verbs_dispatch_like_compiled_ones() {
        let plugins = installed("sweep", &["recon.sweep"]);
        let run = plugins
            .dispatch("recon.sweep", "10.0.0.0/24")
            .expect("the route exists");
        assert_eq!(run.outcome, Outcome::Succeeded);
        assert_eq!(run.output, "recon.sweep ran: 10.0.0.0/24");
        assert!(run.artifact.is_none());
        assert!(plugins.dispatch("no.such.verb", "").is_none());
    }

    #[test]
    fn artifact_runs_ride_the_dispatch_like_a_compiled_handler_s() {
        // ABI 2's whole point: a module verb's artifact run reaches the
        // session's upload arm through the same HandlerOutput a compiled
        // handler's does, named and typed.
        struct ArtifactLibrary;
        impl Library for ArtifactLibrary {
            fn abi(&self) -> Result<u32, String> {
                Ok(ABI_VERSION)
            }
            fn name(&self) -> String {
                "dump".into()
            }
            fn verb_count(&self) -> u32 {
                1
            }
            fn verb_name(&self, index: u32) -> Option<String> {
                (index == 0).then(|| "collect.dump".to_string())
            }
            fn run(&self, _index: u32, arguments: &str) -> RunStatus {
                RunStatus::Succeeded(
                    "collected".into(),
                    Some(ArtifactRun {
                        name: "dump.bin".into(),
                        content_type: "application/octet-stream".into(),
                        data: arguments.as_bytes().to_vec(),
                    }),
                )
            }
        }
        let plugins = Plugins::new();
        plugins.install(ModuleEntry::new(
            "dump".into(),
            vec!["collect.dump".into()],
            Box::new(ArtifactLibrary),
        ));

        let run = plugins
            .dispatch("collect.dump", "BYTES")
            .expect("the route exists");
        assert_eq!(run.outcome, Outcome::Succeeded);
        assert_eq!(run.output, "collected");
        let artifact = run.artifact.expect("the run carries its artifact");
        assert_eq!(artifact.name, "dump.bin");
        assert_eq!(artifact.content_type, "application/octet-stream");
        assert_eq!(artifact.data, b"BYTES");
    }

    #[test]
    fn the_guards_refuse_what_a_module_cannot_own() {
        for verb in [
            "unnamespaced",
            ".leading",
            "trailing.",
            "shell.exec",
            "file.push",
            "shell.interact",
            "tunnel.socks",
        ] {
            assert!(validate_verb(verb).is_err(), "{verb} should refuse");
        }
        assert!(validate_verb("recon.sweep").is_ok());
        assert!(validate_verb("collect.cred").is_ok());
    }

    #[test]
    fn the_advertisement_source_reads_the_routes() {
        let plugins = installed("sweep", &["recon.sweep", "persist.install"]);
        let mut advertised = plugins.advertised_verbs();
        advertised.sort();
        assert_eq!(advertised, vec!["persist.install", "recon.sweep"]);
    }

    #[test]
    fn unload_drops_the_routes_and_names_the_missing() {
        let plugins = installed("sweep", &["recon.sweep"]);
        let report = plugins.unload("sweep").expect("the unload runs");
        assert!(report.contains("recon.sweep"), "{report}");
        assert!(plugins.dispatch("recon.sweep", "").is_none());
        assert!(plugins.list().contains("no modules"));
        let missing = plugins.unload("ghost").expect_err("nothing to unload");
        assert!(missing.contains("ghost"), "{missing}");
    }

    #[test]
    fn a_later_registration_replaces_the_route() {
        let plugins = Plugins::new();
        plugins.install(ModuleEntry::new(
            "first".into(),
            vec!["recon.sweep".into()],
            Box::new(FakeLibrary::of("first", &["recon.sweep"])),
        ));
        plugins.install(ModuleEntry::new(
            "second".into(),
            vec!["recon.sweep".into()],
            Box::new(FakeLibrary::of("second", &["recon.sweep"])),
        ));
        let run = plugins.dispatch("recon.sweep", "x").expect("routed");
        assert!(run.output.starts_with("recon.sweep ran"), "{}", run.output);
        // Both modules remain listed; the verb names its current owner
        // only through dispatch -- the listing reports membership.
        assert!(plugins.list().contains("first"));
        assert!(plugins.list().contains("second"));
    }

    #[test]
    fn handles_and_hashes_validate_before_anything_loads() {
        for handle in ["", "has space", "bad/slash", &"x".repeat(65)] {
            assert!(validate_handle(handle).is_err(), "{handle:?}");
        }
        assert!(validate_handle("sweep.2").is_ok());
        assert!(verify_sha256(b"bytes", "deadbeef").is_err());
        use sha2::{Digest, Sha256};
        let good = Sha256::digest(b"bytes");
        let good: String = good.iter().map(|b| format!("{b:02x}")).collect();
        assert!(verify_sha256(b"bytes", &good).is_ok());
        // Case-insensitive comparison: the token is hex either way.
        assert!(verify_sha256(b"bytes", &good.to_uppercase()).is_ok());
    }

    #[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
    #[test]
    fn garbage_bytes_refuse_as_a_module() {
        let plugins = Plugins::new();
        use sha2::{Digest, Sha256};
        let hash: String = Sha256::digest(b"not a module")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let cause = plugins
            .load("junk", b"not a module", &hash)
            .expect_err("not a loadable image");
        assert!(cause.contains("not a loadable module"), "{cause}");
    }

    #[cfg(all(unix, not(target_os = "android"), not(target_os = "macos")))]
    #[test]
    fn the_artifact_section_parses_as_the_sdk_writes_it() {
        // The protocol's byte layout is the contract the SDK's writer and
        // this reader share without sharing a crate: pin the absent run,
        // the named run, and the refusal of an oversized section against
        // hand-built frames shaped exactly like protocol 2 responses.
        let mut absent = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
        assert!(executed::read_artifact_section_for_test(&mut absent)
            .expect("the section parses")
            .is_none());

        let mut frame = Vec::new();
        frame.extend_from_slice(&8u32.to_le_bytes());
        frame.extend_from_slice(b"dump.bin");
        frame.extend_from_slice(&24u32.to_le_bytes());
        frame.extend_from_slice(b"application/octet-stream");
        frame.extend_from_slice(&3u32.to_le_bytes());
        frame.extend_from_slice(&[1, 2, 3]);
        let mut present = std::io::Cursor::new(frame);
        let run = executed::read_artifact_section_for_test(&mut present)
            .expect("the section parses")
            .expect("it carries a run");
        assert_eq!(run.name, "dump.bin");
        assert_eq!(run.content_type, "application/octet-stream");
        assert_eq!(run.data, vec![1, 2, 3]);

        let mut huge = Vec::new();
        huge.extend_from_slice(&1u32.to_le_bytes());
        huge.push(b'x');
        huge.extend_from_slice(&(executed::MAX_PAYLOAD_FOR_TEST + 1).to_le_bytes());
        let mut reader = std::io::Cursor::new(huge);
        assert!(executed::read_artifact_section_for_test(&mut reader).is_err());
    }
}
