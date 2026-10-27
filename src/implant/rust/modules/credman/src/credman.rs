//! The credential-manager edge (the module's whole platform surface):
//! advapi32's credential API enumerates the calling logon session's
//! store and hands the generic entries' blobs back decrypted -- the
//! system performs its own decryption in the session that owns the
//! store, so the module owes no key schedule, no cipher, and no
//! dependency beyond advapi32's two functions. Everything that must
//! hold for a test (the row renderings, the blob decoding, the error
//! tables, the time conversion) is a plain function this host runs
//! anywhere; only the calls themselves sit behind `cfg(windows)`, and
//! the Windows crosses the CI lane builds prove they compile.
//!
//! The rows speak the credential-row grammar (architecture.md Sec
//! 15.2): one JSON object per line, `kind` and `principal` required,
//! the rest optional -- the credentials board parses them, masks the
//! `secret` field until an operator reveals it, and the audit chain
//! never carries it. One platform fact shapes the rows' honesty: the
//! enumeration returns every entry's structure in one call, blob
//! included, and the survey simply renders no secret field -- while
//! the domain-credential types come back with no blob at all (the LSA
//! holds those separately), and their rows say so rather than
//! pretending a read the system never performed.

/// The row's kind marker: what the credentials board groups the rows
/// under.
const KIND: &str = "windows-credential-manager";

/// The row's source: the store the rows came from.
const SOURCE: &str = "Windows Credential Manager";

/// One store entry as owned data -- a snapshot the Windows edge takes
/// in a single copy so every renderer after it (survey and read alike)
/// is a plain function over plain data.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) struct Entry {
    /// The entry's target name: the store's own key, what a read's
    /// narrowing matches against.
    pub target: String,
    /// The credential's type among the store's four.
    pub kind: u32,
    /// The entry's username where it carried one.
    pub user: Option<String>,
    /// The entry's persistence scope.
    pub persist: u32,
    /// The last write as a FILETIME (100-nanosecond units since
    /// 1601-01-01), the store's own stamp.
    pub written: u64,
    /// The entry's blob where the record carried one -- `None` for the
    /// generic entry that stored nothing and for the domain types the
    /// system hands back without their blobs at all.
    pub blob: Option<Vec<u8>>,
}

/// The credential types the store carries, as the names the operator
/// reads. A type outside the table stands as its number -- never a
/// guess at what the site's store meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn type_name(kind: u32) -> String {
    match kind {
        1 => "generic".to_string(),
        2 => "domain-password".to_string(),
        3 => "domain-certificate".to_string(),
        4 => "domain-visible-password".to_string(),
        other => format!("type {other}"),
    }
}

/// Whether the type's blob the LSA holds separately: the enumeration
/// returns these entries without their blobs, and the row says so
/// instead of rendering an absence as if it were a read.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn withheld_type(kind: u32) -> bool {
    matches!(kind, 2..=4)
}

/// The persistence scopes an entry can carry, as the names the
/// operator reads; a scope outside the table stands as its number.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn persist_name(persist: u32) -> String {
    match persist {
        1 => "session".to_string(),
        2 => "local-machine".to_string(),
        3 => "enterprise".to_string(),
        other => format!("persist {other}"),
    }
}

/// The Win32 error codes the enumeration meets, as the messages the
/// operator reads (an empty store is not one of them -- it is an
/// honest empty read, the family's own stance). A code outside the
/// table stands as its number -- never a guess at what the site's
/// store meant by it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn enumerate_message(error: u32) -> String {
    match error {
        5 => "access denied".to_string(),
        other => format!("credential manager error {other}"),
    }
}

/// One entry's blob as the secret the row renders: the text the store
/// holds it in where the bytes decode cleanly (a generic entry's
/// password is UTF-16 or plain text), the hex form where they do not
/// (an application may store any bytes it likes) -- the hex prefix
/// keeps a binary blob from reading as a password it never was.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn secret_value(bytes: &[u8]) -> String {
    if let Some(text) = printable_utf16(bytes) {
        return text;
    }
    if let Some(text) = printable_ascii(bytes) {
        return text;
    }
    format!("hex:{}", hex(bytes))
}

/// One entry's row in the credential-row grammar. The survey renders
/// the entry's shape alone (no secret field); the read adds the secret
/// where the store handed its blob back, and names the withholding
/// where the system kept it -- the domain-credential types the LSA
/// holds separately.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn row(entry: &Entry, include_secret: bool, host: Option<&str>) -> String {
    // The principal the row carries: the entry's own username where it
    // has one, the target name where it does not (a domain entry
    // without a username is still its target's row).
    let principal = entry
        .user
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&entry.target);
    let mut note = format!(
        "target={}; type={}; persist={}; written={}",
        entry.target,
        type_name(entry.kind),
        persist_name(entry.persist),
        filetime_utc(entry.written)
    );
    let secret = match (include_secret, entry.blob.as_deref()) {
        (true, Some(bytes)) if !bytes.is_empty() => Some(secret_value(bytes)),
        (true, None) if withheld_type(entry.kind) => {
            note.push_str("; the system hands this type back without its blob");
            None
        }
        _ => None,
    };
    let mut json = format!(
        r#"{{"kind":"{KIND}","principal":"{}","source":"{SOURCE}""#,
        escape_json(principal)
    );
    if let Some(host) = host {
        json.push_str(&format!(r#","host":"{}""#, escape_json(host)));
    }
    json.push_str(&format!(r#","note":"{}""#, escape_json(&note)));
    if let Some(secret) = secret {
        json.push_str(&format!(r#","secret":"{}"}}"#, escape_json(&secret)));
    } else {
        json.push('}');
    }
    json
}

/// The text as a JSON string body: the two characters the grammar
/// reserves, the four short escapes, and the control block as explicit
/// `\u` escapes -- a password carrying any of them renders whole, and
/// the credentials board parses what the row printed.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn escape_json(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                escaped.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// The bytes as lowercase hex, two digits per byte.
#[cfg_attr(not(windows), allow(dead_code))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes as text when every one of them is a printable ASCII
/// character -- the plain secrets an application may store.
#[cfg_attr(not(windows), allow(dead_code))]
fn printable_ascii(bytes: &[u8]) -> Option<String> {
    bytes
        .iter()
        .all(|byte| (0x20..=0x7e).contains(byte))
        .then(|| bytes.iter().map(|byte| *byte as char).collect())
}

/// The bytes as text when they are printable UTF-16LE -- the wide
/// form the credential manager's own dialog stores, every second byte
/// a NUL.
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

/// A FILETIME as UTC text (`1601-01-01T00:00:00Z`): the store stamps
/// every entry's last write, and the survey renders the stamp as the
/// fact it is, in the one timezone that needs no seat to name.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn filetime_utc(filetime: u64) -> String {
    let seconds = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let days = seconds.div_euclid(86_400);
    let day = seconds.rem_euclid(86_400);
    let (year, month, date) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{date:02}T{:02}:{:02}:{:02}Z",
        day / 3600,
        (day % 3600) / 60,
        day % 60
    )
}

/// The civil date a day count since 1970-01-01 names (the standard
/// era-based arithmetic): correct across every leap rule the FILETIME
/// range can stamp.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_pointer = (5 * day_of_year + 2) / 153;
    let date = (day_of_year - (153 * month_pointer + 2) / 5 + 1) as u32;
    let month = if month_pointer < 10 {
        month_pointer + 3
    } else {
        month_pointer - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, date)
}

// ---- the Windows calls ----

#[cfg(windows)]
mod win {
    use std::os::raw::c_void;

    use super::{enumerate_message, Entry};

    /// The credential API's own record, `#[repr(C)]` against its
    /// documented layout. The enumeration reads the header, names,
    /// blob, and scopes; the attribute array stays unread (an
    /// application's private extension the store's own consumers do
    /// not parse).
    #[repr(C)]
    struct CredentialW {
        flags: u32,
        /// The record's `Type` field: the credential's type among the
        /// store's four.
        kind: u32,
        target_name: *const u16,
        comment: *const u16,
        /// The last write as a FILETIME, the store's own stamp.
        last_written: u64,
        blob_size: u32,
        blob: *const u8,
        persist: u32,
        attribute_count: u32,
        attributes: *const c_void,
        target_alias: *const u16,
        user_name: *const u16,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn CredEnumerateW(
            filter: *const u16,
            flags: u32,
            count: *mut u32,
            credentials: *mut *mut *mut CredentialW,
        ) -> i32;
        // One free call for the array the API allocated as a block --
        // the entries are not individually freed.
        fn CredFree(buffer: *mut c_void);
    }

    /// The enumerated store, freed on drop.
    pub(crate) struct Store(*mut *mut CredentialW, usize);

    impl Drop for Store {
        fn drop(&mut self) {
            unsafe { CredFree(self.0.cast()) };
        }
    }

    impl Store {
        /// The raw records in the API's own order.
        fn records(&self) -> impl Iterator<Item = &CredentialW> {
            unsafe { std::slice::from_raw_parts(self.0, self.1) }
                .iter()
                .map(|record| unsafe { &**record })
        }
    }

    /// Enumerates the calling logon session's whole store -- no
    /// filter, no flags: the survey's inventory and the read's source
    /// are the same array the API returns once. The records are copied
    /// out and the block freed inside this one scope; an empty store
    /// (the API's own "not found") is an honest empty read, not a
    /// failure.
    pub(crate) fn enumerate() -> Result<Vec<Entry>, String> {
        let mut count: u32 = 0;
        let mut array: *mut *mut CredentialW = std::ptr::null_mut();
        let ok = unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut array) };
        if ok == 0 {
            let error = std::io::Error::last_os_error()
                .raw_os_error()
                .map(|code| code as u32)
                .unwrap_or(0);
            if error == 1168 {
                return Ok(Vec::new());
            }
            return Err(format!("collect.credman: {}", enumerate_message(error)));
        }
        let store = Store(array, count as usize);
        Ok(store
            .records()
            .map(|record| Entry {
                target: wstr(record.target_name),
                kind: record.kind,
                user: (!record.user_name.is_null()).then(|| wstr(record.user_name)),
                persist: record.persist,
                written: record.last_written,
                blob: blob_of(record),
            })
            .collect())
    }

    /// The record's blob as owned bytes: `None` where the record
    /// carried none -- the generic entry that stored nothing, and the
    /// domain types the system hands back without their blobs at all.
    fn blob_of(record: &CredentialW) -> Option<Vec<u8>> {
        (record.blob_size != 0 && !record.blob.is_null()).then(|| unsafe {
            std::slice::from_raw_parts(record.blob, record.blob_size as usize).to_vec()
        })
    }

    /// A NUL-terminated UTF-16 string as text, lossy: the store's
    /// names are the system's own renderings and already well-formed.
    fn wstr(pointer: *const u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0usize;
        unsafe {
            while *pointer.add(length) != 0 {
                length += 1;
            }
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
    }
}

#[cfg(windows)]
pub(crate) use win::enumerate;

#[cfg(test)]
mod tests {
    use super::*;

    /// A test entry: the survey's and the read's renderers differ in
    /// policy, not in data, so one constructor covers both.
    fn entry(target: &str, kind: u32, user: Option<&str>, blob: Option<&[u8]>) -> Entry {
        Entry {
            target: target.to_string(),
            kind,
            user: user.map(str::to_string),
            persist: 2,
            written: 134_116_992_000_000_000, // 2026-01-01T00:00:00Z
            blob: blob.map(<[u8]>::to_vec),
        }
    }

    #[test]
    fn the_tables_name_the_values_operators_meet() {
        assert_eq!(type_name(1), "generic");
        assert_eq!(type_name(2), "domain-password");
        assert_eq!(type_name(4), "domain-visible-password");
        // An untabled value keeps its number -- never a guessed cause.
        assert_eq!(type_name(9), "type 9");
        assert_eq!(persist_name(2), "local-machine");
        assert_eq!(persist_name(7), "persist 7");
        assert_eq!(enumerate_message(5), "access denied");
        assert_eq!(enumerate_message(1311), "credential manager error 1311");
    }

    #[test]
    fn the_survey_row_carries_the_entrys_shape_without_a_secret() {
        let survey = row(
            &entry("LegacyProxy", 1, Some("CORP\\svc_backup"), None),
            false,
            Some("WEB01"),
        );
        assert!(
            survey.starts_with(r#"{"kind":"windows-credential-manager""#),
            "{survey}"
        );
        assert!(
            survey.contains(r#""principal":"CORP\\svc_backup""#),
            "{survey}"
        );
        assert!(
            survey.contains(r#""source":"Windows Credential Manager""#),
            "{survey}"
        );
        assert!(survey.contains(r#""host":"WEB01""#), "{survey}");
        assert!(
            survey.contains(
                r#""note":"target=LegacyProxy; type=generic; persist=local-machine; written=2026-01-01T00:00:00Z""#
            ),
            "{survey}"
        );
        // The survey renders no secret even though the blob is in
        // hand: a bare task names the store, it never pulls a value.
        assert!(!survey.contains("secret"), "{survey}");
    }

    #[test]
    fn the_read_row_adds_the_secret_the_store_handed_back() {
        let wide: Vec<u8> = "Backup#2026!"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let read = row(
            &entry("LegacyProxy", 1, Some("CORP\\svc_backup"), Some(&wide)),
            true,
            None,
        );
        assert!(read.contains(r#","secret":"Backup#2026!"}"#), "{read}");
        // The host the caller could not name stays absent, not empty.
        assert!(!read.contains("host"), "{read}");
    }

    #[test]
    fn an_entry_without_a_username_carries_its_target_as_principal() {
        let read = row(
            &entry("TERMSRV/web01.corp.example", 2, None, None),
            false,
            None,
        );
        assert!(
            read.contains(r#""principal":"TERMSRV/web01.corp.example""#),
            "{read}"
        );
    }

    #[test]
    fn the_domain_types_name_the_withholding_rather_than_a_read() {
        let read = row(
            &entry("TERMSRV/web01.corp.example", 2, None, None),
            true,
            None,
        );
        assert!(!read.contains("secret"), "{read}");
        assert!(
            read.contains("the system hands this type back without its blob"),
            "{read}"
        );
        // A generic entry that stored nothing renders no withholding:
        // an empty blob is the store's own fact, not the LSA's hand.
        let empty = row(&entry("EmptyApp", 1, Some("app"), Some(b"")), true, None);
        assert!(!empty.contains("secret"), "{empty}");
        assert!(!empty.contains("without its blob"), "{empty}");
    }

    #[test]
    fn blobs_render_as_text_or_hex_never_as_a_guess() {
        // The wide form the dialog stores, then the plain one.
        let wide: Vec<u8> = "P@ssw0rd"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(secret_value(&wide), "P@ssw0rd");
        assert_eq!(secret_value(b"plain secret"), "plain secret");
        // Binary material keeps the hex prefix so it never reads as a
        // password it never was.
        let binary: &[u8] = &[0x00, 0x41, 0xff, 0x42];
        assert_eq!(secret_value(binary), "hex:0041ff42");
    }

    #[test]
    fn a_secret_carrying_reserved_characters_escapes_into_valid_json() {
        // The escapes the grammar reserves, and one control character
        // the \u form carries -- a secret with a newline renders whole
        // on one row.
        assert_eq!(escape_json("before\"after"), r#"before\"after"#);
        assert_eq!(escape_json(r"a\b"), r"a\\b");
        assert_eq!(escape_json("line\nnext"), r"line\nnext");
        assert_eq!(escape_json("tab\there"), r"tab\there");
        assert_eq!(escape_json("\u{1}"), r"\u0001");
        assert_eq!(escape_json("well-formed"), "well-formed");
        // A secret carrying the grammar's reserved character still
        // renders as the row's last field, closed and whole.
        let row = row(
            &entry("Edge", 1, Some("user"), Some(b"\"quoted\"")),
            true,
            None,
        );
        assert!(row.ends_with(r#""secret":"\"quoted\""}"#), "{row}");
    }

    #[test]
    fn filetimes_render_as_utc_from_the_epoch_the_api_stamps() {
        // The FILETIME epoch itself.
        assert_eq!(filetime_utc(0), "1601-01-01T00:00:00Z");
        // 1970-01-01T00:00:00Z, the Unix epoch the arithmetic pivots
        // on.
        assert_eq!(
            filetime_utc(116_444_736_000_000_000),
            "1970-01-01T00:00:00Z"
        );
        // A leap day, midday: the civil arithmetic's hard case.
        assert_eq!(
            filetime_utc(133_536_816_000_000_000),
            "2024-02-29T12:00:00Z"
        );
        // The year boundary, the month table's other seam.
        assert_eq!(
            filetime_utc(134_116_992_000_000_000),
            "2026-01-01T00:00:00Z"
        );
    }
}
