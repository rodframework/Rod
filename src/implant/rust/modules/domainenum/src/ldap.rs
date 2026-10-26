//! A minimal LDAP client covering exactly the credential-free root DSE
//! read: connect, anonymous bind (RFC 4513 simple bind with an empty
//! name and password -- the read AD serves to unauthenticated peers),
//! one baseObject search under the empty DN, done. Hand-encoded BER per
//! RFC 4511: the exchange is three short messages, and a resolver crate
//! (or an LDAP stack with a runtime) would outweigh the payload it
//! carries into a static module.
//!
//! The client never attempts authenticated binds or writes: the
//! credential-backed half of domain enumeration (users, groups, ACLs,
//! SPN objects) is the module's next version, and pretending an
//! anonymous read could reach it would be dishonest tradecraft.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The reply window for each LDAP exchange. The root DSE is a metadata
/// read the directory serves from memory; three seconds is the "the DC
/// is not answering strangers" line.
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

/// What the root DSE named: the naming contexts, the forest root, the
/// capabilities, and the functional levels AD publishes there.
#[derive(Debug, Default, PartialEq)]
pub struct RootDse {
    pub naming_contexts: Vec<String>,
    pub root_domain: Option<String>,
    pub capabilities: Vec<String>,
    pub forest_functionality: Option<u32>,
    pub dc_functionality: Option<u32>,
}

/// The well-known AD capability OIDs, so the finding can say `ad: true`
/// rather than quote an OID (MS-ADTS rootDSE).
const AD_OID: &str = "1.2.840.113556.1.4.1851";
const AD_LDAP_OID: &str = "1.2.840.113556.1.4.1791";

impl RootDse {
    /// Whether the answering directory identified itself as Active
    /// Directory through its capability OIDs.
    pub fn is_active_directory(&self) -> bool {
        self.capabilities
            .iter()
            .any(|oid| oid == AD_OID || oid == AD_LDAP_OID)
    }
}

/// Reads the root DSE from `server` (host:port, conventionally port 389)
/// over one connection: bind, search, done.
pub fn root_dse(server: &str) -> Result<RootDse, String> {
    let mut stream = TcpStream::connect(server).map_err(|e| format!("connect {server}: {e}"))?;
    stream
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(REPLY_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;

    let mut buffer = Vec::new();
    let bind = message(1, &encode_tlv(0x60, &bind_request()));
    stream
        .write_all(&bind)
        .map_err(|e| format!("send bind: {e}"))?;
    let (tag, value, _) = read_message(&mut stream, &mut buffer, 1)?;
    check_result(tag, &value, "bind")?;

    let attributes = [
        "namingContexts",
        "rootDomainNamingContext",
        "supportedCapabilities",
        "forestFunctionality",
        "domainControllerFunctionality",
    ];
    let search = message(2, &encode_tlv(0x63, &search_request(attributes)));
    stream
        .write_all(&search)
        .map_err(|e| format!("send search: {e}"))?;

    // Entries first (the root DSE search returns one), then the done.
    let mut dse = RootDse::default();
    loop {
        let (tag, value, _) = read_message(&mut stream, &mut buffer, 2)?;
        match tag {
            0x64 => absorb_entry(&value, &mut dse), // SearchResultEntry
            0x65 => {
                check_result(tag, &value, "search")?;
                return Ok(dse);
            }
            _ => return Err(format!("unexpected ldap reply (tag {tag:#x})")),
        }
    }
}

// ---- wire encoding ----

/// Anonymous bind: version 3, empty DN, empty simple credentials.
fn bind_request() -> Vec<u8> {
    [
        &encode_tlv(0x02, &[3])[..], // version INTEGER 3
        &encode_tlv(0x04, b"")[..],  // name LDAPDN ""
        &encode_tlv(0x80, b"")[..],  // simple ""
    ]
    .concat()
}

/// Base-object search under the empty DN, filter (objectClass=*), asking
/// for exactly the attributes the sweep reads.
fn search_request(attributes: [&str; 5]) -> Vec<u8> {
    let selection: Vec<u8> = attributes
        .iter()
        .flat_map(|a| encode_tlv(0x04, a.as_bytes()))
        .collect();
    [
        &encode_tlv(0x04, b"")[..],            // baseObject ""
        &encode_tlv(0x0A, &[0])[..],           // scope: baseObject
        &encode_tlv(0x0A, &[0])[..],           // derefAliases: never
        &encode_tlv(0x02, &[0])[..],           // sizeLimit: none
        &encode_tlv(0x02, &[0])[..],           // timeLimit: none
        &encode_tlv(0x01, &[0])[..],           // typesOnly: FALSE
        &encode_tlv(0x87, b"objectClass")[..], // filter: present
        &encode_tlv(0x30, &selection)[..],     // attributes
    ]
    .concat()
}

/// One LDAPMessage: SEQUENCE { messageID, protocolOp }, the operation
/// already encoded as its whole TLV.
fn message(id: u32, protocol_op: &[u8]) -> Vec<u8> {
    let bytes = id.to_be_bytes();
    let leading = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    encode_tlv(
        0x30,
        &[&encode_tlv(0x02, &bytes[leading..]), protocol_op].concat(),
    )
}

/// Wraps `content` in one TLV with the given identifier byte and the
/// minimal length prefix it needs (short form, or the 0x8N long form
/// with the fewest length bytes -- the long-form test pins the shape).
fn encode_tlv(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(id);
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let leading = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let significant = 8 - leading;
        out.push(0x80 | significant as u8);
        out.extend_from_slice(&bytes[leading..]);
    }
    out.extend_from_slice(content);
    out
}

// ---- wire decoding ----

/// One decoded TLV: the identifier byte, the content range within its
/// buffer, and the position just past this value.
struct View {
    id: u8,
    range: std::ops::Range<usize>,
    next: usize,
}

fn view(buffer: &[u8], at: usize) -> Result<View, String> {
    let id = *buffer.get(at).ok_or("ber: empty")?;
    let mut cursor = at + 1;
    let first = *buffer.get(cursor).ok_or("ber: missing length")?;
    let length = if first < 0x80 {
        cursor += 1;
        first as usize
    } else {
        let significant = (first & 0x7F) as usize;
        if significant == 0 || significant > 4 {
            return Err("ber: unsupported length form".into());
        }
        cursor += 1;
        let mut length = 0usize;
        for _ in 0..significant {
            let byte = *buffer.get(cursor).ok_or("ber: truncated length")?;
            length = (length << 8) | byte as usize;
            cursor += 1;
        }
        length
    };
    let start = cursor;
    let stop = start
        .checked_add(length)
        .ok_or_else(|| "ber: length overflow".to_string())?;
    if buffer.len() < stop {
        return Err("ber: truncated value".into());
    }
    Ok(View {
        id,
        range: start..stop,
        next: stop,
    })
}

/// Reads one complete LDAPMessage off the stream into `buffer`, growing
/// it until the message's own TLV lengths say it is whole. Returns the
/// protocol operation's identifier byte, its content, and the message id.
fn read_message(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    expected_id: u32,
) -> Result<(u8, Vec<u8>, usize), String> {
    loop {
        if !buffer.is_empty() {
            if let Ok(whole) = parse_message(buffer, expected_id) {
                buffer.drain(..whole.2);
                return Ok(whole);
            }
        }
        let mut chunk = [0u8; 1024];
        let read = stream.read(&mut chunk).map_err(|e| format!("recv: {e}"))?;
        if read == 0 {
            return Err("connection closed mid-message".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Parses one LDAPMessage out of `buffer` if it is whole, returning the
/// protocol op's id byte, its content bytes, and the total message
/// length (the caller's drain amount). A truncated message is an Err the
/// reader loop turns into "keep reading".
fn parse_message(buffer: &[u8], expected_id: u32) -> Result<(u8, Vec<u8>, usize), String> {
    let outer = view(buffer, 0)?;
    let id_view = view(buffer, outer.range.start)?;
    let mut id = 0u32;
    for byte in &buffer[id_view.range] {
        id = (id << 8) | *byte as u32;
    }
    if id != expected_id {
        return Err(format!("message id {id}, expected {expected_id}"));
    }
    let op = view(buffer, id_view.next)?;
    let tag = op.id;
    Ok((tag, buffer[op.range].to_vec(), outer.next))
}

/// Reads the LDAPResult out of a bind response or search done: result
/// code, matched DN, diagnostic message -- success is code 0.
fn check_result(_tag: u8, value: &[u8], stage: &str) -> Result<(), String> {
    let code_view = view(value, 0)?;
    let mut code = 0u32;
    for byte in &value[code_view.range] {
        code = (code << 8) | *byte as u32;
    }
    if code == 0 {
        return Ok(());
    }
    // The diagnostic message is the third field; reading it is best
    // effort -- the code is the decision.
    let diagnostic = view(value, code_view.next)
        .and_then(|dn| view(value, dn.next))
        .map(|message| String::from_utf8_lossy(&value[message.range]).into_owned())
        .unwrap_or_default();
    Err(format!(
        "{stage} refused (ldap result {code}): {diagnostic}"
    ))
}

/// Folds one SearchResultEntry into the root DSE under construction.
fn absorb_entry(value: &[u8], dse: &mut RootDse) {
    // objectName, then PartialAttributeList (SEQUENCE OF SEQUENCE).
    let Ok(name) = view(value, 0) else { return };
    let Ok(list) = view(value, name.next) else {
        return;
    };
    let mut at = list.range.start;
    while at < list.range.end {
        let Ok(attribute) = view(value, at) else {
            break;
        };
        at = attribute.next;
        let Ok(type_view) = view(value, attribute.range.start) else {
            break;
        };
        let attribute_name = String::from_utf8_lossy(&value[type_view.range]).into_owned();
        let Ok(values_view) = view(value, type_view.next) else {
            break;
        };
        let mut values = Vec::new();
        let mut vat = values_view.range.start;
        while vat < values_view.range.end {
            let Ok(one) = view(value, vat) else { break };
            values.push(String::from_utf8_lossy(&value[one.range]).into_owned());
            vat = one.next;
        }
        match attribute_name.as_str() {
            "namingContexts" => dse.naming_contexts.extend(values),
            "rootDomainNamingContext" => dse.root_domain = values.into_iter().next(),
            "supportedCapabilities" => dse.capabilities.extend(values),
            "forestFunctionality" => {
                dse.forest_functionality = values.first().and_then(|v| v.parse().ok())
            }
            "domainControllerFunctionality" => {
                dse.dc_functionality = values.first().and_then(|v| v.parse().ok())
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_anonymous_bind_is_the_documented_eleven_bytes() {
        // SEQUENCE(60) { INTEGER 3, OCTET "", [0] "" }.
        assert_eq!(
            bind_request(),
            vec![0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]
        );
    }

    #[test]
    fn a_message_carries_its_id_and_operation() {
        let bind = message(1, &encode_tlv(0x60, &bind_request()));
        // LDAPMessage SEQUENCE wraps the id INTEGER then the operation.
        let outer = view(&bind, 0).expect("whole");
        let id = view(&bind, outer.range.start).expect("id");
        assert_eq!(&bind[id.range], &[1]);
        let op = view(&bind, id.next).expect("op");
        assert_eq!(op.id, 0x60);
        assert_eq!(outer.next, bind.len());
    }

    #[test]
    fn long_form_lengths_encode_and_read_back() {
        let content = vec![0u8; 300];
        let tlv = encode_tlv(0x04, &content);
        assert_eq!(&tlv[..3], &[0x04, 0x82, 0x01]); // 0x82: two length bytes, 0x0100+0x2c=300
        let parsed = view(&tlv, 0).expect("whole");
        assert_eq!(parsed.range.len(), 300);
    }

    #[test]
    fn a_root_dse_entry_folds_into_the_struct() {
        // Build one SearchResultEntry by hand: objectName "", then one
        // PartialAttributeList carrying namingContexts twice and the AD
        // capability OID.
        let attribute = |name: &str, values: &[&str]| -> Vec<u8> {
            let vals: Vec<u8> = values
                .iter()
                .flat_map(|v| encode_tlv(0x04, v.as_bytes()))
                .collect();
            // PartialAttribute: SEQUENCE { type, SET OF values }.
            encode_tlv(
                0x30,
                &[
                    &encode_tlv(0x04, name.as_bytes())[..],
                    &encode_tlv(0x31, &vals)[..],
                ]
                .concat(),
            )
        };
        let entry_content = [
            &encode_tlv(0x04, b"")[..],
            &encode_tlv(
                0x30,
                &[
                    &attribute("namingContexts", &["DC=corp,DC=example,DC=com"])[..],
                    &attribute("supportedCapabilities", &[AD_OID])[..],
                    &attribute("rootDomainNamingContext", &["DC=example,DC=com"])[..],
                    &attribute("forestFunctionality", &["7"])[..],
                ]
                .concat(),
            )[..],
        ]
        .concat();
        let value = entry_content;
        let mut dse = RootDse::default();
        absorb_entry(&value, &mut dse);
        assert_eq!(dse.naming_contexts, vec!["DC=corp,DC=example,DC=com"]);
        assert_eq!(dse.root_domain.as_deref(), Some("DC=example,DC=com"));
        assert_eq!(dse.forest_functionality, Some(7));
        assert!(dse.is_active_directory());
    }

    #[test]
    fn a_refusal_reports_its_code() {
        // LDAPResult { code 49 (invalid credentials), "", "" }.
        let result = [
            &encode_tlv(0x0A, &[49])[..],
            &encode_tlv(0x04, b"")[..],
            &encode_tlv(0x04, b"80090308: LdapErr")[..],
        ]
        .concat();
        let error = check_result(0x61, &result, "bind").expect_err("code 49 refuses");
        assert!(error.contains("ldap result 49"), "{error}");
        assert!(error.contains("LdapErr"), "{error}");
    }
}
