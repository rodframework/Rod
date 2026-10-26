//! A minimal LDAP client covering what the domain-discovery sweep reads:
//! connect, bind (anonymous or simple), a base-object root DSE read, and
//! paged subtree searches. Hand-encoded BER per RFC 4511 -- the exchange
//! stays a handful of short messages, and a resolver crate (or an LDAP
//! stack with a runtime) would outweigh the payload it carries into a
//! static module.
//!
//! The paged-results control (RFC 2696) is not optional equipment: AD
//! caps a non-paged reply at its MaxPageSize (1500 objects by default)
//! and a real domain's user list outruns that, so every search rides the
//! control and the caller walks the cookies. The client never attempts
//! writes -- the sweep is a read, and pretending otherwise would be
//! dishonest tradecraft.
//!
//! The bind is a simple bind on the cleartext port: the secret crosses
//! the implant-to-DC path in the open unless the site's own IPsec or a
//! TLS front seals it. That exposure is the module's declared OPSEC
//! note (the manifest's `[opsec]`), not a fact to hide in code.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The reply window for each LDAP exchange. The reads here are metadata
/// the directory serves from memory; three seconds is the "the DC is not
/// answering" line.
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

/// The paged-results control (RFC 2696).
const PAGED_CONTROL: &str = "1.2.840.113556.1.4.319";

/// The page size the sweep requests: small enough that a page of
/// security descriptors stays a modest buffer, large enough that a
/// domain-sized read takes dozens of round trips, not thousands.
pub(crate) const PAGE_SIZE: u32 = 500;

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

    /// The domain naming context: the first context that starts at a
    /// `DC=` component (the configuration and schema contexts start at
    /// `CN=`). The authenticated searches base themselves here.
    pub fn default_naming_context(&self) -> Option<&str> {
        self.naming_contexts
            .iter()
            .find(|context| context.starts_with("DC="))
            .map(String::as_str)
    }

    fn absorb(&mut self, entry: &Entry) {
        // First-wins across the entries a reply carries: the root DSE
        // read is one entry, but the fold stays well-behaved if a
        // directory ever answers with more.
        for value in entry.values("namingContexts") {
            self.naming_contexts
                .push(String::from_utf8_lossy(value).into_owned());
        }
        for value in entry.values("supportedCapabilities") {
            self.capabilities
                .push(String::from_utf8_lossy(value).into_owned());
        }
        if self.root_domain.is_none() {
            self.root_domain = entry.first_text("rootDomainNamingContext");
        }
        if self.forest_functionality.is_none() {
            self.forest_functionality = entry
                .first_text("forestFunctionality")
                .and_then(|t| t.parse().ok());
        }
        if self.dc_functionality.is_none() {
            self.dc_functionality = entry
                .first_text("domainControllerFunctionality")
                .and_then(|t| t.parse().ok());
        }
    }
}

/// One search-result entry: its DN and attributes, values kept as bytes
/// because the sweep reads both text (`samAccountName`) and binary
/// (`objectSid`, `nTSecurityDescriptor`) attributes off the same wire.
#[derive(Debug, Default, PartialEq)]
pub struct Entry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<Vec<u8>>)>,
}

impl Entry {
    /// Every value of the exact attribute name.
    pub fn values(&self, name: &str) -> Vec<&[u8]> {
        self.attributes
            .iter()
            .filter(|(attribute, _)| attribute == name)
            .flat_map(|(_, values)| values.iter().map(Vec::as_slice))
            .collect()
    }

    /// Every value of an attribute including its `name;range=N-M` forms,
    /// and whether a ranged form was served: AD answers a request for
    /// `member` on a large group as `member;range=0-1499`, and the
    /// caller must know the list was the first range, not the whole one.
    pub fn values_with_range(&self, name: &str) -> (Vec<&[u8]>, bool) {
        let mut values = Vec::new();
        let mut ranged = false;
        for (attribute, entries) in &self.attributes {
            let (base, _) = attribute
                .split_once(';')
                .unwrap_or((attribute.as_str(), ""));
            if base == name {
                values.extend(entries.iter().map(Vec::as_slice));
                ranged |= attribute.contains(';');
            }
        }
        (values, ranged)
    }

    /// The first value of an attribute as text.
    pub fn first_text(&self, name: &str) -> Option<String> {
        self.values(name)
            .first()
            .map(|value| String::from_utf8_lossy(value).into_owned())
    }
}

/// One search filter: the three shapes the sweep needs -- presence,
/// equality (binary-safe; the assertion value rides an OCTET STRING, so
/// an `objectSid` lookup needs no string escaping), and the two
/// junctions to compose them.
pub(crate) enum Filter {
    Present(String),
    Equal(String, Vec<u8>),
    And(Vec<Filter>),
    Or(Vec<Filter>),
}

/// The search scope the sweep reads: the base object itself (the domain
/// root) or the whole subtree beneath it.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SearchScope {
    Base,
    Subtree,
}

/// One page of a search's outcome: the entries read, the cookie the
/// next page continues from (`None` when the read is complete), and the
/// nonzero result code the directory ended on when it ended on one --
/// the entries read up to a refusal stand; discarding them would turn a
/// capped read into a fake empty one.
pub(crate) struct PageOutcome {
    pub entries: Vec<Entry>,
    pub cookie: Option<Vec<u8>>,
    pub stopped: Option<u32>,
}

/// One LDAP connection: the stream, the undrained reply bytes, and the
/// next message id. Message ids are per-connection and monotonic; every
/// request pairs with the reply carrying its id.
pub(crate) struct Connection {
    stream: TcpStream,
    buffer: Vec<u8>,
    next_id: u32,
}

impl Connection {
    pub(crate) fn connect(server: &str) -> Result<Connection, String> {
        let stream = TcpStream::connect(server).map_err(|e| format!("connect {server}: {e}"))?;
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .map_err(|e| format!("set timeout: {e}"))?;
        stream
            .set_write_timeout(Some(REPLY_TIMEOUT))
            .map_err(|e| format!("set timeout: {e}"))?;
        Ok(Connection {
            stream,
            buffer: Vec::new(),
            next_id: 1,
        })
    }

    /// RFC 4513 simple bind with an empty name and password -- the read
    /// AD serves to unauthenticated peers.
    pub(crate) fn bind_anonymous(&mut self) -> Result<(), String> {
        let id = self.send(0x60, &anonymous_bind_request(), &[])?;
        let (tag, value, _) = self.read(id)?;
        check_result(tag, &value, "bind")
    }

    /// Simple bind with the task's credential: the name is whatever
    /// principal form the operator rode (UPN or `DOMAIN\user` -- AD
    /// accepts both as the bind name).
    pub(crate) fn bind_simple(&mut self, name: &str, password: &str) -> Result<(), String> {
        let id = self.send(0x60, &simple_bind_request(name, password), &[])?;
        let (tag, value, _) = self.read(id)?;
        check_result(tag, &value, "bind")
    }

    /// The base-object root DSE read: naming contexts, forest root,
    /// capabilities, functional levels.
    pub(crate) fn root_dse(&mut self) -> Result<RootDse, String> {
        let attributes = [
            "namingContexts",
            "rootDomainNamingContext",
            "supportedCapabilities",
            "forestFunctionality",
            "domainControllerFunctionality",
        ];
        let outcome = self.search_page(
            "",
            SearchScope::Base,
            &Filter::Present("objectClass".into()),
            &attributes,
            &[],
        )?;
        let mut dse = RootDse::default();
        for entry in &outcome.entries {
            dse.absorb(entry);
        }
        Ok(dse)
    }

    /// One page of a paged search under `base`. An empty `cookie` starts
    /// the read; the outcome's cookie continues it.
    pub(crate) fn search_page(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &Filter,
        attributes: &[&str],
        cookie: &[u8],
    ) -> Result<PageOutcome, String> {
        let controls = paged_control(PAGE_SIZE, cookie);
        let request = search_request(base, scope, filter, attributes);
        let id = self.send(0x63, &request, &controls)?;

        let mut entries = Vec::new();
        loop {
            let (tag, value, rest) = self.read(id)?;
            match tag {
                0x64 => entries.push(parse_entry(&value)),
                0x65 => {
                    let (code, cookie) = parse_done(&value, &rest)?;
                    if code != 0 && entries.is_empty() {
                        let diagnostic = diagnostic_of(&value);
                        return Err(format!("search refused (ldap result {code}): {diagnostic}"));
                    }
                    return Ok(PageOutcome {
                        entries,
                        cookie,
                        stopped: (code != 0).then_some(code),
                    });
                }
                0x73 => {} // searchResRef: a referral the sweep does not chase
                other => return Err(format!("unexpected ldap reply (tag {other:#x})")),
            }
        }
    }

    fn send(&mut self, op_tag: u8, protocol_op: &[u8], controls: &[u8]) -> Result<u32, String> {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = message(id, op_tag, protocol_op, controls);
        self.stream
            .write_all(&bytes)
            .map_err(|e| format!("send: {e}"))?;
        Ok(id)
    }

    /// Reads one complete reply, returning its protocol operation's tag
    /// and content plus the bytes trailing the operation inside the
    /// message -- where the LDAPMessage carries its optional controls.
    fn read(&mut self, expected_id: u32) -> Result<(u8, Vec<u8>, Vec<u8>), String> {
        loop {
            if !self.buffer.is_empty() {
                if let Ok(whole) = parse_message(&self.buffer, expected_id) {
                    self.buffer.drain(..whole.3);
                    return Ok((whole.0, whole.1, whole.2));
                }
            }
            let mut chunk = [0u8; 4096];
            let read = self
                .stream
                .read(&mut chunk)
                .map_err(|e| format!("recv: {e}"))?;
            if read == 0 {
                return Err("connection closed mid-message".into());
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Reads the root DSE from `server` (host:port, conventionally port 389)
/// over one anonymous connection: the shape the credential-free `info`
/// scope runs.
pub fn root_dse(server: &str) -> Result<RootDse, String> {
    let mut connection = Connection::connect(server)?;
    connection.bind_anonymous()?;
    connection.root_dse()
}

// ---- wire encoding ----

/// Anonymous bind: version 3, empty DN, empty simple credentials.
fn anonymous_bind_request() -> Vec<u8> {
    [
        &encode_tlv(0x02, &[3])[..], // version INTEGER 3
        &encode_tlv(0x04, b"")[..],  // name LDAPDN ""
        &encode_tlv(0x80, b"")[..],  // simple ""
    ]
    .concat()
}

fn simple_bind_request(name: &str, password: &str) -> Vec<u8> {
    [
        &encode_tlv(0x02, &[3])[..],                // version INTEGER 3
        &encode_tlv(0x04, name.as_bytes())[..],     // name
        &encode_tlv(0x80, password.as_bytes())[..], // simple
    ]
    .concat()
}

fn search_request(base: &str, scope: SearchScope, filter: &Filter, attributes: &[&str]) -> Vec<u8> {
    let selection: Vec<u8> = attributes
        .iter()
        .flat_map(|a| encode_tlv(0x04, a.as_bytes()))
        .collect();
    let scope_byte = match scope {
        SearchScope::Base => 0u8,
        SearchScope::Subtree => 2,
    };
    [
        &encode_tlv(0x04, base.as_bytes())[..], // baseObject
        &encode_tlv(0x0A, &[scope_byte])[..],   // scope
        &encode_tlv(0x0A, &[0])[..],            // derefAliases: never
        &encode_tlv(0x02, &[0])[..],            // sizeLimit: none (pages bound it)
        &encode_tlv(0x02, &[0])[..],            // timeLimit: none
        &encode_tlv(0x01, &[0])[..],            // typesOnly: FALSE
        &encode_filter(filter)[..],             // filter
        &encode_tlv(0x30, &selection)[..],      // attributes
    ]
    .concat()
}

fn encode_filter(filter: &Filter) -> Vec<u8> {
    match filter {
        Filter::Present(name) => encode_tlv(0x87, name.as_bytes()),
        Filter::Equal(name, value) => encode_tlv(
            0xA3,
            &[
                &encode_tlv(0x04, name.as_bytes())[..],
                &encode_tlv(0x04, value)[..],
            ]
            .concat(),
        ),
        Filter::And(children) => encode_tlv(
            0xA0,
            &children
                .iter()
                .map(encode_filter)
                .collect::<Vec<_>>()
                .concat(),
        ),
        Filter::Or(children) => encode_tlv(
            0xA1,
            &children
                .iter()
                .map(encode_filter)
                .collect::<Vec<_>>()
                .concat(),
        ),
    }
}

/// The paged-results control, wrapped as the LDAPMessage's trailing
/// `[0]` controls arm: non-critical (a control-ignorant directory then
/// answers the plain search instead of refusing), page size, cookie.
fn paged_control(size: u32, cookie: &[u8]) -> Vec<u8> {
    let value = encode_tlv(
        0x30,
        &[&encode_uint(0x02, size)[..], &encode_tlv(0x04, cookie)[..]].concat(),
    );
    let control = encode_tlv(
        0x30,
        &[
            &encode_tlv(0x04, PAGED_CONTROL.as_bytes())[..],
            &encode_tlv(0x01, &[0])[..], // criticality FALSE
            &encode_tlv(0x04, &value)[..],
        ]
        .concat(),
    );
    encode_tlv(0xA0, &encode_tlv(0x30, &control))
}

/// One LDAPMessage: SEQUENCE { messageID, protocolOp, controls [0] },
/// the operation carried as its whole TLV and the controls arm
/// pre-encoded (empty for none).
fn message(id: u32, op_tag: u8, protocol_op: &[u8], controls: &[u8]) -> Vec<u8> {
    encode_tlv(
        0x30,
        &[
            &encode_uint(0x02, id)[..],
            &encode_tlv(op_tag, protocol_op)[..],
            controls,
        ]
        .concat(),
    )
}

/// An unsigned INTEGER TLV in its minimal big-endian form.
fn encode_uint(id: u8, value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let leading = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    encode_tlv(id, &bytes[leading..])
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

/// Parses one LDAPMessage out of `buffer` if it is whole: the protocol
/// op's id byte and content, the bytes trailing the operation inside
/// the message (the optional controls arm), and the total message
/// length (the caller's drain amount). A truncated message is an Err
/// the reader loop turns into "keep reading".
fn parse_message(buffer: &[u8], expected_id: u32) -> Result<(u8, Vec<u8>, Vec<u8>, usize), String> {
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
    let controls = buffer[op.next..outer.range.end].to_vec();
    Ok((tag, buffer[op.range].to_vec(), controls, outer.next))
}

/// Reads the LDAPResult out of a bind response or search done: result
/// code, matched DN, diagnostic message -- success is code 0.
fn check_result(_tag: u8, value: &[u8], stage: &str) -> Result<(), String> {
    let code = result_code(value).ok_or("ber: empty result")?;
    if code == 0 {
        return Ok(());
    }
    let diagnostic = diagnostic_of(value);
    Err(format!(
        "{stage} refused (ldap result {code}): {diagnostic}"
    ))
}

/// The result code off an LDAPResult's content.
fn result_code(value: &[u8]) -> Option<u32> {
    let code_view = view(value, 0).ok()?;
    let mut code = 0u32;
    for byte in &value[code_view.range] {
        code = (code << 8) | *byte as u32;
    }
    Some(code)
}

/// The diagnostic message, third field of an LDAPResult -- best effort,
/// the code is the decision.
fn diagnostic_of(value: &[u8]) -> String {
    view(value, 0)
        .and_then(|code| view(value, code.next))
        .and_then(|dn| view(value, dn.next))
        .map(|message| String::from_utf8_lossy(&value[message.range]).into_owned())
        .unwrap_or_default()
}

/// One searchResDone: its result code and the paged-results cookie, when
/// the done carried one at all -- a cookie with bytes means another page
/// stands behind it.
fn parse_done(value: &[u8], controls: &[u8]) -> Result<(u32, Option<Vec<u8>>), String> {
    let code = result_code(value).ok_or("ber: empty result")?;
    Ok((code, paged_cookie(controls)))
}

/// The paged-results cookie out of the LDAPMessage's controls arm:
/// `[0] { SEQUENCE OF Control }`, each Control a SEQUENCE of the type
/// OCTET STRING, optional criticality, optional value. Returns None for
/// every shape that is not the paged control carrying a non-empty
/// cookie -- including the final page's empty cookie.
fn paged_cookie(controls: &[u8]) -> Option<Vec<u8>> {
    let wrapper = view(controls, 0).ok()?;
    if wrapper.id != 0xA0 {
        return None;
    }
    let list = view(controls, wrapper.range.start).ok()?;
    if list.id != 0x30 {
        return None;
    }
    let mut at = list.range.start;
    while at < list.range.end {
        let control = view(controls, at).ok()?;
        at = control.next;
        let type_view = view(controls, control.range.start).ok()?;
        if &controls[type_view.range] != PAGED_CONTROL.as_bytes() {
            continue;
        }
        // Optional criticality, then the control value OCTET STRING.
        let mut field = view(controls, type_view.next).ok()?;
        if field.id == 0x01 {
            field = view(controls, field.next).ok()?;
        }
        if field.id != 0x04 {
            return None;
        }
        let inner = view(controls, field.range.start).ok()?;
        let size = view(controls, inner.range.start).ok()?;
        let cookie = view(controls, size.next).ok()?;
        if cookie.id == 0x04 && !cookie.range.is_empty() {
            return Some(controls[cookie.range].to_vec());
        }
        return None;
    }
    None
}

/// Folds one SearchResultEntry's content into a generic Entry: the DN,
/// then the PartialAttributeList (SEQUENCE OF SEQUENCE). Malformed
/// content yields what parsed -- the sweep reports the rows it read.
fn parse_entry(value: &[u8]) -> Entry {
    let mut entry = Entry::default();
    let Ok(name) = view(value, 0) else {
        return entry;
    };
    let Ok(list) = view(value, name.next) else {
        return entry;
    };
    entry.dn = String::from_utf8_lossy(&value[name.range]).into_owned();
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
            let Ok(one) = view(value, vat) else {
                break;
            };
            values.push(value[one.range].to_vec());
            vat = one.next;
        }
        entry.attributes.push((attribute_name, values));
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_anonymous_bind_is_the_documented_eleven_bytes() {
        // SEQUENCE(60) { INTEGER 3, OCTET "", [0] "" }.
        assert_eq!(
            anonymous_bind_request(),
            vec![0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]
        );
    }

    #[test]
    fn a_simple_bind_carries_the_credential_verbatim() {
        // Version 3, the principal as the bind name, the secret in the
        // simple arm -- a secret with spaces rides the OCTET STRING
        // whole, exactly as the trailing pass parameter delivered it.
        assert_eq!(
            simple_bind_request("jdoe@corp.example.com", "s3cret two"),
            vec![0x02, 0x01, 0x03]
                .into_iter()
                .chain(encode_tlv(0x04, b"jdoe@corp.example.com"))
                .chain(encode_tlv(0x80, b"s3cret two"))
                .collect::<Vec<u8>>()
        );
    }

    #[test]
    fn a_message_carries_its_id_operation_and_controls() {
        let controls = paged_control(PAGE_SIZE, &[]);
        let bind = message(1, 0x60, &anonymous_bind_request(), &controls);
        // LDAPMessage SEQUENCE wraps the id INTEGER, the operation, and
        // then -- trailing inside the message -- the [0] controls arm.
        let outer = view(&bind, 0).expect("whole");
        let id = view(&bind, outer.range.start).expect("id");
        assert_eq!(&bind[id.range], &[1]);
        let op = view(&bind, id.next).expect("op");
        assert_eq!(op.id, 0x60);
        assert_eq!(bind[op.next], 0xA0, "controls ride after the operation");
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
    fn filters_encode_to_their_ber_shapes() {
        // Presence: context-7 with the attribute's bytes.
        assert_eq!(
            encode_filter(&Filter::Present("servicePrincipalName".into())),
            encode_tlv(0x87, b"servicePrincipalName")
        );
        // Equality: [3] SEQUENCE { attr, value } -- binary values ride
        // the OCTET STRING without escaping, the objectSid lookup's
        // whole trick.
        assert_eq!(
            encode_filter(&Filter::Equal("objectSid".into(), vec![1, 2, 0xff])),
            encode_tlv(
                0xA3,
                &[
                    &encode_tlv(0x04, b"objectSid")[..],
                    &encode_tlv(0x04, &[1, 2, 0xff])[..]
                ]
                .concat()
            )
        );
        // Junctions: [0] and, [1] or, children concatenated.
        let compound = Filter::Or(vec![
            Filter::And(vec![
                Filter::Equal("objectCategory".into(), b"person".to_vec()),
                Filter::Equal("objectClass".into(), b"user".to_vec()),
            ]),
            Filter::Equal("objectClass".into(), b"group".to_vec()),
        ]);
        let encoded = encode_filter(&compound);
        assert_eq!(encoded[0], 0xA1);
        let inner = view(&encoded, 0).expect("whole");
        assert_eq!(encoded[inner.range.start], 0xA0);
    }

    #[test]
    fn the_paged_control_names_the_rfc_oid_and_carries_the_cookie() {
        let first = paged_control(500, &[]);
        // The control rides the [0] arm; its type is the RFC 2696 OID
        // and its value opens with the page size.
        assert!(first.starts_with(&[0xA0]), "controls arm");
        assert!(
            first
                .windows(PAGED_CONTROL.len())
                .any(|w| w == PAGED_CONTROL.as_bytes()),
            "the OID rides the control: {first:?}"
        );
        assert!(
            first.windows(3).any(|w| w == [0x02, 0x02, 0x01]),
            "size 500 = 0x01F4"
        );
        assert!(first.windows(2).any(|w| w == [0x04, 0x00]), "empty cookie");

        // A cookie round-trips through the reply-side parser: the done
        // message's controls arm, rebuilt by hand as the DC would send
        // it, yields the cookie bytes back.
        let cookie = b"page-2".to_vec();
        let value = encode_tlv(
            0x30,
            &[&encode_uint(0x02, 500)[..], &encode_tlv(0x04, &cookie)[..]].concat(),
        );
        let control = encode_tlv(
            0x30,
            &[
                &encode_tlv(0x04, PAGED_CONTROL.as_bytes())[..],
                &encode_tlv(0x01, &[0])[..],
                &encode_tlv(0x04, &value)[..],
            ]
            .concat(),
        );
        let controls = encode_tlv(0xA0, &encode_tlv(0x30, &control));
        assert_eq!(paged_cookie(&controls), Some(cookie));

        // The final page's empty cookie reads as None: no page follows.
        let last = encode_tlv(0xA0, &encode_tlv(0x30, &control_without_cookie()));
        assert_eq!(paged_cookie(&last), None);
        // So does a controls arm for some other control entirely.
        let foreign = encode_tlv(0xA0, &encode_tlv(0x30, &encode_tlv(0x04, b"1.2.3.4.5")[..]));
        assert_eq!(paged_cookie(&foreign), None);
    }

    fn control_without_cookie() -> Vec<u8> {
        let value = encode_tlv(
            0x30,
            &[&encode_uint(0x02, 500)[..], &encode_tlv(0x04, b"")[..]].concat(),
        );
        encode_tlv(
            0x30,
            &[
                &encode_tlv(0x04, PAGED_CONTROL.as_bytes())[..],
                &encode_tlv(0x01, &[0])[..],
                &encode_tlv(0x04, &value)[..],
            ]
            .concat(),
        )
    }

    #[test]
    fn an_entry_folds_into_dn_and_attributes() {
        // One SearchResultEntry by hand: objectName, then a
        // PartialAttributeList carrying namingContexts twice and the AD
        // capability OID -- the same shape the root DSE serves.
        let attribute = |name: &str, values: &[&str]| -> Vec<u8> {
            let vals: Vec<u8> = values
                .iter()
                .flat_map(|v| encode_tlv(0x04, v.as_bytes()))
                .collect();
            encode_tlv(
                0x30,
                &[
                    &encode_tlv(0x04, name.as_bytes())[..],
                    &encode_tlv(0x31, &vals)[..],
                ]
                .concat(),
            )
        };
        let value = [
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
        let entry = parse_entry(&value);
        assert_eq!(entry.dn, "");
        assert_eq!(
            entry.values("namingContexts"),
            vec![b"DC=corp,DC=example,DC=com".as_slice()]
        );
        assert_eq!(
            entry.first_text("rootDomainNamingContext").as_deref(),
            Some("DC=example,DC=com")
        );

        let mut dse = RootDse::default();
        dse.absorb(&entry);
        assert_eq!(dse.naming_contexts, vec!["DC=corp,DC=example,DC=com"]);
        assert_eq!(dse.root_domain.as_deref(), Some("DC=example,DC=com"));
        assert_eq!(dse.forest_functionality, Some(7));
        assert!(dse.is_active_directory());
        assert_eq!(
            dse.default_naming_context(),
            Some("DC=corp,DC=example,DC=com")
        );
    }

    #[test]
    fn ranged_values_read_under_their_suffixed_name() {
        // AD answers a large group's member request as
        // member;range=0-1499 -- the suffix is not a different
        // attribute, and the range fact rides back with the values.
        let ranged = Entry {
            dn: "CN=Domain Users,DC=corp,DC=example,DC=com".into(),
            attributes: vec![(
                "member;range=0-1499".into(),
                vec![b"CN=a,DC=corp".to_vec(), b"CN=b,DC=corp".to_vec()],
            )],
        };
        let (values, capped) = ranged.values_with_range("member");
        assert_eq!(values.len(), 2);
        assert!(capped);
        let plain = Entry {
            dn: String::new(),
            attributes: vec![("member".into(), vec![b"CN=a".to_vec()])],
        };
        let (values, capped) = plain.values_with_range("member");
        assert_eq!(values.len(), 1);
        assert!(!capped);
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

    #[test]
    fn a_done_with_entries_and_a_code_keeps_the_entries() {
        // The searchResDone carries result 4 (sizeLimitExceeded) with
        // entries already read: the code parses out beside a diagnostic,
        // and the caller keeps what was read -- parse_done reports both
        // halves without inventing a refusal the entries contradict.
        let done = [
            &encode_tlv(0x0A, &[4])[..],
            &encode_tlv(0x04, b"")[..],
            &encode_tlv(0x04, b"size limit exceeded")[..],
        ]
        .concat();
        let (code, cookie) = parse_done(&done, &[]).expect("done parses");
        assert_eq!(code, 4);
        assert_eq!(cookie, None);
        assert!(diagnostic_of(&done).contains("size limit"));
    }
}
