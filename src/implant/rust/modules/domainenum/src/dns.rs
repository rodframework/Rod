//! A minimal DNS client for the two queries domain discovery needs --
//! SRV (where the domain's services live) and A (where a named host
//! lives) -- over UDP, hand-encoded per RFC 1035. The module carries no
//! resolver crate: a static memfd-exec'd module earns its keep by staying
//! small, and both wire formats here fit in a screenful of code each.
//!
//! The bounds are deliberate: recursion desired, a three-second reply
//! window, and no TCP retry behind a truncated reply (the TC bit) -- a
//! truncated SRV answer is a name server declining, and the sweep
//! reports the gap rather than fighting the infrastructure for it.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

/// A three-second reply window per query. DNS on a reachable resolver
/// answers in milliseconds; three seconds is the "the site is filtering
/// me" line, past which the sweep moves on.
const REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// One SRV record: the service's port and the target host naming it.
#[derive(Debug, PartialEq, Eq)]
pub struct SrvRecord {
    pub port: u16,
    pub target: String,
}

/// One A record's IPv4 address in dotted-quad form.
#[derive(Debug, PartialEq, Eq)]
pub struct ARecord(pub String);

/// The first nameserver in /etc/resolv.conf. A missing file or a file
/// without a nameserver answers None -- the caller decides what a
/// resolver-less host means for its sweep.
pub fn system_nameserver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    nameserver_from(&text)
}

/// The first nameserver a resolv.conf names, port 53 implied. Pure so
/// the parsing is testable without a resolver behind it.
fn nameserver_from(text: &str) -> Option<SocketAddr> {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver") {
            if let Some(host) = fields.next() {
                return (host, 53).to_socket_addrs().ok()?.next();
            }
        }
    }
    None
}

/// Queries SRV records for `name` (for example
/// `_ldap._tcp.dc._msdcs.corp.example.com`) against `server`. Returns the
/// records in reply order, or Err with the one-line cause the finding
/// reports.
pub fn srv(server: SocketAddr, name: &str) -> Result<Vec<SrvRecord>, String> {
    let query = build_query(name, 33);
    let reply = exchange(server, &query)?;
    srv_records(&reply)
}

/// The SRV reading of one reply: every SRV answer's port and target,
/// target names resolved in reply coordinates (they may compress).
fn srv_records(reply: &[u8]) -> Result<Vec<SrvRecord>, String> {
    let answers = parse_answers(reply)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.record_type != 33 {
            continue;
        }
        let target_at = answer.data.start + 6;
        if reply.len() < target_at + 1 {
            continue;
        }
        let port = u16::from_be_bytes([reply[answer.data.start + 4], reply[answer.data.start + 5]]);
        if let Ok((target, _)) = read_name(reply, target_at) {
            records.push(SrvRecord { port, target });
        }
    }
    Ok(records)
}

/// Queries A records for `name`, returning every address the reply
/// carries. Used to give a DC found by name (a logon server) or by SRV
/// target an address the topology view can plot.
pub fn address(server: SocketAddr, name: &str) -> Result<Vec<ARecord>, String> {
    let query = build_query(name, 1);
    let reply = exchange(server, &query)?;
    a_records(&reply)
}

/// The A reading of one reply: every four-byte IN A answer as a dotted
/// quad.
fn a_records(reply: &[u8]) -> Result<Vec<ARecord>, String> {
    let answers = parse_answers(reply)?;
    let mut records = Vec::new();
    for answer in answers {
        if answer.record_type != 1 || answer.data.len() != 4 {
            continue;
        }
        let quad = &reply[answer.data];
        records.push(ARecord(format!(
            "{}.{}.{}.{}",
            quad[0], quad[1], quad[2], quad[3]
        )));
    }
    Ok(records)
}

/// One query, one reply, over UDP with the reply window above.
fn exchange(server: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    socket
        .connect(server)
        .map_err(|e| format!("connect: {e}"))?;
    socket
        .send_to(query, server)
        .map_err(|e| format!("send: {e}"))?;
    let mut reply = [0u8; 512];
    let (read, _) = socket
        .recv_from(&mut reply)
        .map_err(|e| format!("recv: {e}"))?;
    let reply = reply[..read].to_vec();
    // RCODE lives in the header's second word, low nibble of the third
    // byte (flags): 0 is NOERROR, 3 is NXDOMAIN -- everything else is the
    // server's refusal, reported by number.
    let rcode = reply.get(3).map(|b| b & 0x0f).unwrap_or(0xff);
    if rcode != 0 {
        return Err(format!("dns rcode {rcode}"));
    }
    Ok(reply)
}

/// A query header (id 0, recursion desired, one question) plus the
/// question itself: labels, class IN, and the type.
fn build_query(name: &str, record_type: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(17 + name.len());
    query.extend_from_slice(&[
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    encode_name(name, &mut query);
    query.extend_from_slice(&record_type.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);
    query
}

/// Writes `name` as DNS labels: each dot-separated part with a length
/// byte, terminated by the empty label. The empty name is just the
/// terminator.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

struct Answer {
    record_type: u16,
    /// The RDATA's byte range within the reply it came from -- kept as a
    /// range because a compressed name inside the RDATA resolves against
    /// the whole reply, never the slice.
    data: std::ops::Range<usize>,
}

/// Walks the answer section of a reply. The question section is skipped
/// by re-reading the encoded name (a question name may itself carry
/// compression, so the skip must parse it, not scan for zeros).
fn parse_answers(reply: &[u8]) -> Result<Vec<Answer>, String> {
    let questions = u16::from_be_bytes([reply[4], reply[5]]) as usize;
    let answers = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    let mut at = 12;
    for _ in 0..questions {
        let (_, next) = read_name(reply, at)?;
        at = next + 4;
    }
    let mut parsed = Vec::with_capacity(answers);
    for _ in 0..answers {
        let (_, next) = read_name(reply, at)?;
        if reply.len() < next + 10 {
            return Err("truncated answer".into());
        }
        let record_type = u16::from_be_bytes([reply[next], reply[next + 1]]);
        let data_len = u16::from_be_bytes([reply[next + 8], reply[next + 9]]) as usize;
        let start = next + 10;
        if reply.len() < start + data_len {
            return Err("truncated rdata".into());
        }
        parsed.push(Answer {
            record_type,
            data: start..start + data_len,
        });
        at = start + data_len;
    }
    Ok(parsed)
}

/// Reads a wire name starting at `at`, following compression pointers
/// (0xC0-prefixed offsets into the message). Returns the dotted name and
/// the position just past the name **where it started**: a stored name
/// ends at its first pointer (two bytes) or at its terminating empty
/// label, never at wherever the pointer chase landed. Pointer depth is
/// capped: a malformed reply cannot spin the reader forever.
fn read_name(message: &[u8], at: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = at;
    let mut followed = 0;
    let mut end = None;
    loop {
        let length = *message
            .get(pos)
            .ok_or_else(|| "name ran off the message".to_string())?;
        if length == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if length & 0xC0 == 0xC0 {
            let high = (length & 0x3F) as usize;
            let low = *message
                .get(pos + 1)
                .ok_or_else(|| "pointer ran off the message".to_string())?
                as usize;
            followed += 1;
            if followed > 8 {
                return Err("pointer loop".into());
            }
            // The first pointer closes the stored name; hops after it
            // stay inside the chase and never move the outer end.
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = (high << 8) | low;
            continue;
        }
        let start = pos + 1;
        let stop = start + length as usize;
        let label = message
            .get(start..stop)
            .ok_or_else(|| "label ran off the message".to_string())?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = stop;
    }
    Ok((labels.join("."), end.unwrap_or(pos)))
}

// The socket exchanges above are the only blocking surface; the reader is
// pure and the tests exercise it byte for byte. Reading an A record off
// localhost is not a test -- it is a dependency on a resolver.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_srv_query_is_the_expected_bytes() {
        let query = build_query("_ldap._tcp.corp.example.com", 33);
        assert_eq!(&query[..12], &[0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            &query[12..],
            b"\x05_ldap\x04_tcp\x04corp\x07example\x03com\x00\x00\x21\x00\x01"
        );
    }

    #[test]
    fn srv_answers_parse_with_compressed_targets() {
        // One question (name, QTYPE SRV, QCLASS IN), one SRV answer: the
        // answer name and the RDATA target both compress to a pointer at
        // offset 12 (the question's name) -- exactly the shape a real
        // resolver replies with.
        let mut reply = Vec::new();
        reply.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(b"\x05_ldap\x04_tcp\x04corp\x00"); // offset 12
        reply.extend_from_slice(&[0, 33, 0, 1]); // question QTYPE, QCLASS
        reply.extend_from_slice(&[0xC0, 12, 0, 33, 0, 1]); // NAME ptr, SRV, IN
        reply.extend_from_slice(&[0, 0, 0, 60, 0, 8]); // TTL, RDLENGTH 8
        reply.extend_from_slice(&[0, 0, 0, 0, 0, 100]); // priority, weight, port 100
        reply.extend_from_slice(&[0xC0, 12]); // target: pointer to offset 12
        let records = srv_records(&reply).expect("the reply parses");
        assert_eq!(
            records,
            vec![SrvRecord {
                port: 100,
                target: "_ldap._tcp.corp".into()
            }]
        );
    }

    #[test]
    fn address_answers_parse_into_dotted_quads() {
        let mut reply = Vec::new();
        reply.extend_from_slice(&[0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(b"\x04dc01\x04corp\x00");
        reply.extend_from_slice(&[0, 1, 0, 1]); // question QTYPE, QCLASS
        reply.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]); // NAME ptr, A, IN
        reply.extend_from_slice(&[0, 0, 0, 60, 0, 4]);
        reply.extend_from_slice(&[10, 0, 0, 10]);
        let records = a_records(&reply).expect("the reply parses");
        assert_eq!(records, vec![ARecord("10.0.0.10".into())]);
    }

    #[test]
    fn a_pointer_loop_is_refused_rather_than_spun() {
        // A name whose pointer hops between two offsets never terminates;
        // the depth cap turns it into an error.
        let mut reply = vec![0u8; 40];
        reply[3] = 0;
        reply[4] = 0;
        reply[12] = 0xC0;
        reply[13] = 12;
        assert!(read_name(&reply, 12).is_err());
    }

    #[test]
    fn nameservers_come_from_resolv_conf_lines() {
        let server = nameserver_from("nameserver 127.0.0.53\noptions edns0\n");
        assert_eq!(
            server.map(|s| s.to_string()).as_deref(),
            Some("127.0.0.53:53")
        );
        // Comments and the wrong keyword never match; absence is None.
        assert_eq!(
            nameserver_from("# nameserver skipped\nsearch corp.example.com\n"),
            None
        );
    }
}
