//! The teamserver's userspace WireGuard termination (architecture.md
//! Sec 8, Sec 15.3 ADR-004).
//!
//! One [`Router`] is one listener's tunnel state: the server's static
//! X25519 key, one boringtun [`Tunn`] per known peer, and the
//! receiver-index demux that maps an established session's data packets
//! back to their peer. The WireGuard mac1 field cannot do that demux --
//! it is keyed by the responder's static public key, so every peer of
//! one server produces the same mac -- which leaves two spec-shaped
//! routes: handshakes are matched by bounded trial decryption (the
//! encrypted static only opens under the right peer's exchange), and
//! data packets carry the receiver index the server itself assigned
//! when it answered the handshake.
//!
//! The C ABI at the bottom of this file is the .NET seam: the caller
//! owns the UDP socket and the frame paths, hands received datagrams to
//! [`ffi::rod_wg_inject`], and sends whatever network bytes come back.
//! Inner payloads cross both ways wrapped as minimal IPv4 packets
//! (protocol 253, the experimental/testing allocation): boringtun's
//! receive path validates the inner header, so the wrap is a
//! requirement of reusing it, and the marker protocol keeps the
//! carriage self-describing on both sides.

use std::collections::HashMap;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;

/// The inner carriage's IP protocol marker (RFC 3692 experimental range).
pub const INNER_PROTOCOL: u8 = 253;

/// One peer's tunnel.
struct Peer {
    tunn: Tunn,
}

/// The errors the router reports; the C ABI flattens them to codes.
#[derive(Debug, PartialEq, Eq)]
pub enum RouterError {
    UnknownPeer,
    PeerExists,
    NoSession,
    InvalidKey,
}

/// What [`Router::inject`] did with a datagram.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Injected {
    /// Bytes to send back on the socket (a handshake response, a cookie
    /// reply, a keepalive). Empty when the datagram produced none.
    pub network: Vec<u8>,
    /// The inner payload a data packet carried, IP wrap stripped.
    pub tunnel: Vec<u8>,
}

/// One listener's WireGuard state: the server key and the peer set.
pub struct Router {
    server_private: [u8; 32],
    peers: HashMap<[u8; 32], Peer>,
    /// Receiver index -> peer public key, rebuilt as handshakes complete.
    /// A stale entry only ever misses and drops.
    indexes: HashMap<u32, [u8; 32]>,
}

const MAX_PACKET: usize = 65535;

impl Router {
    /// Build a router over the server's static private key (32 raw
    /// bytes). The key is held for the peers added later; boringtun's
    /// `Tunn` consumes a private key per peer by value.
    pub fn new(server_private: [u8; 32]) -> Router {
        Router {
            server_private,
            peers: HashMap::new(),
            indexes: HashMap::new(),
        }
    }

    /// Add a peer by its static public key (32 raw bytes).
    pub fn add_peer(&mut self, peer_public: [u8; 32]) -> Result<(), RouterError> {
        if self.peers.contains_key(&peer_public) {
            return Err(RouterError::PeerExists);
        }
        let public = x25519::PublicKey::from(peer_public);
        let private = x25519::StaticSecret::from(self.server_private);
        let tunn = Tunn::new(private, public, None, None, 0, None);
        self.peers.insert(peer_public, Peer { tunn });
        Ok(())
    }

    /// Drop a peer; its index entries go stale and simply miss.
    pub fn remove_peer(&mut self, peer_public: &[u8; 32]) -> bool {
        self.peers.remove(peer_public).is_some()
    }

    /// Feed one received UDP datagram. Handshake initiations are matched
    /// across the peer set by bounded trial decryption; data packets by
    /// receiver index. Cookie replies and responses are dropped -- the
    /// server never initiates, so nothing it sent expects an answer.
    pub fn inject(&mut self, datagram: &[u8]) -> Injected {
        let mut result = Injected::default();
        if datagram.len() < 4 {
            return result;
        }
        match datagram[0] {
            1 => self.inject_initiation(datagram, &mut result),
            4 => self.inject_data(datagram, &mut result),
            _ => {}
        }
        result
    }

    fn inject_initiation(&mut self, datagram: &[u8], result: &mut Injected) {
        let mut scratch = [0u8; MAX_PACKET];
        for public in self.peers.keys().copied().collect::<Vec<_>>() {
            let Some(peer) = self.peers.get_mut(&public) else {
                continue;
            };
            if let TunnResult::WriteToNetwork(written) =
                peer.tunn.decapsulate(None, datagram, &mut scratch)
            {
                result.network = written.to_vec();
                // The response's sender index is the receiver index on
                // every data packet of the session it opened.
                if result.network.len() >= 8 {
                    let index =
                        u32::from_le_bytes(result.network[4..8].try_into().expect("four bytes"));
                    self.indexes.insert(index, public);
                }
                return;
            }
        }
    }

    fn inject_data(&mut self, datagram: &[u8], result: &mut Injected) {
        if datagram.len() < 8 {
            return;
        }
        let index = u32::from_le_bytes(datagram[4..8].try_into().expect("four bytes"));
        let Some(public) = self.indexes.get(&index).copied() else {
            return;
        };
        let Some(peer) = self.peers.get_mut(&public) else {
            return;
        };
        let mut scratch = [0u8; MAX_PACKET];
        // A data packet may demand follow-up network output (a
        // keepalive); the decapsulated payload is what the carriage
        // consumes. The drain contract repeats with an empty datagram.
        let mut feed = Some(datagram);
        for _ in 0..4 {
            let src = feed.take().unwrap_or_default();
            match peer.tunn.decapsulate(None, src, &mut scratch) {
                TunnResult::WriteToNetwork(written) => {
                    if result.network.is_empty() {
                        result.network = written.to_vec();
                    }
                    feed = Some(&[]);
                }
                TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                    if let Some(payload) = unwrap_inner(inner) {
                        result.tunnel = payload.to_vec();
                    }
                    // Anything else is not this carriage's traffic; drop.
                    return;
                }
                _ => return,
            }
        }
    }

    /// Seal one inner payload to a peer as a network datagram. Requires a
    /// session established by that peer's handshake: the server only
    /// answers, so the answer rides the session the question opened --
    /// and boringtun with no session would queue the packet and emit a
    /// fresh initiation instead, which is a shape the caller cannot use.
    pub fn send(&mut self, peer_public: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, RouterError> {
        let Some(peer) = self.peers.get_mut(peer_public) else {
            return Err(RouterError::UnknownPeer);
        };
        let packet = wrap_inner(payload);
        let mut scratch = [0u8; MAX_PACKET];
        match peer.tunn.encapsulate(&packet, &mut scratch) {
            // Without a session boringtun emits a handshake initiation
            // (type 1) and queues the payload; that is not an answer.
            TunnResult::WriteToNetwork(written) if written.first() == Some(&4) => {
                Ok(written.to_vec())
            }
            _ => Err(RouterError::NoSession),
        }
    }

    /// Drive one peer's timers; keepalive or retry bytes land in the
    /// returned network output. Returns `None` when the peer is unknown.
    pub fn tick(&mut self, peer_public: &[u8; 32]) -> Option<Vec<u8>> {
        let peer = self.peers.get_mut(peer_public)?;
        let mut scratch = [0u8; MAX_PACKET];
        match peer.tunn.update_timers(&mut scratch) {
            TunnResult::WriteToNetwork(written) => Some(written.to_vec()),
            _ => None,
        }
    }
}

/// Wrap a payload as the carriage's minimal IPv4 packet: protocol 253,
/// honest total length, addresses in the documentation range. boringtun
/// hands up only well-formed inner IP, so the wrap is the contract.
pub fn wrap_inner(payload: &[u8]) -> Vec<u8> {
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

/// Strip the carriage's IPv4 wrap; `None` when the bytes are not this
/// carriage's shape (short header, wrong version, wrong protocol).
pub fn unwrap_inner(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != INNER_PROTOCOL {
        return None;
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = total.min(packet.len());
    (end > 20).then(|| &packet[20..end])
}

/// The C ABI the teamserver P/Invokes. Every function catches unwinds:
/// a panic crossing the boundary into a managed caller is undefined
/// behavior, so it flattens to the error code instead.
pub mod ffi {
    use super::*;

    /// Status codes shared with the managed side.
    pub const OK: i32 = 0;
    pub const ERR_UNKNOWN_PEER: i32 = -1;
    pub const ERR_PEER_EXISTS: i32 = -2;
    pub const ERR_NO_SESSION: i32 = -3;
    pub const ERR_OUTPUT_TOO_SMALL: i32 = -4;
    pub const ERR_INVALID_KEY: i32 = -5;
    pub const ERR_PANIC: i32 = -6;
    pub const ERR_NULL: i32 = -7;

    fn guard<T>(f: impl FnOnce() -> T, on_panic: T) -> T {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(on_panic)
    }

    /// One listener's router, over the server's 32-byte private key.
    ///
    /// # Safety
    ///
    /// `server_private` must point to 32 readable bytes for the duration
    /// of the call; the returned handle belongs to [`rod_wg_free`] alone.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_new(server_private: *const u8, len: usize) -> *mut Router {
        guard(
            || {
                if server_private.is_null() || len != 32 {
                    return std::ptr::null_mut();
                }
                let slice = unsafe { std::slice::from_raw_parts(server_private, 32) };
                let mut key = [0u8; 32];
                key.copy_from_slice(slice);
                Box::into_raw(Box::new(Router::new(key)))
            },
            std::ptr::null_mut(),
        )
    }

    /// Drop a router constructed by [`rod_wg_new`].
    ///
    /// # Safety
    ///
    /// `router` must be a handle from [`rod_wg_new`] not yet freed, and
    /// no other thread may hold it.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_free(router: *mut Router) {
        guard(
            || {
                if !router.is_null() {
                    drop(unsafe { Box::from_raw(router) });
                }
            },
            (),
        )
    }

    fn key_at(ptr: *const u8) -> Option<[u8; 32]> {
        if ptr.is_null() {
            return None;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, 32) };
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Some(key)
    }

    /// Register a peer by its 32-byte static public key.
    ///
    /// # Safety
    ///
    /// `router` must be a live handle and `peer_public` must point to 32
    /// readable bytes for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_peer_add(router: *mut Router, peer_public: *const u8) -> i32 {
        guard(
            || match (router.as_mut(), key_at(peer_public)) {
                (Some(router), Some(peer)) => match router.add_peer(peer) {
                    Ok(()) => OK,
                    Err(RouterError::PeerExists) => ERR_PEER_EXISTS,
                    Err(_) => ERR_INVALID_KEY,
                },
                _ => ERR_NULL,
            },
            ERR_PANIC,
        )
    }

    /// Remove a peer by its 32-byte static public key.
    ///
    /// # Safety
    ///
    /// `router` must be a live handle and `peer_public` must point to 32
    /// readable bytes for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_peer_remove(
        router: *mut Router,
        peer_public: *const u8,
    ) -> i32 {
        guard(
            || match (router.as_mut(), key_at(peer_public)) {
                (Some(router), Some(peer)) => i32::from(!router.remove_peer(&peer)),
                _ => ERR_NULL,
            },
            ERR_PANIC,
        )
    }

    /// Feed one received datagram. Network bytes to send back land in
    /// `net_out` (capacity `net_cap`), the carried inner payload in
    /// `tun_out` (capacity `tun_cap`); the written lengths land in the
    /// out-params, cleared to zero first in every case.
    ///
    /// # Safety
    ///
    /// `router` must be a live handle; `datagram` must point to
    /// `datagram_len` readable bytes and the out buffers to their
    /// declared capacities, for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_inject(
        router: *mut Router,
        datagram: *const u8,
        datagram_len: usize,
        net_out: *mut u8,
        net_cap: usize,
        net_len: *mut usize,
        tun_out: *mut u8,
        tun_cap: usize,
        tun_len: *mut usize,
    ) -> i32 {
        guard(
            || {
                let router = match router.as_mut() {
                    Some(r) => r,
                    None => return ERR_NULL,
                };
                if let Some(n) = net_len.as_mut() {
                    *n = 0;
                }
                if let Some(t) = tun_len.as_mut() {
                    *t = 0;
                }
                if datagram.is_null() || net_out.is_null() || tun_out.is_null() {
                    return ERR_NULL;
                }
                let datagram = unsafe { std::slice::from_raw_parts(datagram, datagram_len) };
                let injected = router.inject(datagram);
                if injected.network.len() > net_cap || injected.tunnel.len() > tun_cap {
                    return ERR_OUTPUT_TOO_SMALL;
                }
                unsafe {
                    if !injected.network.is_empty() {
                        std::ptr::copy_nonoverlapping(
                            injected.network.as_ptr(),
                            net_out,
                            injected.network.len(),
                        );
                    }
                    if !injected.tunnel.is_empty() {
                        std::ptr::copy_nonoverlapping(
                            injected.tunnel.as_ptr(),
                            tun_out,
                            injected.tunnel.len(),
                        );
                    }
                }
                if let Some(n) = net_len.as_mut() {
                    *n = injected.network.len();
                }
                if let Some(t) = tun_len.as_mut() {
                    *t = injected.tunnel.len();
                }
                OK
            },
            ERR_PANIC,
        )
    }

    /// Seal one inner payload to a peer; the datagram lands in `out`.
    ///
    /// # Safety
    ///
    /// `router` must be a live handle; `peer_public` must point to 32
    /// readable bytes, `payload` to `payload_len`, `out` to `out_cap`,
    /// for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_send(
        router: *mut Router,
        peer_public: *const u8,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        guard(
            || {
                let router = match router.as_mut() {
                    Some(r) => r,
                    None => return ERR_NULL,
                };
                if let Some(n) = out_len.as_mut() {
                    *n = 0;
                }
                if peer_public.is_null() || payload.is_null() || out.is_null() {
                    return ERR_NULL;
                }
                let key = key_at(peer_public).expect("checked above");
                let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
                let datagram = match router.send(&key, payload) {
                    Ok(d) => d,
                    Err(RouterError::UnknownPeer) => return ERR_UNKNOWN_PEER,
                    Err(RouterError::NoSession) => return ERR_NO_SESSION,
                    Err(_) => return ERR_NO_SESSION,
                };
                if datagram.len() > out_cap {
                    return ERR_OUTPUT_TOO_SMALL;
                }
                unsafe { std::ptr::copy_nonoverlapping(datagram.as_ptr(), out, datagram.len()) };
                if let Some(n) = out_len.as_mut() {
                    *n = datagram.len();
                }
                OK
            },
            ERR_PANIC,
        )
    }

    /// Drive a peer's timers; any keepalive or retry datagram lands in
    /// `out`. A tick that produced nothing returns OK with length zero.
    ///
    /// # Safety
    ///
    /// `router` must be a live handle; `peer_public` must point to 32
    /// readable bytes and `out` to `out_cap`, for the duration of the
    /// call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_tick(
        router: *mut Router,
        peer_public: *const u8,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        guard(
            || {
                let router = match router.as_mut() {
                    Some(r) => r,
                    None => return ERR_NULL,
                };
                if let Some(n) = out_len.as_mut() {
                    *n = 0;
                }
                if peer_public.is_null() || out.is_null() {
                    return ERR_NULL;
                }
                let key = key_at(peer_public).expect("checked above");
                let Some(datagram) = router.tick(&key) else {
                    return ERR_UNKNOWN_PEER;
                };
                if datagram.len() > out_cap {
                    return ERR_OUTPUT_TOO_SMALL;
                }
                unsafe { std::ptr::copy_nonoverlapping(datagram.as_ptr(), out, datagram.len()) };
                if let Some(n) = out_len.as_mut() {
                    *n = datagram.len();
                }
                OK
            },
            ERR_PANIC,
        )
    }
}

/// The client-side helper the managed integration tests drive before the
/// implant's own carriage exists (cargo feature `test-client`): one
/// initiator tunnel against a server key, the same poll discipline the
/// implant will run -- handshake exchange first, payloads over the
/// session after. Never compiled into a release library.
#[cfg(feature = "test-client")]
pub mod test_client {
    use super::*;
    use std::sync::Mutex;

    struct Client {
        tunn: Tunn,
    }

    /// One client tunnel: the implant's stand-in for tests.
    pub struct WgTestClient {
        inner: Mutex<Client>,
    }

    const MAX_PACKET: usize = 65535;

    impl WgTestClient {
        /// Build a client over its 32-byte static private key against the
        /// server's 32-byte static public key.
        pub fn new(client_private: [u8; 32], server_public: [u8; 32]) -> WgTestClient {
            let private = x25519::StaticSecret::from(client_private);
            let public = x25519::PublicKey::from(server_public);
            WgTestClient {
                inner: Mutex::new(Client {
                    tunn: Tunn::new(private, public, None, None, 0, None),
                }),
            }
        }

        /// One contact out: a handshake initiation when no session stands,
        /// else the wrapped payload as a data packet.
        pub fn contact(&self, payload: &[u8]) -> Vec<u8> {
            let mut client = self.inner.lock().expect("client lock");
            let mut buf = [0u8; MAX_PACKET];
            match client.tunn.encapsulate(&wrap_inner(payload), &mut buf) {
                TunnResult::WriteToNetwork(written) => written.to_vec(),
                _ => Vec::new(),
            }
        }

        /// Feed a server datagram; the drained inner payload, when the
        /// datagram carried one, comes back.
        pub fn receive(&self, datagram: &[u8]) -> Vec<u8> {
            let mut client = self.inner.lock().expect("client lock");
            let mut buf = [0u8; MAX_PACKET];
            let mut feed = Some(datagram);
            for _ in 0..4 {
                let src = feed.take().unwrap_or_default();
                match client.tunn.decapsulate(None, src, &mut buf) {
                    TunnResult::WriteToNetwork(_) => feed = Some(&[]),
                    TunnResult::WriteToTunnelV4(inner, _)
                    | TunnResult::WriteToTunnelV6(inner, _) => {
                        return unwrap_inner(inner).map(|p| p.to_vec()).unwrap_or_default();
                    }
                    _ => return Vec::new(),
                }
            }
            Vec::new()
        }
    }

    /// The client's static public key for its private half, for the peer
    /// registration on the router side.
    ///
    /// # Safety
    ///
    /// `private` must point to 32 readable bytes and `out` to 32 writable
    /// bytes, for the duration of the call.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_test_public(private: *const u8, out: *mut u8) -> i32 {
        if private.is_null() || out.is_null() {
            return -7;
        }
        let slice = unsafe { std::slice::from_raw_parts(private, 32) };
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        let secret = x25519::StaticSecret::from(key);
        let public = x25519::PublicKey::from(&secret);
        unsafe {
            std::ptr::copy_nonoverlapping(public.as_bytes().as_ptr(), out, 32);
        }
        0
    }

    /// Build a test client over the private/server-public key pair.
    ///
    /// # Safety
    ///
    /// Each key pointer must address 32 readable bytes for the duration
    /// of the call; the returned handle belongs to
    /// [`rod_wg_test_free`] alone.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_test_new(
        client_private: *const u8,
        server_public: *const u8,
    ) -> *mut WgTestClient {
        let read = |ptr: *const u8| -> Option<[u8; 32]> {
            if ptr.is_null() {
                return None;
            }
            let slice = unsafe { std::slice::from_raw_parts(ptr, 32) };
            let mut key = [0u8; 32];
            key.copy_from_slice(slice);
            Some(key)
        };
        match (read(client_private), read(server_public)) {
            (Some(private), Some(public)) => {
                Box::into_raw(Box::new(WgTestClient::new(private, public)))
            }
            _ => std::ptr::null_mut(),
        }
    }

    /// One contact out; the datagram lands in `out`.
    ///
    /// # Safety
    ///
    /// `client` must be a live handle; `payload` must point to
    /// `payload_len` readable bytes and `out` to `out_cap` writable ones.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_test_contact(
        client: *mut WgTestClient,
        payload: *const u8,
        payload_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        if client.is_null() || payload.is_null() || out.is_null() {
            return -7;
        }
        let client = unsafe { &*client };
        let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
        let datagram = client.contact(payload);
        if datagram.len() > out_cap {
            return -4;
        }
        unsafe { std::ptr::copy_nonoverlapping(datagram.as_ptr(), out, datagram.len()) };
        if let Some(n) = out_len.as_mut() {
            *n = datagram.len();
        }
        0
    }

    /// Feed a server datagram; the drained payload lands in `out`.
    ///
    /// # Safety
    ///
    /// `client` must be a live handle; `datagram` must point to
    /// `datagram_len` readable bytes and `out` to `out_cap` writable ones.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_test_receive(
        client: *mut WgTestClient,
        datagram: *const u8,
        datagram_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> i32 {
        if client.is_null() || datagram.is_null() || out.is_null() {
            return -7;
        }
        let client = unsafe { &*client };
        let datagram = unsafe { std::slice::from_raw_parts(datagram, datagram_len) };
        let payload = client.receive(datagram);
        if payload.len() > out_cap {
            return -4;
        }
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), out, payload.len()) };
        if let Some(n) = out_len.as_mut() {
            *n = payload.len();
        }
        0
    }

    /// Drop a test client.
    ///
    /// # Safety
    ///
    /// `client` must be a handle from [`rod_wg_test_new`] not yet freed.
    #[no_mangle]
    pub unsafe extern "C" fn rod_wg_test_free(client: *mut WgTestClient) {
        if !client.is_null() {
            drop(unsafe { Box::from_raw(client) });
        }
    }
}
