// End-to-end tests over the router: a client tunnel driven the way the
// implant's carriage will drive one (plain boringtun, poll discipline),
// against the server-side router the teamserver P/Invokes into.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;
use rod_wg::{unwrap_inner, wrap_inner, Router};

fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret = x25519::StaticSecret::from([seed; 32]);
    let public = x25519::PublicKey::from(&secret);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(secret.as_bytes());
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_bytes());
    (priv_bytes, pub_bytes)
}

fn client_tunn(server_public: [u8; 32], client_private: [u8; 32]) -> Tunn {
    let private = x25519::StaticSecret::from(client_private);
    let public = x25519::PublicKey::from(server_public);
    Tunn::new(private, public, None, None, 0, None)
}

/// Drive one client-side contact: encapsulate the payload over the
/// standing session. The first contact of a client is the handshake
/// exchange (`client_connect`); a payload only rides a session.
fn client_contact(client: &mut Tunn, payload: &[u8], buf: &mut [u8; 65535]) -> Vec<u8> {
    match client.encapsulate(&wrap_inner(payload), buf) {
        TunnResult::WriteToNetwork(written) => written.to_vec(),
        other => panic!("client contact failed: {:?}", other),
    }
}

/// Run the handshake exchange against the router and leave the client
/// with a standing session: one initiation out, one response back.
fn client_connect(client: &mut Tunn, router: &mut Router, buf: &mut [u8; 65535]) {
    let datagram = match client.encapsulate(&[], buf) {
        TunnResult::WriteToNetwork(written) => written.to_vec(),
        other => panic!("client handshake failed: {:?}", other),
    };
    let injected = router.inject(&datagram);
    assert!(
        !injected.network.is_empty(),
        "the handshake answer goes back"
    );
    client_receive(client, &injected.network, buf);
}

/// Feed the client a server datagram and drain the follow-up cycle.
fn client_receive(client: &mut Tunn, datagram: &[u8], buf: &mut [u8; 65535]) {
    match client.decapsulate(None, datagram, buf) {
        TunnResult::Done => {}
        TunnResult::WriteToNetwork(_) => {
            // A keepalive or queued packet: drain until quiet.
            for _ in 0..4 {
                if let TunnResult::Done = client.decapsulate(None, &[], buf) {
                    break;
                }
            }
        }
        other => panic!("client receive failed: {:?}", other),
    }
}

#[test]
fn handshake_carries_a_payload_both_ways() {
    let (server_priv, server_pub) = keys(9);
    let (client_priv, client_pub) = keys(7);
    let mut router = Router::new(server_priv);
    router.add_peer(client_pub).expect("peer added");

    let mut client = client_tunn(server_pub, client_priv);
    let mut buf = [0u8; 65535];

    // The handshake exchange precedes any payload.
    client_connect(&mut client, &mut router, &mut buf);
    let datagram = client_contact(&mut client, b"poll-body", &mut buf);
    let injected = router.inject(&datagram);
    assert_eq!(injected.tunnel, b"poll-body".to_vec());
    let answer = router
        .send(&client_pub, b"tasking-body")
        .expect("session answers");
    let mut seen = None;
    match client.decapsulate(None, &answer, &mut buf) {
        TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
            seen = unwrap_inner(inner).map(|p| p.to_vec());
        }
        TunnResult::Done => {
            if let TunnResult::WriteToTunnelV4(inner, _) = client.decapsulate(None, &[], &mut buf) {
                seen = unwrap_inner(inner).map(|p| p.to_vec());
            }
        }
        other => panic!("client answer failed: {:?}", other),
    }
    assert_eq!(seen, Some(b"tasking-body".to_vec()));
}

#[test]
fn subsequent_contacts_ride_the_session_without_handshakes() {
    let (server_priv, server_pub) = keys(9);
    let (client_priv, client_pub) = keys(7);
    let mut router = Router::new(server_priv);
    router.add_peer(client_pub).expect("peer added");
    let mut client = client_tunn(server_pub, client_priv);
    let mut buf = [0u8; 65535];

    client_connect(&mut client, &mut router, &mut buf);

    // The second contact is a data packet: no handshake answer returns.
    let second = client_contact(&mut client, b"two", &mut buf);
    assert_eq!(second[0], 4, "a data packet, not an initiation");
    let injected = router.inject(&second);
    assert!(injected.network.is_empty());
    assert_eq!(injected.tunnel, b"two".to_vec());
}

#[test]
fn an_initiation_from_an_unknown_peer_drops_whole() {
    let (server_priv, server_pub) = keys(9);
    let (_stranger_priv, stranger_pub) = keys(11);
    let mut router = Router::new(server_priv);

    // The stranger is not in the peer set; its initiation finds no key.
    let private = x25519::StaticSecret::from([13; 32]);
    let mut stranger = Tunn::new(
        private,
        x25519::PublicKey::from(server_pub),
        None,
        None,
        0,
        None,
    );
    let mut buf = [0u8; 65535];
    let datagram = match stranger.encapsulate(&wrap_inner(b"x"), &mut buf) {
        TunnResult::WriteToNetwork(written) => written.to_vec(),
        other => panic!("stranger contact failed: {:?}", other),
    };
    let _ = stranger_pub;
    let injected = router.inject(&datagram);
    assert!(injected.network.is_empty());
    assert!(injected.tunnel.is_empty());
}

#[test]
fn two_peers_demux_by_their_own_handshakes() {
    let (server_priv, server_pub) = keys(9);
    let (client_a_priv, client_a_pub) = keys(7);
    let (client_b_priv, client_b_pub) = keys(8);
    let mut router = Router::new(server_priv);
    router.add_peer(client_a_pub).expect("peer a");
    router.add_peer(client_b_pub).expect("peer b");

    let mut a = client_tunn(server_pub, client_a_priv);
    let mut b = client_tunn(server_pub, client_b_priv);
    let mut buf = [0u8; 65535];

    client_connect(&mut a, &mut router, &mut buf);
    let datagram_a = client_contact(&mut a, b"from-a", &mut buf);
    assert_eq!(router.inject(&datagram_a).tunnel, b"from-a".to_vec());

    client_connect(&mut b, &mut router, &mut buf);
    let datagram_b = client_contact(&mut b, b"from-b", &mut buf);
    assert_eq!(router.inject(&datagram_b).tunnel, b"from-b".to_vec());

    // Answers land on the right session.
    for (client, public, marker) in [
        (&mut a, client_a_pub, b"a-answer"),
        (&mut b, client_b_pub, b"b-answer"),
    ] {
        let answer = router.send(&public, marker).expect("session answers");
        let mut seen = None;
        match client.decapsulate(None, &answer, &mut buf) {
            TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                seen = unwrap_inner(inner).map(|p| p.to_vec());
            }
            TunnResult::Done => {
                if let TunnResult::WriteToTunnelV4(inner, _) =
                    client.decapsulate(None, &[], &mut buf)
                {
                    seen = unwrap_inner(inner).map(|p| p.to_vec());
                }
            }
            other => panic!("answer failed: {:?}", other),
        }
        assert_eq!(seen, Some(marker.to_vec()));
    }
}

#[test]
fn send_without_a_session_refuses() {
    let (server_priv, _server_pub) = keys(9);
    let (_client_priv, client_pub) = keys(7);
    let mut router = Router::new(server_priv);
    router.add_peer(client_pub).expect("peer added");
    // No handshake has arrived: the server has no session to answer on.
    assert!(router.send(&client_pub, b"early").is_err());
}

#[test]
fn peer_removal_cuts_the_peer_off() {
    let (server_priv, server_pub) = keys(9);
    let (client_priv, client_pub) = keys(7);
    let mut router = Router::new(server_priv);
    router.add_peer(client_pub).expect("peer added");
    let mut client = client_tunn(server_pub, client_priv);
    let mut buf = [0u8; 65535];

    client_connect(&mut client, &mut router, &mut buf);
    assert!(router.remove_peer(&client_pub));
    assert!(router.send(&client_pub, b"gone").is_err());
    // A fresh initiation from the removed peer finds no key again.
    let mut fresh = client_tunn(server_pub, client_priv);
    let datagram = client_contact(&mut fresh, b"again", &mut buf);
    let injected = router.inject(&datagram);
    assert!(injected.network.is_empty());
    assert!(injected.tunnel.is_empty());
}

#[test]
fn the_inner_wrap_round_trips_and_rejects_foreign_shapes() {
    let wrapped = wrap_inner(b"payload");
    assert_eq!(unwrap_inner(&wrapped), Some(&b"payload"[..]));
    // A TCP-shaped inner packet is not this carriage's traffic.
    let mut tcp = wrap_inner(b"payload");
    tcp[9] = 6;
    assert_eq!(unwrap_inner(&tcp), None);
    // Short or non-v4 bytes are not either.
    assert_eq!(unwrap_inner(&[0x45, 0, 0, 1]), None);
    assert_eq!(
        unwrap_inner(&[0x60, 0, 0, 1, 0, 0, 0, 0, 0, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        None
    );
}
