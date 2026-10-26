//! The local half of domain discovery: what the host itself knows about
//! the domain it joined, read from documented local sources before any
//! packet leaves the machine. Windows answers from the session
//! environment (`USERDNSDOMAIN` and friends -- the sources a domain-joined
//! session writes by default); Linux answers from the identity client
//! configuration (`krb5.conf`, `sssd.conf`, `smb.conf`) and
//! `/etc/resolv.conf`'s search list. Every field is optional and every
//! answer carries its source -- a field the host cannot name a source for
//! is a field the module reports as absent, not guessed.

/// The domain posture the local sources name.
#[derive(Default)]
pub struct DomainContext {
    /// The DNS domain (for example `corp.example.com`).
    pub dns_domain: Option<String>,
    /// The NetBIOS domain name (for example `CORP`).
    pub netbios_domain: Option<String>,
    /// The Kerberos realm (usually the DNS domain uppercased).
    pub realm: Option<String>,
    /// The logon server the session used, UNC form (`\\DC01`) on Windows.
    pub logon_server: Option<String>,
    /// The host the findings will be attributed to.
    pub host: String,
    /// The primary source the context came from, reported on the finding.
    pub source: &'static str,
}

impl DomainContext {
    /// Reads the context from the platform's local sources: the session
    /// environment on Windows, the identity-client configuration files on
    /// Linux. Pure reads -- no network, no process spawns.
    pub fn read() -> DomainContext {
        if cfg!(windows) {
            read_windows()
        } else {
            read_linux()
        }
    }
}

fn read_windows() -> DomainContext {
    let dns_domain = std::env::var("USERDNSDOMAIN")
        .ok()
        .filter(|v| !v.is_empty());
    // The realm is the uppercased DNS domain when the session names one;
    // USERDOMAIN is NetBIOS, not a realm, so it does not stand in.
    let realm = dns_domain.as_ref().map(|domain| domain.to_uppercase());
    DomainContext {
        host: hostname(),
        dns_domain,
        netbios_domain: std::env::var("USERDOMAIN").ok().filter(|v| !v.is_empty()),
        realm,
        logon_server: std::env::var("LOGONSERVER")
            .ok()
            .filter(|v| !v.is_empty() && v != r"\\"),
        source: "env",
    }
}

fn read_linux() -> DomainContext {
    let krb5 = read_file("/etc/krb5.conf");
    let sssd = read_file("/etc/sssd/sssd.conf");
    let smb = read_file("/etc/samba/smb.conf");
    let resolv = read_file("/etc/resolv.conf");

    // krb5.conf's default_realm names the realm directly; the domain_realm
    // and sssd sections are the DNS-domain sources. Realm wins over a
    // guessed case mapping because it is the configured fact.
    let realm = ini_value(&krb5, "libdefaults", "default_realm")
        .or_else(|| ini_value(&smb, "global", "realm"));
    let dns_domain = section_suffix(&sssd, "domain")
        .map(|domain| domain.to_ascii_lowercase())
        .or_else(|| search_domain(&resolv));
    DomainContext {
        host: hostname(),
        dns_domain,
        netbios_domain: ini_value(&smb, "global", "workgroup"),
        realm,
        logon_server: None,
        source: "krb5/sssd/resolv",
    }
}

/// The first search-list domain in a resolv.conf, falling back to the
/// `domain` entry, lowercased (search lists are case-insensitive and the
/// downstream queries are lowercase protocols). Single-label entries are
/// local suffixes, not a domain posture -- a name without a dot is not a
/// DNS domain this sweep can query.
fn search_domain(resolv: &str) -> Option<String> {
    for line in resolv.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("search") | Some("domain") => {
                if let Some(first) = fields.next() {
                    if first.contains('.') {
                        return Some(first.to_ascii_lowercase());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// One `key = value` pair out of an INI section (`section` may hold a
/// section name prefix for sssd's `domain/corp` sections, or a whole
/// section name for krb5's file format).
fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = header == section || header.starts_with(&format!("{section}/"));
            continue;
        }
        if in_section {
            if let Some((name, value)) = line.split_once('=') {
                if name.trim().eq_ignore_ascii_case(key) {
                    let value = value.trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

/// The name half of sssd's `domain/<name>` sections: the joined domain
/// is the section header itself, not any key under it.
fn section_suffix(text: &str, prefix: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(header) = line
            .trim()
            .strip_prefix('[')
            .and_then(|l| l.strip_suffix(']'))
        {
            if let Some(name) = header.strip_prefix(&format!("{prefix}/")) {
                let name = name.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

fn read_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The hostname without libc's gethostname: /etc/hostname on Unix (the
/// file every mainstream distribution writes), the COMPUTERNAME variable
/// on Windows -- the same platform sources the hostenum module reads.
pub fn hostname() -> String {
    if cfg!(windows) {
        return std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    }
    std::fs::read_to_string("/etc/hostname")
        .map(|text| text.trim().to_string())
        .ok()
        .filter(|text| !text.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_search_list_names_the_dns_domain() {
        let resolv = "# managed\nnameserver 10.0.0.53\nsearch corp.example.com lab\n";
        assert_eq!(search_domain(resolv).as_deref(), Some("corp.example.com"));
        assert_eq!(
            search_domain("domain old.example.com\n").as_deref(),
            Some("old.example.com")
        );
        // Single-label search entries are local suffixes, not a domain.
        assert_eq!(search_domain("search internal\n"), None);
        assert_eq!(search_domain("nameserver 10.0.0.53\n"), None);
    }

    #[test]
    fn ini_values_read_across_the_identity_files_dialects() {
        // krb5.conf: key = value under [libdefaults].
        let krb5 = "[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n";
        assert_eq!(
            ini_value(krb5, "libdefaults", "default_realm").as_deref(),
            Some("CORP.EXAMPLE.COM")
        );
        // sssd: the joined domain is the section name itself.
        let sssd = "[domain/corp.example.com]\nid_provider = ad\n";
        assert_eq!(
            section_suffix(sssd, "domain").as_deref(),
            Some("corp.example.com")
        );
        // smb.conf: workgroup under [global].
        let smb = "[global]\n  workgroup = CORP\n  realm = CORP.EXAMPLE.COM\n";
        assert_eq!(
            ini_value(smb, "global", "workgroup").as_deref(),
            Some("CORP")
        );
        assert_eq!(
            ini_value(smb, "global", "realm").as_deref(),
            Some("CORP.EXAMPLE.COM")
        );
        // Absent stays absent, never a guess.
        assert_eq!(ini_value(smb, "global", "missing"), None);
    }
}
