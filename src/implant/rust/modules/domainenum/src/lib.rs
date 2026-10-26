//! The domain-discovery plugin module (architecture.md Sec 5.4): the
//! credential-free half of domain recon in one verb, `recon.domainenum`.
//! It reads the host's own domain posture (context sources on disk and
//! in the environment), locates the domain controllers (the logon server
//! on Windows, DNS SRV records on Linux), and asks the first answering
//! DC for the anonymous LDAP root DSE -- the naming contexts, forest
//! root, and functional levels every directory serves to strangers.
//!
//! Every finding is one JSON line in the recon grammar
//! (extending/modules.md): `host` required, the DC rows carry `port` and
//! `service` so the topology view plots them like any portscan finding,
//! and every row names the `source` it was read from. What the module
//! cannot reach without credentials it does not guess: the
//! authenticated half of enumeration (users, groups, ACLs, SPN objects)
//! is the module's next version, and the refusal to fake it is the
//! tradecraft boundary this one holds.

mod context;
mod dns;
mod ldap;

use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

pub struct DomainEnum;

impl Plugin for DomainEnum {
    fn name(&self) -> &'static str {
        "domainenum"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("recon.domainenum", domainenum)]
    }
}

/// The sweep's scopes, read from the task's argument string: a bare
/// scope token (`spns`), a `scope=` assignment, or empty for the whole
/// sweep. An argument the grammar does not know refuses the task rather
/// than half-sweeping under a typo.
#[derive(Debug, PartialEq, Eq)]
enum Scope {
    All,
    Info,
    Trusts,
    Spns,
}

fn parse_scope(arguments: &str) -> Result<Scope, String> {
    let arguments = arguments.trim();
    if arguments.is_empty() {
        return Ok(Scope::All);
    }
    let scope = arguments
        .strip_prefix("scope=")
        .unwrap_or(arguments)
        .trim()
        .to_ascii_lowercase();
    match scope.as_str() {
        "all" => Ok(Scope::All),
        "info" => Ok(Scope::Info),
        "trusts" => Ok(Scope::Trusts),
        "spns" => Ok(Scope::Spns),
        other => Err(format!(
            "recon.domainenum: unknown scope '{other}' (all, info, trusts, spns)"
        )),
    }
}

fn domainenum(arguments: &str) -> Result<String, String> {
    let scope = parse_scope(arguments)?;
    let context = context::DomainContext::read();
    let mut lines = Vec::new();

    // The posture line always comes first: it is the local read, it
    // never fails, and everything after it interprets against it.
    lines.push(finding(
        &context.host,
        &[
            ("domain", opt_text(context.dns_domain.as_deref())),
            ("netbios", opt_text(context.netbios_domain.as_deref())),
            ("realm", opt_text(context.realm.as_deref())),
            ("logon-server", opt_text(context.logon_server.as_deref())),
        ],
        source_field(context.source),
    ));

    if matches!(scope, Scope::All | Scope::Info) {
        info_rows(&context, &mut lines);
    }
    if matches!(scope, Scope::All | Scope::Trusts) {
        trust_rows(&context, &mut lines);
    }
    if matches!(scope, Scope::All | Scope::Spns) {
        spn_rows(&context, &mut lines);
    }
    Ok(lines.join("\n"))
}

/// DC discovery and the root DSE read: the `info` scope. Windows answers
/// from the logon server and skips DNS; Linux asks the resolver for the
/// domain's SRV records. Both then give the first DC that answers TCP 389
/// one anonymous root DSE read.
fn info_rows(context: &context::DomainContext, lines: &mut Vec<String>) {
    let controllers = locate_controllers(context);
    for controller in &controllers {
        lines.push(finding(
            &controller.host,
            &[
                ("port", Some(Field::Number(controller.port as u32))),
                ("service", Some(Field::Text("ldap"))),
                ("state", Some(Field::Text("open"))),
            ],
            source_field(controller.source),
        ));
    }
    if controllers.is_empty() {
        if let Some(domain) = context.dns_domain.as_deref() {
            lines.push(finding(
                &context.host,
                &[(
                    "hint",
                    Some(Field::Text(&format!(
                        "no domain controller located for {domain}"
                    ))),
                )],
                None,
            ));
        }
        return;
    }
    for controller in &controllers {
        let target = format!("{}:{}", controller.host, controller.port);
        match ldap::root_dse(&target) {
            Ok(dse) => {
                let forest = dse
                    .root_domain
                    .as_ref()
                    .map(|nc| nc.trim_start_matches("DC=").replace(",DC=", "."));
                let contexts = dse.naming_contexts.join("; ");
                let is_ad = dse.is_active_directory().to_string();
                lines.push(finding(
                    &controller.host,
                    &[
                        ("domain", opt_text(context.dns_domain.as_deref())),
                        ("forest", opt_text(forest.as_deref())),
                        ("ad", Some(Field::Text(&is_ad))),
                        ("forest-level", dse.forest_functionality.map(Field::Number)),
                        ("dc-level", dse.dc_functionality.map(Field::Number)),
                        (
                            "contexts",
                            (!contexts.is_empty()).then(|| Field::Text(&contexts)),
                        ),
                    ],
                    source_field("ldap-rootdse"),
                ));
                return;
            }
            Err(cause) => {
                lines.push(finding(
                    &controller.host,
                    &[(
                        "hint",
                        Some(Field::Text(&format!("root dse refused: {cause}"))),
                    )],
                    source_field("ldap-rootdse"),
                ));
            }
        }
    }
}

/// The `trusts` scope: what the credential-free surface can name. The
/// root DSE's forest root (already on the info row) is one trust fact --
/// the domain's upward boundary; krb5.conf's capaths section names the
/// cross-realm paths the site's clients were configured to walk. The
/// full trustedDomain list needs credentials: the next version's half.
fn trust_rows(context: &context::DomainContext, lines: &mut Vec<String>) {
    if let Some(realm) = context.realm.as_deref() {
        let pairs = capaths_from(&read_file_or_empty("/etc/krb5.conf"));
        for (from, to) in pairs {
            if from.eq_ignore_ascii_case(realm) {
                lines.push(finding(
                    &context.host,
                    &[
                        ("trust", Some(Field::Text(&to))),
                        ("direction", Some(Field::Text("krb5-capath"))),
                    ],
                    source_field("krb5.conf"),
                ));
            }
        }
        return;
    }
    lines.push(finding(
        &context.host,
        &[(
            "hint",
            Some(Field::Text(
                "no trust readable without credentials; try scope=info for the forest root",
            )),
        )],
        None,
    ));
}

/// The `spns` scope without credentials is DNS: the domain's service
/// location records name every directory role a DC plays. Each SRV
/// record becomes a finding row the topology view plots directly.
fn spn_rows(context: &context::DomainContext, lines: &mut Vec<String>) {
    let Some(domain) = context.dns_domain.as_deref() else {
        lines.push(finding(
            &context.host,
            &[(
                "hint",
                Some(Field::Text(
                    "no dns domain named locally; spn sweep needs one",
                )),
            )],
            None,
        ));
        return;
    };
    let Some(resolver) = dns::system_nameserver() else {
        lines.push(finding(
            &context.host,
            &[(
                "hint",
                Some(Field::Text(
                    "no nameserver in /etc/resolv.conf; spn sweep cannot resolve",
                )),
            )],
            None,
        ));
        return;
    };
    let services = [
        ("kerberos", "_kerberos._udp"),
        ("kpasswd", "_kpasswd._tcp"),
        ("ldap", "_ldap._tcp"),
        ("gc", "_gc._tcp"),
        ("http", "_http._tcp"),
        ("dc", "_ldap._tcp.dc._msdcs"),
    ];
    for (service, prefix) in services {
        let name = format!("{prefix}.{domain}");
        match dns::srv(resolver, &name) {
            Ok(records) => {
                for record in records {
                    let addresses = dns::address(resolver, &record.target)
                        .map(|found| {
                            found
                                .into_iter()
                                .map(|dns::ARecord(ip)| format!("\"{ip}\""))
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    lines.push(format!(
                        "{{\"host\":{},\"port\":{},\"service\":\"{service}\",\"state\":\"open\",\"source\":\"dns-srv\",\"addresses\":[{addresses}]}}",
                        quote(&record.target),
                        record.port,
                    ));
                }
            }
            Err(cause) => lines.push(finding(
                &context.host,
                &[("hint", Some(Field::Text(&format!("srv {name}: {cause}"))))],
                None,
            )),
        }
    }
}

/// One located DC: the host as the DNS grammar wants it (FQDN where the
/// source gave one), the port its LDAP service answers on, and the
/// source the row reports.
struct Controller {
    host: String,
    port: u16,
    source: &'static str,
}

fn locate_controllers(context: &context::DomainContext) -> Vec<Controller> {
    // The logon server names a DC outright: \\DC01 becomes DC01 with the
    // DNS domain appended when the context carries one, so the row's
    // host resolves off-domain too.
    if let Some(logon) = context
        .logon_server
        .as_deref()
        .map(|name| name.trim_start_matches('\\'))
        .filter(|name| !name.is_empty())
    {
        let host = match context.dns_domain.as_deref() {
            Some(domain) if !logon.contains('.') => format!("{logon}.{domain}"),
            _ => logon.to_string(),
        };
        return vec![Controller {
            host,
            port: 389,
            source: "logonserver",
        }];
    }
    let Some(domain) = context.dns_domain.as_deref() else {
        return Vec::new();
    };
    let Some(resolver) = dns::system_nameserver() else {
        return Vec::new();
    };
    match dns::srv(resolver, &format!("_ldap._tcp.dc._msdcs.{domain}")) {
        Ok(records) => records
            .into_iter()
            .map(|record| Controller {
                host: record.target,
                port: record.port,
                source: "dns-srv",
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The [capaths] pairs a krb5.conf carries: krb5.conf's grammar maps a
/// source realm to every realm it may reach, each row read as the pair
/// the trust sweep reports.
fn capaths_from(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut in_section = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = header.trim() == "capaths";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((from, targets)) = line.split_once('=') {
            for target in targets.split_whitespace() {
                pairs.push((from.trim().to_string(), target.to_string()));
            }
        }
    }
    pairs
}

fn read_file_or_empty(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// One finding field: a string (quoted), a number, or an already-encoded
/// JSON fragment. The grammar's fields are flat scalars; the one nested
/// case (the addresses array) renders through `Raw` at its call site.
enum Field<'a> {
    Text(&'a str),
    Number(u32),
}

fn opt_text<'a>(value: Option<&'a str>) -> Option<Field<'a>> {
    value.map(Field::Text)
}

fn source_field<'a>(source: &'a str) -> Option<(&'a str, Field<'a>)> {
    Some(("source", Field::Text(source)))
}

/// One finding row: `host` plus the fields that are present, serialized
/// in map order (the grammar reads field order as irrelevant; the writer
/// stays deterministic anyway, like the hostenum module's).
fn finding<'a>(
    host: &str,
    fields: &[(&'a str, Option<Field<'a>>)],
    source: Option<(&'a str, Field<'a>)>,
) -> String {
    let mut rendered: Vec<(String, String)> = Vec::with_capacity(fields.len() + 2);
    rendered.push(("host".into(), quote(host)));
    for (key, value) in fields {
        if let Some(value) = value {
            rendered.push(((*key).into(), render(value)));
        }
    }
    if let Some((key, value)) = source {
        rendered.push((key.into(), render(&value)));
    }
    rendered.sort_by(|left, right| left.0.cmp(&right.0));
    let body = rendered
        .iter()
        .map(|(key, value)| format!("\"{key}\":{value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn render(field: &Field) -> String {
    match field {
        Field::Text(text) => quote(text),
        Field::Number(number) => number.to_string(),
    }
}

/// JSON string quoting for the finding's values: the two escapes the
/// grammar needs (quote, backslash), control characters dropped rather
/// than escaped -- the same rule the hostenum module's writer keeps.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

rod_plugin!(DomainEnum);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_from_the_task_grammar() {
        assert_eq!(parse_scope("").unwrap(), Scope::All);
        assert_eq!(parse_scope("spns").unwrap(), Scope::Spns);
        assert_eq!(parse_scope("scope=trusts").unwrap(), Scope::Trusts);
        assert_eq!(parse_scope("  INFO ").unwrap(), Scope::Info);
        assert!(parse_scope("sweep").is_err());
    }

    #[test]
    fn every_line_of_the_sweep_is_one_json_object_with_a_host() {
        // Whatever the local posture and resolver situation, the verb
        // answers with grammar-shaped lines only.
        for scope in ["all", "info", "trusts", "spns"] {
            let output = domainenum(scope).expect("the sweep runs");
            assert!(!output.is_empty(), "{scope}: no lines");
            for line in output.lines() {
                assert!(
                    line.starts_with('{') && line.ends_with('}'),
                    "{scope}: {line}"
                );
                assert!(line.contains("\"host\":"), "{scope}: {line}");
            }
        }
    }

    #[test]
    fn the_posture_line_is_alone_when_info_finds_nothing() {
        // A host with no domain posture and no resolver: the info scope
        // answers the honest local line and nothing else.
        let output = domainenum("info").expect("the sweep runs");
        assert_eq!(output.lines().count(), 1, "{output}");
    }

    #[test]
    fn hints_carry_the_reason_not_a_fake_finding() {
        let output = domainenum("trusts").expect("the sweep runs");
        assert!(
            output.contains("no trust readable without credentials"),
            "{output}"
        );
    }

    #[test]
    fn findings_render_fields_in_grammar_shape() {
        let row = finding(
            "dc01.corp.example.com",
            &[
                ("port", Some(Field::Number(389))),
                ("service", Some(Field::Text("ldap"))),
                ("state", Some(Field::Text("open"))),
            ],
            source_field("dns-srv"),
        );
        assert_eq!(
            row,
            "{\"host\":\"dc01.corp.example.com\",\"port\":389,\"service\":\"ldap\",\"source\":\"dns-srv\",\"state\":\"open\"}"
        );
    }

    #[test]
    fn quoting_escapes_the_two_characters_that_break_json() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("ctrl\u{1}cut"), "\"ctrlcut\"");
    }

    #[test]
    fn capaths_pairs_read_from_the_section_only() {
        let krb5 = "[libdefaults]\n default_realm = CORP.EXAMPLE.COM\n\
                    [capaths]\n CORP.EXAMPLE.COM = OTHER.EXAMPLE.COM LAB.EXAMPLE.COM\n\
                    [domain_realm]\n .other.example.com = OTHER.EXAMPLE.COM\n";
        assert_eq!(
            capaths_from(krb5),
            vec![
                ("CORP.EXAMPLE.COM".into(), "OTHER.EXAMPLE.COM".into()),
                ("CORP.EXAMPLE.COM".into(), "LAB.EXAMPLE.COM".into()),
            ]
        );
        assert!(capaths_from("[libdefaults]\ndefault_realm = X\n").is_empty());
    }
}
