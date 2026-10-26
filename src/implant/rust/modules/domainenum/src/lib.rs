//! The domain-discovery plugin module (architecture.md Sec 5.4):
//! `recon.domainenum`, both halves of domain recon in one verb.
//!
//! The credential-free half reads the host's own domain posture (context
//! sources on disk and in the environment), locates the domain
//! controllers (the logon server on Windows, DNS SRV records on Linux),
//! and asks the first answering DC for the anonymous LDAP root DSE. The
//! authenticated half (v1.1) rides a credential in the task's argument
//! grammar -- `user=` and the trailing `pass=`, where the platform's
//! `$cred-<id>` placeholder has already resolved to the stored secret --
//! and reads the directory itself over a simple bind: domain users,
//! groups with their membership, the escalation-relevant ACEs off
//! object security descriptors, the SPN-bearing service accounts, and
//! the trustedDomain objects. The simple bind crosses the wire in the
//! clear unless the site seals it; that exposure is the module's
//! declared OPSEC note, not a fact to hide.
//!
//! Every finding is one JSON line in the recon grammar
//! (extending/modules.md): `host` required -- the DC that served the
//! authenticated rows, the local host for the local ones -- the DC rows
//! carry `port` and `service` so the topology view plots them, and every
//! row names the `source` it was read from. The sweep refuses nothing
//! silently: what it cannot reach it reports as a hint row carrying the
//! reason, and a read the directory caps or the row budget truncates
//! says so as its last line.

mod acl;
mod arguments;
mod context;
mod dns;
mod ldap;

use std::collections::HashMap;

use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

use arguments::Scope;
use ldap::{Filter, SearchScope};

/// The sweep's output budget: the read-side parse bound is ten thousand
/// finding lines per task (extending/modules.md), so the sweep stops
/// there and says so rather than printing past what the picture reads.
const ROW_BUDGET: usize = 10_000;

/// How many distinct trustee SIDs the `acls` scope will resolve against
/// the directory before letting the remaining SIDs stand as strings:
/// each lookup is a round trip, and a forest's worth of foreign
/// principals is not worth stalling the sweep for.
const TRUSTEE_LOOKUPS: usize = 128;

pub struct DomainEnum;

impl Plugin for DomainEnum {
    fn name(&self) -> &'static str {
        "domainenum"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("recon.domainenum", domainenum)]
    }
}

fn domainenum(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    let credential = arguments::credential(&arguments)?;
    let context = context::DomainContext::read();
    let mut rows = Rows::new();

    // The posture line always comes first: it is the local read, it
    // never fails, and everything after it interprets against it.
    rows.push(posture_line(&context));

    if matches!(arguments.scope, Scope::All | Scope::Info) {
        info_rows(&context, &mut rows);
    }

    // One directory connection serves every authenticated scope the task
    // asked for. The `info` scope stays the anonymous half it was even
    // when a credential rode the task.
    let mut directory = if credential.is_some() && arguments.scope != Scope::Info {
        open_directory(&context, credential, &mut rows)?
    } else {
        None
    };

    if matches!(arguments.scope, Scope::All | Scope::Trusts) {
        trust_rows(&context, &mut rows);
        match directory.as_mut() {
            Some(directory) => trust_object_rows(directory, &mut rows),
            None if credential.is_none() => rows.hint(
                &context.host,
                "no trust readable without credentials: task user= and pass= for the \
                 trustedDomain objects (scope=info names the forest root without one)",
            ),
            None => {} // no DC: open_directory already said so
        }
    }

    if matches!(arguments.scope, Scope::All | Scope::Spns) {
        spn_rows(&context, &mut rows);
        if let Some(directory) = directory.as_mut() {
            spn_object_rows(directory, &mut rows);
        }
    }

    // The authenticated-only scopes share one missing-credential hint:
    // three identical refusals would teach nothing the first did not.
    let mut missing_hinted = false;
    for scope in [Scope::Users, Scope::Groups, Scope::Acls] {
        if arguments.scope != Scope::All && arguments.scope != scope {
            continue;
        }
        match directory.as_mut() {
            Some(directory) => match scope {
                Scope::Users => user_rows(directory, &mut rows),
                Scope::Groups => group_rows(directory, &mut rows),
                Scope::Acls => acl_rows(directory, &mut rows),
                _ => unreachable!("the loop names exactly these scopes"),
            },
            None if credential.is_none() && !missing_hinted => {
                missing_hinted = true;
                rows.hint(
                    &context.host,
                    "the authenticated read (users, groups, acls) needs user= and pass= \
                     riding the task; pass may carry a $cred-<id> placeholder that \
                     resolves at dispatch",
                );
            }
            None => {}
        }
    }

    Ok(rows.finish(&context.host).join("\n"))
}

/// The local posture row, identical for every scope.
fn posture_line(context: &context::DomainContext) -> String {
    finding(
        &context.host,
        &[
            ("domain", opt_text(context.dns_domain.as_deref())),
            ("netbios", opt_text(context.netbios_domain.as_deref())),
            ("realm", opt_text(context.realm.as_deref())),
            ("logon-server", opt_text(context.logon_server.as_deref())),
        ],
        source_field(context.source),
    )
}

/// DC discovery and the root DSE read: the `info` scope. Windows answers
/// from the logon server and skips DNS; Linux asks the resolver for the
/// domain's SRV records. Both then give the first DC that answers TCP 389
/// one anonymous root DSE read.
fn info_rows(context: &context::DomainContext, rows: &mut Rows) {
    let controllers = locate_controllers(context);
    for controller in &controllers {
        rows.push(finding(
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
            rows.hint(
                &context.host,
                &format!("no domain controller located for {domain}"),
            );
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
                rows.push(finding(
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
            Err(cause) => rows.push(finding(
                &controller.host,
                &[(
                    "hint",
                    Some(Field::Text(&format!("root dse refused: {cause}"))),
                )],
                source_field("ldap-rootdse"),
            )),
        }
    }
}

/// The `trusts` scope's local half: krb5.conf's capaths section names
/// the cross-realm paths the site's clients were configured to walk.
/// The trustedDomain objects are the authenticated half's read.
fn trust_rows(context: &context::DomainContext, rows: &mut Rows) {
    let Some(realm) = context.realm.as_deref() else {
        return;
    };
    for (from, to) in capaths_from(&read_file_or_empty("/etc/krb5.conf")) {
        if from.eq_ignore_ascii_case(realm) {
            rows.push(finding(
                &context.host,
                &[
                    ("trust", Some(Field::Text(&to))),
                    ("direction", Some(Field::Text("krb5-capath"))),
                ],
                source_field("krb5.conf"),
            ));
        }
    }
}

/// The `trusts` scope's authenticated half: every trustedDomain object
/// under the domain naming context, with the direction named where the
/// number is one of the three the directory serves.
fn trust_object_rows(directory: &mut Directory, rows: &mut Rows) {
    let host = directory.host.clone();
    let filter = Filter::Equal("objectClass".into(), b"trustedDomain".to_vec());
    let attributes = [
        "name",
        "flatName",
        "trustDirection",
        "trustType",
        "trustAttributes",
    ];
    walk_pages(
        directory,
        SearchScope::Subtree,
        &filter,
        &attributes,
        rows,
        &mut |entry, rows| {
            if let Some(row) = trust_finding(&host, entry) {
                rows.push(row);
            }
        },
    );
}

/// The `spns` scope without credentials is DNS: the domain's service
/// location records name every directory role a DC plays. Each SRV
/// record becomes a finding row the topology view plots directly.
fn spn_rows(context: &context::DomainContext, rows: &mut Rows) {
    let Some(domain) = context.dns_domain.as_deref() else {
        rows.hint(
            &context.host,
            "no dns domain named locally; spn sweep needs one",
        );
        return;
    };
    let Some(resolver) = dns::system_nameserver() else {
        rows.hint(
            &context.host,
            "no nameserver in /etc/resolv.conf; spn sweep cannot resolve",
        );
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
                    rows.push(format!(
                        "{{\"host\":{},\"port\":{},\"service\":\"{service}\",\"state\":\"open\",\"source\":\"dns-srv\",\"addresses\":[{addresses}]}}",
                        quote(&record.target),
                        record.port,
                    ));
                }
            }
            Err(cause) => rows.hint(&context.host, &format!("srv {name}: {cause}")),
        }
    }
}

/// The `spns` scope's authenticated half: the accounts that hold service
/// principal names -- the kerberoast target list the directory serves to
/// any authenticated reader.
fn spn_object_rows(directory: &mut Directory, rows: &mut Rows) {
    let host = directory.host.clone();
    let filter = Filter::And(vec![
        Filter::Equal("objectCategory".into(), b"person".to_vec()),
        Filter::Equal("objectClass".into(), b"user".to_vec()),
        Filter::Present("servicePrincipalName".into()),
    ]);
    let attributes = [
        "sAMAccountName",
        "servicePrincipalName",
        "userAccountControl",
    ];
    walk_pages(
        directory,
        SearchScope::Subtree,
        &filter,
        &attributes,
        rows,
        &mut |entry, rows| {
            if let Some(row) = spn_finding(&host, entry) {
                rows.push(row);
            }
        },
    );
}

/// The `users` scope: every person-class user under the domain naming
/// context, paged, with the flags an escalation read keys on.
fn user_rows(directory: &mut Directory, rows: &mut Rows) {
    let host = directory.host.clone();
    let filter = Filter::And(vec![
        Filter::Equal("objectCategory".into(), b"person".to_vec()),
        Filter::Equal("objectClass".into(), b"user".to_vec()),
    ]);
    let attributes = [
        "sAMAccountName",
        "userAccountControl",
        "description",
        "adminCount",
    ];
    walk_pages(
        directory,
        SearchScope::Subtree,
        &filter,
        &attributes,
        rows,
        &mut |entry, rows| {
            rows.push(user_finding(&host, entry));
        },
    );
}

/// The `groups` scope: every group, one row per member read -- the
/// directory serves large groups ranged, and the rows say when they do.
fn group_rows(directory: &mut Directory, rows: &mut Rows) {
    let host = directory.host.clone();
    let filter = Filter::Equal("objectClass".into(), b"group".to_vec());
    let attributes = ["sAMAccountName", "member"];
    walk_pages(
        directory,
        SearchScope::Subtree,
        &filter,
        &attributes,
        rows,
        &mut |entry, rows| {
            for row in group_findings(&host, entry, rows) {
                rows.push(row);
            }
        },
    );
}

/// The `acls` scope: the escalation-relevant ACEs on the domain root,
/// the person-class users, and the groups -- a WriteDacl, a GenericAll,
/// a DCSync replication right -- with trustees named through the
/// enumerated objects, the well-known and RID tables, and (bounded)
/// lookups against the directory itself.
fn acl_rows(directory: &mut Directory, rows: &mut Rows) {
    let host = directory.host.clone();

    // The domain root first: its descriptor carries the forest's pivots
    // and its objectSid is the domain SID the RID naming keys on.
    let mut domain_sid = None;
    let mut sid_names: HashMap<String, String> = HashMap::new();
    let mut grants = Vec::new();
    let root_attributes = [
        "objectSid",
        "sAMAccountName",
        "name",
        "nTSecurityDescriptor",
    ];
    match directory.connection.search_page(
        &directory.base,
        SearchScope::Base,
        &Filter::Present("objectClass".into()),
        &root_attributes,
        &[],
    ) {
        Ok(outcome) => {
            for entry in &outcome.entries {
                if let Some((sid, name)) = identity_of(entry) {
                    sid_names.insert(sid.clone(), name);
                    domain_sid.get_or_insert(sid);
                }
                grants.extend(grants_of(entry));
            }
        }
        Err(cause) => rows.hint(&host, &format!("domain root read: {cause}")),
    }

    let filter = Filter::Or(vec![
        Filter::And(vec![
            Filter::Equal("objectCategory".into(), b"person".to_vec()),
            Filter::Equal("objectClass".into(), b"user".to_vec()),
        ]),
        Filter::Equal("objectClass".into(), b"group".to_vec()),
    ]);
    let attributes = ["objectSid", "sAMAccountName", "nTSecurityDescriptor"];
    let mut cookie: Option<Vec<u8>> = None;
    loop {
        let outcome = match directory.connection.search_page(
            &directory.base,
            SearchScope::Subtree,
            &filter,
            &attributes,
            cookie.as_deref().unwrap_or(&[]),
        ) {
            Ok(outcome) => outcome,
            Err(cause) => {
                rows.hint(&host, &format!("acl read stopped: {cause}"));
                break;
            }
        };
        for entry in &outcome.entries {
            if let Some((sid, name)) = identity_of(entry) {
                sid_names.insert(sid, name);
            }
            grants.extend(grants_of(entry));
        }
        if grants.len() >= rows.remaining() {
            grants.truncate(rows.remaining());
            rows.mark_truncated();
            break;
        }
        if let Some(code) = outcome.stopped {
            rows.hint(
                &host,
                &format!("the directory capped the acl read (ldap result {code})"),
            );
            break;
        }
        match outcome.cookie {
            Some(next) if !next.is_empty() => cookie = Some(next),
            _ => break,
        }
    }

    // Trustee naming, cheapest first: the objects the sweep itself
    // enumerated, the SID tables, then lookups against the directory --
    // bounded, because each is a round trip.
    let mut unresolved: Vec<(String, Vec<u8>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for grant in &grants {
        let Some(sid) = acl::sid_string(&grant.trustee) else {
            continue;
        };
        if !seen.insert(sid.clone()) {
            continue;
        }
        if sid_names.contains_key(&sid) {
            continue;
        }
        if let Some(name) = acl::well_known(&sid) {
            sid_names.insert(sid, name.to_string());
            continue;
        }
        if let Some(name) = domain_sid
            .as_deref()
            .and_then(|domain| acl::domain_rid(&sid, domain))
        {
            sid_names.insert(sid, name.to_string());
            continue;
        }
        unresolved.push((sid, grant.trustee.clone()));
    }
    for (sid, bytes) in unresolved.iter().take(TRUSTEE_LOOKUPS) {
        if let Ok(outcome) = directory.connection.search_page(
            &directory.base,
            SearchScope::Subtree,
            &Filter::Equal("objectSid".into(), bytes.clone()),
            &["sAMAccountName", "name"],
            &[],
        ) {
            if let Some(found) = outcome.entries.first() {
                if let Some(name) = found
                    .first_text("sAMAccountName")
                    .or_else(|| found.first_text("name"))
                {
                    sid_names.insert(sid.clone(), name);
                }
            }
        }
    }

    for grant in grants {
        let trustee = acl::sid_string(&grant.trustee)
            .and_then(|sid| sid_names.get(&sid).cloned())
            .or_else(|| acl::sid_string(&grant.trustee))
            .unwrap_or_else(|| "unparseable trustee".into());
        rows.push(finding(
            &host,
            &[
                ("object", Some(Field::Text(&grant.object))),
                ("right", Some(Field::Text(&grant.rights))),
                ("trustee", Some(Field::Text(&trustee))),
                ("inherited", grant.inherited.then_some(Field::Text("true"))),
            ],
            source_field("ldap-acls"),
        ));
    }
}

// ---- the authenticated half's plumbing ----

/// One bound directory: the DC that answered, the connection the bind
/// holds, and the naming context the searches base on.
struct Directory {
    host: String,
    connection: ldap::Connection,
    base: String,
}

/// Opens the directory for the task's credential: the first located DC
/// that accepts the bind. A reachable DC refusing the credential is the
/// task's failure -- a wrong password counts toward the account's
/// lockout, so the refusal is loud, not a row to sweep past.
fn open_directory(
    context: &context::DomainContext,
    credential: Option<(&str, &str)>,
    rows: &mut Rows,
) -> Result<Option<Directory>, String> {
    let Some((user, password)) = credential else {
        return Ok(None);
    };
    let mut refusal = None;
    for controller in locate_controllers(context) {
        let target = format!("{}:{}", controller.host, controller.port);
        let Ok(mut connection) = ldap::Connection::connect(&target) else {
            continue;
        };
        if let Err(cause) = connection.bind_simple(user, password) {
            refusal = Some(format!("{target}: {cause}"));
            continue;
        }
        // The bound root DSE names the domain's naming context outright;
        // a directory that serves none falls back to the locally known
        // DNS domain, the same fact the posture row carries.
        let base = connection
            .root_dse()
            .ok()
            .and_then(|dse| dse.default_naming_context().map(str::to_string))
            .or_else(|| domain_dn(context.dns_domain.as_deref()));
        let Some(base) = base else {
            rows.hint(
                &context.host,
                "no naming context served and no dns domain named locally; \
                 the authenticated read has no base",
            );
            return Ok(None);
        };
        return Ok(Some(Directory {
            host: controller.host,
            connection,
            base,
        }));
    }
    if let Some(refusal) = refusal {
        return Err(format!("ldap bind refused: {refusal}"));
    }
    rows.hint(
        &context.host,
        "no domain controller located for the authenticated read",
    );
    Ok(None)
}

/// Walks a paged search to its end, visiting every entry. The walk stops
/// on the directory's own refusal (keeping the rows it already served),
/// on an empty cookie, and at the row budget.
fn walk_pages(
    directory: &mut Directory,
    scope: SearchScope,
    filter: &Filter,
    attributes: &[&str],
    rows: &mut Rows,
    visit: &mut dyn FnMut(&ldap::Entry, &mut Rows),
) {
    let mut cookie: Option<Vec<u8>> = None;
    loop {
        let outcome = match directory.connection.search_page(
            &directory.base,
            scope,
            filter,
            attributes,
            cookie.as_deref().unwrap_or(&[]),
        ) {
            Ok(outcome) => outcome,
            Err(cause) => {
                rows.hint(&directory.host, &format!("ldap read stopped: {cause}"));
                return;
            }
        };
        for entry in &outcome.entries {
            visit(entry, rows);
        }
        if let Some(code) = outcome.stopped {
            rows.hint(
                &directory.host,
                &format!("the directory capped the read (ldap result {code})"),
            );
            return;
        }
        match outcome.cookie {
            Some(next) if !next.is_empty() => cookie = Some(next),
            _ => return,
        }
        if rows.exhausted() {
            rows.mark_truncated();
            return;
        }
    }
}

// ---- per-entry rows, pure so the grammar stays testable ----

/// One user row: the account, whether it is enabled, and the two flags
/// an escalation read keys on -- a description the account carries, and
/// the adminCount mark of a principal the directory ever elevated.
fn user_finding(host: &str, entry: &ldap::Entry) -> String {
    let user = entry
        .first_text("sAMAccountName")
        .unwrap_or_else(|| rdn(&entry.dn));
    let disabled = entry
        .first_text("userAccountControl")
        .and_then(|text| text.parse::<u32>().ok())
        .map(|flags| flags & 0x0002 != 0);
    let description = entry.first_text("description").filter(|d| !d.is_empty());
    let admin = entry
        .first_text("adminCount")
        .map(|t| t == "1")
        .unwrap_or(false);
    finding(
        host,
        &[
            ("user", Some(Field::Text(&user))),
            (
                "enabled",
                disabled.map(|off| Field::Text(if off { "false" } else { "true" })),
            ),
            ("desc", description.as_deref().map(Field::Text)),
            ("admin", admin.then_some(Field::Text("true"))),
        ],
        source_field("ldap-users"),
    )
}

/// One group's rows: the group itself when the directory served no
/// members, one row per member otherwise -- the DN is the raw fact the
/// member attribute carries.
fn group_findings(host: &str, entry: &ldap::Entry, rows: &mut Rows) -> Vec<String> {
    let group = entry
        .first_text("sAMAccountName")
        .unwrap_or_else(|| rdn(&entry.dn));
    let (members, capped) = entry.values_with_range("member");
    if capped {
        rows.hint_once(
            host,
            "member-range",
            "a group's member list was served ranged (a group larger than the directory's \
             page limit): the rows carry the first range it served",
        );
    }
    if members.is_empty() {
        return vec![finding(
            host,
            &[("group", Some(Field::Text(&group)))],
            source_field("ldap-groups"),
        )];
    }
    members
        .iter()
        .map(|member| {
            let member = String::from_utf8_lossy(member);
            finding(
                host,
                &[
                    ("group", Some(Field::Text(&group))),
                    ("member", Some(Field::Text(&member))),
                ],
                source_field("ldap-groups"),
            )
        })
        .collect()
}

/// One SPN-bearing account's row: the account, its service principals,
/// and whether it is enabled -- the kerberoast list's shape.
fn spn_finding(host: &str, entry: &ldap::Entry) -> Option<String> {
    let spns: Vec<String> = entry
        .values("servicePrincipalName")
        .iter()
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect();
    if spns.is_empty() {
        return None; // a present filter misses nothing, but no row lies
    }
    let user = entry
        .first_text("sAMAccountName")
        .unwrap_or_else(|| rdn(&entry.dn));
    let enabled = entry
        .first_text("userAccountControl")
        .and_then(|text| text.parse::<u32>().ok())
        .map(|flags| flags & 0x0002 == 0);
    let joined = spns.join("; ");
    Some(finding(
        host,
        &[
            ("user", Some(Field::Text(&user))),
            ("spn", Some(Field::Text(&joined))),
            (
                "enabled",
                enabled.map(|on| Field::Text(if on { "true" } else { "false" })),
            ),
        ],
        source_field("ldap-spns"),
    ))
}

/// One trustedDomain object's row: the partner domain, its NetBIOS
/// name, and the numeric trust facts with the direction named where the
/// number is one of the three the directory serves.
fn trust_finding(host: &str, entry: &ldap::Entry) -> Option<String> {
    let trust = entry.first_text("name")?;
    let netbios = entry.first_text("flatName");
    let direction = entry
        .first_text("trustDirection")
        .map(|value| match value.as_str() {
            "1" => "inbound".to_string(),
            "2" => "outbound".to_string(),
            "3" => "bidirectional".to_string(),
            other => other.to_string(),
        });
    let trust_type = entry.first_text("trustType");
    let trust_attributes = entry.first_text("trustAttributes");
    Some(finding(
        host,
        &[
            ("trust", Some(Field::Text(&trust))),
            ("netbios", netbios.as_deref().map(Field::Text)),
            ("direction", direction.as_deref().map(Field::Text)),
            ("trust-type", trust_type.as_deref().map(Field::Text)),
            (
                "trust-attributes",
                trust_attributes.as_deref().map(Field::Text),
            ),
        ],
        source_field("ldap-trusts"),
    ))
}

/// One escalation grant off an entry's security descriptors: the ACEs
/// whose masks carry a right worth reporting, with the object's
/// account name (its RDN when the object carries none -- the domain
/// root, for one).
#[derive(Debug)]
struct Grant {
    object: String,
    rights: String,
    trustee: Vec<u8>,
    inherited: bool,
}

fn grants_of(entry: &ldap::Entry) -> Vec<Grant> {
    let object = entry
        .first_text("sAMAccountName")
        .or_else(|| entry.first_text("name"))
        .unwrap_or_else(|| rdn(&entry.dn));
    let mut grants = Vec::new();
    for descriptor in entry.values("nTSecurityDescriptor") {
        for ace in acl::allowed_aces(descriptor) {
            let mut rights: Vec<String> = acl::generic_rights(ace.mask)
                .into_iter()
                .map(str::to_string)
                .collect();
            if ace.mask & 0x100 == 0x100 {
                rights.push(match &ace.object_type {
                    Some(guid) => acl::object_right(guid),
                    None => "AllExtendedRights".to_string(),
                });
            }
            if rights.is_empty() {
                continue; // a read-only grant names no escalation path
            }
            grants.push(Grant {
                object: object.clone(),
                rights: rights.join("; "),
                trustee: ace.trustee,
                inherited: ace.inherited,
            });
        }
    }
    grants
}

/// An entry's (SID, account name) identity, for the trustee map.
fn identity_of(entry: &ldap::Entry) -> Option<(String, String)> {
    let name = entry
        .first_text("sAMAccountName")
        .or_else(|| entry.first_text("name"))?;
    let sid = entry
        .values("objectSid")
        .first()
        .and_then(|sid| acl::sid_string(sid))?;
    Some((sid, name))
}

/// The DNS domain as a distinguished name base (`corp.example.com` to
/// `DC=corp,DC=example,DC=com`).
fn domain_dn(dns_domain: Option<&str>) -> Option<String> {
    let domain = dns_domain?;
    let components: Vec<String> = domain
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| format!("DC={part}"))
        .collect();
    // A single label is a local suffix, not a DNS domain -- the same
    // line the posture read holds.
    (components.len() > 1).then(|| components.join(","))
}

/// The value half of a DN's first RDN (`CN=Name,OU=...` to `Name`) --
/// the displayable identity of an object that carries no account name.
fn rdn(dn: &str) -> String {
    let first = dn.split(',').next().unwrap_or(dn);
    first
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or(first)
        .to_string()
}

// ---- the sweep's row bookkeeping ----

/// The sweep's rows under the output budget: finding rows count against
/// it, hints never do (a hint is the honesty mechanism, and there are
/// few), and a truncation says so as the last line.
struct Rows {
    lines: Vec<String>,
    remaining: usize,
    truncated: bool,
    once: Vec<&'static str>,
}

impl Rows {
    fn new() -> Rows {
        Rows {
            lines: Vec::new(),
            remaining: ROW_BUDGET,
            truncated: false,
            once: Vec::new(),
        }
    }

    fn push(&mut self, line: String) {
        if self.remaining == 0 {
            self.truncated = true;
            return;
        }
        self.lines.push(line);
        self.remaining -= 1;
    }

    fn hint(&mut self, host: &str, text: &str) {
        self.lines
            .push(finding(host, &[("hint", Some(Field::Text(text)))], None));
    }

    /// The same hint once per sweep, keyed by its cause.
    fn hint_once(&mut self, host: &str, key: &'static str, text: &str) {
        if !self.once.contains(&key) {
            self.once.push(key);
            self.hint(host, text);
        }
    }

    fn remaining(&self) -> usize {
        self.remaining
    }

    fn exhausted(&self) -> bool {
        self.remaining == 0
    }

    fn mark_truncated(&mut self) {
        self.truncated = true;
    }

    fn finish(mut self, host: &str) -> Vec<String> {
        if self.truncated {
            self.hint(
                host,
                &format!("row budget ({ROW_BUDGET}) reached; the read stopped there"),
            );
        }
        self.lines
    }
}

// ---- the credential-free half's unchanged helpers ----

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

/// One finding field: a string (quoted) or a number.
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
    fn every_scope_answers_grammar_shaped_lines() {
        // Whatever the local posture and resolver situation, the verb
        // answers with grammar-shaped lines only -- the credential-free
        // sweep, and the honest hints where the authenticated scopes
        // meet no credential.
        for scope in ["all", "info", "trusts", "spns", "users", "groups", "acls"] {
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
        // Without a credential the sweeps teach what would unlock them
        // instead of printing a finding-shaped guess.
        let trusts = domainenum("trusts").expect("the sweep runs");
        assert!(
            trusts.contains("no trust readable without credentials"),
            "{trusts}"
        );
        let users = domainenum("users").expect("the sweep runs");
        assert!(users.contains("needs user= and pass="), "{users}");
    }

    #[test]
    fn user_rows_carry_the_escalation_flags() {
        let entry = ldap::Entry {
            dn: "CN=jdoe,DC=corp,DC=example,DC=com".into(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"jdoe".to_vec()]),
                ("userAccountControl".into(), vec![b"512".to_vec()]),
                ("description".into(), vec![b"break glass".to_vec()]),
                ("adminCount".into(), vec![b"1".to_vec()]),
            ],
        };
        let row = user_finding("dc01.corp.example.com", &entry);
        assert!(row.contains("\"user\":\"jdoe\""), "{row}");
        assert!(row.contains("\"enabled\":\"true\""), "{row}");
        assert!(row.contains("\"desc\":\"break glass\""), "{row}");
        assert!(row.contains("\"admin\":\"true\""), "{row}");
        assert!(row.contains("\"source\":\"ldap-users\""), "{row}");

        // A disabled account (the ACCOUNTDISABLE bit) and a bare one
        // with neither flag: absent fields drop out, they do not guess.
        let disabled = ldap::Entry {
            dn: String::new(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"stale".to_vec()]),
                ("userAccountControl".into(), vec![b"514".to_vec()]),
            ],
        };
        let row = user_finding("dc", &disabled);
        assert!(row.contains("\"enabled\":\"false\""), "{row}");
        assert!(!row.contains("desc"), "{row}");
        assert!(!row.contains("admin"), "{row}");

        let bare = ldap::Entry {
            dn: "CN=No Sam Here,DC=corp".into(),
            attributes: vec![],
        };
        let row = user_finding("dc", &bare);
        assert!(row.contains("\"user\":\"No Sam Here\""), "{row}");
    }

    #[test]
    fn group_rows_carry_membership_and_say_when_ranged() {
        let mut rows = Rows::new();
        let group = ldap::Entry {
            dn: "CN=Domain Admins,DC=corp".into(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"Domain Admins".to_vec()]),
                (
                    "member".into(),
                    vec![b"CN=jdoe,DC=corp".to_vec(), b"CN=svc,DC=corp".to_vec()],
                ),
            ],
        };
        let lines = group_findings("dc01", &group, &mut rows);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].contains("\"group\":\"Domain Admins\""),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains("\"member\":\"CN=jdoe,DC=corp\""),
            "{}",
            lines[0]
        );

        let empty = ldap::Entry {
            dn: String::new(),
            attributes: vec![("sAMAccountName".into(), vec![b"Empty Group".to_vec()])],
        };
        let lines = group_findings("dc01", &empty, &mut rows);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("\"group\":\"Empty Group\""),
            "{}",
            lines[0]
        );

        let ranged = ldap::Entry {
            dn: String::new(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"Big Group".to_vec()]),
                ("member;range=0-1499".into(), vec![b"CN=a".to_vec()]),
            ],
        };
        let lines = group_findings("dc01", &ranged, &mut rows);
        assert_eq!(lines.len(), 1);
        let hinted = rows.finish("dc01").join("\n");
        assert!(hinted.contains("served ranged"), "{hinted}");
    }

    #[test]
    fn spn_rows_name_the_service_accounts() {
        let entry = ldap::Entry {
            dn: "CN=sqlsvc,DC=corp".into(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"sqlsvc".to_vec()]),
                (
                    "servicePrincipalName".into(),
                    vec![
                        b"MSSQLSvc/sql01:1433".to_vec(),
                        b"MSSQLSvc/sql02:1433".to_vec(),
                    ],
                ),
                ("userAccountControl".into(), vec![b"512".to_vec()]),
            ],
        };
        let row = spn_finding("dc01", &entry).expect("the account holds spns");
        assert!(
            row.contains("\"spn\":\"MSSQLSvc/sql01:1433; MSSQLSvc/sql02:1433\""),
            "{row}"
        );
        assert!(row.contains("\"enabled\":\"true\""), "{row}");

        let none = ldap::Entry {
            dn: String::new(),
            attributes: vec![("sAMAccountName".into(), vec![b"plain".to_vec()])],
        };
        assert!(spn_finding("dc01", &none).is_none());
    }

    #[test]
    fn trust_rows_read_the_direction_and_the_raw_numbers() {
        let entry = ldap::Entry {
            dn: "CN=lab.corp.example.com,DC=corp".into(),
            attributes: vec![
                ("name".into(), vec![b"lab.corp.example.com".to_vec()]),
                ("flatName".into(), vec![b"LAB".to_vec()]),
                ("trustDirection".into(), vec![b"3".to_vec()]),
                ("trustType".into(), vec![b"2".to_vec()]),
                ("trustAttributes".into(), vec![b"32".to_vec()]),
            ],
        };
        let row = trust_finding("dc01", &entry).expect("the object names a partner");
        assert!(row.contains("\"trust\":\"lab.corp.example.com\""), "{row}");
        assert!(row.contains("\"netbios\":\"LAB\""), "{row}");
        assert!(row.contains("\"direction\":\"bidirectional\""), "{row}");
        assert!(row.contains("\"trust-type\":\"2\""), "{row}");

        // An unnumbered direction stands as read, never guessed.
        let odd = ldap::Entry {
            dn: String::new(),
            attributes: vec![
                ("name".into(), vec![b"odd.example.com".to_vec()]),
                ("trustDirection".into(), vec![b"7".to_vec()]),
            ],
        };
        let row = trust_finding("dc01", &odd).expect("the object names a partner");
        assert!(row.contains("\"direction\":\"7\""), "{row}");
    }

    #[test]
    fn acl_grants_render_the_named_rights() {
        // One entry: a group carrying a WriteDacl grant to a SID the
        // tables know (Everyone), and an object ACE naming DCSync.
        let everyone = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let mut write_dacl = vec![0x00, 0x00];
        write_dacl.extend_from_slice(&(4 + 4 + everyone.len() as u16).to_le_bytes());
        write_dacl.extend_from_slice(&0x40000u32.to_le_bytes());
        write_dacl.extend_from_slice(&everyone);

        let dcsync = [
            0xad, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2,
            0xdc, 0xd2,
        ];
        let mut object = vec![0x05, 0x00];
        object.extend_from_slice(&(4 + 4 + 4 + 16 + everyone.len() as u16).to_le_bytes());
        object.extend_from_slice(&0x100u32.to_le_bytes());
        object.extend_from_slice(&1u32.to_le_bytes());
        object.extend_from_slice(&dcsync);
        object.extend_from_slice(&everyone);

        let mut acl = vec![2u8, 0];
        acl.extend_from_slice(&((write_dacl.len() + object.len() + 8) as u16).to_le_bytes());
        acl.extend_from_slice(&2u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&write_dacl);
        acl.extend_from_slice(&object);
        let mut descriptor = vec![1u8, 0];
        descriptor.extend_from_slice(&0u16.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&0u32.to_le_bytes());
        descriptor.extend_from_slice(&20u32.to_le_bytes());
        descriptor.extend_from_slice(&acl);

        let entry = ldap::Entry {
            dn: "CN=Helpdesk,DC=corp".into(),
            attributes: vec![
                ("sAMAccountName".into(), vec![b"Helpdesk".to_vec()]),
                ("nTSecurityDescriptor".into(), vec![descriptor]),
            ],
        };
        let grants = grants_of(&entry);
        assert_eq!(grants.len(), 2);
        assert!(grants.iter().any(|g| g.rights == "WriteDacl"), "{grants:?}");
        assert!(
            grants
                .iter()
                .any(|g| g.rights == "DS-Replication-Get-Changes-All"),
            "{grants:?}"
        );

        // The row rendering names Everyone through the table.
        let row = finding(
            "dc01",
            &[
                ("object", Some(Field::Text(&grants[0].object))),
                ("right", Some(Field::Text(&grants[0].rights))),
                (
                    "trustee",
                    Some(Field::Text(&acl::sid_string(&grants[0].trustee).unwrap())),
                ),
            ],
            source_field("ldap-acls"),
        );
        assert!(row.contains("\"object\":\"Helpdesk\""), "{row}");
        assert!(row.contains("\"trustee\":\"S-1-1-0\""), "{row}");
    }

    #[test]
    fn the_row_budget_truncates_and_says_so() {
        let mut rows = Rows::new();
        rows.remaining = 2;
        rows.push(finding("h", &[("a", Some(Field::Text("1")))], None));
        rows.push(finding("h", &[("a", Some(Field::Text("2")))], None));
        rows.push(finding("h", &[("a", Some(Field::Text("3")))], None));
        assert!(rows.exhausted());
        let lines = rows.finish("h");
        assert_eq!(lines.len(), 3, "two rows plus the truncation hint");
        assert!(lines[2].contains("row budget"), "{}", lines[2]);
    }

    #[test]
    fn dns_domains_become_dn_bases() {
        assert_eq!(
            domain_dn(Some("corp.example.com")).as_deref(),
            Some("DC=corp,DC=example,DC=com")
        );
        assert_eq!(domain_dn(Some("single")).as_deref(), None);
        assert_eq!(domain_dn(None), None);
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
