//! The task-argument grammar: `recon.domainenum [scope] [user] [pass]`.
//! The operator UI serializes a task form by joining parameter values
//! with single spaces in declaration order, so the positional reading is
//! the canonical wire shape; the `key=` assignments are the hand-typed
//! alternative. The password is the raw remainder either way -- a secret
//! with spaces survives the grammar only as the remainder, which is why
//! the pass parameter is the verb's trailing one.
//!
//! The credential rides the argument string as the platform's
//! placeholder resolution carries it (architecture.md Sec 15.3): the
//! operator drops `$cred-<id>` into the pass field, the teamserver
//! substitutes the stored secret at dispatch, and every stored form
//! keeps the placeholder -- the module sees only the resolved secret.

/// One sweep scope: what the task asked the verb to read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The whole sweep the task's credential affords: every scope below.
    All,
    /// Local posture, DC location, the anonymous root DSE.
    Info,
    /// The domain's trust relationships.
    Trusts,
    /// Service principals: DNS SRV records, plus the SPN-bearing
    /// accounts when a credential rode the task.
    Spns,
    /// Domain user accounts over authenticated LDAP.
    Users,
    /// Domain groups and their membership over authenticated LDAP.
    Groups,
    /// The escalation-relevant ACEs on domain objects.
    Acls,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub scope: Scope,
    /// The bind principal: UPN (`jdoe@corp.example.com`) or
    /// `DOMAIN\jdoe` -- either form is a legal simple-bind name.
    pub user: Option<String>,
    /// The bind secret; the raw remainder of the argument string.
    pub password: Option<String>,
}

/// Parses the argument grammar. A scope token the grammar does not know
/// refuses the task rather than half-sweeping under a typo.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    if text.is_empty() {
        return Ok(Arguments {
            scope: Scope::All,
            user: None,
            password: None,
        });
    }
    let (scope_token, rest) = split_first_token(text);
    let scope = scope_of(scope_token)?;
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Ok(Arguments {
            scope,
            user: None,
            password: None,
        });
    }

    // The user: `user=` up to whitespace, or the positional token.
    let (user, rest) = if let Some(value) = rest.strip_prefix("user=") {
        let (value, remainder) = split_first_token(value);
        (Some(value.to_string()), remainder)
    } else if rest.starts_with("pass=") {
        (None, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (Some(value.to_string()), remainder)
    };

    // The password: `pass=` then everything after, or the positional
    // remainder verbatim.
    let password = if let Some(value) = rest.trim_start().strip_prefix("pass=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else if rest.trim().is_empty() {
        None
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments {
        scope,
        user,
        password,
    })
}

/// The scope half of the grammar: a bare token or `scope=<token>`,
/// case-insensitive.
fn scope_of(token: &str) -> Result<Scope, String> {
    let scope = token.strip_prefix("scope=").unwrap_or(token);
    match scope.to_ascii_lowercase().as_str() {
        "all" => Ok(Scope::All),
        "info" => Ok(Scope::Info),
        "trusts" => Ok(Scope::Trusts),
        "spns" => Ok(Scope::Spns),
        "users" => Ok(Scope::Users),
        "groups" => Ok(Scope::Groups),
        "acls" => Ok(Scope::Acls),
        other => Err(format!(
            "recon.domainenum: unknown scope '{other}' (all, info, trusts, spns, users, groups, acls)"
        )),
    }
}

/// The credential pair the sweep may bind with: both halves or none --
/// a simple bind with an empty password is the anonymous bind in
/// disguise, and half a credential riding the task is an operator error
/// to refuse, not a read to attempt.
pub(crate) fn credential(arguments: &Arguments) -> Result<Option<(&str, &str)>, String> {
    match (&arguments.user, &arguments.password) {
        (Some(user), Some(password)) => Ok(Some((user, password))),
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("recon.domainenum: user= rode the task without pass=; the bind needs both".into())
        }
        (None, Some(_)) => {
            Err("recon.domainenum: pass= rode the task without user=; the bind needs both".into())
        }
    }
}

fn split_first_token(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((first, rest)) => (first, rest),
        None => (text, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_positional_form_is_the_wire_shape() {
        // The UI joins values with single spaces: scope, user, then the
        // pass as the trailing remainder -- spaces inside the secret
        // survive.
        assert_eq!(
            parse("users jdoe@corp.example.com s3cret two words").unwrap(),
            Arguments {
                scope: Scope::Users,
                user: Some("jdoe@corp.example.com".into()),
                password: Some("s3cret two words".into()),
            }
        );
        assert_eq!(
            parse("all CORP\\svc-scan hunter2").unwrap(),
            Arguments {
                scope: Scope::All,
                user: Some("CORP\\svc-scan".into()),
                password: Some("hunter2".into()),
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("scope=groups user=jdoe pass=plain").unwrap(),
            Arguments {
                scope: Scope::Groups,
                user: Some("jdoe".into()),
                password: Some("plain".into()),
            }
        );
        // A keyed pass without a user is the one bare-credential shape
        // the positional read cannot express.
        assert_eq!(
            parse("acls pass=hunter2").unwrap(),
            Arguments {
                scope: Scope::Acls,
                user: None,
                password: Some("hunter2".into()),
            }
        );
    }

    #[test]
    fn scope_tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().scope, Scope::All);
        assert_eq!(parse("spns").unwrap().scope, Scope::Spns);
        assert_eq!(parse("scope=trusts").unwrap().scope, Scope::Trusts);
        assert_eq!(parse("  INFO ").unwrap().scope, Scope::Info);
        assert!(parse("sweep").is_err());
        // The scope list the refusal teaches covers every scope.
        let refusal = parse("sweep").unwrap_err();
        for scope in ["all", "info", "trusts", "spns", "users", "groups", "acls"] {
            assert!(refusal.contains(scope), "{refusal}");
        }
    }

    #[test]
    fn a_credentialless_task_parses_clean() {
        assert_eq!(
            parse("trusts").unwrap(),
            Arguments {
                scope: Scope::Trusts,
                user: None,
                password: None,
            }
        );
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                scope: Scope::All,
                user: None,
                password: None,
            }
        );
    }

    #[test]
    fn half_credentials_refuse_the_task() {
        // Either half alone names an operator error, not a bind to
        // attempt: an empty-password simple bind is the anonymous bind.
        let user_only = Arguments {
            scope: Scope::Users,
            user: Some("jdoe".into()),
            password: None,
        };
        assert!(credential(&user_only).is_err());
        let pass_only = Arguments {
            scope: Scope::Users,
            user: None,
            password: Some("hunter2".into()),
        };
        assert!(credential(&pass_only).is_err());
        let whole = Arguments {
            scope: Scope::Users,
            user: Some("jdoe".into()),
            password: Some("hunter2".into()),
        };
        assert_eq!(credential(&whole).unwrap(), Some(("jdoe", "hunter2")));
    }
}
