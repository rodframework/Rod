//! The task-argument grammar: `collect.credman [action] [target]`.
//! The operator UI serializes a task form by joining parameter values
//! with single spaces in declaration order, so the positional reading
//! is the canonical wire shape; the `key=` assignments are the
//! hand-typed alternative, and the target name is the raw remainder
//! either way -- a target the store carries rides whole
//! (`TERMSRV/web01.corp.example` keeps its slashes and its dots), which
//! is why the target parameter is the verb's trailing one.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the lsasecrets grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// The survey read: the store's entries named -- target, type,
    /// user, persistence, last write -- one row per entry, no secret
    /// in any row. The default: a bare `collect.credman` is a read,
    /// never a value pulled.
    List,
    /// Take the entries' material -- every entry's, or the one the
    /// trailing target picks, matched against the entry's target name.
    Read,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The one entry `read` narrows to; absent reads the whole store.
    /// Read only, the raw remainder of the grammar.
    pub target: Option<String>,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (action_token, rest) = split_first_token(text);
    let action = action_of(action_token)?;
    let rest = rest.trim_start();

    // The target: `target=` then everything after, or the positional
    // remainder verbatim.
    let target = if rest.is_empty() {
        None
    } else if let Some(value) = rest.strip_prefix("target=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments { action, target })
}

/// Checks the parsed grammar against the action it names: read carries
/// its optional target, list is a survey that carries none. A task the
/// action cannot honor refuses here, before anything opens the store.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: credman <list|read> [target]";
    match arguments {
        Arguments {
            action: Action::List,
            target: Some(_),
        } => Err(format!(
            "a target rides read only; list is the survey; {grammar}"
        )),
        Arguments {
            action: Action::List,
            target: None,
        } => Ok(()),
        Arguments {
            action: Action::Read,
            target: _,
        } => Ok(()),
    }
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "read" => Ok(Action::Read),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "collect.credman: unknown action '{action}' (list, read)"
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
        // The UI joins values with single spaces: the action, then the
        // target as the trailing remainder -- the slashes and the dots
        // ride whole.
        assert_eq!(
            parse("read TERMSRV/web01.corp.example").unwrap(),
            Arguments {
                action: Action::Read,
                target: Some("TERMSRV/web01.corp.example".into()),
            }
        );
        assert_eq!(
            parse("list").unwrap(),
            Arguments {
                action: Action::List,
                target: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=read target=LegacyProxy").unwrap(),
            Arguments {
                action: Action::Read,
                target: Some("LegacyProxy".into()),
            }
        );
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                action: Action::List,
                target: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("READ").unwrap().action, Action::Read);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("dump LegacyProxy").unwrap_err();
        assert!(action.contains("unknown action 'dump'"), "{action}");
        assert!(action.contains("list, read"), "{action}");
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Read: the whole store bare, or the one target.
        assert!(validate(&parse("read").unwrap()).is_ok());
        assert!(validate(&parse("read WindowsLive:token").unwrap()).is_ok());

        // List: a survey, never a target.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("").unwrap()).is_ok());
        let refused = parse("list WindowsLive:token").unwrap();
        assert!(validate(&refused).is_err());
    }
}
