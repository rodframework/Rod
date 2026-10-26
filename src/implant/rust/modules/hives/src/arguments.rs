//! The task-argument grammar: `collect.hives [action] <directory>`.
//! The operator UI serializes a task form by joining parameter values
//! with single spaces in declaration order, so the positional reading
//! is the canonical wire shape; the `key=` assignments are the
//! hand-typed alternative, and the directory is the raw remainder
//! either way -- a path with spaces survives the grammar only as the
//! remainder, which is why the directory parameter is the verb's
//! trailing one.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the runkeys grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the readiness facts: the backup privilege in hand or
    /// not, and each source hive in place or not. The default: a bare
    /// `collect.hives` is a read, never a write.
    List,
    /// Save the three hives into the task-named directory.
    Save,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The directory the dumps land in; save only, the raw remainder
    /// of the grammar.
    pub directory: Option<String>,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (action_token, rest) = split_first_token(text);
    let action = action_of(action_token)?;
    let rest = rest.trim_start();

    // The directory: `directory=` then everything after, or the
    // positional remainder verbatim.
    let directory = if rest.is_empty() {
        None
    } else if let Some(value) = rest.strip_prefix("directory=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments { action, directory })
}

/// Checks the parsed grammar against the action it names: save needs
/// its directory, list is a read that carries none. A task the action
/// cannot honor refuses here, before anything touches the disk.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: hives <save|list> <directory>";
    match arguments {
        Arguments {
            action: Action::List,
            directory: Some(_),
        } => Err(format!(
            "directory rides save only; list is the read; {grammar}"
        )),
        Arguments {
            action: Action::List,
            directory: None,
        } => Ok(()),
        Arguments {
            action: Action::Save,
            directory: None,
        } => Err(format!(
            "save needs the directory the dumps land in as the trailing remainder; {grammar}"
        )),
        Arguments {
            action: Action::Save,
            directory: Some(_),
        } => Ok(()),
    }
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "save" => Ok(Action::Save),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "collect.hives: unknown action '{action}' (save, list)"
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
        // directory as the trailing remainder -- spaces inside the
        // path survive.
        assert_eq!(
            parse(r"save C:\loot dir").unwrap(),
            Arguments {
                action: Action::Save,
                directory: Some(r"C:\loot dir".into()),
            }
        );
        assert_eq!(
            parse("list").unwrap(),
            Arguments {
                action: Action::List,
                directory: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=save directory=C:\\loot").unwrap(),
            Arguments {
                action: Action::Save,
                directory: Some(r"C:\loot".into()),
            }
        );
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                action: Action::List,
                directory: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("SAVE").unwrap().action, Action::Save);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("dump C:\\loot").unwrap_err();
        assert!(action.contains("unknown action 'dump'"), "{action}");
        assert!(action.contains("save, list"), "{action}");
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Save: the directory.
        assert!(validate(&parse(r"save C:\loot").unwrap()).is_ok());
        assert!(validate(&parse("save").unwrap()).is_err());

        // List: a read, never a directory.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("").unwrap()).is_ok());
        assert!(validate(&parse(r"list C:\loot").unwrap()).is_err());
    }
}
