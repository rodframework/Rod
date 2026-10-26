//! The task-argument grammar: `persist.services [action] [name]
//! <command>`. The operator UI serializes a task form by joining
//! parameter values with single spaces in declaration order, so the
//! positional reading is the canonical wire shape; the `key=`
//! assignments are the hand-typed alternative, and the command is the
//! raw remainder either way -- a binary path with arguments survives
//! the grammar only as the remainder, which is why the command
//! parameter is the verb's trailing one.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the runkeys grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do with the seat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the service seats the database carries. The default: a
    /// bare `persist.services` is a read, never a write.
    List,
    /// Create one service record with its binary path.
    Install,
    /// Mark one service record for deletion.
    Remove,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The service name -- the seat's own name in the database. For
    /// `list`, a filter narrowing the report to one service.
    pub name: Option<String>,
    /// The binary path the service runs; the raw remainder of the
    /// grammar.
    pub command: Option<String>,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (action_token, rest) = split_first_token(text);
    let action = action_of(action_token)?;
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Ok(Arguments {
            action,
            name: None,
            command: None,
        });
    }

    // The name: `name=` or the positional token; absent when the
    // command rode keyed behind the action alone.
    let (name, rest) = if let Some(value) = rest.strip_prefix("name=") {
        let (value, remainder) = split_first_token(value);
        (Some(value.to_string()), remainder)
    } else if rest.starts_with("command=") {
        (None, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (Some(value.to_string()), remainder)
    };

    // The command: `command=` then everything after, or the positional
    // remainder verbatim.
    let command = if rest.trim().is_empty() {
        None
    } else if let Some(value) = rest.trim_start().strip_prefix("command=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments {
        action,
        name,
        command,
    })
}

/// Checks the parsed grammar against the action it names: install
/// needs its seat and its command, remove needs the seat and refuses a
/// command, and list is a read that carries no command. A task the
/// action cannot honor refuses here, before anything touches the
/// service database.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: services <install|remove|list> <name> <command>";
    match (&arguments.action, &arguments.name, &arguments.command) {
        (Action::Install, None, _) => Err(format!(
            "install needs the service name for the seat; {grammar}"
        )),
        (Action::Install, Some(_), None) => Err(format!(
            "install needs the command as the trailing remainder; {grammar}"
        )),
        (Action::Remove, None, _) => Err(format!(
            "remove needs the service name it deletes; {grammar}"
        )),
        (Action::Remove, Some(_), Some(_)) => Err(format!(
            "command rides install only; remove takes the name alone; {grammar}"
        )),
        (Action::List, _, Some(_)) => Err(format!(
            "command rides install only; list is the read; {grammar}"
        )),
        _ => Ok(()),
    }
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "install" => Ok(Action::Install),
        "remove" => Ok(Action::Remove),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "persist.services: unknown action '{action}' (install, remove, list)"
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
        // The UI joins values with single spaces: action, name, then the
        // command as the trailing remainder -- spaces and arguments
        // inside the binary path survive.
        assert_eq!(
            parse("install UpdateCheck C:\\ProgramData\\update.exe /quiet").unwrap(),
            Arguments {
                action: Action::Install,
                name: Some("UpdateCheck".into()),
                command: Some("C:\\ProgramData\\update.exe /quiet".into()),
            }
        );
        assert_eq!(
            parse("remove UpdateCheck").unwrap(),
            Arguments {
                action: Action::Remove,
                name: Some("UpdateCheck".into()),
                command: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=install name=UpdateCheck command=cmd /c x").unwrap(),
            Arguments {
                action: Action::Install,
                name: Some("UpdateCheck".into()),
                command: Some("cmd /c x".into()),
            }
        );
        // A keyed command behind the action alone is the one shape the
        // positional read cannot express -- the name is absent and the
        // validation refuses it, naming the part install needs.
        assert_eq!(
            parse("list command=cmd /c x").unwrap(),
            Arguments {
                action: Action::List,
                name: None,
                command: Some("cmd /c x".into()),
            }
        );
        assert_eq!(
            parse("remove name=UpdateCheck").unwrap(),
            Arguments {
                action: Action::Remove,
                name: Some("UpdateCheck".into()),
                command: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("INSTALL").unwrap().action, Action::Install);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(
            parse("list UpdateCheck").unwrap().name,
            Some("UpdateCheck".into())
        );
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("uninstall UpdateCheck").unwrap_err();
        assert!(action.contains("unknown action 'uninstall'"), "{action}");
        assert!(action.contains("install, remove, list"), "{action}");

        let keyed = parse("name=UpdateCheck").unwrap_err();
        assert!(
            keyed.contains("unknown action 'name=UpdateCheck'"),
            "{keyed}"
        );
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Install: the seat and its command.
        assert!(validate(&parse("install UpdateCheck cmd /c x").unwrap()).is_ok());
        assert!(validate(&parse("install").unwrap()).is_err());
        assert!(validate(&parse("install UpdateCheck").unwrap()).is_err());

        // Remove: the seat alone.
        assert!(validate(&parse("remove UpdateCheck").unwrap()).is_ok());
        assert!(validate(&parse("remove").unwrap()).is_err());
        assert!(validate(&parse("remove UpdateCheck cmd /c x").unwrap()).is_err());

        // List: a read, with an optional name filter, never a command.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("list UpdateCheck").unwrap()).is_ok());
        assert!(validate(&parse("list UpdateCheck cmd /c x").unwrap()).is_err());
    }
}
