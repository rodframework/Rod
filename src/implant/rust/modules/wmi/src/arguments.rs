//! The task-argument grammar: `persist.wmi [action] [name] [trigger]
//! <command>`. The operator UI serializes a task form by joining
//! parameter values with single spaces in declaration order, so the
//! positional reading is the canonical wire shape; the `key=`
//! assignments are the hand-typed alternative, and the command is the
//! raw remainder either way -- a command line survives the grammar only
//! as the remainder, which is why the command parameter is the verb's
//! trailing one. The trigger is one token by the same rule: the forms
//! it takes (a clock time, an image name, the logon word) are all
//! token-shaped, and the module builds the query they name.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the runkeys grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do with the seat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the bound subscriptions the repository carries. The
    /// default: a bare `persist.wmi` is a read, never a write.
    List,
    /// Create the subscription triple under one seat name.
    Install,
    /// Delete the triple the seat name carries.
    Remove,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The seat name -- the one name the filter, the consumer, and the
    /// binding's two sides share. For `list`, a filter narrowing the
    /// report to one seat.
    pub name: Option<String>,
    /// When the seat fires: `daily:HH:MM`, `process:<image name>`, or
    /// `logon`; install only.
    pub trigger: Option<String>,
    /// The command line the consumer runs; the raw remainder of the
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
            trigger: None,
            command: None,
        });
    }

    // The name: `name=` or the positional token; absent when a later
    // slot rode keyed behind the action alone.
    let (name, rest) = if let Some(value) = rest.strip_prefix("name=") {
        let (value, remainder) = split_first_token(value);
        (Some(value.to_string()), remainder)
    } else if rest.starts_with("trigger=") || rest.starts_with("command=") {
        (None, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (Some(value.to_string()), remainder)
    };

    // The trigger: `trigger=` or the positional token; absent when the
    // command rode keyed behind it.
    let rest = rest.trim_start();
    let (trigger, rest) = if rest.is_empty() {
        (None, rest)
    } else if let Some(value) = rest.strip_prefix("trigger=") {
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
        trigger,
        command,
    })
}

/// Checks the parsed grammar against the action it names: install
/// needs its seat, its trigger, and its command, with the trigger one
/// the query builder answers; remove needs the seat and refuses both
/// install-only slots; list is a read that carries neither. A task the
/// action cannot honor refuses here, before anything touches the
/// repository.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: wmi <install|remove|list> <name> <trigger> <command>";
    let trigger_forms = "the trigger forms are: daily:HH:MM, process:<image name>, logon";
    match arguments {
        Arguments {
            action: Action::Install,
            name: None,
            ..
        } => Err(format!(
            "install needs the seat name for the triple; {grammar}"
        )),
        Arguments {
            action: Action::Install,
            name: Some(_),
            trigger: None,
            ..
        } => Err(format!("install needs its trigger; {trigger_forms}")),
        Arguments {
            action: Action::Install,
            name: Some(name),
            trigger: Some(trigger),
            command: None,
        } => {
            check_name(name)?;
            crate::subscription::trigger_query(trigger)?;
            Err(format!(
                "install needs the command as the trailing remainder; {grammar}"
            ))
        }
        Arguments {
            action: Action::Install,
            name: Some(name),
            trigger: Some(trigger),
            command: Some(_),
        } => {
            check_name(name)?;
            crate::subscription::trigger_query(trigger).map(|_| ())
        }
        Arguments {
            action: Action::Remove,
            name: None,
            ..
        } => Err(format!("remove needs the seat name it deletes; {grammar}")),
        Arguments {
            action: Action::Remove,
            name: Some(name),
            trigger,
            command,
        } => {
            check_name(name)?;
            if trigger.is_some() || command.is_some() {
                Err(format!(
                    "trigger and command ride install only; remove takes the name alone; {grammar}"
                ))
            } else {
                Ok(())
            }
        }
        Arguments {
            action: Action::List,
            trigger,
            command,
            ..
        } => {
            if trigger.is_some() || command.is_some() {
                Err(format!(
                    "trigger and command ride install only; list is the read; {grammar}"
                ))
            } else {
                Ok(())
            }
        }
    }
}

/// The seat name rides quoted WMI object paths, so the two characters
/// that would leave the quotes refuse here -- a name that cannot be
/// pathed safely cannot be installed or deleted by name either.
fn check_name(name: &str) -> Result<(), String> {
    if name.contains('"') || name.contains('\\') {
        return Err(format!(
            "persist.wmi: the seat name cannot carry a quote or a backslash: '{name}'"
        ));
    }
    Ok(())
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
            "persist.wmi: unknown action '{action}' (install, remove, list)"
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
        // The UI joins values with single spaces: action, name,
        // trigger, then the command as the trailing remainder --
        // spaces and arguments inside the command line survive.
        assert_eq!(
            parse("install SeatA daily:09:30 cmd.exe /c update.exe /quiet").unwrap(),
            Arguments {
                action: Action::Install,
                name: Some("SeatA".into()),
                trigger: Some("daily:09:30".into()),
                command: Some("cmd.exe /c update.exe /quiet".into()),
            }
        );
        assert_eq!(
            parse("remove SeatA").unwrap(),
            Arguments {
                action: Action::Remove,
                name: Some("SeatA".into()),
                trigger: None,
                command: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=install name=SeatA trigger=logon command=cmd /c x").unwrap(),
            Arguments {
                action: Action::Install,
                name: Some("SeatA".into()),
                trigger: Some("logon".into()),
                command: Some("cmd /c x".into()),
            }
        );
        assert_eq!(
            parse("install SeatA trigger=process:notepad.exe command=cmd /c x").unwrap(),
            Arguments {
                action: Action::Install,
                name: Some("SeatA".into()),
                trigger: Some("process:notepad.exe".into()),
                command: Some("cmd /c x".into()),
            }
        );
        assert_eq!(
            parse("remove name=SeatA").unwrap(),
            Arguments {
                action: Action::Remove,
                name: Some("SeatA".into()),
                trigger: None,
                command: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("INSTALL").unwrap().action, Action::Install);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(parse("list SeatA").unwrap().name, Some("SeatA".into()));
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("uninstall SeatA").unwrap_err();
        assert!(action.contains("unknown action 'uninstall'"), "{action}");
        assert!(action.contains("install, remove, list"), "{action}");

        let trigger =
            validate(&parse("install SeatA daily command=cmd /c x").unwrap()).unwrap_err();
        assert!(trigger.contains("unknown trigger 'daily'"), "{trigger}");
        assert!(
            trigger.contains("daily:HH:MM, process:<image name>, logon"),
            "{trigger}"
        );
    }

    #[test]
    fn seat_names_that_cannot_path_refuse() {
        assert!(validate(&parse(r#"install He"llo logon cmd /c x"#).unwrap()).is_err());
        assert!(validate(&parse(r"install He\llo logon cmd /c x").unwrap()).is_err());
        assert!(validate(&parse("install Hello logon cmd /c x").unwrap()).is_ok());
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Install: the seat, the trigger, and the command.
        assert!(validate(&parse("install SeatA logon cmd /c x").unwrap()).is_ok());
        assert!(validate(&parse("install logon cmd /c x").unwrap()).is_err());
        assert!(validate(&parse("install SeatA cmd /c x").unwrap()).is_err());
        assert!(validate(&parse("install SeatA logon").unwrap()).is_err());

        // Remove: the seat alone.
        assert!(validate(&parse("remove SeatA").unwrap()).is_ok());
        assert!(validate(&parse("remove").unwrap()).is_err());
        assert!(validate(&parse("remove SeatA logon cmd /c x").unwrap()).is_err());

        // List: a read, with an optional name filter, never a trigger
        // or command.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("list SeatA").unwrap()).is_ok());
        assert!(validate(&parse("list SeatA logon cmd /c x").unwrap()).is_err());
    }
}
