//! The task-argument grammar: `persist.hijack [action] [binary] [dll]
//! <source>`. The operator UI serializes a task form by joining
//! parameter values with single spaces in declaration order, so the
//! positional reading is the canonical wire shape; the `key=`
//! assignments are the hand-typed alternative, and the source path is
//! the raw remainder either way -- a path with spaces survives the
//! grammar only in that trailing slot, which is one reason the source
//! rides last.
//!
//! The slots refuse what they do not know rather than half-reading
//! under a typo (the same rule the runkeys grammar holds), and the
//! per-action validation teaches the shape each action needs.

/// What the task asked the verb to do with the seat.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the host binary's open slots: the DLLs it imports that
    /// a planted file beside it could claim. A read, never a write --
    /// but unlike the family's registry and repository seats there is
    /// no system ledger to enumerate, so the read names the binary it
    /// inspects.
    List,
    /// Copy an already-pushed file into the seat, after validating
    /// the slot.
    Install,
    /// Delete the planted file.
    Remove,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The host binary whose directory the seat lives in -- a full
    /// path, because the loader's first search stop is that directory
    /// and the module speaks of it exactly. For `list`, the binary
    /// whose slots the report reads.
    pub binary: Option<String>,
    /// The imported DLL name the seat claims; for `list`, a filter
    /// narrowing the report to it.
    pub dll: Option<String>,
    /// The file to plant, already delivered by `file.push` or any
    /// other means; install only.
    pub source: Option<String>,
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
            binary: None,
            dll: None,
            source: None,
        });
    }

    // The binary: `binary=` or the positional token; absent when a
    // later slot rode keyed behind the action alone.
    let (binary, rest) = if let Some(value) = rest.strip_prefix("binary=") {
        let (value, remainder) = split_first_token(value);
        (Some(value.to_string()), remainder)
    } else if rest.starts_with("dll=") || rest.starts_with("source=") {
        (None, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (Some(value.to_string()), remainder)
    };

    // The dll: `dll=` or the positional token; absent when the source
    // rode keyed behind it.
    let rest = rest.trim_start();
    let (dll, rest) = if rest.is_empty() {
        (None, rest)
    } else if let Some(value) = rest.strip_prefix("dll=") {
        let (value, remainder) = split_first_token(value);
        (Some(value.to_string()), remainder)
    } else if rest.starts_with("source=") {
        (None, rest)
    } else {
        let (value, remainder) = split_first_token(rest);
        (Some(value.to_string()), remainder)
    };

    // The source: `source=` then everything after, or the positional
    // remainder verbatim.
    let source = if rest.trim().is_empty() {
        None
    } else if let Some(value) = rest.trim_start().strip_prefix("source=") {
        (!value.trim().is_empty()).then(|| value.trim().to_string())
    } else {
        Some(rest.trim().to_string())
    };

    Ok(Arguments {
        action,
        binary,
        dll,
        source,
    })
}

/// Checks the parsed grammar against the action it names: install
/// needs its binary, its dll, and its source; remove needs the binary
/// and dll and refuses the install-only source; list needs the binary
/// it inspects. The shape checks (a full backslashed path, an imported
/// name rather than a path) ride the same validation, so a task the
/// action cannot honor refuses before anything touches the disk.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    let grammar = "the grammar is: hijack <install|remove|list> <binary> <dll> <source>";
    match arguments {
        Arguments {
            action: Action::List,
            source: Some(_),
            ..
        } => Err(format!(
            "source rides install only; list is the read; {grammar}"
        )),
        Arguments {
            action: Action::List,
            binary: None,
            ..
        } => Err(format!(
            "list needs the host binary whose slots it reads; {grammar}"
        )),
        Arguments {
            action: Action::List,
            binary: Some(binary),
            dll: Some(dll),
            ..
        } => {
            check_binary(binary)?;
            check_dll(dll)
        }
        Arguments {
            action: Action::List,
            binary: Some(binary),
            ..
        } => check_binary(binary),

        Arguments {
            action: Action::Install,
            binary: None,
            ..
        } => Err(format!(
            "install needs the host binary whose directory the seat lives in; {grammar}"
        )),
        Arguments {
            action: Action::Install,
            binary: Some(_),
            dll: None,
            ..
        } => Err(format!(
            "install needs the imported dll name the seat claims; {grammar}"
        )),
        Arguments {
            action: Action::Install,
            binary: Some(binary),
            dll: Some(dll),
            source: None,
        } => {
            check_binary(binary)?;
            check_dll(dll)?;
            Err(format!(
                "install needs the source file as the trailing remainder; {grammar}"
            ))
        }
        Arguments {
            action: Action::Install,
            binary: Some(binary),
            dll: Some(dll),
            source: Some(_),
        } => {
            check_binary(binary)?;
            check_dll(dll)
        }

        Arguments {
            action: Action::Remove,
            binary: None,
            ..
        } => Err(format!(
            "remove needs the host binary the seat sits beside; {grammar}"
        )),
        Arguments {
            action: Action::Remove,
            binary: Some(_),
            dll: None,
            ..
        } => Err(format!("remove needs the dll name it deletes; {grammar}")),
        Arguments {
            action: Action::Remove,
            binary: Some(_),
            dll: Some(_),
            source: Some(_),
        } => Err(format!(
            "source rides install only; remove takes the binary and dll alone; {grammar}"
        )),
        Arguments {
            action: Action::Remove,
            binary: Some(binary),
            dll: Some(dll),
            source: None,
        } => {
            check_binary(binary)?;
            check_dll(dll)
        }
    }
}

/// The binary rides a token slot, so a spaced path cannot cross the
/// wire as one value -- it reads as two tokens and the next slot's
/// shape check refuses the remainder. What this check owns is the
/// other fact: the loader's first search stop is the binary's own
/// directory, which only a full backslashed path names.
fn check_binary(binary: &str) -> Result<(), String> {
    if !binary.contains('\\') {
        return Err(format!(
            "persist.hijack: the binary rides as a full path (its directory is the \
             seat the loader reads first): '{binary}'"
        ));
    }
    Ok(())
}

/// The dll is an imported name, not a path: a separator in it would
/// move the seat out of the binary's directory, and the loader never
/// looks there anyway.
fn check_dll(dll: &str) -> Result<(), String> {
    if dll.contains('\\') || dll.contains('/') || dll.contains(char::is_whitespace) {
        return Err(format!(
            "persist.hijack: the dll is the imported name beside the binary, not a \
             path: '{dll}'"
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
            "persist.hijack: unknown action '{action}' (install, remove, list)"
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
        // The UI joins values with single spaces: action, binary, dll,
        // then the source as the trailing remainder -- spaces inside
        // the source path survive.
        assert_eq!(
            parse(r"install C:\app\app.exe VERSION.DLL C:\temp\my payload.dll").unwrap(),
            Arguments {
                action: Action::Install,
                binary: Some(r"C:\app\app.exe".into()),
                dll: Some("VERSION.DLL".into()),
                source: Some(r"C:\temp\my payload.dll".into()),
            }
        );
        assert_eq!(
            parse(r"remove C:\app\app.exe VERSION.DLL").unwrap(),
            Arguments {
                action: Action::Remove,
                binary: Some(r"C:\app\app.exe".into()),
                dll: Some("VERSION.DLL".into()),
                source: None,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse(r"action=install binary=C:\app\app.exe dll=VERSION.DLL source=cmd /c x").unwrap(),
            Arguments {
                action: Action::Install,
                binary: Some(r"C:\app\app.exe".into()),
                dll: Some("VERSION.DLL".into()),
                source: Some("cmd /c x".into()),
            }
        );
        assert_eq!(
            parse(r"list binary=C:\app\app.exe").unwrap(),
            Arguments {
                action: Action::List,
                binary: Some(r"C:\app\app.exe".into()),
                dll: None,
                source: None,
            }
        );
        assert_eq!(
            parse(r"remove C:\app\app.exe dll=VERSION.DLL").unwrap(),
            Arguments {
                action: Action::Remove,
                binary: Some(r"C:\app\app.exe".into()),
                dll: Some("VERSION.DLL".into()),
                source: None,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("").unwrap().action, Action::List);
        assert_eq!(parse("INSTALL").unwrap().action, Action::Install);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(
            parse(r"list C:\app\app.exe").unwrap().binary,
            Some(r"C:\app\app.exe".into())
        );
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse(r"uninstall C:\app\app.exe").unwrap_err();
        assert!(action.contains("unknown action 'uninstall'"), "{action}");
        assert!(action.contains("install, remove, list"), "{action}");
    }

    #[test]
    fn binary_paths_the_wire_cannot_carry_refuse() {
        // A spaced path crosses the wire as two tokens: the second
        // lands in the dll slot, whose shape check refuses it and so
        // teaches what happened.
        let spaced = validate(&parse(r"list C:\Program Files\app\app.exe").unwrap()).unwrap_err();
        assert!(
            spaced.contains("imported name beside the binary"),
            "{spaced}"
        );

        // A path without a directory cannot name the seat.
        let bare = validate(&parse("list app.exe").unwrap()).unwrap_err();
        assert!(bare.contains("full path"), "{bare}");

        assert!(validate(&parse(r"list C:\app\app.exe").unwrap()).is_ok());
    }

    #[test]
    fn dll_names_that_are_paths_refuse() {
        assert!(validate(&parse(r"install C:\app\app.exe ..\x.dll src").unwrap()).is_err());
        assert!(validate(&parse(r"remove C:\app\app.exe system32\x.dll").unwrap()).is_err());
        assert!(validate(&parse(r"install C:\app\app.exe VERSION.DLL src").unwrap()).is_ok());
    }

    #[test]
    fn each_action_gets_the_parts_it_needs() {
        // Install: the binary, the dll, and the source.
        assert!(
            validate(&parse(r"install C:\app\app.exe VERSION.DLL C:\temp\p.dll").unwrap()).is_ok()
        );
        assert!(validate(&parse(r"install VERSION.DLL C:\temp\p.dll").unwrap()).is_err());
        assert!(validate(&parse(r"install C:\app\app.exe C:\temp\p.dll").unwrap()).is_err());
        assert!(validate(&parse(r"install C:\app\app.exe VERSION.DLL").unwrap()).is_err());

        // Remove: the binary and dll alone.
        assert!(validate(&parse(r"remove C:\app\app.exe VERSION.DLL").unwrap()).is_ok());
        assert!(validate(&parse(r"remove C:\app\app.exe").unwrap()).is_err());
        assert!(
            validate(&parse(r"remove C:\app\app.exe VERSION.DLL C:\temp\p.dll").unwrap()).is_err()
        );

        // List: the binary it inspects, an optional dll filter, never
        // a source.
        assert!(validate(&parse("list").unwrap()).is_err());
        assert!(validate(&parse(r"list C:\app\app.exe").unwrap()).is_ok());
        assert!(validate(&parse(r"list C:\app\app.exe VERSION.DLL").unwrap()).is_ok());
        assert!(validate(&parse(r"list C:\app\app.exe VERSION.DLL p.dll").unwrap()).is_err());
    }
}
