//! The task-argument grammar: `evasion.unload [action] [dll]
//! [functions]`. The bare task stays the read it always was (ntdll's
//! whole `.text` against the fresh copy); the two widening slots scope
//! the same act -- the library the task names (per-DLL, ntdll.dll the
//! default) and the exports it narrows to (per-function, comma-joined,
//! the whole `.text` the default). The operator UI serializes a task
//! form by joining parameter values with single spaces in declaration
//! order, so the positional reading is the canonical wire shape and
//! the `key=` assignments are the hand-typed alternative; the function
//! list is the raw remainder, which is why the functions parameter is
//! the verb's trailing one.

/// What the task asked the verb to do with the named library's mapped
/// `.text`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Compare the mapped `.text` against the fresh copy and report
    /// the differing bytes. The default: a read, never a write.
    List,
    /// Copy the fresh `.text` over the mapped one -- the write the
    /// operator names.
    Restore,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    /// The library the task names; absent means the v1.0 default,
    /// ntdll.dll.
    pub dll: Option<String>,
    /// The exports the task narrows to, comma-joined in the grammar;
    /// empty means the whole `.text`.
    pub functions: Vec<String>,
}

/// Parses the argument grammar. The parse is the whole refusal: a
/// token it does not know, a path where a library's name belongs, or
/// an empty name between commas refuses the task before anything
/// touches memory.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (token, rest) = split_first_token(text);
    let action = action_of(token)?;
    let rest = rest.trim();

    // The dll slot: the `dll=` assignment, or the first bare token --
    // unless the remainder opens with the functions slot, which lets a
    // task narrow functions under the default library.
    let (dll, rest) = if let Some(value) = rest.strip_prefix("dll=") {
        let (name, remainder) = split_first_token(value);
        (Some(name.trim().to_string()), remainder.trim())
    } else if rest.starts_with("functions=") || rest.is_empty() {
        (None, rest)
    } else {
        let (name, remainder) = split_first_token(rest);
        (Some(name.trim().to_string()), remainder.trim())
    };

    // The functions slot: `functions=` then the comma-joined list, or
    // the positional remainder verbatim.
    let functions = if rest.is_empty() {
        Vec::new()
    } else {
        let list = rest.strip_prefix("functions=").unwrap_or(rest);
        split_functions(list)?
    };

    Ok(Arguments {
        action,
        dll,
        functions,
    })
}

/// Checks the parsed grammar against what the slots carry: the dll is
/// a library's name, never a path, and the function list carries whole
/// names alone. A task the grammar cannot honor refuses here, before
/// anything opens an image.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    if let Some(dll) = &arguments.dll {
        if dll.chars().any(|c| matches!(c, '\\' | '/' | ':')) {
            return Err(format!(
                "evasion.unload: '{dll}' is a path, not a library's name -- the fresh \
                 copy resolves under System32 and KnownDlls; {GRAMMAR}"
            ));
        }
        if dll.is_empty() {
            return Err(format!("evasion.unload: the dll slot is empty; {GRAMMAR}"));
        }
    }
    for name in &arguments.functions {
        if name.is_empty() {
            return Err(format!(
                "evasion.unload: an empty name rides the function list; {GRAMMAR}"
            ));
        }
        if name.chars().any(char::is_whitespace) {
            return Err(format!(
                "evasion.unload: '{name}' carries whitespace -- export names carry \
                 none; {GRAMMAR}"
            ));
        }
    }
    Ok(())
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "restore" => Ok(Action::Restore),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "evasion.unload: unknown action '{action}' (list, restore); {GRAMMAR}"
        )),
    }
}

/// The comma-joined function list: whole names, no empties between
/// commas -- a typo refuses the task rather than half-reading under
/// it.
fn split_functions(list: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for name in list.split(',') {
        names.push(name.trim().to_string());
    }
    if names.iter().any(String::is_empty) {
        return Err(format!(
            "evasion.unload: an empty name rides the function list; {GRAMMAR}"
        ));
    }
    Ok(names)
}

const GRAMMAR: &str = "the grammar is: unload <list|restore> [dll] [functions]";

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
        // The UI joins values with single spaces: the action, the
        // library, then the comma-joined list as the trailing
        // remainder -- the v1.0 bare task unchanged beneath both.
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                action: Action::List,
                dll: None,
                functions: Vec::new(),
            }
        );
        assert_eq!(
            parse("restore kernel32.dll CreateFileW,ReadFile").unwrap(),
            Arguments {
                action: Action::Restore,
                dll: Some("kernel32.dll".into()),
                functions: vec!["CreateFileW".into(), "ReadFile".into()],
            }
        );
        assert_eq!(
            parse("list ntdll.dll").unwrap(),
            Arguments {
                action: Action::List,
                dll: Some("ntdll.dll".into()),
                functions: Vec::new(),
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=restore dll=kernelbase.dll functions=A,B").unwrap(),
            Arguments {
                action: Action::Restore,
                dll: Some("kernelbase.dll".into()),
                functions: vec!["A".into(), "B".into()],
            }
        );
        // The functions slot opens alone: the default library rides.
        assert_eq!(
            parse("restore functions=NtOpenFile").unwrap(),
            Arguments {
                action: Action::Restore,
                dll: None,
                functions: vec!["NtOpenFile".into()],
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("RESTORE").unwrap().action, Action::Restore);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(
            parse("  restore  ntdll.dll  ").unwrap().dll,
            Some("ntdll.dll".into())
        );
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let unknown = parse("unhook").unwrap_err();
        assert!(unknown.contains("unknown action 'unhook'"), "{unknown}");
        assert!(unknown.contains("list, restore"), "{unknown}");
    }

    #[test]
    fn a_path_where_a_name_belongs_refuses() {
        let refused = parse(r"restore C:\Windows\System32\ntdll.dll").unwrap();
        assert!(validate(&refused).is_err());
        let error = validate(&refused).unwrap_err();
        assert!(error.contains("not a library's name"), "{error}");
    }

    #[test]
    fn the_function_list_carries_whole_names_alone() {
        // An empty name between commas refuses the task outright --
        // at the parse, before anything runs.
        let error = parse("restore ntdll.dll NtOpenFile,,NtClose").unwrap_err();
        assert!(error.contains("empty name"), "{error}");

        // A name carrying whitespace is no export name.
        let refused = parse("restore ntdll.dll Two Words").unwrap();
        let error = validate(&refused).unwrap_err();
        assert!(error.contains("whitespace"), "{error}");

        // Whole names alone pass.
        let parsed = parse("restore ntdll.dll NtOpenFile, NtClose").unwrap();
        assert_eq!(
            parsed.functions,
            vec!["NtOpenFile".to_string(), "NtClose".to_string()]
        );
        assert!(validate(&parsed).is_ok());
    }
}
