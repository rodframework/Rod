//! The task-argument grammar: `evasion.unload [action]`. One slot,
//! one word: the bare task is the read (the differing-byte count),
//! and the write is a word the operator speaks -- the same
//! bare-task-is-a-read rule the browser and hijack grammars hold.
//! The operator UI serializes a task form by joining parameter values
//! with single spaces in declaration order, so the positional reading
//! is the canonical wire shape and the `key=` assignment is the
//! hand-typed alternative.

/// What the task asked the verb to do with ntdll's mapped `.text`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Compare the mapped `.text` against the disk copy and report
    /// the differing-byte count. The default: a read, never a write.
    List,
    /// Copy the disk `.text` over the mapped one -- the write the
    /// operator names.
    Restore,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
}

/// Parses the argument grammar. The parse is the whole refusal: a
/// token it does not know, or anything after the action slot, refuses
/// the task before anything touches memory.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    let (token, rest) = split_first_token(text);
    let action = action_of(token)?;
    if !rest.trim().is_empty() {
        return Err(format!(
            "evasion.unload: the grammar takes the action alone; '{}' rides \
             nothing; {GRAMMAR}",
            rest.trim()
        ));
    }
    Ok(Arguments { action })
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

const GRAMMAR: &str = "the grammar is: unload <list|restore>";

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
            parse("").unwrap(),
            Arguments {
                action: Action::List
            }
        );
        assert_eq!(
            parse("list").unwrap(),
            Arguments {
                action: Action::List
            }
        );
        assert_eq!(
            parse("restore").unwrap(),
            Arguments {
                action: Action::Restore
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("RESTORE").unwrap().action, Action::Restore);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(parse("  restore  ").unwrap().action, Action::Restore);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let unknown = parse("unhook").unwrap_err();
        assert!(unknown.contains("unknown action 'unhook'"), "{unknown}");
        assert!(unknown.contains("list, restore"), "{unknown}");
    }

    #[test]
    fn anything_after_the_action_refuses() {
        let trailing = parse("restore ntdll").unwrap_err();
        assert!(trailing.contains("rides nothing"), "{trailing}");
        assert!(trailing.contains("unload <list|restore>"), "{trailing}");
    }
}
