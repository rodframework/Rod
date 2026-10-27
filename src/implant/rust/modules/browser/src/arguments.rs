//! The task-argument grammar: `collect.browser [action] [browser]`.
//! The operator UI serializes a task form by joining parameter values
//! with single spaces in declaration order, so the positional reading
//! is the canonical wire shape; the `key=` assignments are the
//! hand-typed alternative. Both actions are reads over the same
//! scope, so the grammar carries no payload and no per-action shape
//! to validate -- the parse is the whole refusal: a token it does not
//! know, or anything after the browser slot, refuses the task before
//! anything touches a store.

/// What the task asked the verb to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Report the logins the stores carry: origin, username, and the
    /// profile each lives in. The default: a bare `collect.browser`
    /// is a read, never a write.
    List,
    /// The same rows with each password unsealed under the profile's
    /// key, a row that refuses decryption naming why instead of
    /// quietly dropping.
    Export,
}

/// Which Chromium store the task sweeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Chrome,
    Edge,
    /// Both, in the fixed order the sweep prints them. The default.
    All,
}

/// A parsed task argument string.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    pub action: Action,
    pub scope: Scope,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let text = arguments.trim();
    // A keyed scope without an action is the one shape the positional
    // read cannot express -- the default action stands.
    let (action, rest) = if text.starts_with("browser=") {
        (Action::List, text)
    } else {
        let (action_token, rest) = split_first_token(text);
        (action_of(action_token)?, rest)
    };
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Ok(Arguments {
            action,
            scope: Scope::All,
        });
    }

    let (scope_token, rest) = split_first_token(rest);
    let scope = scope_of(scope_token)?;
    let rest = rest.trim_start();
    if !rest.is_empty() {
        return Err(format!(
            "collect.browser: the grammar takes the action and the browser alone; '{rest}' \
             rides nothing; {GRAMMAR}"
        ));
    }
    Ok(Arguments { action, scope })
}

/// The action half of the grammar: a bare token or `action=<token>`,
/// case-insensitive.
fn action_of(token: &str) -> Result<Action, String> {
    let action = token.strip_prefix("action=").unwrap_or(token);
    match action.to_ascii_lowercase().as_str() {
        "" | "list" => Ok(Action::List),
        "export" => Ok(Action::Export),
        // The refusal quotes the token as the operator typed it; the
        // case-fold was this parser's own doing.
        _ => Err(format!(
            "collect.browser: unknown action '{action}' (list, export); {GRAMMAR}"
        )),
    }
}

/// The browser half of the grammar, case-insensitive. A bare token
/// that is not a browser refuses naming the three -- `browser list
/// chrome extra` reads its third token as nothing, and the refusal
/// teaches the shape instead of sweeping half a scope.
fn scope_of(token: &str) -> Result<Scope, String> {
    let browser = token.strip_prefix("browser=").unwrap_or(token);
    match browser.to_ascii_lowercase().as_str() {
        "chrome" => Ok(Scope::Chrome),
        "edge" => Ok(Scope::Edge),
        "all" => Ok(Scope::All),
        _ => Err(format!(
            "collect.browser: unknown browser '{browser}' (chrome, edge, all); {GRAMMAR}"
        )),
    }
}

const GRAMMAR: &str = "the grammar is: browser <list|export> <chrome|edge|all>";

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
            parse("export chrome").unwrap(),
            Arguments {
                action: Action::Export,
                scope: Scope::Chrome,
            }
        );
        assert_eq!(
            parse("list edge").unwrap(),
            Arguments {
                action: Action::List,
                scope: Scope::Edge,
            }
        );
        assert_eq!(
            parse("list").unwrap(),
            Arguments {
                action: Action::List,
                scope: Scope::All,
            }
        );
        assert_eq!(
            parse("").unwrap(),
            Arguments {
                action: Action::List,
                scope: Scope::All,
            }
        );
    }

    #[test]
    fn the_keyed_form_teaches_the_same_read() {
        assert_eq!(
            parse("action=export browser=edge").unwrap(),
            Arguments {
                action: Action::Export,
                scope: Scope::Edge,
            }
        );
        // A keyed scope without an action is the one shape the
        // positional read cannot express -- the default action stands.
        assert_eq!(
            parse("browser=edge").unwrap(),
            Arguments {
                action: Action::List,
                scope: Scope::Edge,
            }
        );
        // A keyed scope after a positional action reads the same.
        assert_eq!(
            parse("export browser=chrome").unwrap(),
            Arguments {
                action: Action::Export,
                scope: Scope::Chrome,
            }
        );
    }

    #[test]
    fn tokens_read_bare_assigned_and_cased() {
        assert_eq!(parse("EXPORT").unwrap().action, Action::Export);
        assert_eq!(parse("action=List").unwrap().action, Action::List);
        assert_eq!(parse("list CHROME").unwrap().scope, Scope::Chrome);
        assert_eq!(parse("list browser=Edge").unwrap().scope, Scope::Edge);
    }

    #[test]
    fn unknown_tokens_refuse_naming_the_choices() {
        // A typo refuses the task rather than half-reading under it.
        let action = parse("dump").unwrap_err();
        assert!(action.contains("unknown action 'dump'"), "{action}");
        assert!(action.contains("list, export"), "{action}");

        let browser = parse("list firefox").unwrap_err();
        assert!(browser.contains("unknown browser 'firefox'"), "{browser}");
        assert!(browser.contains("chrome, edge, all"), "{browser}");

        // Anything after the browser slot rides nothing.
        let leftover = parse("list chrome extra").unwrap_err();
        assert!(leftover.contains("'extra'"), "{leftover}");
    }
}
