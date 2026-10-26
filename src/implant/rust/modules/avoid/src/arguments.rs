//! The task-argument grammar: `evasion.avoid <target>`. One slot, one
//! word: the patch is a sensitive act, and the grammar names its
//! target rather than guessing a default -- a bare task refuses
//! teaching the three words, never patching nothing and never patching
//! everything unasked.

/// A parsed task argument string: the target word, validated against
/// the table the grammar shares with the patch edge.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Arguments {
    /// What the task patches: `amsi`, `etw`, or `all`.
    pub target: Option<String>,
}

/// Parses the argument grammar.
pub(crate) fn parse(arguments: &str) -> Result<Arguments, String> {
    let target = arguments.trim();
    Ok(Arguments {
        target: (!target.is_empty()).then(|| target.to_string()),
    })
}

/// Checks the parsed grammar: the word must be one of the three the
/// table answers. A task the table cannot honor refuses here, before
/// anything touches memory.
pub(crate) fn validate(arguments: &Arguments) -> Result<(), String> {
    match &arguments.target {
        Some(word) if crate::patch::targets_of(word).is_some() => Ok(()),
        Some(word) => Err(format!(
            "evasion.avoid: unknown target '{word}' (the targets are: amsi, etw, all)"
        )),
        None => Err(
            "evasion.avoid: the patch names its target (amsi, etw, all) -- a bare task \
             patches nothing and refuses rather than guess"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_read_bare_and_cased() {
        assert_eq!(
            parse("amsi").unwrap(),
            Arguments {
                target: Some("amsi".into())
            }
        );
        assert_eq!(
            parse("  ALL  ").unwrap(),
            Arguments {
                target: Some("ALL".into())
            }
        );
        assert_eq!(parse("").unwrap(), Arguments { target: None });
    }

    #[test]
    fn the_words_the_table_knows_pass_and_others_refuse() {
        for word in ["amsi", "etw", "all", "EtW"] {
            assert!(validate(&parse(word).unwrap()).is_ok(), "{word}");
        }
        let unknown = validate(&parse("edr").unwrap()).unwrap_err();
        assert!(unknown.contains("unknown target 'edr'"), "{unknown}");
        assert!(unknown.contains("amsi, etw, all"), "{unknown}");

        let bare = validate(&parse("").unwrap()).unwrap_err();
        assert!(bare.contains("bare task"), "{bare}");
    }
}
