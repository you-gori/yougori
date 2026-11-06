//! The synthetic conformance corpus (S12 G0: BENCH-03 starts with offline protocol
//! fixtures; S8 "public artifacts use permitted synthetic or approved fixtures").
//!
//! One JSONL file per dialect, one [`ConformanceCase`] per line, plus a paired corpus
//! that pairs a reference case with a candidate case. Every prompt is a placeholder that
//! starts with `synthetic`, and no line carries a credential. The files are embedded at
//! build time, so loading them reads no file system.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::DigestBuilder;
use crate::foundation::report::{Disclosure, FixtureRef, Label, ReportError};

use super::conformance::{CaseError, ConformanceCase};
use super::dialect::Dialect;

const CHAT_COMPLETIONS_JSONL: &str = include_str!("fixtures/openai_chat_completions.jsonl");
const RESPONSES_JSONL: &str = include_str!("fixtures/openai_responses.jsonl");
const MESSAGES_JSONL: &str = include_str!("fixtures/anthropic_messages.jsonl");
const PAIRED_JSONL: &str = include_str!("fixtures/paired_tool_calls.jsonl");

/// Domain of [`corpus_fingerprint`].
pub const CORPUS_DOMAIN: &str = "yougori/serving-protocol/offline-corpus/v1";

/// Why a corpus line was refused (S12 G0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixtureError {
    /// The line is not a case of the expected shape; unknown fields are refused.
    Parse {
        line: usize,
        detail: String,
    },
    /// The case belongs to another dialect's file.
    WrongDialect {
        line: usize,
        found: Dialect,
    },
    DuplicateCase {
        line: usize,
    },
    Inconsistent {
        line: usize,
        error: CaseError,
    },
    /// A paired item names a case its corpus does not have.
    UnknownCase {
        line: usize,
    },
}

impl fmt::Display for FixtureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { line, detail } => write!(f, "line {line}: {detail}"),
            Self::WrongDialect { line, found } => write!(f, "line {line}: a {found} case"),
            Self::DuplicateCase { line } => write!(f, "line {line}: the case id repeats"),
            Self::Inconsistent { line, error } => write!(f, "line {line}: {error}"),
            Self::UnknownCase { line } => write!(f, "line {line}: names an unknown case"),
        }
    }
}

impl std::error::Error for FixtureError {}

/// The embedded corpus text of one dialect.
pub fn corpus_text(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::OpenAiChatCompletions => CHAT_COMPLETIONS_JSONL,
        Dialect::OpenAiResponses => RESPONSES_JSONL,
        Dialect::AnthropicMessages => MESSAGES_JSONL,
    }
}

/// Non-blank lines with their one-based numbers; a checkout's line endings do not matter.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty())
}

/// The corpus text with line endings normalised, as digested.
fn normalised(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Parses one dialect's cases, refusing unknown fields, another dialect's cases,
/// repeated ids and expectations that contradict themselves.
pub fn parse_cases(dialect: Dialect, text: &str) -> Result<Vec<ConformanceCase>, FixtureError> {
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    for (line, content) in lines(text) {
        let case: ConformanceCase =
            serde_json::from_str(content).map_err(|error| FixtureError::Parse {
                line,
                detail: error.to_string(),
            })?;
        if case.dialect != dialect {
            return Err(FixtureError::WrongDialect {
                line,
                found: case.dialect,
            });
        }
        if !ids.insert(case.case.clone()) {
            return Err(FixtureError::DuplicateCase { line });
        }
        case.check()
            .map_err(|error| FixtureError::Inconsistent { line, error })?;
        cases.push(case);
    }
    Ok(cases)
}

/// The embedded cases of one dialect.
pub fn load_cases(dialect: Dialect) -> Result<Vec<ConformanceCase>, FixtureError> {
    parse_cases(dialect, corpus_text(dialect))
}

/// The configuration an offline run of one dialect's corpus is observed under: the
/// digest of the corpus text, so a changed corpus is a changed configuration (CORE-01).
pub fn corpus_fingerprint(dialect: Dialect) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(
        DigestBuilder::new(CORPUS_DOMAIN)
            .str(dialect.tag())
            .str(&normalised(corpus_text(dialect)))
            .finish(),
    )
}

/// The corpus as a CORE-08 fixture reference: permitted synthetic content, identified by
/// digest (S8 redaction; BENCH-13 fixture hashes).
pub fn corpus_fixture(dialect: Dialect) -> Result<FixtureRef, ReportError> {
    Ok(FixtureRef::digesting(
        Label::new(format!("serving-protocol.{}", dialect.tag()))?,
        normalised(corpus_text(dialect)).as_bytes(),
        Disclosure::PermittedSynthetic,
    ))
}

/// One paired item: a reference case and a candidate case of one dialect's corpus
/// (S7 line 127; S11 BENCH-04).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedItem {
    pub item: Label,
    pub dialect: Dialect,
    pub reference_case: Label,
    pub candidate_case: Label,
}

/// The embedded paired corpus. Every named case exists in its dialect's corpus and every
/// item id is unique.
pub fn load_paired_items() -> Result<Vec<PairedItem>, FixtureError> {
    let mut known = BTreeSet::new();
    for dialect in Dialect::ALL {
        for case in load_cases(dialect)? {
            known.insert((dialect, case.case));
        }
    }
    let mut items = Vec::new();
    let mut ids = BTreeSet::new();
    for (line, content) in lines(PAIRED_JSONL) {
        let item: PairedItem =
            serde_json::from_str(content).map_err(|error| FixtureError::Parse {
                line,
                detail: error.to_string(),
            })?;
        if !ids.insert(item.item.clone()) {
            return Err(FixtureError::DuplicateCase { line });
        }
        for case in [&item.reference_case, &item.candidate_case] {
            if !known.contains(&(item.dialect, case.clone())) {
                return Err(FixtureError::UnknownCase { line });
            }
        }
        items.push(item);
    }
    Ok(items)
}
