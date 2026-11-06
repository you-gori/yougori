//! Text a product document shows a person (CORE-07; VM part §4.7 line 2139: "prevent
//! control characters from spoofing approval UI").
//!
//! Reasons, fact lines and progress descriptions come from the Display of typed sources,
//! some of which name things a guest, template or provider chose. [`ShownText`] writes every
//! character `foundation::text` judges hazardous as a visible escape and bounds the length
//! when it is made, and refuses either one when read back, so a stored or forwarded document
//! can neither break a CLI line nor disguise a desktop label.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::text::is_hazardous;

/// The most characters one shown text holds.
pub const MAX_SHOWN_CHARS: usize = 2_000;

/// What a cut text ends with.
const CUT: &str = "...";

/// One line of text for a person: no hazardous character, at most [`MAX_SHOWN_CHARS`]
/// characters, never empty.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ShownText(String);

impl ShownText {
    /// `text` with every hazardous character written as its `\u{...}` escape, cut to
    /// [`MAX_SHOWN_CHARS`] characters; an empty text becomes "-".
    pub fn new(text: &str) -> Self {
        let mut shown = String::with_capacity(text.len().min(MAX_SHOWN_CHARS));
        let mut count = 0usize;
        for character in text.chars() {
            let escaped: Vec<char> = if is_hazardous(character) {
                character.escape_unicode().collect()
            } else {
                vec![character]
            };
            if count + escaped.len() > MAX_SHOWN_CHARS - CUT.len() {
                shown.push_str(CUT);
                return Self(shown);
            }
            count += escaped.len();
            shown.extend(escaped);
        }
        if shown.is_empty() {
            shown.push('-');
        }
        Self(shown)
    }

    /// Accepts `text` only as it is: refused when empty, too long or holding a hazardous
    /// character.
    pub fn exact(text: &str) -> Result<Self, ShownTextError> {
        if text.is_empty() {
            return Err(ShownTextError::Empty);
        }
        if text.chars().count() > MAX_SHOWN_CHARS {
            return Err(ShownTextError::TooLong {
                max: MAX_SHOWN_CHARS,
            });
        }
        if let Some(character) = text.chars().find(|character| is_hazardous(*character)) {
            return Err(ShownTextError::Hazardous { character });
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShownText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ShownText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::exact(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a text was refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShownTextError {
    Empty,
    TooLong { max: usize },
    Hazardous { character: char },
}

impl fmt::Display for ShownTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a shown text is empty"),
            Self::TooLong { max } => write!(f, "a shown text is longer than {max} characters"),
            Self::Hazardous { character } => write!(
                f,
                "a shown text holds the hazardous character {}",
                character.escape_unicode()
            ),
        }
    }
}

impl std::error::Error for ShownTextError {}
