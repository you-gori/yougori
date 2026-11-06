//! Bounded, validated text in confinement profiles (VM-W07: exceptions are "recorded";
//! VM part §4.7 and §8.2 on attacker-controlled text, applied through the one shared
//! classification in `foundation::text`).
//!
//! Tool and owner names use the shared identifier grammar
//! ([`validate_identifier`]); an exception's reason is free text a person wrote, shown in
//! approval and audit views, so it is bounded and refuses every character
//! [`is_hazardous`] judges hazardous.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{validate_identifier, IdError};
use crate::foundation::text::is_hazardous;

/// Longest accepted exception reason, in bytes.
pub const MAX_REASON_BYTES: usize = 512;

/// Why a name or a recorded reason was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextRefusal {
    /// Empty or blank.
    Empty,
    /// Longer than the bound.
    TooLong { bytes: usize, max: usize },
    /// A character `foundation::text` judges hazardous: a control, line break,
    /// bidirectional, invisible, private-use or unprintable character could spoof or hide
    /// text in an approval view (VM part §4.7).
    Hazardous { character: char },
    /// Not the shared identifier grammar.
    Identifier { error: IdError },
}

impl fmt::Display for TextRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the text is empty"),
            Self::TooLong { bytes, max } => write!(f, "the text has {bytes} bytes; at most {max}"),
            Self::Hazardous { character } => write!(
                f,
                "the text contains the hazardous character U+{:04X}",
                u32::from(*character)
            ),
            Self::Identifier { error } => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TextRefusal {}

macro_rules! confinement_name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Accepts the shared identifier grammar: 1–128 letters, digits, '.', '_', ':'
            /// or '-', starting with a letter or digit.
            pub fn new(value: impl Into<String>) -> Result<Self, TextRefusal> {
                let value = value.into();
                validate_identifier(&value).map_err(|error| TextRefusal::Identifier { error })?;
                Ok(Self(value))
            }

            /// The name as given.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = TextRefusal;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(name: $name) -> Self {
                name.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

confinement_name!(
    /// A tool a workload profile requires to work, such as `git` or `gdb` (VM-W07
    /// "Required tools work"; VM-R65). The name is a label; removing a tool name does not
    /// remove the equivalent computation (VM-R65), so confinement never rests on it.
    ToolName
);

confinement_name!(
    /// The person or team that owns a recorded exception (VM-W07; VM-R57 "explicit
    /// supported exceptions").
    OwnerName
);

/// Why an exception was granted, as a person recorded it (VM-R57 "explicit supported
/// exceptions"; §3.4 "documented compatibility handling"). Bounded, not blank, and free of
/// hazardous characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RecordedReason(String);

impl RecordedReason {
    /// Refuses blank, over-long and hazardous-character text.
    pub fn new(text: impl Into<String>) -> Result<Self, TextRefusal> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(TextRefusal::Empty);
        }
        if text.len() > MAX_REASON_BYTES {
            return Err(TextRefusal::TooLong {
                bytes: text.len(),
                max: MAX_REASON_BYTES,
            });
        }
        if let Some(character) = text.chars().find(|character| is_hazardous(*character)) {
            return Err(TextRefusal::Hazardous { character });
        }
        Ok(Self(text))
    }

    /// The reason as recorded.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RecordedReason {
    type Error = TextRefusal;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<RecordedReason> for String {
    fn from(reason: RecordedReason) -> Self {
        reason.0
    }
}

impl fmt::Display for RecordedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
