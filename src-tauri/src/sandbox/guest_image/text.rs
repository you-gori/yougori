//! Names and text in build records (VM-W05, line 2590: "build records"; VM-W46, line
//! 2669: "reproducible inputs").
//!
//! Every name in a record is checked when it is made or read, so a record holds no
//! path, no control character and no empty part:
//!
//! - [`ImageName`]: the image line, under the shared identifier rule.
//! - [`InputName`] and [`InputVersion`]: inputs, tools, packages and steps. Package
//!   ecosystems use `+`, `/`, `@` and `~` in names and versions (`libstdc++`,
//!   `1:2.3~rc1-r0`), so these allow them besides the identifier characters, never a
//!   leading `/` or `.`, an empty path component or a `..` component.
//! - [`BuildArgument`], [`EnvironmentName`] and [`EnvironmentValue`]: build commands as
//!   data, bounded and free of control characters.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::foundation::ids::{validate_identifier, IdError};

/// Longest input name or version.
pub const MAX_NAME_BYTES: usize = 128;

/// Longest build argument or environment value.
pub const MAX_ARGUMENT_BYTES: usize = 4096;

/// Why a name or a piece of command text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum TextError {
    Empty,
    TooLong {
        max_bytes: usize,
    },
    /// A character outside the rule of this kind of text.
    InvalidCharacter {
        character: char,
    },
    /// The text must start with a letter or digit.
    InvalidStart,
    /// An empty path component, a trailing `/` or a `.` or `..` component.
    InvalidComponent,
    /// A control character, such as a newline or NUL.
    ControlCharacter,
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the text is empty"),
            Self::TooLong { max_bytes } => write!(f, "the text is longer than {max_bytes} bytes"),
            Self::InvalidCharacter { character } => {
                write!(f, "the text contains {character:?}")
            }
            Self::InvalidStart => f.write_str("the text must start with a letter or digit"),
            Self::InvalidComponent => {
                f.write_str("the text has an empty, '.' or '..' path component")
            }
            Self::ControlCharacter => f.write_str("the text contains a control character"),
        }
    }
}

impl std::error::Error for TextError {}

/// The input-name rule: 1–128 bytes of ASCII letters, digits and `. _ - + / : @ ~`,
/// starting with a letter or digit, with no empty, `.` or `..` path component.
fn validate_input_text(value: &str) -> Result<(), TextError> {
    let first = value.chars().next().ok_or(TextError::Empty)?;
    if value.len() > MAX_NAME_BYTES {
        return Err(TextError::TooLong {
            max_bytes: MAX_NAME_BYTES,
        });
    }
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '.' | '_' | '-' | '+' | '/' | ':' | '@' | '~'))
    }) {
        return Err(TextError::InvalidCharacter { character });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(TextError::InvalidStart);
    }
    if value
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(TextError::InvalidComponent);
    }
    Ok(())
}

/// Command text: at most [`MAX_ARGUMENT_BYTES`] and no control character. Empty text is
/// allowed, since an argument vector may hold an empty argument.
fn validate_command_text(value: &str) -> Result<(), TextError> {
    if value.len() > MAX_ARGUMENT_BYTES {
        return Err(TextError::TooLong {
            max_bytes: MAX_ARGUMENT_BYTES,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(TextError::ControlCharacter);
    }
    Ok(())
}

/// An environment variable name: 1–128 bytes of `A-Z`, `0-9` and `_`, not starting with
/// a digit.
fn validate_environment_name(value: &str) -> Result<(), TextError> {
    let first = value.chars().next().ok_or(TextError::Empty)?;
    if value.len() > MAX_NAME_BYTES {
        return Err(TextError::TooLong {
            max_bytes: MAX_NAME_BYTES,
        });
    }
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_')
    }) {
        return Err(TextError::InvalidCharacter { character });
    }
    if first.is_ascii_digit() {
        return Err(TextError::InvalidStart);
    }
    Ok(())
}

/// Defines a checked text newtype: written as its text, read through `$check`.
macro_rules! checked_text {
    ($(#[$meta:meta])* $name:ident, $error:ty, $check:path) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into();
                $check(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

checked_text!(
    /// The name of one guest image line, such as `yougori-guest-developer`: the shared
    /// identifier rule. Release numbers and the rollback floor are kept per line.
    ImageName,
    IdError,
    validate_identifier
);

checked_text!(
    /// The name of an input, a tool, a package or a build step.
    InputName,
    TextError,
    validate_input_text
);

checked_text!(
    /// The exact version of a tool or a package, compared exactly and never ordered.
    InputVersion,
    TextError,
    validate_input_text
);

checked_text!(
    /// One argument of a build step's argument vector.
    BuildArgument,
    TextError,
    validate_command_text
);

checked_text!(
    /// The name of an environment variable a build step sets.
    EnvironmentName,
    TextError,
    validate_environment_name
);

checked_text!(
    /// The value of an environment variable a build step sets.
    EnvironmentValue,
    TextError,
    validate_command_text
);
