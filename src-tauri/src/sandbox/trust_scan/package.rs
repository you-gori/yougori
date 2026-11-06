//! Package identities and bounded text read from scanner reports (VM-W47, line 2670;
//! VM-P28, line 2803: malformed or oversized input stays bounded).
//!
//! A scanner names packages inside a pinned component: a crate in a lockfile, a Debian
//! package in a guest image. Names and versions come from files another party may write
//! (a lockfile in a repository), so each is bounded and refused when it carries a
//! character outside its alphabet; target names may hold any text that
//! [`crate::foundation::text`] does not judge hazardous.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::IdError;
use crate::foundation::text::is_hazardous;

/// Longest package name: npm's limit, the longest of the supported ecosystems.
pub const MAX_PACKAGE_NAME_BYTES: usize = 214;
/// Longest package version.
pub const MAX_PACKAGE_VERSION_BYTES: usize = 128;
/// Longest scan target name (a lockfile path or an image reference).
pub const MAX_TARGET_BYTES: usize = 1024;
/// Longest fix statement. Bounded so that every statement fits trust's component
/// version alphabet after escaping (`fix-` plus three bytes per byte, at most 124).
pub const MAX_FIX_BYTES: usize = 40;

/// Why a piece of report text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum TextProblem {
    Empty,
    TooLong {
        max_bytes: usize,
    },
    /// A character outside the field's alphabet.
    Forbidden {
        character: char,
    },
    /// An identifier that does not start with a letter or digit.
    InvalidStart,
}

impl TextProblem {
    /// The same problem for an identifier refused by `validate_identifier`.
    pub fn from_id_error(error: &IdError) -> Self {
        match error {
            IdError::Empty => Self::Empty,
            IdError::TooLong { max } => Self::TooLong { max_bytes: *max },
            IdError::InvalidCharacter { character } => Self::Forbidden {
                character: *character,
            },
            IdError::InvalidStart | IdError::InvalidDigest => Self::InvalidStart,
        }
    }
}

impl fmt::Display for TextProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("it is empty"),
            Self::TooLong { max_bytes } => write!(f, "it is longer than {max_bytes} bytes"),
            // Written as an escape, so a hazardous character never reaches a display.
            Self::Forbidden { character } => {
                write!(
                    f,
                    "it contains the character {}",
                    character.escape_unicode()
                )
            }
            Self::InvalidStart => f.write_str("it does not start with a letter or digit"),
        }
    }
}

impl std::error::Error for TextProblem {}

fn check(value: &str, max_bytes: usize, allowed: fn(char) -> bool) -> Result<(), TextProblem> {
    if value.is_empty() {
        return Err(TextProblem::Empty);
    }
    if value.len() > max_bytes {
        return Err(TextProblem::TooLong { max_bytes });
    }
    match value.chars().find(|character| !allowed(*character)) {
        Some(character) => Err(TextProblem::Forbidden { character }),
        None => Ok(()),
    }
}

fn token_character(character: char) -> bool {
    character.is_ascii_graphic()
}

fn statement_character(character: char) -> bool {
    character.is_ascii_graphic() || character == ' '
}

fn target_character(character: char) -> bool {
    !is_hazardous(character)
}

macro_rules! bounded_text {
    ($(#[$doc:meta])* $name:ident, $max:expr, $allowed:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TextProblem> {
                let value = value.into();
                check(&value, $max, $allowed)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = TextProblem;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
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
    };
}

bounded_text!(
    /// A package name as a scanner reports it: 1 to [`MAX_PACKAGE_NAME_BYTES`] printable
    /// ASCII characters, no space.
    PackageName,
    MAX_PACKAGE_NAME_BYTES,
    token_character
);

bounded_text!(
    /// A package version as a scanner reports it: 1 to [`MAX_PACKAGE_VERSION_BYTES`]
    /// printable ASCII characters, no space. Versions are compared exactly, never ordered.
    PackageVersion,
    MAX_PACKAGE_VERSION_BYTES,
    token_character
);

bounded_text!(
    /// A fix as a scanner states it: a fixed version (`1.6.1`, `3.0.13-1~deb12u1`) or a
    /// version requirement (`>=1.6.1`), 1 to [`MAX_FIX_BYTES`] printable ASCII characters
    /// or spaces. Kept exactly as reported (line 2459 "available fixes").
    FixStatement,
    MAX_FIX_BYTES,
    statement_character
);

bounded_text!(
    /// The name of one scanned target inside a report: an OSV-Scanner source path or a
    /// Trivy result target. Any text without a hazardous character, up to
    /// [`MAX_TARGET_BYTES`].
    TargetName,
    MAX_TARGET_BYTES,
    target_character
);

/// A package ecosystem this module reads. Each scanner's own names map onto these;
/// any other ecosystem in a report is refused as unsupported, never guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    CratesIo,
    Go,
    Npm,
    Pypi,
    Debian,
    Ubuntu,
    Alpine,
}

impl Ecosystem {
    pub const ALL: [Self; 7] = [
        Self::CratesIo,
        Self::Go,
        Self::Npm,
        Self::Pypi,
        Self::Debian,
        Self::Ubuntu,
        Self::Alpine,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::CratesIo => "crates_io",
            Self::Go => "go",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
            Self::Alpine => "alpine",
        }
    }

    /// The form in which two names of this ecosystem are compared: ASCII lowercase in
    /// every ecosystem, `_` and `-` equal for crates, and runs of `-`, `_` and `.` equal
    /// to one `-` for Python (PEP 503). Comparing more loosely than a registry only
    /// makes more findings applicable, never fewer.
    pub fn name_key(self, name: &PackageName) -> String {
        let lower = name.as_str().to_ascii_lowercase();
        match self {
            Self::CratesIo => lower.replace('_', "-"),
            Self::Pypi => {
                let mut key = String::with_capacity(lower.len());
                let mut in_separator_run = false;
                for character in lower.chars() {
                    if matches!(character, '-' | '_' | '.') {
                        if !in_separator_run {
                            key.push('-');
                        }
                        in_separator_run = true;
                    } else {
                        key.push(character);
                        in_separator_run = false;
                    }
                }
                key
            }
            Self::Go | Self::Npm | Self::Debian | Self::Ubuntu | Self::Alpine => lower,
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One package at one exact version in one ecosystem.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: PackageName,
    pub version: PackageVersion,
}

impl PackageRef {
    /// The comparison form of the name; see [`Ecosystem::name_key`].
    pub fn name_key(&self) -> String {
        self.ecosystem.name_key(&self.name)
    }
}

impl fmt::Display for PackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.ecosystem, self.name, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_versions_are_bounded_printable_ascii_tokens() {
        assert!(PackageName::new("smallvec").is_ok());
        assert!(PackageName::new("@scope/name").is_ok());
        assert!(PackageVersion::new("1:1.2.13.dfsg-1").is_ok());
        assert!(PackageVersion::new("3.0.11-1~deb12u2").is_ok());
        assert_eq!(PackageName::new(""), Err(TextProblem::Empty));
        assert_eq!(
            PackageName::new("a".repeat(MAX_PACKAGE_NAME_BYTES + 1)),
            Err(TextProblem::TooLong {
                max_bytes: MAX_PACKAGE_NAME_BYTES
            })
        );
        assert!(PackageName::new("a".repeat(MAX_PACKAGE_NAME_BYTES)).is_ok());
        assert_eq!(
            PackageVersion::new("1.0 beta"),
            Err(TextProblem::Forbidden { character: ' ' })
        );
        assert_eq!(
            PackageName::new("smallvec\u{1b}[31m"),
            Err(TextProblem::Forbidden {
                character: '\u{1b}'
            })
        );
        assert_eq!(
            PackageName::new("sma\u{202e}llvec"),
            Err(TextProblem::Forbidden {
                character: '\u{202e}'
            })
        );
        assert_eq!(
            PackageName::new("caf\u{e9}"),
            Err(TextProblem::Forbidden {
                character: '\u{e9}'
            })
        );
        // The refusal never prints the character itself.
        let message = TextProblem::Forbidden {
            character: '\u{202e}',
        }
        .to_string();
        assert!(message.contains("\\u{202e}") && !message.contains('\u{202e}'));
    }

    #[test]
    fn fix_statements_allow_spaces_and_stay_short() {
        assert!(FixStatement::new(">=0.6.14, <1.0.0").is_ok());
        assert_eq!(
            FixStatement::new("1".repeat(MAX_FIX_BYTES + 1)),
            Err(TextProblem::TooLong {
                max_bytes: MAX_FIX_BYTES
            })
        );
        assert_eq!(
            FixStatement::new("1.0\t"),
            Err(TextProblem::Forbidden { character: '\t' })
        );
    }

    #[test]
    fn target_names_refuse_only_hazardous_characters() {
        assert!(TargetName::new("fixture-image (debian 12.7)").is_ok());
        assert!(TargetName::new("/build/caf\u{e9}/Cargo.lock").is_ok());
        assert_eq!(
            TargetName::new("Cargo.lock\nforged line"),
            Err(TextProblem::Forbidden { character: '\n' })
        );
        assert_eq!(
            TargetName::new("x".repeat(MAX_TARGET_BYTES + 1)),
            Err(TextProblem::TooLong {
                max_bytes: MAX_TARGET_BYTES
            })
        );
    }

    #[test]
    fn name_keys_only_widen_matching() {
        let crate_name = PackageName::new("Serde_JSON").unwrap();
        assert_eq!(Ecosystem::CratesIo.name_key(&crate_name), "serde-json");
        let python = PackageName::new("Zope.._Interface").unwrap();
        assert_eq!(Ecosystem::Pypi.name_key(&python), "zope-interface");
        let go = PackageName::new("github.com/Foo/bar_baz").unwrap();
        assert_eq!(Ecosystem::Go.name_key(&go), "github.com/foo/bar_baz");
        assert_eq!(
            Ecosystem::Debian.name_key(&PackageName::new("libssl3").unwrap()),
            "libssl3"
        );
    }

    #[test]
    fn serde_reads_validate_and_refuse_unknown_fields() {
        let package: PackageRef = serde_json::from_str(
            r#"{"ecosystem":"crates_io","name":"smallvec","version":"1.6.0"}"#,
        )
        .unwrap();
        assert_eq!(package.to_string(), "crates_io smallvec 1.6.0");
        assert!(serde_json::from_str::<PackageRef>(
            r#"{"ecosystem":"crates_io","name":"smallvec","version":"1.6.0","extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<PackageRef>(
            r#"{"ecosystem":"crates_io","name":"small vec","version":"1.6.0"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<PackageRef>(
            r#"{"ecosystem":"maven","name":"x","version":"1"}"#
        )
        .is_err());
        assert_eq!(
            serde_json::to_string(&Ecosystem::ALL).unwrap(),
            r#"["crates_io","go","npm","pypi","debian","ubuntu","alpine"]"#
        );
    }
}
