//! Fixes stated for a package inside a component (line 2459: "Define severity,
//! reachability, available fixes ... and patch deadlines"; VM-W47, line 2670: "Gate by
//! ... remediation window").
//!
//! A scanner or advisory names a finding's fix as a release of the vulnerable package: a
//! fixed version (`1.6.1`, `3.0.13-1~deb12u1`) or a requirement (`>=0.6.14, <1.0.0`). That
//! is not a version of the pinned component that contains the package; the component is
//! fixed once a build carrying such a release is pinned. [`PackageFix`] keeps the package
//! and every statement exactly as reported, so a finding records its fix without
//! inventing a component version ([`Remediation::PackageFixAvailable`]). Text is bounded
//! printable ASCII, so a statement never carries a control or direction character into a
//! display.
//!
//! [`Remediation::PackageFixAvailable`]: super::Remediation::PackageFixAvailable

use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest package name: npm's limit, the longest of the ecosystems scanners report.
pub const MAX_FIX_PACKAGE_BYTES: usize = 214;
/// Longest single fixed version or requirement.
pub const MAX_FIX_REQUIREMENT_BYTES: usize = 128;
/// Most statements of one fix.
pub const MAX_FIX_REQUIREMENTS: usize = 32;

/// Why a package fix was refused. A refused character is named as an escape, never
/// printed itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum FixRefusal {
    Empty {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        max_bytes: usize,
    },
    /// A character outside the field's alphabet: printable ASCII, and for a requirement
    /// also the space.
    Forbidden {
        field: &'static str,
        character: char,
    },
    /// A fix names at least one fixed version or requirement.
    NoRequirement,
    TooManyRequirements {
        count: usize,
        max: usize,
    },
}

impl fmt::Display for FixRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "the fix's {field} is empty"),
            Self::TooLong { field, max_bytes } => {
                write!(f, "the fix's {field} is longer than {max_bytes} bytes")
            }
            Self::Forbidden { field, character } => write!(
                f,
                "the fix's {field} contains the character {}",
                character.escape_unicode()
            ),
            Self::NoRequirement => f.write_str("a fix names at least one version or requirement"),
            Self::TooManyRequirements { count, max } => write!(
                f,
                "the fix names {count} versions or requirements; at most {max} are kept"
            ),
        }
    }
}

impl std::error::Error for FixRefusal {}

fn check(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    space_allowed: bool,
) -> Result<(), FixRefusal> {
    if value.is_empty() {
        return Err(FixRefusal::Empty { field });
    }
    if value.len() > max_bytes {
        return Err(FixRefusal::TooLong { field, max_bytes });
    }
    match value
        .chars()
        .find(|character| !(character.is_ascii_graphic() || (space_allowed && *character == ' ')))
    {
        Some(character) => Err(FixRefusal::Forbidden { field, character }),
        None => Ok(()),
    }
}

/// A fix stated for one package inside a component, as a scanner or advisory reports it
/// (line 2459 "available fixes"): the package's name and each fixed version or
/// requirement in report order, exactly as written. Any one statement names a release
/// that fixes the finding. Read strictly: unknown fields, an empty list, more than
/// [`MAX_FIX_REQUIREMENTS`] statements and text outside the bounds are refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackageFixWire")]
pub struct PackageFix {
    package: String,
    requirements: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageFixWire {
    package: String,
    requirements: Vec<String>,
}

impl TryFrom<PackageFixWire> for PackageFix {
    type Error = FixRefusal;

    fn try_from(wire: PackageFixWire) -> Result<Self, Self::Error> {
        Self::new(wire.package, wire.requirements)
    }
}

impl PackageFix {
    /// Checks the package name (1 to [`MAX_FIX_PACKAGE_BYTES`] printable ASCII characters,
    /// no space) and each statement (1 to [`MAX_FIX_REQUIREMENT_BYTES`] printable ASCII
    /// characters or spaces), keeping them as given.
    pub fn new(package: impl Into<String>, requirements: Vec<String>) -> Result<Self, FixRefusal> {
        let package = package.into();
        check("package", &package, MAX_FIX_PACKAGE_BYTES, false)?;
        if requirements.is_empty() {
            return Err(FixRefusal::NoRequirement);
        }
        if requirements.len() > MAX_FIX_REQUIREMENTS {
            return Err(FixRefusal::TooManyRequirements {
                count: requirements.len(),
                max: MAX_FIX_REQUIREMENTS,
            });
        }
        for requirement in &requirements {
            check("requirement", requirement, MAX_FIX_REQUIREMENT_BYTES, true)?;
        }
        Ok(Self {
            package,
            requirements,
        })
    }

    /// The package the statements are about, as reported.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Each fixed version or requirement, in report order, as reported.
    pub fn requirements(&self) -> &[String] {
        &self.requirements
    }
}

impl fmt::Display for PackageFix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.package)?;
        for (index, requirement) in self.requirements.iter().enumerate() {
            if index > 0 {
                f.write_str(" or ")?;
            }
            write!(f, "{requirement:?}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statements(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_fix_keeps_the_reported_text() {
        let fix =
            PackageFix::new("smallvec", statements(&[">=0.6.14, <1.0.0", ">=1.6.1"])).unwrap();
        assert_eq!(fix.package(), "smallvec");
        assert_eq!(fix.requirements(), [">=0.6.14, <1.0.0", ">=1.6.1"]);
        assert_eq!(
            fix.to_string(),
            "smallvec \">=0.6.14, <1.0.0\" or \">=1.6.1\""
        );
        let debian = PackageFix::new("libssl3", statements(&["3.0.13-1~deb12u1"])).unwrap();
        assert_eq!(debian.requirements(), ["3.0.13-1~deb12u1"]);
        let longest = "1".repeat(MAX_FIX_REQUIREMENT_BYTES);
        assert!(PackageFix::new("a".repeat(MAX_FIX_PACKAGE_BYTES), vec![longest]).is_ok());
    }

    #[test]
    fn text_and_counts_are_bounded() {
        assert_eq!(
            PackageFix::new("", statements(&["1.0"])),
            Err(FixRefusal::Empty { field: "package" })
        );
        assert_eq!(
            PackageFix::new("small vec", statements(&["1.0"])),
            Err(FixRefusal::Forbidden {
                field: "package",
                character: ' '
            })
        );
        assert_eq!(
            PackageFix::new("a".repeat(MAX_FIX_PACKAGE_BYTES + 1), statements(&["1.0"])),
            Err(FixRefusal::TooLong {
                field: "package",
                max_bytes: MAX_FIX_PACKAGE_BYTES
            })
        );
        assert_eq!(
            PackageFix::new("smallvec", Vec::new()),
            Err(FixRefusal::NoRequirement)
        );
        assert_eq!(
            PackageFix::new("smallvec", statements(&[""])),
            Err(FixRefusal::Empty {
                field: "requirement"
            })
        );
        assert_eq!(
            PackageFix::new("smallvec", vec!["1".repeat(MAX_FIX_REQUIREMENT_BYTES + 1)]),
            Err(FixRefusal::TooLong {
                field: "requirement",
                max_bytes: MAX_FIX_REQUIREMENT_BYTES
            })
        );
        assert_eq!(
            PackageFix::new(
                "smallvec",
                vec!["1.6.1".to_owned(); MAX_FIX_REQUIREMENTS + 1]
            ),
            Err(FixRefusal::TooManyRequirements {
                count: MAX_FIX_REQUIREMENTS + 1,
                max: MAX_FIX_REQUIREMENTS
            })
        );
        let hidden = PackageFix::new("smallvec", statements(&[">=1.6.1\u{202e}"])).unwrap_err();
        assert_eq!(
            hidden,
            FixRefusal::Forbidden {
                field: "requirement",
                character: '\u{202e}'
            }
        );
        let message = hidden.to_string();
        assert!(message.contains("\\u{202e}") && !message.contains('\u{202e}'));
        assert!(PackageFix::new("smallvec", statements(&["1.0\t"])).is_err());
    }

    #[test]
    fn fixes_are_read_strictly() {
        let fix = PackageFix::new("smallvec", statements(&[">=1.6.1"])).unwrap();
        let json = serde_json::to_value(&fix).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"package": "smallvec", "requirements": [">=1.6.1"]})
        );
        assert_eq!(serde_json::from_value::<PackageFix>(json).unwrap(), fix);
        for bad in [
            serde_json::json!({"package": "smallvec", "requirements": [">=1.6.1"], "approved": true}),
            serde_json::json!({"package": "smallvec", "requirements": []}),
            serde_json::json!({"package": "smallvec"}),
            serde_json::json!({"package": "small\nvec", "requirements": ["1"]}),
        ] {
            assert!(
                serde_json::from_value::<PackageFix>(bad.clone()).is_err(),
                "{bad} was accepted"
            );
        }
    }
}
