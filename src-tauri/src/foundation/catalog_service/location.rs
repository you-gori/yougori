//! Where the engine keeps its catalog, as configured under a setting (S02; the directory
//! counterpart of the trust roots' `TrustRootLocation`, S08).
//!
//! Nothing here reads the environment or the disk: the engine passes the setting's value
//! in, and an absent value is reported as not configured with its remedy. There is no
//! built-in default, so the catalog is never created anywhere the owner did not choose.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

/// Why a configured catalog location cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LocationProblem {
    /// The path is relative, so it would depend on the engine's working directory.
    NotAbsolute,
    /// The installed engine's own catalog, which a disposable acceptance engine on the same
    /// computer never opens (the engine glue decides which roots are the installed engine's).
    InstalledEngine { root: PathBuf },
}

impl fmt::Display for LocationProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the catalog location is not an absolute path"),
            Self::InstalledEngine { root } => write!(
                f,
                "the catalog location {} is the installed Yougori engine's catalog",
                root.display()
            ),
        }
    }
}

/// The catalog root directory as configured under the setting `setting`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogLocation {
    /// Nothing is configured: no catalog is opened.
    NotConfigured { setting: &'static str },
    /// The configured value cannot be used: no catalog is opened.
    Invalid {
        setting: &'static str,
        problem: LocationProblem,
    },
    /// The directory the catalog lives in; it is created on open if missing.
    Directory {
        setting: &'static str,
        path: PathBuf,
    },
}

impl CatalogLocation {
    /// The location configured as `value` under `setting` (an environment variable or a
    /// settings key the engine chooses). Absent or empty is not configured; a relative
    /// path is invalid. Nothing is read here.
    pub fn from_setting(setting: &'static str, value: Option<&OsStr>) -> Self {
        match value.filter(|value| !value.is_empty()) {
            None => Self::NotConfigured { setting },
            Some(value) => {
                let path = PathBuf::from(value);
                if path.is_absolute() {
                    Self::Directory { setting, path }
                } else {
                    Self::Invalid {
                        setting,
                        problem: LocationProblem::NotAbsolute,
                    }
                }
            }
        }
    }

    /// What the owner does to open the catalog; `None` when a directory is configured.
    pub fn remedy(&self) -> Option<String> {
        match self {
            Self::NotConfigured { setting } => Some(format!(
                "No catalog location is configured and none is built in, so no catalog is \
                 opened and nothing is imported into one. Set {setting} to the absolute path \
                 of a directory on a drive with room for imported artifacts; it is created \
                 if missing."
            )),
            Self::Invalid {
                setting,
                problem: problem @ LocationProblem::InstalledEngine { .. },
            } => Some(format!(
                "{problem}, which this disposable acceptance engine never opens, so no catalog \
                 is opened. Set {setting} to the absolute path of a folder of this engine's own."
            )),
            Self::Invalid { setting, problem } => Some(format!(
                "{problem}: {setting} must be the absolute path of the catalog directory; no \
                 catalog is opened until it is."
            )),
            Self::Directory { .. } => None,
        }
    }
}
