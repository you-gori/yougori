//! Local file paths handed to the OpenSSH client as option values (VM-W41: arguments
//! cannot become programs or options).
//!
//! OpenSSH splits an option value on whitespace and on `=`, honours quotes, `#` and `\`
//! escapes in newer releases, and expands `%` tokens, a leading `~` and `${VAR}` in file
//! options such as `UserKnownHostsFile` and `IdentityFile`. A path is therefore accepted
//! only in a form none of that can change: absolute, `/`-separated, and made of ASCII
//! letters, digits, `.`, `_`, `+` and `-`. A Windows path is written with its drive and
//! forward slashes (`C:/Users/...`), which the Windows OpenSSH client accepts; backslashes
//! are refused rather than escaped.
//!
//! The engine writes and reads the file and the client opens it from another working
//! directory, so the path must name the same file for both. On Windows it must therefore
//! start with a drive: a path rooted with `/` alone resolves against the current drive of
//! whoever opens it, so the two could read different files, and a file planted at the root
//! of another drive could stand in for the rendered one. Drive-relative (`C:kh`), UNC
//! (`//server/share`, `\\server\share`, `\\?\UNC\...`) and device (`\\.\...`) forms are
//! refused as well, by the same rules (no drive, `\`, `?` or an empty component); the
//! verbatim drive form `\\?\C:\...` cannot be written without `\` and `?`, so it is refused
//! too, and `C:/...` is the one drive-qualified form. A component that is a reserved DOS
//! device name (`NUL`, `CON`, `COM1` and the rest, with any extension) is refused on
//! Windows, which would open the device instead. Elsewhere a path must start with `/`;
//! `C:/...` is a relative path there.

use std::fmt;
use std::path::Path;

use serde::Serialize;

/// The longest path accepted.
pub const MAX_SSH_PATH_BYTES: usize = 1_024;

/// Why a path was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum SshPathRefusal {
    /// The path does not start with `/` (elsewhere) or a drive such as `C:/` (Windows).
    NotAbsolute,
    /// On Windows, the path starts with `/` but no drive, so it would resolve against the
    /// current drive of whoever opens it.
    DriveRequired,
    /// A character OpenSSH could read as syntax, or one outside the accepted set.
    InvalidCharacter {
        character: char,
    },
    /// An empty, `.` or `..` component, or on Windows a reserved device name.
    InvalidComponent,
    TooLong {
        max_bytes: u64,
    },
}

impl fmt::Display for SshPathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("an SSH file path must be absolute"),
            Self::DriveRequired => {
                f.write_str("an SSH file path on Windows must start with a drive, such as C:/")
            }
            Self::InvalidCharacter { character } => write!(
                f,
                "{character:?} is not allowed in an SSH file path; use ASCII letters, digits, \
                 '.', '_', '+', '-' and '/'"
            ),
            Self::InvalidComponent => f.write_str(
                "an SSH file path has no empty, '.' or '..' components, and on Windows no \
                 device names",
            ),
            Self::TooLong { max_bytes } => {
                write!(f, "an SSH file path is at most {max_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for SshPathRefusal {}

/// An absolute local path in a form OpenSSH reads literally; see the module notes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SshFilePath(String);

/// Whether `component` is a reserved DOS device name, with or without an extension.
#[cfg(windows)]
fn is_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let numbered = |prefix: &str| {
        stem.get(..3)
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && stem.len() == 4
            && stem.as_bytes().get(3).is_some_and(u8::is_ascii_digit)
    };
    ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
        || numbered("COM")
        || numbered("LPT")
}

#[cfg(not(windows))]
fn is_device_name(_component: &str) -> bool {
    false
}

impl SshFilePath {
    /// Accepts `C:/a/b` on Windows and `/a/b` elsewhere, with components of ASCII
    /// letters, digits, `.`, `_`, `+` and `-`, none empty, `.` or `..` (nor, on Windows,
    /// a device name), up to [`MAX_SSH_PATH_BYTES`].
    pub fn new(path: impl Into<String>) -> Result<Self, SshPathRefusal> {
        let path = path.into();
        if path.len() > MAX_SSH_PATH_BYTES {
            return Err(SshPathRefusal::TooLong {
                max_bytes: u64::try_from(MAX_SSH_PATH_BYTES).unwrap_or(u64::MAX),
            });
        }
        let (has_drive, rest) = match path.strip_prefix('/') {
            Some(rest) => (false, rest),
            None => {
                let mut characters = path.chars();
                match (characters.next(), characters.next(), characters.next()) {
                    (Some(drive), Some(':'), Some('/')) if drive.is_ascii_alphabetic() => {
                        (true, path.get(3..).ok_or(SshPathRefusal::NotAbsolute)?)
                    }
                    _ => return Err(SshPathRefusal::NotAbsolute),
                }
            }
        };
        if let Some(character) = rest.chars().find(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-' | '/'))
        }) {
            return Err(SshPathRefusal::InvalidCharacter { character });
        }
        if rest
            .split('/')
            .any(|component| matches!(component, "" | "." | "..") || is_device_name(component))
        {
            return Err(SshPathRefusal::InvalidComponent);
        }
        // Checked last, so a path refused for its characters or components is refused
        // the same way on every platform.
        if cfg!(windows) && !has_drive {
            return Err(SshPathRefusal::DriveRequired);
        }
        if !cfg!(windows) && has_drive {
            return Err(SshPathRefusal::NotAbsolute);
        }
        Ok(Self(path))
    }

    /// The path as OpenSSH receives it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path for local file operations.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for SshFilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
