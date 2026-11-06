//! A strict parser for the text of `/proc/<pid>/status`, reading the lines VM-CP-04 needs
//! (line 3154: the launcher's unprivileged uid, `NoNewPrivs: 1`, `Seccomp: 2`) and the
//! lines that show the jail's dropped capabilities and new PID namespace. It is a pure
//! function over a string (§12.1 Tier 0, line 2762); reading the file is the host's job.
//!
//! The parse is bounded and refuses rather than guesses (VM-P28 line 2803): the text must
//! fit [`MAX_STATUS_BYTES`] and end with a newline; every line is `Key:` with a key of
//! letters, digits and '_', and no line repeats a key or holds a control character other
//! than tab; each needed line appears exactly once, with tab-separated fields in the
//! kernel's exact format (decimal without sign or leading zeros, capabilities as sixteen
//! lowercase hexadecimal digits). Lines the parser does not need are checked for form only.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

/// The longest status text accepted, in bytes.
pub const MAX_STATUS_BYTES: usize = 16 * 1024;
/// The lines the parser needs.
pub const NEEDED_KEYS: [&str; 9] = [
    "Pid",
    "Uid",
    "Gid",
    "NSpid",
    "CapPrm",
    "CapEff",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
];

/// The real, effective, saved and filesystem ids of a `Uid:` or `Gid:` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct IdQuad {
    pub real: u32,
    pub effective: u32,
    pub saved: u32,
    pub filesystem: u32,
}

impl IdQuad {
    /// Whether all four ids are `id`.
    pub fn all_equal(self, id: u32) -> bool {
        [self.real, self.effective, self.saved, self.filesystem]
            .iter()
            .all(|value| *value == id)
    }
}

impl fmt::Display for IdQuad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.real, self.effective, self.saved, self.filesystem
        )
    }
}

/// The process's seccomp mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompMode {
    /// `0`.
    Disabled,
    /// `1`, strict mode.
    Strict,
    /// `2`, filter mode, as Firecracker's default filters install.
    Filter,
}

impl SeccompMode {
    pub const fn number(self) -> u8 {
        match self {
            Self::Disabled => 0,
            Self::Strict => 1,
            Self::Filter => 2,
        }
    }
}

/// What the parser read from one status text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcStatus {
    pub pid: u32,
    pub uid: IdQuad,
    pub gid: IdQuad,
    /// The process's id in each PID namespace, outermost first.
    pub namespace_pids: Vec<u32>,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub cap_ambient: u64,
    pub no_new_privs: bool,
    pub seccomp: SeccompMode,
}

/// Why a status text was refused. Line numbers count from 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum StatusError {
    TooLarge {
        bytes: usize,
        max_bytes: usize,
    },
    MissingFinalNewline,
    EmptyLine {
        line: usize,
    },
    NoColon {
        line: usize,
    },
    InvalidKey {
        line: usize,
    },
    ControlCharacter {
        line: usize,
    },
    DuplicateKey {
        key: String,
    },
    Missing {
        key: &'static str,
    },
    /// A needed line whose value is not in the kernel's format.
    Malformed {
        key: &'static str,
        line: usize,
    },
}

impl fmt::Display for StatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max_bytes } => {
                write!(f, "the status text is {bytes} bytes, more than {max_bytes}")
            }
            Self::MissingFinalNewline => f.write_str("the status text does not end with a newline"),
            Self::EmptyLine { line } => write!(f, "line {line} is empty"),
            Self::NoColon { line } => write!(f, "line {line} has no ':'"),
            Self::InvalidKey { line } => write!(f, "line {line} has an invalid key"),
            Self::ControlCharacter { line } => {
                write!(f, "line {line} holds a control character")
            }
            Self::DuplicateKey { key } => write!(f, "the key {key:?} appears twice"),
            Self::Missing { key } => write!(f, "the {key} line is missing"),
            Self::Malformed { key, line } => {
                write!(
                    f,
                    "the {key} line (line {line}) is not in the kernel's format"
                )
            }
        }
    }
}

impl std::error::Error for StatusError {}

/// Decimal digits without sign or leading zeros.
fn decimal(text: &str) -> Option<u64> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if canonical {
        text.parse().ok()
    } else {
        None
    }
}

/// A user or group id: decimal, below `u32::MAX`, which is no valid id.
fn id(text: &str) -> Option<u32> {
    decimal(text)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value < u32::MAX)
}

fn pid(text: &str) -> Option<u32> {
    decimal(text)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
}

fn fields(value: &str) -> Option<Vec<&str>> {
    value
        .strip_prefix('\t')
        .map(|rest| rest.split('\t').collect())
}

fn id_quad(value: &str) -> Option<IdQuad> {
    match fields(value)?.as_slice() {
        [real, effective, saved, filesystem] => Some(IdQuad {
            real: id(real)?,
            effective: id(effective)?,
            saved: id(saved)?,
            filesystem: id(filesystem)?,
        }),
        _ => None,
    }
}

fn single(value: &str) -> Option<&str> {
    match fields(value)?.as_slice() {
        [only] => Some(only),
        _ => None,
    }
}

fn capability(value: &str) -> Option<u64> {
    let text = single(value)?;
    let lowercase_hex = text.len() == 16
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if lowercase_hex {
        u64::from_str_radix(text, 16).ok()
    } else {
        None
    }
}

fn flag(value: &str) -> Option<bool> {
    match single(value)? {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn seccomp(value: &str) -> Option<SeccompMode> {
    match single(value)? {
        "0" => Some(SeccompMode::Disabled),
        "1" => Some(SeccompMode::Strict),
        "2" => Some(SeccompMode::Filter),
        _ => None,
    }
}

fn namespace_pids(value: &str) -> Option<Vec<u32>> {
    fields(value)?.into_iter().map(pid).collect()
}

/// One needed line: its line number and value.
type Needed<'a> = Option<(usize, &'a str)>;

fn needed_line<'a>(
    needed: &[Needed<'a>],
    position: usize,
) -> Result<(usize, &'a str), StatusError> {
    let key = NEEDED_KEYS.get(position).copied().unwrap_or("?");
    needed
        .get(position)
        .copied()
        .flatten()
        .ok_or(StatusError::Missing { key })
}

fn read<'a, T>(
    key: &'static str,
    (number, value): (usize, &'a str),
    parse: impl Fn(&'a str) -> Option<T>,
) -> Result<T, StatusError> {
    parse(value).ok_or(StatusError::Malformed { key, line: number })
}

/// Parses the text of `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> Result<ProcStatus, StatusError> {
    if text.len() > MAX_STATUS_BYTES {
        return Err(StatusError::TooLarge {
            bytes: text.len(),
            max_bytes: MAX_STATUS_BYTES,
        });
    }
    let body = text
        .strip_suffix('\n')
        .ok_or(StatusError::MissingFinalNewline)?;
    let mut keys = BTreeSet::new();
    let mut needed: [Needed<'_>; NEEDED_KEYS.len()] = [None; NEEDED_KEYS.len()];
    for (index, line) in body.split('\n').enumerate() {
        let number = index + 1;
        if line.is_empty() {
            return Err(StatusError::EmptyLine { line: number });
        }
        if line
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            return Err(StatusError::ControlCharacter { line: number });
        }
        let (key, value) = line
            .split_once(':')
            .ok_or(StatusError::NoColon { line: number })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(StatusError::InvalidKey { line: number });
        }
        if !keys.insert(key) {
            return Err(StatusError::DuplicateKey {
                key: key.to_owned(),
            });
        }
        if let Some(slot) = NEEDED_KEYS
            .iter()
            .position(|needed_key| *needed_key == key)
            .and_then(|position| needed.get_mut(position))
        {
            *slot = Some((number, value));
        }
    }
    let line = |position: usize| needed_line(&needed, position);
    Ok(ProcStatus {
        pid: read("Pid", line(0)?, |value| single(value).and_then(pid))?,
        uid: read("Uid", line(1)?, id_quad)?,
        gid: read("Gid", line(2)?, id_quad)?,
        namespace_pids: read("NSpid", line(3)?, namespace_pids)?,
        cap_permitted: read("CapPrm", line(4)?, capability)?,
        cap_effective: read("CapEff", line(5)?, capability)?,
        cap_ambient: read("CapAmb", line(6)?, capability)?,
        no_new_privs: read("NoNewPrivs", line(7)?, flag)?,
        seccomp: read("Seccomp", line(8)?, seccomp)?,
    })
}

#[cfg(test)]
pub(super) mod fixtures {
    /// The status of a jailed Firecracker process: jail uid and gid, no capabilities, PID
    /// 1 in its own namespace, no_new_privs and seccomp filters.
    pub(in super::super) const JAILED: &str = "Name:\tfirecracker\n\
Umask:\t0022\n\
State:\tS (sleeping)\n\
Tgid:\t48211\n\
Ngid:\t0\n\
Pid:\t48211\n\
PPid:\t1\n\
TracerPid:\t0\n\
Uid:\t64001\t64001\t64001\t64001\n\
Gid:\t64001\t64001\t64001\t64001\n\
FDSize:\t64\n\
Groups:\t\n\
NStgid:\t48211\t1\n\
NSpid:\t48211\t1\n\
NSpgid:\t48211\t1\n\
NSsid:\t48211\t1\n\
VmPeak:\t 1130512 kB\n\
VmRSS:\t   41236 kB\n\
Threads:\t4\n\
SigQ:\t0/63304\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t000001ffffffffff\n\
CapAmb:\t0000000000000000\n\
NoNewPrivs:\t1\n\
Seccomp:\t2\n\
Seccomp_filters:\t3\n\
Speculation_Store_Bypass:\tthread force mitigated\n\
Cpus_allowed_list:\t0-7\n\
voluntary_ctxt_switches:\t150\n\
nonvoluntary_ctxt_switches:\t3\n";

    /// The same process started without the jail: root, full capabilities, the host's
    /// PID namespace, no no_new_privs and no seccomp.
    pub(in super::super) const UNJAILED: &str = "Name:\tfirecracker\n\
Pid:\t48211\n\
Uid:\t0\t0\t0\t0\n\
Gid:\t0\t0\t0\t0\n\
NSpid:\t48211\n\
CapInh:\t0000000000000000\n\
CapPrm:\t000001ffffffffff\n\
CapEff:\t000001ffffffffff\n\
CapBnd:\t000001ffffffffff\n\
CapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\n\
Seccomp:\t0\n";
}

#[cfg(test)]
mod tests {
    use super::fixtures::{JAILED, UNJAILED};
    use super::*;

    #[test]
    fn a_jailed_status_reads_exactly() {
        let status = parse_status(JAILED).unwrap();
        assert_eq!(status.pid, 48211);
        assert!(status.uid.all_equal(64001));
        assert!(status.gid.all_equal(64001));
        assert_eq!(status.namespace_pids, vec![48211, 1]);
        assert_eq!(status.cap_permitted, 0);
        assert_eq!(status.cap_effective, 0);
        assert_eq!(status.cap_ambient, 0);
        assert!(status.no_new_privs);
        assert_eq!(status.seccomp, SeccompMode::Filter);
        assert_eq!(status.seccomp.number(), 2);
        assert_eq!(status.uid.to_string(), "64001 64001 64001 64001");
    }

    #[test]
    fn an_unjailed_status_reads_too() {
        let status = parse_status(UNJAILED).unwrap();
        assert!(status.uid.all_equal(0));
        assert_eq!(status.cap_effective, 0x1ff_ffff_ffff);
        assert!(!status.no_new_privs);
        assert_eq!(status.seccomp, SeccompMode::Disabled);
        assert_eq!(status.namespace_pids, vec![48211]);
    }

    fn replace(line: &str, with: &str) -> String {
        assert!(JAILED.contains(line), "{line}");
        JAILED.replacen(line, with, 1)
    }

    #[test]
    fn malformed_needed_lines_are_refused() {
        let cases = [
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid:\t64001\t64001\t64001\n",
                "Uid",
            ),
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid:\t64001\t64001\t64001\t64001\t1\n",
                "Uid",
            ),
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid: 64001 64001 64001 64001\n",
                "Uid",
            ),
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid:\t064001\t64001\t64001\t64001\n",
                "Uid",
            ),
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid:\t+64001\t64001\t64001\t64001\n",
                "Uid",
            ),
            (
                "Uid:\t64001\t64001\t64001\t64001\n",
                "Uid:\t4294967295\t64001\t64001\t64001\n",
                "Uid",
            ),
            (
                "Gid:\t64001\t64001\t64001\t64001\n",
                "Gid:\t64001\t\t64001\t64001\n",
                "Gid",
            ),
            ("Pid:\t48211\n", "Pid:\t0\n", "Pid"),
            ("Pid:\t48211\n", "Pid:\t-1\n", "Pid"),
            ("NSpid:\t48211\t1\n", "NSpid:\t48211\t\n", "NSpid"),
            ("NSpid:\t48211\t1\n", "NSpid:\t48211 1\n", "NSpid"),
            (
                "CapEff:\t0000000000000000\n",
                "CapEff:\t000000000000000\n",
                "CapEff",
            ),
            (
                "CapEff:\t0000000000000000\n",
                "CapEff:\t00000000000000AB\n",
                "CapEff",
            ),
            (
                "CapPrm:\t0000000000000000\n",
                "CapPrm:\t0x00000000000000\n",
                "CapPrm",
            ),
            ("CapAmb:\t0000000000000000\n", "CapAmb:\t\n", "CapAmb"),
            ("NoNewPrivs:\t1\n", "NoNewPrivs:\t2\n", "NoNewPrivs"),
            ("NoNewPrivs:\t1\n", "NoNewPrivs:\t 1\n", "NoNewPrivs"),
            ("NoNewPrivs:\t1\n", "NoNewPrivs:1\n", "NoNewPrivs"),
            ("Seccomp:\t2\n", "Seccomp:\t3\n", "Seccomp"),
            ("Seccomp:\t2\n", "Seccomp:\t2\t2\n", "Seccomp"),
            ("Seccomp:\t2\n", "Seccomp:\tfilter\n", "Seccomp"),
        ];
        for (line, with, key) in cases {
            let text = replace(line, with);
            assert!(
                matches!(parse_status(&text), Err(StatusError::Malformed { key: found, .. }) if found == key),
                "{with:?}: {:?}",
                parse_status(&text)
            );
        }
    }

    #[test]
    fn malformed_lines_of_any_kind_are_refused() {
        assert_eq!(
            parse_status(&replace("Umask:\t0022\n", "Umask 0022\n")),
            Err(StatusError::NoColon { line: 2 })
        );
        assert_eq!(
            parse_status(&replace("Umask:\t0022\n", "Um ask:\t0022\n")),
            Err(StatusError::InvalidKey { line: 2 })
        );
        assert_eq!(
            parse_status(&replace("Umask:\t0022\n", ":\t0022\n")),
            Err(StatusError::InvalidKey { line: 2 })
        );
        assert_eq!(
            parse_status(&replace("Umask:\t0022\n", "\n")),
            Err(StatusError::EmptyLine { line: 2 })
        );
        assert_eq!(
            parse_status(&replace("Umask:\t0022\n", "Umask:\t0022\r\n")),
            Err(StatusError::ControlCharacter { line: 2 })
        );
        assert_eq!(
            parse_status(&replace(
                "Name:\tfirecracker\n",
                "Name:\tfire\u{1b}[2Jcracker\n"
            )),
            Err(StatusError::ControlCharacter { line: 1 })
        );
        assert_eq!(
            parse_status(JAILED.trim_end_matches('\n')),
            Err(StatusError::MissingFinalNewline)
        );
        assert_eq!(
            parse_status(&format!("{JAILED}Seccomp:\t2\n")),
            Err(StatusError::DuplicateKey {
                key: "Seccomp".to_owned()
            })
        );
        assert_eq!(
            parse_status(&format!("{JAILED}Umask:\t0077\n")),
            Err(StatusError::DuplicateKey {
                key: "Umask".to_owned()
            })
        );
        assert_eq!(parse_status(""), Err(StatusError::MissingFinalNewline));
        assert_eq!(parse_status("\n"), Err(StatusError::EmptyLine { line: 1 }));
        let padded = format!("{JAILED}{}", "Pad:\tx\n".repeat(MAX_STATUS_BYTES / 7));
        assert!(matches!(
            parse_status(&padded),
            Err(StatusError::TooLarge { .. })
        ));
    }

    #[test]
    fn every_needed_line_is_required() {
        for key in NEEDED_KEYS {
            let text: String = JAILED
                .lines()
                .filter(|line| line.split_once(':').map(|(found, _)| found) != Some(key))
                .map(|line| format!("{line}\n"))
                .collect();
            assert_eq!(
                parse_status(&text),
                Err(StatusError::Missing { key }),
                "{key}"
            );
        }
    }

    #[test]
    fn errors_describe_themselves() {
        for error in [
            StatusError::MissingFinalNewline,
            StatusError::Missing { key: "Seccomp" },
            StatusError::Malformed {
                key: "Uid",
                line: 9,
            },
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
