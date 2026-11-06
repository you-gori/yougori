//! The guest kernel's build facts: its configuration read into V15's
//! [`KernelBuildRecord`], the digest the host compares, and the kernel-record check a
//! workload profile's requirements impose (VM-CP-05, line 3155: "the kernel build record
//! (`CONFIG_IO_URING` absent) match the signed manifest", control "a test image with
//! io_uring enabled fails the kernel-record check on the host"; §3.4, line 2095: pin
//! kernel versions and "test actual required features"; line 2097: "a configured boot
//! argument is not evidence the kernel enforced it").
//!
//! - [`parse_kernel_config`]: a Linux `.config` read into a build record bound to the
//!   kernel image's digest. Only the options `sandbox_contract::confinement` reads are
//!   kept; one it does not find stays unknown, never assumed absent.
//! - [`kernel_record_digest`]: one digest over a record (the kernel image and every
//!   listed option), the value VM-CP-05's comparison observes.
//! - [`KernelRequirements`]: the absent options and forced settings a confinement
//!   profile relies on, and the one check that judges a record against them, used at
//!   selection and by VM-CP-05's positive control ([`KernelControl`]).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox_contract::confinement::{
    ConfinementProfile, KernelBuildRecord, KernelOption, KernelRecordRefusal, KernelSetting,
    OptionState,
};

/// Largest kernel configuration read.
pub const MAX_KERNEL_CONFIG_BYTES: usize = 1 << 20;

/// Domain of [`kernel_record_digest`].
pub const KERNEL_RECORD_DOMAIN: &str = "yougori/sandbox/guest-image/kernel-record/v1";

/// Why a kernel configuration was not read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum KernelConfigError {
    TooLarge {
        max_bytes: usize,
    },
    /// The configuration is not UTF-8 text.
    NotText,
    /// Line `line` (from one) ends with a carriage return; a configuration uses LF.
    CarriageReturn {
        line: usize,
    },
    /// Line `line` is neither blank, a comment nor a `CONFIG_` assignment.
    Malformed {
        line: usize,
    },
    /// An option this contract reads is given a value other than `y`, `m` or `n`.
    NotTristate {
        line: usize,
        option: KernelOption,
    },
    /// An option this contract reads is set twice.
    Repeated {
        line: usize,
        option: KernelOption,
    },
}

impl fmt::Display for KernelConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(
                    f,
                    "the kernel configuration is larger than {max_bytes} bytes"
                )
            }
            Self::NotText => f.write_str("the kernel configuration is not UTF-8 text"),
            Self::CarriageReturn { line } => {
                write!(f, "line {line} of the kernel configuration ends with CR")
            }
            Self::Malformed { line } => {
                write!(
                    f,
                    "line {line} of the kernel configuration is not an assignment"
                )
            }
            Self::NotTristate { line, option } => {
                write!(f, "line {line} gives {option} a value other than y, m or n")
            }
            Self::Repeated { line, option } => write!(f, "line {line} sets {option} again"),
        }
    }
}

impl std::error::Error for KernelConfigError {}

fn tracked(name: &str) -> Option<KernelOption> {
    KernelOption::ALL
        .into_iter()
        .find(|option| option.config_name() == name)
}

fn is_config_name(name: &str) -> bool {
    name.strip_prefix("CONFIG_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// Reads a Linux `.config` as the build record of the kernel image with digest
/// `kernel_image`: `CONFIG_X=y` is built in, `=m` a module, `=n` and
/// `# CONFIG_X is not set` not set. Other comments and blank lines are skipped, and
/// options this contract does not read are ignored whatever their value.
pub fn parse_kernel_config(
    kernel_image: Digest,
    config: &[u8],
) -> Result<KernelBuildRecord, KernelConfigError> {
    if config.len() > MAX_KERNEL_CONFIG_BYTES {
        return Err(KernelConfigError::TooLarge {
            max_bytes: MAX_KERNEL_CONFIG_BYTES,
        });
    }
    let text = std::str::from_utf8(config).map_err(|_| KernelConfigError::NotText)?;
    let mut options: Vec<(KernelOption, OptionState)> = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        let number = index + 1;
        if line.ends_with('\r') {
            return Err(KernelConfigError::CarriageReturn { line: number });
        }
        let assignment = if let Some(comment) = line.strip_prefix('#') {
            comment
                .strip_prefix(' ')
                .and_then(|rest| rest.strip_suffix(" is not set"))
                .filter(|name| is_config_name(name))
                .map(|name| (name, Some(OptionState::NotSet)))
        } else if line.is_empty() {
            None
        } else {
            let (name, value) = line
                .split_once('=')
                .filter(|(name, _)| is_config_name(name))
                .ok_or(KernelConfigError::Malformed { line: number })?;
            let state = match value {
                "y" => Some(OptionState::BuiltIn),
                "m" => Some(OptionState::Module),
                "n" => Some(OptionState::NotSet),
                _ => None,
            };
            Some((name, state))
        };
        let Some((name, state)) = assignment else {
            continue;
        };
        let Some(option) = tracked(name) else {
            continue;
        };
        let state = state.ok_or(KernelConfigError::NotTristate {
            line: number,
            option,
        })?;
        if options.iter().any(|(seen, _)| *seen == option) {
            return Err(KernelConfigError::Repeated {
                line: number,
                option,
            });
        }
        options.push((option, state));
    }
    // Repeats are refused above with their line; this mapping only keeps the call total.
    KernelBuildRecord::new(kernel_image, options).map_err(|refusal| match refusal {
        KernelRecordRefusal::DuplicateOption { option } => {
            KernelConfigError::Repeated { line: 0, option }
        }
    })
}

const fn state_tag(state: OptionState) -> &'static str {
    match state {
        OptionState::NotSet => "not_set",
        OptionState::BuiltIn => "built_in",
        OptionState::Module => "module",
    }
}

/// One digest over `record`: the kernel image's digest and every listed option with its
/// state, in option order. Two records have the same digest exactly when they describe
/// the same kernel image with the same listed options.
pub fn kernel_record_digest(record: &KernelBuildRecord) -> Digest {
    let options: Vec<(KernelOption, OptionState)> = record.options().collect();
    options
        .iter()
        .fold(
            DigestBuilder::new(KERNEL_RECORD_DOMAIN)
                .digest(&record.kernel_image())
                .u64(options.len() as u64),
            |builder, (option, state)| builder.str(option.config_name()).str(state_tag(*state)),
        )
        .finish()
}

/// Why a kernel's build record does not meet a profile's requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum KernelRequirementFailure {
    /// The profile relies on the option being absent; the record shows it built, or
    /// does not list it (`state` is `None`), which is unknown and never absent.
    OptionNotAbsent {
        option: KernelOption,
        state: Option<OptionState>,
    },
    /// No option that forces the setting is built in.
    SettingNotForced { setting: KernelSetting },
}

impl fmt::Display for KernelRequirementFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptionNotAbsent {
                option,
                state: Some(state),
            } => write!(
                f,
                "the profile needs {option} absent and the kernel was built with it {}",
                state_tag(*state)
            ),
            Self::OptionNotAbsent {
                option,
                state: None,
            } => write!(
                f,
                "the profile needs {option} absent and the kernel's build record does not \
                 list it"
            ),
            Self::SettingNotForced { setting } => {
                write!(
                    f,
                    "the profile needs {setting} and no build option forces it"
                )
            }
        }
    }
}

impl std::error::Error for KernelRequirementFailure {}

/// What a profile needs of the kernel's build: options absent and settings forced at
/// build time. A boot argument or a guest's claim never meets a requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KernelRequirements {
    absent: BTreeSet<KernelOption>,
    settings: BTreeSet<KernelSetting>,
}

impl KernelRequirements {
    pub fn new(
        absent: impl IntoIterator<Item = KernelOption>,
        settings: impl IntoIterator<Item = KernelSetting>,
    ) -> Self {
        Self {
            absent: absent.into_iter().collect(),
            settings: settings.into_iter().collect(),
        }
    }

    /// The requirements of `profile`: the options its forbidden interfaces rely on being
    /// absent, and its kernel settings.
    pub fn of_profile(profile: &ConfinementProfile) -> Self {
        Self::new(
            profile.required_absent_options(),
            profile.kernel_settings().iter().copied(),
        )
    }

    pub fn absent(&self) -> &BTreeSet<KernelOption> {
        &self.absent
    }

    pub fn settings(&self) -> &BTreeSet<KernelSetting> {
        &self.settings
    }

    /// The kernel-record check: every required option is listed as not set, and every
    /// required setting is forced by a built-in option. The first failure in option,
    /// then setting, order is returned.
    pub fn check(&self, record: &KernelBuildRecord) -> Result<(), KernelRequirementFailure> {
        for option in &self.absent {
            let state = record.state(*option);
            if !state.is_some_and(OptionState::is_absent) {
                return Err(KernelRequirementFailure::OptionNotAbsent {
                    option: *option,
                    state,
                });
            }
        }
        for setting in &self.settings {
            let forced = setting
                .forced_by()
                .iter()
                .any(|option| record.state(*option) == Some(OptionState::BuiltIn));
            if !forced {
                return Err(KernelRequirementFailure::SettingNotForced { setting: *setting });
            }
        }
        Ok(())
    }
}

/// VM-CP-05's positive control: the kernel-record check run on a test image built with
/// io_uring. It happened only when the test record really has io_uring built (in or as
/// a module) and the check refused it for exactly that option; a test image without
/// io_uring, or requirements that do not need it absent, show nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KernelControl {
    happened: bool,
}

impl KernelControl {
    /// Runs the control with `requirements` on the io_uring test image's `test_record`.
    pub fn run(requirements: &KernelRequirements, test_record: &KernelBuildRecord) -> Self {
        let enabled = matches!(
            test_record.state(KernelOption::IoUring),
            Some(OptionState::BuiltIn | OptionState::Module)
        );
        let refused = matches!(
            requirements.check(test_record),
            Err(KernelRequirementFailure::OptionNotAbsent {
                option: KernelOption::IoUring,
                ..
            })
        );
        Self {
            happened: enabled && refused,
        }
    }

    /// Whether the check refused the io_uring test image.
    pub const fn happened(self) -> bool {
        self.happened
    }
}
