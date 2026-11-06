//! The versioned helper ABI (GPU-W11, line 1321: "Package model helpers through CORE-08
//! with authenticated pinned artifact identity and a stable ABI").
//!
//! The helper ABI is the interface between the runner's helper loader and a helper: the
//! entry points the loader calls, the arguments it passes and the results it expects. It
//! is versioned `major.minor`:
//!
//! - a minor version only adds to its major (new optional entry points or fields), so a
//!   loader providing `1.3` loads helpers built for `1.0` to `1.3`;
//! - a helper built for a newer minor than the loader provides needs something the
//!   loader lacks and is refused;
//! - a major version breaks compatibility: a helper is loaded only by a loader providing
//!   its exact major. A loader may provide several majors during a migration.
//!
//! This is not the native-operation ABI of `boundaries::NativeAbi`, whose versions must
//! match exactly because driver operations have no optional subset.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// One helper ABI version, `major.minor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperAbi {
    pub major: u16,
    pub minor: u16,
}

impl HelperAbi {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl fmt::Display for HelperAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Why a helper's ABI is not one this host's loader provides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum HelperAbiRefusal {
    /// The loader provides no version of the helper's major; majors break compatibility.
    MajorNotProvided {
        required: HelperAbi,
        provided: Vec<HelperAbi>,
    },
    /// The helper needs a newer minor of its major than the loader provides.
    MinorTooNew {
        required: HelperAbi,
        provided: HelperAbi,
    },
}

impl fmt::Display for HelperAbiRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MajorNotProvided { required, provided } => {
                let provided: Vec<String> = provided.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "the helper needs ABI {required}; this host's loader provides only {}",
                    provided.join(", ")
                )
            }
            Self::MinorTooNew { required, provided } => write!(
                f,
                "the helper needs ABI {required}; this host's loader provides {provided}"
            ),
        }
    }
}

impl std::error::Error for HelperAbiRefusal {}

/// Why a host ABI declaration was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostAbiError {
    /// A loader that provides no ABI would load nothing.
    Empty,
    /// One major is listed twice; each major has one newest minor.
    DuplicateMajor { major: u16 },
}

impl fmt::Display for HostAbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the helper loader provides no ABI"),
            Self::DuplicateMajor { major } => {
                write!(f, "helper ABI major {major} is listed twice")
            }
        }
    }
}

impl std::error::Error for HostAbiError {}

/// The helper ABI versions this host's loader provides: for each major, its newest minor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostHelperAbi {
    majors: BTreeMap<u16, u16>,
}

impl HostHelperAbi {
    /// A loader providing each of `provided`, at most one version per major.
    pub fn new(provided: impl IntoIterator<Item = HelperAbi>) -> Result<Self, HostAbiError> {
        let mut majors = BTreeMap::new();
        for abi in provided {
            if majors.insert(abi.major, abi.minor).is_some() {
                return Err(HostAbiError::DuplicateMajor { major: abi.major });
            }
        }
        if majors.is_empty() {
            return Err(HostAbiError::Empty);
        }
        Ok(Self { majors })
    }

    /// A loader providing exactly one version.
    pub fn single(abi: HelperAbi) -> Self {
        Self {
            majors: BTreeMap::from([(abi.major, abi.minor)]),
        }
    }

    /// The provided versions, by major.
    pub fn provided(&self) -> Vec<HelperAbi> {
        self.majors
            .iter()
            .map(|(major, minor)| HelperAbi::new(*major, *minor))
            .collect()
    }

    /// Whether a helper built for `required` loads here: its major is provided, at a
    /// minor no older than the helper's.
    pub fn check(&self, required: HelperAbi) -> Result<(), HelperAbiRefusal> {
        let Some(minor) = self.majors.get(&required.major) else {
            return Err(HelperAbiRefusal::MajorNotProvided {
                required,
                provided: self.provided(),
            });
        };
        if required.minor > *minor {
            return Err(HelperAbiRefusal::MinorTooNew {
                required,
                provided: HelperAbi::new(required.major, *minor),
            });
        }
        Ok(())
    }
}
