//! What one VM-CP-12 scan covers (§17, line 3162; §8.1, line 2439: "A probe suite
//! demonstrates named properties at a time"): the launch it checks, its fixture
//! credential, the locations the caller names for each of the five places the row lists,
//! and the bounds of one run.
//!
//! A [`ScanPlan`] names at least one location for each [`LocationRole`], each an
//! absolute file or directory path written in plain components. Its subject
//! ([`ScanPlan::subject`]) carries the digest of exactly those locations, so evidence
//! about one set of locations never answers for another (CORE-01 `CredentialScanSubject`).

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::fixture::FixtureCredential;
use crate::foundation::evidence::{CredentialScanSubject, SandboxBootSubject};
use crate::foundation::ids::{Digest, DigestBuilder};

/// Domain of [`ScanPlan::locations_digest`]: the number of locations, then each one's
/// role tag and path, in the plan's order (by role, then path).
pub const LOCATIONS_DOMAIN: &str = "yougori/host-checks/credential-scan/locations/v1";

/// The most locations one plan names.
pub const MAX_LOCATIONS: usize = 64;

/// The places §17 VM-CP-12 names, each with the expectation that judges it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationRole {
    /// "the launch specification": must not contain the fixture.
    LaunchSpecification,
    /// "the relay's inputs and logs": must not contain the fixture.
    RelayInputsAndLogs,
    /// "the audit": must not contain the fixture.
    Audit,
    /// "the fake provider's echoed response": must not contain the fixture.
    EchoedResponse,
    /// "the executor's outbound request": must contain the fixture.
    ExecutorRequest,
}

impl LocationRole {
    pub const ALL: [Self; 5] = [
        Self::LaunchSpecification,
        Self::RelayInputsAndLogs,
        Self::Audit,
        Self::EchoedResponse,
        Self::ExecutorRequest,
    ];

    /// The stable tag hashed into [`ScanPlan::locations_digest`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LaunchSpecification => "launch_specification",
            Self::RelayInputsAndLogs => "relay_inputs_and_logs",
            Self::Audit => "audit",
            Self::EchoedResponse => "echoed_response",
            Self::ExecutorRequest => "executor_request",
        }
    }

    /// The name of the VM-CP-12 expectation that judges this place.
    pub const fn expectation(self) -> &'static str {
        match self {
            Self::LaunchSpecification => "cp12.launch-specification",
            Self::RelayInputsAndLogs => "cp12.relay-inputs-and-logs",
            Self::Audit => "cp12.audit",
            Self::EchoedResponse => "cp12.echoed-response",
            Self::ExecutorRequest => "cp12.executor-request",
        }
    }

    /// Whether the fixture must be found here: only in the executor's outbound request.
    pub const fn must_contain(self) -> bool {
        matches!(self, Self::ExecutorRequest)
    }
}

impl fmt::Display for LocationRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LaunchSpecification => "the launch specification",
            Self::RelayInputsAndLogs => "the relay's inputs and logs",
            Self::Audit => "the audit",
            Self::EchoedResponse => "the fake provider's echoed response",
            Self::ExecutorRequest => "the executor's outbound request",
        })
    }
}

/// One location the caller names: a file, or a directory whose whole tree is read.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamedLocation {
    pub role: LocationRole,
    pub path: PathBuf,
}

impl NamedLocation {
    pub fn new(role: LocationRole, path: impl Into<PathBuf>) -> Self {
        Self {
            role,
            path: path.into(),
        }
    }

    /// The path as text; a plan holds only paths that are text.
    pub fn path_text(&self) -> &str {
        self.path.to_str().unwrap_or_default()
    }
}

/// Why a plan was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "plan", rename_all = "snake_case")]
pub enum PlanError {
    /// More than [`MAX_LOCATIONS`] locations.
    TooManyLocations { limit: usize },
    /// No location is named for this place.
    RoleNotNamed { role: LocationRole },
    /// The path at this position of the list is not text.
    PathNotText { index: usize },
    /// The path is not absolute.
    NotAbsolute { path: String },
    /// The path has a `.` or `..` component.
    NotPlain { path: String },
    /// The path is named twice.
    RepeatedPath { path: String },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyLocations { limit } => {
                write!(f, "a credential scan names at most {limit} locations")
            }
            Self::RoleNotNamed { role } => write!(f, "no location is named for {role}"),
            Self::PathNotText { index } => write!(f, "location {index} is not a text path"),
            Self::NotAbsolute { path } => write!(f, "the location {path} is not absolute"),
            Self::NotPlain { path } => {
                write!(f, "the location {path} has a `.` or `..` component")
            }
            Self::RepeatedPath { path } => write!(f, "the location {path} is named twice"),
        }
    }
}

impl std::error::Error for PlanError {}

/// One launch's credential scan: what VM-CP-12 reads and looks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanPlan {
    launch: SandboxBootSubject,
    fixture: FixtureCredential,
    /// By role, then path.
    locations: Vec<NamedLocation>,
}

impl ScanPlan {
    pub fn new(
        launch: SandboxBootSubject,
        fixture: FixtureCredential,
        locations: Vec<NamedLocation>,
    ) -> Result<Self, PlanError> {
        if locations.len() > MAX_LOCATIONS {
            return Err(PlanError::TooManyLocations {
                limit: MAX_LOCATIONS,
            });
        }
        let mut checked = Vec::with_capacity(locations.len());
        let mut paths = BTreeSet::new();
        for (index, location) in locations.into_iter().enumerate() {
            let path = plain_path(&location.path, index)?;
            if !paths.insert(path.clone()) {
                return Err(PlanError::RepeatedPath { path: text(&path) });
            }
            checked.push(NamedLocation {
                role: location.role,
                path,
            });
        }
        for role in LocationRole::ALL {
            if !checked.iter().any(|location| location.role == role) {
                return Err(PlanError::RoleNotNamed { role });
            }
        }
        checked.sort();
        Ok(Self {
            launch,
            fixture,
            locations: checked,
        })
    }

    pub const fn launch(&self) -> &SandboxBootSubject {
        &self.launch
    }

    pub const fn fixture(&self) -> &FixtureCredential {
        &self.fixture
    }

    /// The named locations, by role, then path.
    pub fn locations(&self) -> &[NamedLocation] {
        &self.locations
    }

    /// The digest of exactly the named locations, in [`LOCATIONS_DOMAIN`].
    pub fn locations_digest(&self) -> Digest {
        self.locations
            .iter()
            .fold(
                DigestBuilder::new(LOCATIONS_DOMAIN).u64(self.locations.len() as u64),
                |builder, location| builder.str(location.role.tag()).str(location.path_text()),
            )
            .finish()
    }

    /// The CORE-01 subject of this scan: the launch and the digest of its locations.
    pub fn subject(&self) -> CredentialScanSubject {
        CredentialScanSubject {
            launch: self.launch,
            locations: self.locations_digest(),
        }
    }
}

/// `path` rebuilt from its components, refused unless it is text, absolute and has no
/// `.` or `..` component.
fn plain_path(path: &Path, index: usize) -> Result<PathBuf, PlanError> {
    let shown = path.to_str().ok_or(PlanError::PathNotText { index })?;
    if !path.is_absolute() {
        return Err(PlanError::NotAbsolute {
            path: shown.to_owned(),
        });
    }
    let dotted = shown
        .split(['/', '\\'])
        .any(|component| component == "." || component == "..");
    let plain = path.components().all(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::Normal(_)
        )
    });
    if dotted || !plain {
        return Err(PlanError::NotPlain {
            path: shown.to_owned(),
        });
    }
    Ok(path.components().collect())
}

fn text(path: &Path) -> String {
    path.to_str().unwrap_or_default().to_owned()
}
