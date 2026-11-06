//! VM-CP-02's golden file (line 3152: the QEMU argv matches the approved profile's
//! golden file, versioned with the backend; VM-P02, line 2777: the measured configuration
//! matches the approved profile, with no universal device-count target; §3.4 line 2101:
//! record the actual profile).
//!
//! A golden file records a profile's canonical argument vector, in which each per-launch
//! value (instance name, sizes, host paths, context id) is replaced by its role, together
//! with the backend version and the platform, under one digest. Any change to a fixed
//! argument, its order or the backend version changes the digest. An observed process is
//! canonicalized against the launch that should have produced it and compared option by
//! option, reporting unexpected, missing and changed arguments; a launch plan's own vector
//! is compared the same way before anything is started ([`GoldenFile::compare_plan`]).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::argv::{compare, flatten, pairs_of, ArgumentDifference, ObservedArgv, Pair};
use super::platform::ProfileKind;
use super::profile::QemuProfile;
use crate::foundation::evidence::{BackendVersion, OsKind};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::sandbox::backend::{Architecture, BackendIdentity, BackendKind};

/// The digest domain of a golden file.
pub const GOLDEN_DOMAIN: &str = "yougori/sandbox/qemu/golden/v1";
/// The golden file format this module reads and writes.
pub const GOLDEN_FORMAT: u32 = 1;

/// The approved argument vector of one profile on one platform for one backend build.
/// It is an input read from the release, so unknown fields are refused and the digest
/// is checked before any comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenFile {
    pub format: u32,
    pub backend_kind: BackendKind,
    pub backend_version: BackendVersion,
    pub os: OsKind,
    pub architecture: Architecture,
    pub profile: ProfileKind,
    /// The canonical argument vector, without the executable.
    pub arguments: Vec<String>,
    pub digest: Digest,
}

/// Why a golden comparison was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum GoldenRefusal {
    UnsupportedFormat {
        format: u32,
    },
    /// The recorded digest does not cover the recorded content.
    DigestMismatch {
        recorded: Digest,
        computed: Digest,
    },
    NotQemuBackend {
        kind: BackendKind,
    },
    /// The golden file belongs to another backend build; it says nothing about this one.
    OtherBackendVersion {
        golden: BackendVersion,
        running: BackendVersion,
    },
    /// The golden file is for another profile or platform than the launch.
    OtherProfile {
        golden: ProfileKind,
        launch: ProfileKind,
        golden_os: OsKind,
        launch_os: OsKind,
    },
}

impl fmt::Display for GoldenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat { format } => {
                write!(f, "golden file format {format} is not supported")
            }
            Self::DigestMismatch { .. } => {
                f.write_str("the golden file's digest does not match its content")
            }
            Self::NotQemuBackend { kind } => write!(f, "{kind} is not a QEMU backend"),
            Self::OtherBackendVersion { golden, running } => write!(
                f,
                "the golden file is for QEMU {golden}, but the backend is {running}"
            ),
            Self::OtherProfile {
                golden,
                launch,
                golden_os,
                launch_os,
            } => write!(
                f,
                "the golden file is for the {golden} on {golden_os}, but the launch uses the \
                 {launch} on {launch_os}"
            ),
        }
    }
}

impl std::error::Error for GoldenRefusal {}

/// The digest of a canonical argument vector with its backend version and platform.
pub fn golden_digest(
    backend_kind: BackendKind,
    backend_version: &BackendVersion,
    os: OsKind,
    architecture: Architecture,
    profile: ProfileKind,
    arguments: &[String],
) -> Digest {
    arguments
        .iter()
        .fold(
            DigestBuilder::new(GOLDEN_DOMAIN)
                .u64(u64::from(GOLDEN_FORMAT))
                .str(backend_kind.tag())
                .str(backend_version.as_str())
                .str(os.tag())
                .str(architecture.tag())
                .str(profile.tag())
                .u64(arguments.len() as u64),
            |builder, argument| builder.str(argument),
        )
        .finish()
}

/// How an observed process compares with a golden file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoldenComparison {
    pub golden: Digest,
    /// The digest of the observed vector, canonicalized against the launch.
    pub observed: Digest,
    pub differences: Vec<ArgumentDifference>,
    /// The same arguments in another order.
    pub reordered: bool,
}

impl GoldenComparison {
    /// The observed configuration is the approved one.
    pub fn matches(&self) -> bool {
        self.golden == self.observed
    }
}

impl GoldenFile {
    /// Records the golden file of `profile` for `backend`.
    pub fn of(profile: &QemuProfile, backend: &BackendIdentity) -> Result<Self, GoldenRefusal> {
        if backend.kind != BackendKind::Qemu {
            return Err(GoldenRefusal::NotQemuBackend { kind: backend.kind });
        }
        let platform = profile.platform();
        let arguments = profile.canonical_argv();
        let digest = golden_digest(
            backend.kind,
            &backend.version,
            platform.os,
            platform.architecture,
            profile.fixed().kind,
            &arguments,
        );
        Ok(Self {
            format: GOLDEN_FORMAT,
            backend_kind: backend.kind,
            backend_version: backend.version.clone(),
            os: platform.os,
            architecture: platform.architecture,
            profile: profile.fixed().kind,
            arguments,
            digest,
        })
    }

    fn computed_digest(&self) -> Digest {
        golden_digest(
            self.backend_kind,
            &self.backend_version,
            self.os,
            self.architecture,
            self.profile,
            &self.arguments,
        )
    }

    /// Checks the format and that the digest covers the content.
    pub fn verify(&self) -> Result<(), GoldenRefusal> {
        if self.format != GOLDEN_FORMAT {
            return Err(GoldenRefusal::UnsupportedFormat {
                format: self.format,
            });
        }
        let computed = self.computed_digest();
        if computed != self.digest {
            return Err(GoldenRefusal::DigestMismatch {
                recorded: self.digest,
                computed,
            });
        }
        Ok(())
    }

    /// Compares an observed process with this golden file. `launch` is the profile the
    /// process was started from: its per-launch values are what the observed vector is
    /// canonicalized against, and `backend` must be the build this file was recorded
    /// for.
    pub fn compare(
        &self,
        observed: &ObservedArgv,
        launch: &QemuProfile,
        backend: &BackendIdentity,
    ) -> Result<GoldenComparison, GoldenRefusal> {
        self.applies_to(launch, backend)?;
        Ok(self.compare_applicable(observed, launch))
    }

    /// Compares the vector `launch` starts QEMU with, before anything is started: whether
    /// the plan is the approved configuration. The checks of [`GoldenFile::compare`] come
    /// first.
    pub fn compare_plan(
        &self,
        launch: &QemuProfile,
        backend: &BackendIdentity,
    ) -> Result<GoldenComparison, GoldenRefusal> {
        self.applies_to(launch, backend)?;
        Ok(self.comparison(&pairs_of(&launch.canonical_argv()), launch.internet()))
    }

    /// [`GoldenFile::compare`] for a launch this file was already shown to apply to, with
    /// the same `backend` ([`GoldenFile::compare_plan`]): whether it applies depends only on
    /// the file, the launch's profile and platform and the backend build, so it cannot
    /// refuse again.
    pub(super) fn compare_applicable(
        &self,
        observed: &ObservedArgv,
        launch: &QemuProfile,
    ) -> GoldenComparison {
        let bindings = launch.bindings();
        let canonical: Vec<_> = observed
            .pairs()
            .iter()
            .map(|pair| bindings.canonicalize(pair))
            .collect();
        self.comparison(&canonical, launch.internet())
    }

    /// Checks that this file may judge `launch` on `backend`: its format and digest, a
    /// QEMU build of the version it was recorded for, and the launch's profile and
    /// platform.
    fn applies_to(
        &self,
        launch: &QemuProfile,
        backend: &BackendIdentity,
    ) -> Result<(), GoldenRefusal> {
        self.verify()?;
        for kind in [self.backend_kind, backend.kind] {
            if kind != BackendKind::Qemu {
                return Err(GoldenRefusal::NotQemuBackend { kind });
            }
        }
        if backend.version != self.backend_version {
            return Err(GoldenRefusal::OtherBackendVersion {
                golden: self.backend_version.clone(),
                running: backend.version.clone(),
            });
        }
        let platform = launch.platform();
        if launch.fixed().kind != self.profile
            || platform.os != self.os
            || platform.architecture != self.architecture
        {
            return Err(GoldenRefusal::OtherProfile {
                golden: self.profile,
                launch: launch.fixed().kind,
                golden_os: self.os,
                launch_os: platform.os,
            });
        }
        Ok(())
    }

    /// The comparison of a canonical vector with this file's.
    fn comparison(&self, canonical: &[Pair], internet: bool) -> GoldenComparison {
        let mut expected = self.arguments.clone();
        if internet && !expected.iter().any(|arg| arg == "-netdev") {
            expected.extend(super::profile::internet_arguments());
        }
        let approved = golden_digest(self.backend_kind, &self.backend_version, self.os, self.architecture, self.profile, &expected);
        let observed_digest = golden_digest(
            self.backend_kind,
            &self.backend_version,
            self.os,
            self.architecture,
            self.profile,
            &flatten(canonical),
        );
        let (differences, reordered) = compare(&pairs_of(&expected), canonical);
        GoldenComparison {
            golden: approved,
            observed: observed_digest,
            differences,
            reordered,
        }
    }
}
