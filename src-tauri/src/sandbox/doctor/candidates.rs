//! The VM backends a host's doctor examines, by host operating system (VM-D2, line 3196;
//! VM-W17, line 2616; VM-W19 to VM-W21, lines 2618–2620; the M01–M05 acceptance of the
//! remaining-only view: "VM-W19 also covers the minimal compatible Linux QEMU profile",
//! "For selected shipped QEMU Linux/macOS profiles, retain the pinned `qemu-secure` build
//! requirement").

use serde::Serialize;

use crate::foundation::evidence::OsKind;
use crate::sandbox::backend::BackendKind;

/// Why a backend is examined on a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRole {
    /// The backend the plan names first for this operating system.
    Primary,
    /// The backend used when the primary one is not available (VM-D2: QEMU/WHPX after HCS).
    Fallback,
    /// A further profile the plan keeps for this operating system.
    Alternative,
}

/// One backend examined on a host, with the plan's reason in its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub backend: BackendKind,
    pub role: CandidateRole,
    pub basis: &'static str,
}

const WINDOWS: [Candidate; 2] = [
    Candidate {
        backend: BackendKind::Hcs,
        role: CandidateRole::Primary,
        basis: "VM-D2 (a): run the HCS spike (VM-W20) first; the HCS decision is still open (M04)",
    },
    Candidate {
        backend: BackendKind::Qemu,
        role: CandidateRole::Fallback,
        basis: "VM-D2 (a): QEMU/WHPX as the fallback (VM-W19)",
    },
];

const LINUX: [Candidate; 2] = [
    Candidate {
        backend: BackendKind::Firecracker,
        role: CandidateRole::Primary,
        basis: "VM-W17: Linux reference backend with supported Firecracker jailer setup",
    },
    Candidate {
        backend: BackendKind::Qemu,
        role: CandidateRole::Alternative,
        basis: "VM-W19: the minimal compatible QEMU Linux profile",
    },
];

const MACOS: [Candidate; 2] = [
    Candidate {
        backend: BackendKind::VirtualizationFramework,
        role: CandidateRole::Primary,
        basis: "VM-W21: native-architecture macOS VM helper on the supported framework",
    },
    Candidate {
        backend: BackendKind::Qemu,
        role: CandidateRole::Alternative,
        basis: "a selected shipped QEMU macOS profile, on the pinned qemu-secure build",
    },
];

/// The backends examined on `os`, primary first. Inside WSL2 there are none: the plan
/// runs sandboxes on the Windows host, and nested virtualization is a separate experiment
/// (VM-W20).
pub fn candidates(os: OsKind) -> &'static [Candidate] {
    match os {
        OsKind::Windows => &WINDOWS,
        OsKind::Linux => &LINUX,
        OsKind::MacOs => &MACOS,
        OsKind::Wsl2 => &[],
    }
}

/// Why `os` has no candidate backend, when it has none.
pub(super) fn no_candidates(os: OsKind) -> Option<&'static str> {
    candidates(os).is_empty().then_some(
        "No VM sandbox backend runs inside WSL2: sandboxes run on the Windows host, and nested virtualization is a separate experiment (VM-W20).",
    )
}
