//! Tests for V15, one file per area, with shared builders: the built-in profiles, an
//! honest guest's report, and a host corroboration and signed manifest for the strict
//! guest image. Everything is a fake; nothing here probes a guest or boots anything.

mod evaluate;
mod gaps;
mod profile;
mod residue;
mod responsibility;

use super::*;
use crate::foundation::ids::{digest, Digest};

pub(super) fn builtin(workload: WorkloadProfile) -> ConfinementProfile {
    ConfinementProfile::builtin(workload).unwrap()
}

pub(super) fn strict() -> ConfinementProfile {
    builtin(WorkloadProfile::StrictTool)
}

pub(super) fn developer() -> ConfinementProfile {
    builtin(WorkloadProfile::Developer)
}

pub(super) fn image(name: &str) -> Digest {
    digest("yougori/test/confinement/image/v1", &[name.as_bytes()])
}

pub(super) fn tool_name(name: &str) -> ToolName {
    ToolName::new(name).unwrap()
}

pub(super) fn plain_tool(name: &str) -> RequiredTool {
    RequiredTool::plain(tool_name(name))
}

pub(super) fn tool_needing(name: &str, interfaces: &[Interface]) -> RequiredTool {
    RequiredTool {
        name: tool_name(name),
        interfaces: interfaces.to_vec(),
        capabilities: Vec::new(),
    }
}

pub(super) fn exception(target: ExceptionTarget, tool: &str) -> ConfinementException {
    ConfinementException {
        target,
        tool: tool_name(tool),
        reason: RecordedReason::new("needed by the pinned toolchain").unwrap(),
        owner: OwnerName::new("platform-security").unwrap(),
    }
}

pub(super) fn interface_target(interface: Interface) -> ExceptionTarget {
    ExceptionTarget::Interface { interface }
}

pub(super) fn capability_target(capability: LinuxCapability) -> ExceptionTarget {
    ExceptionTarget::Capability { capability }
}

pub(super) fn refused(document: ProfileDocument) -> ProfileRefusal {
    ConfinementProfile::new(document).unwrap_err()
}

/// `document` with `interface` no longer forbidden.
pub(super) fn without(mut document: ProfileDocument, interface: Interface) -> ProfileDocument {
    document
        .forbidden
        .retain(|entry| entry.interface != interface);
    document
}

/// The kernel the strict manifest promises: io_uring built out, the rest as listed.
pub(super) fn strict_kernel(kernel_image: Digest, io_uring: OptionState) -> KernelBuildRecord {
    KernelBuildRecord::new(
        kernel_image,
        [
            (KernelOption::IoUring, io_uring),
            (KernelOption::BpfSyscall, OptionState::BuiltIn),
            (KernelOption::Modules, OptionState::BuiltIn),
            (KernelOption::Vsockets, OptionState::BuiltIn),
        ],
    )
    .unwrap()
}

pub(super) fn manifest() -> ManifestExpectation {
    ManifestExpectation {
        root_image: image("root-strict"),
        kernel: strict_kernel(image("kernel-strict"), OptionState::NotSet),
    }
}

pub(super) fn matching_host() -> HostCorroboration {
    HostCorroboration::host_observed(
        image("root-strict"),
        strict_kernel(image("kernel-strict"), OptionState::NotSet),
        [],
    )
}

/// The errno an honest probe sees: seccomp runs at system call entry, so it answers
/// first whenever it is declared; otherwise the primary answers.
pub(super) fn honest_errno(entry: &ForbiddenInterface) -> Errno {
    let mechanism = if entry.uses(Mechanism::Seccomp) {
        Mechanism::Seccomp
    } else {
        entry.primary
    };
    match enforcement(mechanism, entry.interface) {
        Enforcement::Enforces(failures) => failures[0],
        Enforcement::CannotEnforce(reason) => panic!("{reason}"),
    }
}

/// What an honest guest under `profile` reports.
pub(super) fn honest_document(profile: &ConfinementProfile) -> GuestProbeDocument {
    let interfaces = profile
        .forbidden()
        .iter()
        .filter(|entry| entry.interface != Interface::ProtectedPathWrite)
        .map(|entry| InterfaceProbe {
            interface: entry.interface,
            outcome: ProbeOutcome::Failed {
                errno: honest_errno(entry),
            },
        })
        .collect();
    let protected_paths = match profile.assignment(Interface::ProtectedPathWrite) {
        Some(entry) => profile
            .protected_paths()
            .iter()
            .map(|path| PathProbe {
                path: path.clone(),
                outcome: ProbeOutcome::Failed {
                    errno: honest_errno(entry),
                },
            })
            .collect(),
        None => Vec::new(),
    };
    let uid = match profile.uid() {
        UidPolicy::Fixed { uid, .. } => uid.get(),
        UidPolicy::AnyNonRoot => 1000,
    };
    GuestProbeDocument {
        profile: profile.digest(),
        interfaces,
        protected_paths,
        capabilities: Some(ObservedCapabilities {
            bounding: profile.capabilities().into_iter().collect(),
            permitted: Vec::new(),
            effective: Vec::new(),
        }),
        uid: Some(uid),
        no_new_privs: Some(true),
        kernel_settings: Vec::new(),
        kernel_options: Vec::new(),
        root_image: None,
    }
}

pub(super) fn report(document: GuestProbeDocument) -> GuestReport {
    GuestReport::receive(document).unwrap()
}

/// `document` with the result for `interface` replaced.
pub(super) fn with_result(
    mut document: GuestProbeDocument,
    interface: Interface,
    outcome: ProbeOutcome,
) -> GuestProbeDocument {
    for probe in &mut document.interfaces {
        if probe.interface == interface {
            probe.outcome = outcome;
        }
    }
    document
}

pub(super) fn failed_with(errno: Errno) -> ProbeOutcome {
    ProbeOutcome::Failed { errno }
}

/// Every JSON object key in `value`, recursively.
pub(super) fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                keys(inner, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| keys(item, out)),
        _ => {}
    }
}
