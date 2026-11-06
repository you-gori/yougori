//! Tests for M07A, one file per area, with shared builders: guest layouts, the built-in
//! V15 profiles and profiles with recorded exceptions, an LSM path rule, an LSM ptrace
//! rule or ptrace refused by seccomp alone. Everything is a fake; nothing here installs or
//! probes anything.

mod compiling;
mod gaps;
mod reading;
mod verifying;

use super::*;
use crate::sandbox_contract::confinement::{
    ConfinementException, ConfinementProfile, ExceptionTarget, ForbiddenInterface, Interface,
    LinuxCapability, Mechanism, OwnerName, ProfileDocument, ProtectedPath, RecordedReason,
    RequiredTool, ToolName, WorkloadProfile,
};

pub(super) fn path(text: &str) -> AbsoluteGuestPath {
    AbsoluteGuestPath::parse(text).unwrap()
}

/// Home at `/home/agent`, workspace at `/workspace`; the workload writes beneath
/// `/workspace` and `/tmp`.
pub(super) fn layout() -> GuestLayout {
    layout_with(&["/workspace", "/tmp"])
}

pub(super) fn layout_with(writable_roots: &[&str]) -> GuestLayout {
    GuestLayout::new(LayoutDocument {
        home: path("/home/agent"),
        workspace: path("/workspace"),
        writable_roots: writable_roots.iter().map(|root| path(root)).collect(),
        device_nodes: Vec::new(),
    })
    .unwrap()
}

/// [`layout`] with a GPU's device nodes declared.
pub(super) fn device_layout() -> GuestLayout {
    GuestLayout::new(LayoutDocument {
        home: path("/home/agent"),
        workspace: path("/workspace"),
        writable_roots: vec![path("/workspace"), path("/tmp")],
        device_nodes: [
            "/dev/nvidiactl",
            "/dev/nvidia0",
            "/dev/nvidia-uvm",
            "/dev/dri",
        ]
        .iter()
        .map(|node| path(node))
        .collect(),
    })
    .unwrap()
}

pub(super) fn builtin(workload: WorkloadProfile) -> ConfinementProfile {
    ConfinementProfile::builtin(workload).unwrap()
}

pub(super) fn compiled(profile: &ConfinementProfile) -> GuestPolicy {
    compile(profile, &layout()).unwrap()
}

pub(super) fn tool_name(name: &str) -> ToolName {
    ToolName::new(name).unwrap()
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

/// `document` with `interface` no longer forbidden.
pub(super) fn without(mut document: ProfileDocument, interface: Interface) -> ProfileDocument {
    document
        .forbidden
        .retain(|entry| entry.interface != interface);
    document
}

/// The strict profile with a `perf` tool and a recorded perf_event_open exception.
pub(super) fn strict_with_perf() -> ConfinementProfile {
    let base = builtin(WorkloadProfile::StrictTool);
    let mut document = without(base.document().clone(), Interface::PerfEventOpen);
    document
        .required_tools
        .push(tool_needing("perf", &[Interface::PerfEventOpen]));
    document.exceptions.push(exception(
        ExceptionTarget::Interface {
            interface: Interface::PerfEventOpen,
        },
        "perf",
    ));
    ConfinementProfile::new(document).unwrap()
}

/// The developer profile with a `ping` tool and a recorded CAP_NET_RAW exception.
pub(super) fn developer_with_net_raw() -> ConfinementProfile {
    let mut document = builtin(WorkloadProfile::Developer).document().clone();
    document.capabilities.push(LinuxCapability::NetRaw);
    document.required_tools.push(RequiredTool {
        name: tool_name("ping"),
        interfaces: Vec::new(),
        capabilities: vec![LinuxCapability::NetRaw],
    });
    document.exceptions.push(exception(
        ExceptionTarget::Capability {
            capability: LinuxCapability::NetRaw,
        },
        "ping",
    ));
    ConfinementProfile::new(document).unwrap()
}

/// The service profile with a `gdb` tool and a recorded ptrace exception; ptrace of
/// other users' processes goes to the LSM.
pub(super) fn service_with_gdb() -> ConfinementProfile {
    let base = builtin(WorkloadProfile::Service);
    let mut document = without(base.document().clone(), Interface::Ptrace);
    document.forbidden.push(ForbiddenInterface::new(
        Interface::PtraceOtherUsers,
        Mechanism::Lsm,
    ));
    document
        .required_tools
        .push(tool_needing("gdb", &[Interface::Ptrace]));
    document.exceptions.push(exception(
        ExceptionTarget::Interface {
            interface: Interface::Ptrace,
        },
        "gdb",
    ));
    ConfinementProfile::new(document).unwrap()
}

/// The device profile protecting `~/.profile` by the LSM alone.
pub(super) fn device_with_lsm_path() -> ConfinementProfile {
    let mut document = builtin(WorkloadProfile::Device).document().clone();
    document
        .protected_paths
        .push(ProtectedPath::parse("~/.profile").unwrap());
    document.forbidden.push(ForbiddenInterface::new(
        Interface::ProtectedPathWrite,
        Mechanism::Lsm,
    ));
    ConfinementProfile::new(document).unwrap()
}

/// The strict profile with the LSM behind the read-only mount for its protected paths.
pub(super) fn strict_with_lsm_backup() -> ConfinementProfile {
    let base = builtin(WorkloadProfile::StrictTool);
    let mut document = without(base.document().clone(), Interface::ProtectedPathWrite);
    document.forbidden.push(ForbiddenInterface::with_backup(
        Interface::ProtectedPathWrite,
        Mechanism::ReadOnlyMount,
        Mechanism::Lsm,
    ));
    ConfinementProfile::new(document).unwrap()
}

/// [`device_with_lsm_path`] with no_new_privs off.
pub(super) fn device_with_lsm_path_without_no_new_privs() -> ConfinementProfile {
    let mut document = device_with_lsm_path().document().clone();
    document.no_new_privs = false;
    ConfinementProfile::new(document).unwrap()
}

/// The service document with ptrace refused by seccomp alone, which V15 refuses since
/// M07B (`/proc/<pid>/mem` would stay open).
pub(super) fn service_with_seccomp_only_ptrace() -> ProfileDocument {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    for entry in &mut document.forbidden {
        if entry.interface == Interface::Ptrace {
            entry.backup = None;
        }
    }
    document
}

/// The service profile with ptrace refused by the LSM alone: Yama refuses ptrace(2),
/// process_vm_readv(2), process_vm_writev(2), pidfd_getfd(2) and `/proc/<pid>/mem`.
pub(super) fn service_with_lsm_only_ptrace() -> ConfinementProfile {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    for entry in &mut document.forbidden {
        if entry.interface == Interface::Ptrace {
            entry.primary = Mechanism::Lsm;
            entry.backup = None;
        }
    }
    ConfinementProfile::new(document).unwrap()
}

/// The service profile with ptrace of other users' processes also handed to the LSM, so
/// both ptrace rules land on Yama's admin-only scope.
pub(super) fn service_with_both_ptrace_rules() -> ConfinementProfile {
    let mut document = builtin(WorkloadProfile::Service).document().clone();
    document.forbidden.push(ForbiddenInterface::new(
        Interface::PtraceOtherUsers,
        Mechanism::Lsm,
    ));
    ConfinementProfile::new(document).unwrap()
}

/// `workload`'s built-in profile with an `fio` tool and a recorded io_uring exception,
/// which V15 admits for every workload but the strict one.
pub(super) fn io_uring_excepted(workload: WorkloadProfile) -> ConfinementProfile {
    let mut document = without(builtin(workload).document().clone(), Interface::IoUring);
    document
        .required_tools
        .push(tool_needing("fio", &[Interface::IoUring]));
    document.exceptions.push(exception(
        ExceptionTarget::Interface {
            interface: Interface::IoUring,
        },
        "fio",
    ));
    ConfinementProfile::new(document).unwrap()
}

/// Every built-in profile and every variant above that compiles against [`layout`].
pub(super) fn profiles() -> Vec<ConfinementProfile> {
    let mut profiles: Vec<ConfinementProfile> =
        WorkloadProfile::ALL.into_iter().map(builtin).collect();
    profiles.extend([
        strict_with_perf(),
        developer_with_net_raw(),
        service_with_gdb(),
        device_with_lsm_path(),
        device_with_lsm_path_without_no_new_privs(),
        service_with_lsm_only_ptrace(),
        service_with_both_ptrace_rules(),
    ]);
    profiles
}

/// `body` sealed again, as JSON: what someone who edits and re-seals a policy writes.
pub(super) fn resealed(body: GuestPolicyBody) -> String {
    GuestPolicy::seal(body).unwrap().to_json().unwrap()
}

/// `text` with insignificant JSON whitespace removed and nothing re-escaped, as Go's
/// `json.Compact` does.
pub(super) fn compact(text: &str) -> String {
    let mut out = String::new();
    let (mut in_string, mut escaped) = (false, false);
    for character in text.chars() {
        if in_string {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
            out.push(character);
        } else if !character.is_ascii_whitespace() {
            out.push(character);
        }
    }
    out
}

/// The policy as a JSON value.
pub(super) fn json(policy: &GuestPolicy) -> serde_json::Value {
    serde_json::from_str(&policy.to_json().unwrap()).unwrap()
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
