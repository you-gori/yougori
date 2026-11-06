//! Tests of the Windows `QemuHost` that start no VM (M02, M04): the mapping of a plan's
//! Windows restrictions onto the restricted start, the mapping of the host's read-back
//! into the observed state (an unexpected handle and an unknown SID included), the
//! classification of QEMU's recorded standard error, the private directory's security
//! descriptor, and the starts refused before QEMU runs. The directory tests create and
//! remove directories under this run's temporary directory; one test creates a sandbox
//! desktop for a program that does not exist. No network, no VM, no host setting.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::*;
use crate::foundation::ids::{digest, ExecutionId};
use crate::foundation::process::{
    AdministratorsState, JobSettings, LoweredIntegrity, ObservedGroup, ObservedJobLimits,
    RestrictionReadback, StartMitigation,
};
use crate::sandbox::backend::{BackendKind, HostObserved, Persistence};
use crate::sandbox::qemu::{
    check_windows, plan_launch, GuestResources, HandleKind, InheritedHandles, JobLimit, JobLimits,
    KernelArguments, Mitigation, PathStyle, PrivateDirectory, QemuLaunchInputs, QemuPlatform,
    RestrictingSid, TokenRestrictions, UiRestriction, WindowsFinding, WindowsObservedState,
    CHANGE_NOTIFY_PRIVILEGE, LOW_INTEGRITY_RID, MIB_BYTES,
};
use crate::sandbox::qemu_host::bootstrap::{decode_bootstrap, encode_bootstrap};
use crate::sandbox::qemu_host::host_map::{
    classify_early_exit, exit_text, inherited_handles, job_settings, observed_state,
    restricting_group, restricting_groups, standard_handles, start_mitigations, start_restrictions,
    ui_restrictions, MappingRefusal, ObservationError, StandardStream, MAX_FAILURE_TEXT_BYTES,
    MAX_REPORTED_EXTRA_HANDLES,
};
use crate::sandbox::qemu_host::private_dir::{
    bootstrap_sddl, create_private_directory, directory_sddl, read_sddl, remove_private_directory,
    restrict_bootstrap_file, DirectoryError, HostSids, STDERR_LOG_NAME,
};

pub(super) use super::super::launch_fixture::{
    configuration, launch, Launch, LaunchValues, GIB, MINUTE,
};

pub(super) fn windows_path(path: &str) -> HostPath {
    HostPath::new(PathStyle::Windows, path.replace('/', "\\")).unwrap()
}

/// A fresh path under this run's temporary directory, named for the test's line.
fn scratch(line: u32) -> PathBuf {
    let base = std::env::temp_dir();
    let name = format!("yg-q1-{}-{line}", std::process::id());
    PathBuf::from(base.to_str().unwrap().replace('/', "\\")).join(name)
}

/// Windows inputs whose boot files are never opened: the tests here start no VM.
fn windows_inputs(control: &Path) -> QemuLaunchInputs {
    QemuLaunchInputs {
        platform: QemuPlatform {
            os: OsKind::Windows,
            architecture: Architecture::X86_64,
        },
        resources: GuestResources::new(1, 256 * MIB_BYTES).unwrap(),
        firmware_directory: windows_path(r"C:\q1-absent\share"),
        kernel: windows_path(r"C:\q1-absent\vmlinuz"),
        initrd: None,
        kernel_arguments: KernelArguments::parse("panic=-1 quiet").unwrap(),
        root_image: windows_path(r"C:\q1-absent\root.img"),
        volumes: BTreeMap::new(),
        control: PrivateDirectory::new(windows_path(control.to_str().unwrap())).unwrap(),
        vsock_cid: None,
        egress_endpoints: Vec::new(),
        workload_image: None,
    }
}

fn windows_launch(persistence: Persistence) -> Launch {
    launch(LaunchValues {
        os: OsKind::Windows,
        execution: "exe-q1-unit",
        guest_image: digest("yougori/q1/image/v1", &[b"unit"]),
        artifact: digest("yougori/q1/backend/v1", &[b"unit"]),
        version: "11.1.0",
        reserved_ram_bytes: GIB,
        persistence,
    })
}

fn windows_plan(control: &Path) -> QemuLaunchPlan {
    let launch = windows_launch(Persistence::EphemeralTask);
    plan_launch(
        &launch.request,
        &launch.backend,
        &launch.registry,
        &launch.ledger,
        windows_inputs(control),
    )
    .unwrap()
}

fn vm_role() -> ProcessRole {
    let launch = windows_launch(Persistence::EphemeralTask);
    ProcessRole::VmHost {
        execution: launch.request.execution.clone(),
        vm: crate::sandbox::backend::vm_handle(
            BackendKind::Qemu,
            &launch.request.execution,
            launch.request.generations.boot,
        ),
        boot: launch.request.generations.boot,
    }
}

fn host() -> WindowsQemuHost {
    WindowsQemuHost::new(WindowsHostSettings::standard().unwrap())
}

/// A read-back of a process confined exactly as `start` asks.
fn confined_readback(start: &crate::sandbox::qemu_host::StartRestrictions) -> RestrictionReadback {
    RestrictionReadback {
        token_restricted: true,
        restricting: start
            .restricting
            .iter()
            .map(|group| match group {
                RestrictingGroup::Users => ObservedGroup::Users,
                RestrictingGroup::Everyone => ObservedGroup::Everyone,
                RestrictingGroup::Restricted => ObservedGroup::Restricted,
                RestrictingGroup::LogonSession => ObservedGroup::LogonSession,
                RestrictingGroup::AuthenticatedUsers => ObservedGroup::AuthenticatedUsers,
            })
            .collect(),
        privileges: [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect(),
        administrators: AdministratorsState::DenyOnly,
        integrity_rid: start.integrity.rid(),
        in_job: true,
        job: ObservedJobLimits {
            kill_on_close: true,
            die_on_unhandled_exception: start.job.die_on_unhandled_exception,
            breakaway_ok: false,
            silent_breakaway_ok: false,
            active_process_limit: start.job.active_process_limit,
            job_memory_limit_bytes: start.job.job_memory_limit_bytes,
            ui_restrictions: 0xFF,
        },
        mitigations: start.mitigations.clone(),
        command_line: vec![r"C:\q1\qemu-system-x86_64.exe".to_owned()],
    }
}

fn logged_start(handles_at_start: u32) -> StartObservation {
    StartObservation {
        handles_at_start,
        listed_handles: 2,
        stderr_logged: true,
    }
}

/// The comparator's verdict on `state` against `plan`'s restrictions, observed now.
fn judged(plan: &QemuLaunchPlan, state: WindowsObservedState) -> Vec<WindowsFinding> {
    let launch = windows_launch(Persistence::EphemeralTask);
    let now = launch.registry.now();
    let observed = HostObserved::stamp(state, now, MINUTE, configuration());
    check_windows(
        plan.windows().unwrap(),
        &observed,
        now,
        MINUTE,
        configuration(),
    )
    .unwrap()
    .findings()
    .to_vec()
}

// ---- The restriction mapping ----

#[test]
fn the_profile_restrictions_map_one_to_one_onto_the_restricted_start() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let mapped =
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()).unwrap();
    assert_eq!(
        mapped.restricting,
        [
            RestrictingGroup::Users,
            RestrictingGroup::Everyone,
            RestrictingGroup::Restricted,
            RestrictingGroup::LogonSession,
            RestrictingGroup::AuthenticatedUsers
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(mapped.integrity, LoweredIntegrity::Low);
    assert_eq!(
        mapped.job,
        JobSettings {
            active_process_limit: 1,
            job_memory_limit_bytes: plan.reserved_ram_bytes(),
            die_on_unhandled_exception: true,
            ui_restrictions: true,
        }
    );
    assert_eq!(mapped.job.job_memory_limit_bytes, GIB);
    assert_eq!(
        mapped.mitigations,
        StartMitigation::ALL.into_iter().collect()
    );
    assert!(mapped.stderr_logged);
    // Fewer mitigations map to fewer creation policies, never more.
    let fewer = plan
        .windows()
        .unwrap()
        .clone()
        .with_mitigations([Mitigation::StrictHandleChecks].into_iter().collect())
        .unwrap();
    assert_eq!(
        start_restrictions(&fewer, plan.profile().control().path())
            .unwrap()
            .mitigations,
        [StartMitigation::StrictHandleChecks].into_iter().collect()
    );
}

#[test]
fn what_the_restricted_start_cannot_apply_is_refused_by_name() {
    assert_eq!(
        restricting_group(RestrictingSid::Everyone),
        Ok(RestrictingGroup::Everyone)
    );
    let token = |privileges: &[&str], sids: &[RestrictingSid]| TokenRestrictions {
        retained_privileges: privileges.iter().map(|name| (*name).to_owned()).collect(),
        administrators_deny_only: true,
        restricting_sids: sids.iter().copied().collect(),
    };
    let more = token(
        &[CHANGE_NOTIFY_PRIVILEGE, "SeDebugPrivilege"],
        &[RestrictingSid::Restricted],
    );
    assert!(matches!(
        restricting_groups(&more),
        Err(MappingRefusal::Privileges { .. })
    ));
    assert!(matches!(
        restricting_groups(&token(&[], &[RestrictingSid::Restricted])),
        Err(MappingRefusal::Privileges { .. })
    ));
    assert_eq!(
        restricting_groups(&token(&[CHANGE_NOTIFY_PRIVILEGE], &[])),
        Err(MappingRefusal::NoRestrictingSid)
    );
    assert_eq!(
        restricting_groups(&token(
            &[CHANGE_NOTIFY_PRIVILEGE],
            &[RestrictingSid::Users, RestrictingSid::Everyone]
        )),
        Ok([RestrictingGroup::Users, RestrictingGroup::Everyone]
            .into_iter()
            .collect())
    );

    let limits = |extra: &[JobLimit], active: u32, memory: u64, ui: &[UiRestriction]| JobLimits {
        limits: JobLimit::required()
            .into_iter()
            .chain(extra.iter().copied())
            .collect(),
        active_process_limit: active,
        job_memory_limit_bytes: memory,
        ui_restrictions: ui.iter().copied().collect(),
    };
    for breakaway in [JobLimit::BreakawayOk, JobLimit::SilentBreakawayOk] {
        assert_eq!(
            job_settings(&limits(&[breakaway], 1, GIB, &UiRestriction::ALL)),
            Err(MappingRefusal::Breakaway { limit: breakaway })
        );
    }
    assert_eq!(
        job_settings(&limits(&[], 0, GIB, &UiRestriction::ALL)),
        Err(MappingRefusal::ZeroLimit {
            limit: JobLimit::ActiveProcess
        })
    );
    assert_eq!(
        job_settings(&limits(&[], 1, 0, &UiRestriction::ALL)),
        Err(MappingRefusal::ZeroLimit {
            limit: JobLimit::JobMemory
        })
    );
    // One UI restriction asked sets every one: stricter, not wider.
    let one = job_settings(&limits(&[], 1, GIB, &[UiRestriction::ReadClipboard])).unwrap();
    assert!(one.ui_restrictions);
    let mut without_die = limits(&[], 1, GIB, &[]);
    without_die
        .limits
        .remove(&JobLimit::DieOnUnhandledException);
    let settings = job_settings(&without_die).unwrap();
    assert!(!settings.die_on_unhandled_exception);
    assert!(!settings.ui_restrictions);

    let handles = |stdin, stdout, stderr| InheritedHandles {
        stdin,
        stdout,
        stderr,
    };
    assert_eq!(standard_handles(InheritedHandles::STANDARD), Ok(true));
    assert_eq!(
        standard_handles(handles(
            HandleKind::NullDevice,
            HandleKind::NullDevice,
            HandleKind::NullDevice
        )),
        Ok(false)
    );
    assert_eq!(
        standard_handles(handles(
            HandleKind::File,
            HandleKind::NullDevice,
            HandleKind::LogFile
        )),
        Err(MappingRefusal::StandardHandle {
            stream: StandardStream::Input,
            kind: HandleKind::File
        })
    );
    assert_eq!(
        standard_handles(handles(
            HandleKind::NullDevice,
            HandleKind::NullDevice,
            HandleKind::Pipe
        )),
        Err(MappingRefusal::StandardHandle {
            stream: StandardStream::Error,
            kind: HandleKind::Pipe
        })
    );
    assert_eq!(
        start_mitigations(&[Mitigation::MicrosoftSignedOnly].into_iter().collect()),
        Err(MappingRefusal::Mitigation {
            mitigation: Mitigation::MicrosoftSignedOnly
        })
    );
    for refusal in [
        MappingRefusal::NoRestrictingSid,
        MappingRefusal::ZeroLimit {
            limit: JobLimit::JobMemory,
        },
    ] {
        assert!(!refusal.to_string().is_empty());
    }
}

#[test]
fn a_data_volume_that_would_need_a_low_label_is_refused() {
    let control = scratch(line!());
    let volume = digest("yougori/q1/volume/v1", &[b"data"]);
    let launch = windows_launch(Persistence::DeclaredDataVolumes {
        volumes: [volume].into_iter().collect(),
    });
    let mut inputs = windows_inputs(&control);
    inputs
        .volumes
        .insert(volume, windows_path(r"C:\q1-absent\data.img"));
    let plan = plan_launch(
        &launch.request,
        &launch.backend,
        &launch.registry,
        &launch.ledger,
        inputs,
    )
    .unwrap();
    assert_eq!(
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()),
        Err(MappingRefusal::WritablePath {
            path: windows_path(r"C:\q1-absent\data.img")
        })
    );
}

// ---- The observation mapping ----

#[test]
fn a_readback_of_the_planned_confinement_passes_the_windows_check() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let mapped =
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()).unwrap();
    let state = observed_state(&confined_readback(&mapped), &logged_start(2)).unwrap();
    assert_eq!(state.integrity_rid, LOW_INTEGRITY_RID);
    assert_eq!(
        state.inherited_handles,
        vec![
            HandleKind::NullDevice,
            HandleKind::NullDevice,
            HandleKind::LogFile
        ]
    );
    assert_eq!(state.job.as_ref().unwrap().ui_restrictions.len(), 8);
    assert_eq!(judged(&plan, state), Vec::new());
    // A suspended process holding fewer handles than listed is not a finding.
    let fewer = observed_state(&confined_readback(&mapped), &logged_start(0)).unwrap();
    assert_eq!(fewer.inherited_handles.len(), 3);
}

#[test]
fn a_handle_beyond_the_list_is_reported_as_an_unexpected_other_handle() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let mapped =
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()).unwrap();
    let state = observed_state(&confined_readback(&mapped), &logged_start(3)).unwrap();
    assert_eq!(state.inherited_handles.last(), Some(&HandleKind::Other));
    assert_eq!(
        judged(&plan, state),
        vec![WindowsFinding::UnexpectedInheritedHandle {
            kind: HandleKind::Other
        }]
    );
    let flood = inherited_handles(&logged_start(u32::MAX));
    assert_eq!(
        flood.len(),
        3 + usize::try_from(MAX_REPORTED_EXTRA_HANDLES).unwrap()
    );
    // Without a log, standard error is the NUL device in the list.
    let unlogged = inherited_handles(&StartObservation {
        handles_at_start: 1,
        listed_handles: 1,
        stderr_logged: false,
    });
    assert_eq!(unlogged, vec![HandleKind::NullDevice; 3]);
}

#[test]
fn an_unknown_restricting_sid_is_an_observation_failure_never_dropped() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let mapped =
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()).unwrap();
    let mut readback = confined_readback(&mapped);
    readback.restricting.insert(ObservedGroup::Other {
        sid: "S-1-5-21-1-2-3-500".to_owned(),
    });
    let refused = observed_state(&readback, &logged_start(2));
    assert_eq!(
        refused,
        Err(ObservationError::UnknownRestrictingSid {
            sid: "S-1-5-21-1-2-3-500".to_owned()
        })
    );
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("S-1-5-21-1-2-3-500"));
    // Everyone is known and part of the plan's set (USER32's initialization needs it).
    let with_everyone = confined_readback(&mapped);
    assert!(with_everyone.restricting.contains(&ObservedGroup::Everyone));
    let state = observed_state(&with_everyone, &logged_start(2)).unwrap();
    assert_eq!(judged(&plan, state), Vec::<WindowsFinding>::new());
}

#[test]
fn the_job_reads_back_as_queried() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let mapped =
        start_restrictions(plan.windows().unwrap(), plan.profile().control().path()).unwrap();
    let mut outside = confined_readback(&mapped);
    outside.in_job = false;
    let state = observed_state(&outside, &logged_start(2)).unwrap();
    assert_eq!(state.job, None);
    assert_eq!(judged(&plan, state), vec![WindowsFinding::NotInJob]);

    let mut loose = confined_readback(&mapped);
    loose.job.breakaway_ok = true;
    loose.job.ui_restrictions = 0x02;
    loose.administrators = AdministratorsState::Enabled;
    let state = observed_state(&loose, &logged_start(2)).unwrap();
    let job = state.job.clone().unwrap();
    assert!(job.limits.contains(&JobLimit::BreakawayOk));
    assert_eq!(
        job.ui_restrictions,
        [UiRestriction::ReadClipboard].into_iter().collect()
    );
    let findings = judged(&plan, state);
    assert!(findings.contains(&WindowsFinding::BreakawayAllowed {
        limit: JobLimit::BreakawayOk
    }));
    assert!(findings.contains(&WindowsFinding::AdministratorsEnabled));
    assert_eq!(ui_restrictions(0xFF).len(), 8);
    assert_eq!(ui_restrictions(0), BTreeSet::new());
}

// ---- The classification of QEMU's report ----

/// QEMU 11.1.0's standard error when WHPX refuses `kernel-irqchip=split` (the property
/// setter's own error, the string in the pinned build), after the deprecation warning the
/// profile's `-mon` brings.
const SPLIT_IRQCHIP_STDERR: &str = "qemu-system-x86_64.exe: -mon chardev=qmp,mode=control: warning: -mon is deprecated, use -object with monitor-hmp or monitor-qmp\r\n\
qemu-system-x86_64.exe: -accel whpx,kernel-irqchip=split: WHPX: split irqchip currently not supported\r\n";

/// The pinned build's report when no hypervisor platform is present.
const NO_ACCELERATOR_STDERR: &str =
    "qemu-system-x86_64.exe: WHPX: No accelerator found, hr=80070005\nqemu-system-x86_64.exe: failed to initialize whpx: Operation not permitted\n";

/// A kernel that cannot be read.
const MISSING_KERNEL_STDERR: &str =
    "qemu-system-x86_64.exe: could not load kernel 'D:\\absent\\vmlinuz': No such file or directory\r\n";

/// The warnings a booting QEMU writes (R2's run): neither is a failure.
const WARNINGS_STDERR: &str = "qemu-system-x86_64.exe: -mon chardev=qmp,mode=control: warning: -mon is deprecated, use -object with monitor-hmp or monitor-qmp\n\
qemu-system-x86_64.exe: warning: host doesn't support requested feature: CPUID[eax=80000001h].ECX.svm [bit 2]\n";

#[test]
fn a_whpx_report_is_a_hardware_virtualization_failure_with_qemus_own_text() {
    match classify_early_exit(1, SPLIT_IRQCHIP_STDERR) {
        StartFailure::HardwareVirtualization { detail } => {
            assert_eq!(
                detail,
                "qemu-system-x86_64.exe: -accel whpx,kernel-irqchip=split: WHPX: split irqchip \
                 currently not supported"
            );
        }
        other => panic!("{other:?}"),
    }
    match classify_early_exit(1, NO_ACCELERATOR_STDERR) {
        StartFailure::HardwareVirtualization { detail } => {
            assert!(detail.contains("WHPX: No accelerator found"), "{detail}");
            assert!(detail.contains("failed to initialize whpx"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    // The text is bounded and has no control characters.
    let long = format!("WHPX: {}\u{7}", "x".repeat(4000));
    match classify_early_exit(1, &long) {
        StartFailure::HardwareVirtualization { detail } => {
            assert!(detail.len() <= MAX_FAILURE_TEXT_BYTES + 3);
            assert!(!detail.chars().any(char::is_control));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn any_other_early_exit_is_a_process_failure_with_the_text_and_code() {
    let detail = |failure: StartFailure| match failure {
        StartFailure::Process {
            error: ProcessError::Spawn { detail },
        } => detail,
        other => panic!("{other:?}"),
    };
    let missing = detail(classify_early_exit(1, MISSING_KERNEL_STDERR));
    assert!(missing.contains("code 1"), "{missing}");
    assert!(missing.contains("could not load kernel"), "{missing}");
    let warnings = detail(classify_early_exit(1, WARNINGS_STDERR));
    assert!(warnings.contains("svm"), "{warnings}");
    let silent = detail(classify_early_exit(0xC000_0142, ""));
    assert!(
        silent.contains("0xc0000142 (STATUS_DLL_INIT_FAILED)"),
        "{silent}"
    );
    assert!(silent.contains("wrote nothing"), "{silent}");
    // The option location naming whpx does not make an unrelated error a WHPX one.
    let option = detail(classify_early_exit(
        1,
        "qemu-system-x86_64.exe: -accel whpx,kernel-irqchip=off: Parameter 'x' is missing",
    ));
    assert!(option.contains("Parameter 'x'"), "{option}");
    assert_eq!(exit_text(1), "1");
    assert_eq!(
        exit_text(0xC000_0005),
        "0xc0000005 (STATUS_ACCESS_VIOLATION)"
    );
    assert_eq!(exit_text(0xC000_00FF), "0xc00000ff");
}

// ---- The private directory ----

#[test]
fn host_sids_are_validated_before_they_reach_a_security_descriptor() {
    let sids = HostSids::current().unwrap();
    assert!(sids.user().starts_with("S-1-5-"), "{}", sids.user());
    assert!(sids.logon().as_str().starts_with("S-1-5-5-"));
    assert!(HostSids::new("S-1-5-21-1-2-3-1001".to_owned(), "S-1-5-5-0-1").is_ok());
    for (user, logon) in [
        ("S-1-5-21-1)(A;;FA;;;WD", "S-1-5-5-0-1"),
        ("S-1-", "S-1-5-5-0-1"),
        ("WD", "S-1-5-5-0-1"),
        ("S-1-5-21-1", "S-1-5-5-0-1)(A;;FA;;;WD"),
        ("S-1-5-21-1", "S-1-5-32-545"),
    ] {
        assert!(
            HostSids::new(user.to_owned(), logon).is_err(),
            "{user} {logon} accepted"
        );
    }
}

/// The ACEs of an SDDL string.
fn aces(sddl: &str) -> Vec<String> {
    sddl.split('(')
        .skip(1)
        .map(|ace| {
            ace.trim_end_matches(')')
                .split(')')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn the_private_directory_is_created_new_with_exactly_its_grants_and_a_low_label() {
    let sids = HostSids::current().unwrap();
    let path = scratch(line!());
    create_private_directory(&path, &sids).unwrap();
    let sddl = read_sddl(&path).unwrap();
    eprintln!("private directory: {sddl}");
    assert!(sddl.starts_with("D:P"), "{sddl}");
    assert_eq!(
        aces(&sddl),
        vec![
            format!("A;OICI;FA;;;{}", sids.user()),
            format!("A;;0x100022;;;{}", sids.logon()),
            "ML;;NW;;;LW".to_owned(),
        ],
        "{sddl}"
    );
    assert_eq!(
        directory_sddl(&sids).len(),
        directory_sddl(&sids).trim().len()
    );
    // A second creation is refused, and the first is left as it is.
    std::fs::write(path.join("marker"), b"kept").unwrap();
    assert!(matches!(
        create_private_directory(&path, &sids),
        Err(DirectoryError::Exists { .. })
    ));
    assert_eq!(std::fs::read(path.join("marker")).unwrap(), b"kept");
    remove_private_directory(&path).unwrap();
    assert!(!path.exists());
    // A path that does not exist is already removed.
    remove_private_directory(&path).unwrap();
}

#[test]
fn only_the_bootstrap_file_grants_the_logon_session_read() {
    let sids = HostSids::current().unwrap();
    let path = scratch(line!());
    create_private_directory(&path, &sids).unwrap();
    let role = vm_role();
    let (file, _secret) = encode_bootstrap(&role).unwrap();
    let bootstrap = write_bootstrap_file(&path, file).unwrap();
    restrict_bootstrap_file(&bootstrap, &sids).unwrap();
    let sddl = read_sddl(&bootstrap).unwrap();
    eprintln!("bootstrap file: {sddl}; asked {}", bootstrap_sddl(&sids));
    assert!(sddl.starts_with("D:P"), "{sddl}");
    let found = aces(&sddl);
    assert_eq!(found.len(), 2, "{sddl}");
    assert_eq!(found[0], format!("A;;FA;;;{}", sids.user()));
    assert!(
        found[1] == format!("A;;FR;;;{}", sids.logon())
            || found[1] == format!("A;;0x120089;;;{}", sids.logon()),
        "{sddl}"
    );
    let decoded = decode_bootstrap(&std::fs::read(&bootstrap).unwrap()).unwrap();
    let ProcessRole::VmHost { vm, boot, .. } = role else {
        unreachable!()
    };
    assert_eq!((decoded.vm, decoded.boot), (vm, boot));
    // The log takes only the user's inherited entry and no label of its own (the entry
    // reads back with or without the inherited flag, by the volume's inheritance rules).
    std::fs::File::create_new(path.join(STDERR_LOG_NAME)).unwrap();
    let log = read_sddl(&path.join(STDERR_LOG_NAME)).unwrap();
    let log_aces = aces(&log);
    assert_eq!(log_aces.len(), 1, "{log}");
    assert!(
        log_aces[0] == format!("A;ID;FA;;;{}", sids.user())
            || log_aces[0] == format!("A;;FA;;;{}", sids.user()),
        "{log}"
    );
    assert!(!log.contains(sids.logon().as_str()), "{log}");
    assert!(!log.contains("S:"), "{log}");
    remove_private_directory(&path).unwrap();
    assert!(!path.exists());
}

// ---- Starts refused before QEMU runs ----

#[test]
fn a_start_for_another_role_or_without_windows_restrictions_creates_nothing() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let executable = windows_path(r"C:\q1-absent\qemu-system-x86_64.exe");
    let mut host = host();
    let relay = ProcessRole::GuestRelay {
        execution: ExecutionId::new("exe-q1-unit").unwrap(),
    };
    assert!(matches!(
        host.start(&relay, &executable, &plan),
        Err(StartFailure::Prepare { .. })
    ));
    assert!(!control.exists());

    let linux = launch(LaunchValues {
        os: OsKind::Linux,
        execution: "exe-q1-linux",
        guest_image: digest("yougori/q1/image/v1", &[b"unit"]),
        artifact: digest("yougori/q1/backend/v1", &[b"unit"]),
        version: "11.1.0",
        reserved_ram_bytes: GIB,
        persistence: Persistence::EphemeralTask,
    });
    let unix = |path: &str| HostPath::new(PathStyle::Unix, path).unwrap();
    let linux_plan = plan_launch(
        &linux.request,
        &linux.backend,
        &linux.registry,
        &linux.ledger,
        QemuLaunchInputs {
            platform: QemuPlatform {
                os: OsKind::Linux,
                architecture: Architecture::X86_64,
            },
            resources: GuestResources::new(1, 256 * MIB_BYTES).unwrap(),
            firmware_directory: unix("/opt/q1/share"),
            kernel: unix("/opt/q1/vmlinuz"),
            initrd: None,
            kernel_arguments: KernelArguments::parse("quiet").unwrap(),
            root_image: unix("/opt/q1/root.img"),
            volumes: BTreeMap::new(),
            control: PrivateDirectory::new(unix("/run/q1/a")).unwrap(),
            vsock_cid: None,
            egress_endpoints: Vec::new(),
            workload_image: None,
        },
    )
    .unwrap();
    assert!(linux_plan.windows().is_none());
    match host.start(&vm_role(), &executable, &linux_plan) {
        Err(StartFailure::Prepare { detail }) => {
            assert!(detail.contains("no Windows restrictions"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    assert!(host.held().is_empty());
    assert!(host.cleanup_failures().is_empty());
}

#[test]
fn an_existing_private_directory_is_refused_and_left_untouched() {
    let control = scratch(line!());
    std::fs::create_dir_all(&control).unwrap();
    std::fs::write(control.join("marker"), b"not the host's").unwrap();
    let plan = windows_plan(&control);
    let mut host = host();
    match host.start(
        &vm_role(),
        &windows_path(r"C:\q1-absent\qemu-system-x86_64.exe"),
        &plan,
    ) {
        Err(StartFailure::Prepare { detail }) => {
            assert!(detail.contains("already exists"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        std::fs::read(control.join("marker")).unwrap(),
        b"not the host's"
    );
    assert!(host.held().is_empty());
    std::fs::remove_dir_all(&control).unwrap();
}

#[test]
fn a_program_that_cannot_start_leaves_no_directory_behind() {
    let control = scratch(line!());
    let plan = windows_plan(&control);
    let absent = scratch(line!()).join("qemu-system-x86_64.exe");
    let mut host = host();
    match host.start(&vm_role(), &windows_path(absent.to_str().unwrap()), &plan) {
        Err(StartFailure::Process { error }) => assert!(
            error
                .to_string()
                .contains("could not create the restricted process"),
            "{error}"
        ),
        other => panic!("{other:?}"),
    }
    assert!(!control.exists());
    assert!(host.held().is_empty());
    assert!(host.cleanup_failures().is_empty());
}

#[test]
fn a_process_the_host_does_not_hold_is_not_observed_and_has_no_proof() {
    let mut host = host();
    let stranger = ProcessIdentity {
        pid: 4,
        start_time_ticks: 1,
    };
    assert_eq!(
        host.state(&stranger),
        Err(ObserveFailure::NotHeld { process: stranger })
    );
    assert_eq!(
        host.inspect(&stranger),
        Err(ObserveFailure::NotHeld { process: stranger })
    );
    assert_eq!(host.terminate(&stranger), Err(NoProof::StillRunning));
    assert!(host.take_secret(&stranger).is_none());
    assert!(host.desktop_of(&stranger).is_none());
}

/// PROVES the host build is the OS's build number, spelled as `BuildId` and the host
/// evidence inventory spell it (`26300`, not `10.0.26300`), so the doctor can read the
/// launch records it is stamped on.
#[test]
fn the_host_build_comes_from_the_os() {
    let build = host().host_build().unwrap();
    eprintln!("host build: {build:?}");
    assert_eq!(build.os, OsKind::Windows);
    let text = build.build.as_str();
    assert!(
        !text.contains('.') && text.parse::<u32>().is_ok_and(|number| number >= 10_240),
        "{text}"
    );
    assert_eq!(build.architecture, Architecture::X86_64);
}
