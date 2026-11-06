//! Plan-level tests: building from a launch request, every refusal, and the rules that
//! join the API plan, the jailer plan, the launcher and the expected state.

use std::collections::BTreeSet;

use super::fixtures::{self, Scenario};
use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::{HypervisorKind, OsKind};
use crate::foundation::ids::{digest, GpuDeviceKey};
use crate::foundation::ledger::{Amounts, ReservationState};
use crate::sandbox::backend::{
    BackendKind, Feature, NetworkAuthority, NetworkChannel, OperatorConfidentiality, Persistence,
};
use crate::sandbox::trust::{
    BootMethod, ComponentKind, ComponentVersion, DeviceModel, PinRefusal, SandboxBackend,
};

fn refusal(scenario: &Scenario) -> PlanRefusal {
    scenario.build().unwrap_err()
}

#[test]
fn a_plan_is_deterministic_and_names_firecracker_on_kvm() {
    let plan = fixtures::plan();
    let again = fixtures::plan();
    assert_eq!(plan, again);
    assert_eq!(plan.api().canonical_json(), again.api().canonical_json());
    assert_eq!(plan.api().digest(), again.api().digest());
    assert_eq!(plan.jailer().argv(), again.jailer().argv());
    let backend = plan.backend();
    assert_eq!(backend.kind, BackendKind::Firecracker);
    assert_eq!(backend.hypervisor, HypervisorKind::Kvm);
    assert_eq!(backend.version.as_str(), fixtures::VERSION);
    let configuration = fixtures::configuration();
    assert_eq!(
        backend.artifact,
        *configuration.components[&ComponentKind::Runtime]
            .content_key
            .digest()
    );
    assert_eq!(plan.firecracker_version().as_str(), fixtures::VERSION);
    assert_eq!(plan.profile(), fixtures::profile().identity());
    assert_eq!(plan.jail_id(), plan.jailer().id());
    let json = serde_json::to_value(&plan).unwrap();
    assert_eq!(json["backend"]["kind"], "firecracker");
}

#[test]
fn the_api_plan_follows_the_profile_and_the_fixed_layout() {
    let plan = fixtures::plan();
    let paths: Vec<String> = plan
        .api()
        .calls()
        .iter()
        .map(|call| call.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            "/logger",
            "/metrics",
            "/machine-config",
            "/boot-source",
            "/drives/rootfs",
            "/vsock",
            "/entropy",
            "/actions"
        ]
    );
    let calls = plan.api().calls();
    assert_eq!(calls[2].body["vcpu_count"], 2);
    assert_eq!(calls[2].body["mem_size_mib"], 1024);
    assert_eq!(calls[2].body["smt"], false);
    assert_eq!(calls[4].body["is_read_only"], true);
    assert_eq!(calls[5].body["guest_cid"], GUEST_CID);

    let mut quiet = fixtures::profile();
    quiet.entropy_device = false;
    let plan = Scenario::new(quiet).build().unwrap();
    assert!(plan
        .api()
        .calls()
        .iter()
        .all(|call| call.path != "/entropy"));
}

#[test]
fn logger_metrics_and_link_paths_are_created_by_the_host() {
    let plan = fixtures::plan();
    let host = fixtures::host();
    let chroot = plan.jailer().chroot_dir().unwrap();
    let calls = plan.api().calls();
    let in_jail = |path: &str| chroot.within(&JailPath::new(path).unwrap()).unwrap();
    let sinks: Vec<(SinkKind, HostPath, u32)> = plan
        .launcher()
        .setup()
        .iter()
        .filter_map(|operation| match operation {
            PrivilegedOperation::CreateSink {
                kind,
                path,
                owner_uid,
                ..
            } => Some((*kind, path.clone(), *owner_uid)),
            _ => None,
        })
        .collect();
    let log_path = calls[0].body["log_path"].as_str().unwrap();
    let metrics_path = calls[1].body["metrics_path"].as_str().unwrap();
    assert_eq!(
        sinks,
        [
            (SinkKind::Logger, in_jail(log_path), host.owner.uid),
            (SinkKind::Metrics, in_jail(metrics_path), host.owner.uid),
        ]
    );
    let link = JailPath::new(calls[5].body["uds_path"].as_str().unwrap()).unwrap();
    let socket_directory = in_jail(link.parent().unwrap().as_str());
    assert!(plan.launcher().setup().iter().any(|operation| matches!(
        operation,
        PrivilegedOperation::CreateDirectory { path, .. } if *path == socket_directory
    )));
    assert_eq!(
        plan.jailer().firecracker_args()[1],
        API_SOCKET,
        "the API socket shares the host-created directory"
    );
    assert_eq!(JailPath::new(API_SOCKET).unwrap().parent(), link.parent());
}

#[test]
fn staged_artifacts_are_the_pinned_ones() {
    let plan = fixtures::plan();
    let configuration = fixtures::configuration();
    let staged: Vec<(ArtifactRole, crate::foundation::ids::ContentKey, u64)> = plan
        .launcher()
        .setup()
        .iter()
        .filter_map(|operation| match operation {
            PrivilegedOperation::StageArtifact {
                role,
                content_key,
                length_bytes,
                ..
            } => Some((*role, *content_key, *length_bytes)),
            _ => None,
        })
        .collect();
    let kernel = &configuration.components[&ComponentKind::GuestKernel];
    let image = &configuration.components[&ComponentKind::GuestImage];
    assert_eq!(
        staged,
        [
            (
                ArtifactRole::Kernel,
                kernel.content_key,
                kernel.length_bytes
            ),
            (
                ArtifactRole::RootImage,
                image.content_key,
                image.length_bytes
            ),
        ]
    );
    let PrivilegedOperation::RunJailer {
        jailer_content_key,
        exec_content_key,
        ..
    } = plan.launcher().setup().last().unwrap()
    else {
        panic!("the jailer runs last");
    };
    assert_eq!(
        *jailer_content_key,
        configuration.components[&ComponentKind::Jailer].content_key
    );
    assert_eq!(
        *exec_content_key,
        configuration.components[&ComponentKind::Runtime].content_key
    );
}

#[test]
fn every_privileged_path_lies_inside_what_the_launch_owns() {
    for plan in [fixtures::plan(), fixtures::network_plan()] {
        let jail_dir = plan.jailer().jail_dir().unwrap();
        let netns = plan.jailer().netns().clone();
        let cgroup = format!("/sys/fs/cgroup/{}", plan.jailer().cgroup().unwrap());
        let artifacts = "/var/lib/yougori/artifacts/";
        let owned = |path: &HostPath| {
            let text = path.as_str();
            text.starts_with(&format!("{jail_dir}/")) || *path == netns || text == cgroup
        };
        for operation in plan.launcher().setup() {
            match operation {
                PrivilegedOperation::CreateNetworkNamespace { netns: path }
                | PrivilegedOperation::CreateTapDevice { netns: path, .. }
                | PrivilegedOperation::CreateDirectory { path, .. }
                | PrivilegedOperation::CreateSink { path, .. } => {
                    assert!(owned(path), "{path}")
                }
                PrivilegedOperation::StageArtifact { source, target, .. } => {
                    assert!(source.as_str().starts_with(artifacts), "{source}");
                    assert!(owned(target), "{target}");
                }
                PrivilegedOperation::RunJailer { .. } => {}
                other => panic!("cleanup in setup: {other:?}"),
            }
        }
        for step in plan.launcher().cleanup() {
            match &step.operation {
                PrivilegedOperation::TerminateJail { cgroup: path }
                | PrivilegedOperation::RemoveCgroup { cgroup: path }
                | PrivilegedOperation::RemoveNetworkNamespace { netns: path } => {
                    assert!(owned(path), "{path}")
                }
                PrivilegedOperation::RemoveJail { jail_dir: path } => {
                    assert_eq!(*path, jail_dir)
                }
                other => panic!("setup in cleanup: {other:?}"),
            }
        }
    }
}

#[test]
fn a_new_boot_gets_a_new_jail_namespace_cgroup_and_sockets() {
    let first = Scenario::new(fixtures::profile());
    let mut second = Scenario::new(fixtures::profile());
    second.request.generations = SandboxGenerations {
        boot: SandboxGenerations::FIRST.boot.next().unwrap(),
        ..SandboxGenerations::FIRST
    };
    let first = first.build().unwrap();
    let second = second.build().unwrap();
    assert_ne!(first.jail_id(), second.jail_id());
    assert_ne!(first.jailer().netns(), second.jailer().netns());
    assert_ne!(first.jailer().chroot_dir(), second.jailer().chroot_dir());
    assert_ne!(first.jailer().cgroup(), second.jailer().cgroup());
    assert_eq!(first.api(), second.api());
    let golden = GoldenFile::from_plan(&first);
    assert!(compare_golden(&golden, &GoldenFile::from_plan(&second)).is_match());
    assert!(first
        .api()
        .calls()
        .iter()
        .all(|call| !call.path.starts_with("/snapshot")));
}

#[test]
fn the_host_demand_is_the_cgroup_memory_and_one_slot_per_interface() {
    let plan = fixtures::plan();
    assert_eq!(
        plan.host_demand(),
        &Amounts::new().host_ram_bytes(1088 * MIB_BYTES)
    );
    let network = fixtures::network_plan();
    assert_eq!(
        network.host_demand(),
        &Amounts::new()
            .host_ram_bytes(1088 * MIB_BYTES)
            .network_slots(1)
    );
    assert_eq!(
        plan.expected_state().cgroup_limits[1].value,
        (1088 * MIB_BYTES).to_string()
    );
}

#[test]
fn a_network_interface_needs_a_declaration_and_a_declared_transport() {
    let strict = fixtures::plan();
    assert!(strict
        .api()
        .calls()
        .iter()
        .all(|call| !call.path.starts_with("/network-interfaces")));
    assert!(
        strict
            .host_demand()
            .get(crate::foundation::ledger::ResourceKey::Host(
                crate::foundation::ledger::HostResource::NetworkSlots
            ))
            == 0
    );

    let declared = fixtures::network_plan();
    let calls = declared.api().calls();
    let nic: Vec<_> = calls
        .iter()
        .filter(|call| call.path.starts_with("/network-interfaces"))
        .collect();
    assert_eq!(nic.len(), 1);
    assert_eq!(nic[0].path, "/network-interfaces/eth0");
    assert_eq!(nic[0].body["host_dev_name"], "tap0");

    for (network, allowed) in [
        (NetworkAuthority::offline(), false),
        (
            NetworkAuthority::of([NetworkChannel::TypedCredentialedOperations]),
            false,
        ),
        (
            NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]),
            true,
        ),
        (
            NetworkAuthority::of([NetworkChannel::PublishedService]),
            true,
        ),
    ] {
        let mut scenario = Scenario::new(fixtures::network_profile());
        scenario.request.required.network = network.clone();
        match scenario.build() {
            Ok(_) => assert!(allowed, "{network:?}"),
            Err(refusal) => {
                assert!(!allowed, "{network:?}");
                assert_eq!(
                    refusal,
                    PlanRefusal::NetworkInterfaceNotAuthorized {
                        interfaces: vec![ApiId::new("eth0").unwrap()]
                    }
                );
            }
        }
    }

    let mut undeclared = Scenario::new(fixtures::profile());
    undeclared.request.required.network =
        NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]);
    let plan = undeclared.build().unwrap();
    assert!(plan
        .api()
        .calls()
        .iter()
        .all(|call| !call.path.starts_with("/network-interfaces")));
}

#[test]
fn features_firecracker_cannot_provide_are_refused_by_name() {
    let mut display = Scenario::new(fixtures::profile());
    display.request.device_profile.devices.display = true;
    assert_eq!(
        refusal(&display),
        PlanRefusal::Unsupported {
            feature: Feature::Display
        }
    );

    let mut gpu = Scenario::new(fixtures::profile());
    gpu.request
        .device_profile
        .devices
        .gpus
        .insert(GpuDeviceKey {
            machine: fixtures::machine(),
            device: digest("yougori/test/device/v1", &[b"gpu0"]),
        });
    assert_eq!(
        refusal(&gpu),
        PlanRefusal::Unsupported {
            feature: Feature::GpuAssignment
        }
    );

    let mut confidential = Scenario::new(fixtures::profile());
    confidential.request.required.confidentiality =
        OperatorConfidentiality::VerifiedConfidentialVm {
            scope: digest("yougori/test/scope/v1", &[b"s"]),
        };
    assert_eq!(
        refusal(&confidential),
        PlanRefusal::Unsupported {
            feature: Feature::ConfidentialVm
        }
    );

    for persistence in [
        Persistence::DeclaredDataVolumes {
            volumes: [digest("yougori/test/volume/v1", &[b"v"])]
                .into_iter()
                .collect(),
        },
        Persistence::ControlledServiceRenewal {
            volumes: BTreeSet::new(),
        },
    ] {
        let tag = persistence.tag();
        let mut volumes = Scenario::new(fixtures::profile());
        volumes.request.required.persistence = persistence;
        assert_eq!(
            refusal(&volumes),
            PlanRefusal::PersistenceNotSupported { persistence: tag }
        );
    }
}

#[test]
fn the_request_must_name_this_profile_and_the_pinned_artifacts() {
    let mut other_profile = Scenario::new(fixtures::profile());
    other_profile.request.device_profile = fixtures::network_profile().device_profile();
    assert!(matches!(
        refusal(&other_profile),
        PlanRefusal::DeviceProfileMismatch { .. }
    ));

    let mut changed_profile = Scenario::new(fixtures::profile());
    changed_profile.profile.limits.max_open_descriptors = 4096;
    assert!(matches!(
        refusal(&changed_profile),
        PlanRefusal::DeviceProfileMismatch { .. }
    ));

    let mut backend = Scenario::new(fixtures::profile());
    backend.request.pinned.backend = digest("yougori/test/backend/v1", &[b"other"]);
    assert!(matches!(
        refusal(&backend),
        PlanRefusal::ArtifactMismatch {
            artifact: PinnedArtifact::Backend,
            ..
        }
    ));

    let mut image = Scenario::new(fixtures::profile());
    image.request.pinned.guest_image = digest("yougori/test/image/v1", &[b"other"]);
    assert!(matches!(
        refusal(&image),
        PlanRefusal::ArtifactMismatch {
            artifact: PinnedArtifact::GuestImage,
            ..
        }
    ));
}

#[test]
fn the_pinned_row_must_be_one_firecracker_release_on_linux() {
    let mut qemu = Scenario::new(fixtures::profile());
    qemu.configuration.key.backend = SandboxBackend::QemuSecure;
    assert!(matches!(
        refusal(&qemu),
        PlanRefusal::NotFirecrackerOnLinux { .. }
    ));

    let mut windows = Scenario::new(fixtures::profile());
    windows.configuration.key.os = OsKind::Windows;
    assert!(matches!(
        refusal(&windows),
        PlanRefusal::Pin {
            refusal: PinRefusal::BackendNotOnOs { .. }
        }
    ));

    let mut firmware = Scenario::new(fixtures::profile());
    firmware.configuration.boot = BootMethod::Firmware;
    firmware.configuration.components.insert(
        ComponentKind::Firmware,
        fixtures::component(ComponentKind::Firmware, "1.0", b"firmware"),
    );
    assert!(matches!(
        refusal(&firmware),
        PlanRefusal::FirmwareBoot { .. }
    ));

    let mut no_jailer = Scenario::new(fixtures::profile());
    no_jailer
        .configuration
        .components
        .remove(&ComponentKind::Jailer);
    assert_eq!(
        refusal(&no_jailer),
        PlanRefusal::ComponentMissing {
            component: ComponentKind::Jailer
        }
    );

    let mut no_kernel = Scenario::new(fixtures::profile());
    no_kernel
        .configuration
        .components
        .remove(&ComponentKind::GuestKernel);
    assert!(matches!(
        refusal(&no_kernel),
        PlanRefusal::Pin {
            refusal: PinRefusal::MissingComponent {
                component: ComponentKind::GuestKernel,
                ..
            }
        }
    ));

    let mut mixed = Scenario::new(fixtures::profile());
    mixed.configuration.components.insert(
        ComponentKind::Jailer,
        fixtures::component(ComponentKind::Jailer, "1.9.0", b"jailer binary"),
    );
    assert_eq!(
        refusal(&mixed),
        PlanRefusal::MixedVersions {
            runtime: ComponentVersion::new("1.10.1").unwrap(),
            jailer: ComponentVersion::new("1.9.0").unwrap(),
        }
    );

    let mut unrecordable = Scenario::new(fixtures::profile());
    for kind in [ComponentKind::Runtime, ComponentKind::Jailer] {
        let bytes: &[u8] = if kind == ComponentKind::Runtime {
            b"firecracker binary"
        } else {
            b"jailer binary"
        };
        unrecordable
            .configuration
            .components
            .insert(kind, fixtures::component(kind, "1.10.1:local", bytes));
    }
    assert!(matches!(
        refusal(&unrecordable),
        PlanRefusal::VersionNotRecordable { .. }
    ));
}

#[test]
fn every_needed_device_model_must_be_in_the_pinned_row() {
    let cases = [
        (fixtures::profile(), DeviceModel::VirtioBlk),
        (fixtures::profile(), DeviceModel::VirtioVsock),
        (fixtures::profile(), DeviceModel::VirtioRng),
        (fixtures::network_profile(), DeviceModel::VirtioNet),
    ];
    for (profile, device) in cases {
        let mut scenario = Scenario::new(profile);
        scenario.configuration.devices.remove(&device);
        assert!(matches!(
            refusal(&scenario),
            PlanRefusal::ConfigurationMismatch { .. }
        ));
        scenario.request.configuration = scenario.configuration.fingerprint().unwrap();
        assert_eq!(
            refusal(&scenario),
            PlanRefusal::DeviceModelAbsent { device },
            "{device:?}"
        );
    }
    let mut quiet = fixtures::profile();
    quiet.entropy_device = false;
    let mut scenario = Scenario::new(quiet);
    scenario
        .configuration
        .devices
        .remove(&DeviceModel::VirtioRng);
    scenario
        .configuration
        .devices
        .remove(&DeviceModel::VirtioNet);
    scenario.request.configuration = scenario.configuration.fingerprint().unwrap();
    assert!(scenario.build().is_ok());
}

#[test]
fn profile_host_and_identity_problems_are_refused_first() {
    let mut profile = Scenario::new(fixtures::profile());
    profile.profile.machine.vcpu_count = 0;
    assert_eq!(
        refusal(&profile),
        PlanRefusal::Profile {
            error: ProfileError::VcpuCount { vcpu_count: 0 }
        }
    );

    let mut host = Scenario::new(fixtures::profile());
    host.host.firecracker = HostPath::new("/opt/vm/vmm").unwrap();
    assert!(matches!(
        refusal(&host),
        PlanRefusal::Host {
            error: HostError::ExecFileName { .. }
        }
    ));

    let mut root = Scenario::new(fixtures::profile());
    root.identity = JailIdentity { uid: 0, gid: 0 };
    assert_eq!(
        refusal(&root),
        PlanRefusal::Host {
            error: HostError::UidOutsideRange { uid: 0 }
        }
    );

    let mut owner = Scenario::new(fixtures::profile());
    owner.identity = JailIdentity {
        uid: 64001,
        gid: 1000,
    };
    assert_eq!(
        refusal(&owner),
        PlanRefusal::Host {
            error: HostError::GidOutsideRange { gid: 1000 }
        }
    );
}

#[test]
fn the_reservation_must_be_this_launch_granted_and_large_enough() {
    let mut other = Scenario::new(fixtures::profile());
    let demand = fixtures::demand(&fixtures::profile());
    let foreign = fixtures::reserve(
        &mut other.ledger,
        crate::foundation::ids::ExecutionId::new("exe-other").unwrap(),
        fixtures::tenant(),
        demand.clone(),
    );
    other.request.reservation = foreign;
    assert!(matches!(
        refusal(&other),
        PlanRefusal::Reservation {
            problem: ReservationProblem::OtherExecution { .. }
        }
    ));

    let mut tenant = Scenario::new(fixtures::profile());
    let foreign = fixtures::reserve(
        &mut tenant.ledger,
        fixtures::execution(),
        crate::foundation::ids::TenantId::new("tenant-2").unwrap(),
        demand.clone(),
    );
    tenant.request.reservation = foreign;
    assert!(matches!(
        refusal(&tenant),
        PlanRefusal::Reservation {
            problem: ReservationProblem::OtherTenant { .. }
        }
    ));

    let created = Scenario::new(fixtures::profile());
    let mut created = created;
    created
        .ledger
        .begin_create(created.request.reservation)
        .unwrap();
    assert_eq!(
        refusal(&created),
        PlanRefusal::Reservation {
            problem: ReservationProblem::NotGranted {
                state: ReservationState::InUse
            }
        }
    );

    let small = Scenario::reserving(
        fixtures::network_profile(),
        Amounts::new().host_ram_bytes(1024 * MIB_BYTES),
    );
    assert_eq!(
        refusal(&small),
        PlanRefusal::Reservation {
            problem: ReservationProblem::Insufficient {
                shortfall: Amounts::new()
                    .host_ram_bytes(64 * MIB_BYTES)
                    .network_slots(1)
            }
        }
    );

    let larger = Scenario::reserving(
        fixtures::profile(),
        Amounts::new().host_ram_bytes(4096 * MIB_BYTES),
    );
    assert!(larger.build().is_ok());
}

#[test]
fn a_record_of_another_reservation_is_refused() {
    let scenario = Scenario::new(fixtures::profile());
    let mut inputs = scenario.inputs();
    let mut copy = scenario.request.clone();
    let mut ledger_scenario = Scenario::new(fixtures::profile());
    let second = fixtures::reserve(
        &mut ledger_scenario.ledger,
        fixtures::execution(),
        fixtures::tenant(),
        fixtures::demand(&fixtures::profile()),
    );
    copy.reservation = second;
    inputs.request = &copy;
    assert!(matches!(
        LaunchPlan::build(&inputs),
        Err(PlanRefusal::Reservation {
            problem: ReservationProblem::OtherReservation { .. }
        })
    ));
}

#[test]
fn refusals_describe_themselves_and_serialize_with_a_tag() {
    let refusals = [
        PlanRefusal::Unsupported {
            feature: Feature::Display,
        },
        PlanRefusal::PersistenceNotSupported {
            persistence: "declared_data_volumes",
        },
        PlanRefusal::NetworkInterfaceNotAuthorized {
            interfaces: vec![ApiId::new("eth0").unwrap()],
        },
        PlanRefusal::DeviceModelAbsent {
            device: DeviceModel::VirtioVsock,
        },
        PlanRefusal::Reservation {
            problem: ReservationProblem::NotGranted {
                state: ReservationState::Closed,
            },
        },
        PlanRefusal::Name {
            error: NameError::Empty {
                kind: NameKind::HostPath,
            },
        },
    ];
    for refusal in refusals {
        assert!(!refusal.to_string().is_empty());
        let json = serde_json::to_value(&refusal).unwrap();
        assert!(json["kind"].is_string(), "{json}");
    }
}

#[test]
fn a_jail_path_beyond_the_length_limit_is_refused_not_truncated() {
    let mut long = Scenario::new(fixtures::profile());
    let base = format!("/{}", vec!["a".repeat(120); 8].join("/"));
    long.host.chroot_base = HostPath::new(base).unwrap();
    assert!(matches!(
        refusal(&long),
        PlanRefusal::Name {
            error: NameError::TooLong { .. }
        }
    ));
}

#[test]
fn the_request_must_run_under_the_pinned_configuration() {
    let mut other = Scenario::new(fixtures::profile());
    other.request.configuration =
        crate::foundation::evidence::ConfigurationFingerprint::from_settings([("host", "other")])
            .unwrap();
    assert_eq!(
        refusal(&other),
        PlanRefusal::ConfigurationMismatch {
            requested: other.request.configuration,
            pinned: fixtures::configuration().fingerprint().unwrap(),
        }
    );
    assert!(!refusal(&other).to_string().is_empty());
}
