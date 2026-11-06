//! The launch-set check and its admission through the persisted client (VM-W45, plan line
//! 2668; VM-W46, line 2669; VM-P23, line 2798; M18D in docs/combined-plan-leftover-tasks.md,
//! line 292): releases signed in the test with the fixture's Ed25519 keys and kept on a
//! durable stream in a temporary directory, with the helpers of `tests_persisted`, and a
//! pinned row built here as `sandbox::trust`'s own tests build theirs (that fixture is
//! private to its module).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::tests::{developer_profile, pinned_roots, trust_roots, Fixture, DAY, NOW};
use super::tests_persisted::{
    execution, image, kernel, load, revocation_file, root_signed_by, snapshot_file, targets_file,
    timestamp_file, Chain, Env, Online, IMAGE, KERNEL, OTHER,
};
use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::evidence::OsKind;
use crate::foundation::ids::{digest, ContentKey};
use crate::foundation::report::CommitHash;
use crate::sandbox::trust::{
    Architecture, AssuranceProfile, BootMethod, BuildInputs, ComponentKind, ComponentPin,
    ComponentVersion, ConfigurationKey, DeviceModel, LaunchAdmission, MetadataVersion, OpenRefusal,
    PinRefusal, PinnedConfiguration, ReleaseVersion, SandboxBackend, TargetName, UpdateRefusal,
    VerifiedTarget,
};

const RUNTIME: &[u8] = b"firecracker-1.10.1-yougori";

fn key(bytes: &[u8]) -> ContentKey {
    ContentKey::of(bytes)
}

fn length(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn runtime() -> TargetName {
    TargetName::new("runtime").unwrap()
}

/// Release `version`: the runtime, `kernel` as the guest kernel, and the guest image.
fn release(online: &Online, version: u64, kernel: &[u8]) -> Chain {
    let expires = NOW.plus_seconds(6 * DAY);
    let targets = targets_file(
        online,
        version,
        expires,
        &[
            ("runtime", RUNTIME),
            ("guest-kernel", kernel),
            ("guest-image", IMAGE),
        ],
    );
    let snapshot = snapshot_file(online, version, expires, &targets, version);
    let timestamp = timestamp_file(online, version, expires, &snapshot, version);
    Chain {
        timestamp,
        snapshot,
        targets,
    }
}

fn pin(kind: ComponentKind, version: &str, bytes: &[u8]) -> ComponentPin {
    ComponentPin {
        kind,
        version: ComponentVersion::new(version).unwrap(),
        content_key: key(bytes),
        length_bytes: length(bytes),
        build: BuildInputs {
            source: CommitHash::new("a".repeat(40)).unwrap(),
            toolchain: digest("yougori/test/toolchain/v1", &[version.as_bytes()]),
            configuration: digest("yougori/test/config/v1", &[version.as_bytes()]),
            builder: digest("yougori/test/builder/v1", &[version.as_bytes()]),
        },
    }
}

/// The Linux Firecracker row: runtime, kernel and image of release 1, booted directly.
fn row() -> PinnedConfiguration {
    PinnedConfiguration {
        key: ConfigurationKey {
            os: OsKind::Linux,
            architecture: Architecture::X86_64,
            backend: SandboxBackend::Firecracker,
        },
        boot: BootMethod::DirectKernel,
        components: BTreeMap::from([
            (
                ComponentKind::Runtime,
                pin(ComponentKind::Runtime, "firecracker-1.10.1", RUNTIME),
            ),
            (
                ComponentKind::GuestKernel,
                pin(ComponentKind::GuestKernel, "6.6.52", KERNEL),
            ),
            (
                ComponentKind::GuestImage,
                pin(ComponentKind::GuestImage, "rootfs-2026.10.1", IMAGE),
            ),
        ]),
        devices: BTreeSet::from([
            DeviceModel::VirtioNet,
            DeviceModel::VirtioBlk,
            DeviceModel::VirtioVsock,
        ]),
    }
}

/// The three components of [`row`] as a launch asks for them.
fn components() -> Vec<LaunchComponent> {
    [
        (ComponentKind::Runtime, runtime(), RUNTIME),
        (ComponentKind::GuestKernel, kernel(), KERNEL),
        (ComponentKind::GuestImage, image(), IMAGE),
    ]
    .into_iter()
    .map(|(kind, name, bytes)| LaunchComponent {
        kind,
        name,
        class: ArtifactClass::GuestImage,
        bytes: bytes.to_vec(),
    })
    .collect()
}

/// Each component of [`components`] verified now, one at a time, through the client.
fn verified(client: &PersistedUpdateClient) -> Vec<(ComponentKind, VerifiedTarget)> {
    components()
        .into_iter()
        .map(|component| {
            (
                component.kind,
                client
                    .verify_target(&component.name, component.class)
                    .unwrap(),
            )
        })
        .collect()
}

fn problems(result: Result<LaunchSetAdmission, LaunchSetRefusal>) -> Vec<LaunchSetProblem> {
    match result {
        Err(LaunchSetRefusal::Components {
            configuration,
            problems,
        }) => {
            assert_eq!(configuration, row().key);
            problems
        }
        other => panic!("expected the components refused, got {other:?}"),
    }
}

fn set_problems(result: Result<AdmittedLaunchSet, LaunchSetError>) -> Vec<LaunchSetProblem> {
    match result {
        Err(LaunchSetError::Set { refusal }) => problems(Err(refusal)),
        other => panic!("expected the set refused, got {other:?}"),
    }
}

fn basis(version: u64) -> ReleaseBasis {
    ReleaseBasis {
        snapshot_version: MetadataVersion::new(version),
        targets_version: MetadataVersion::new(version),
    }
}

#[test]
fn a_launch_set_from_one_release_matching_its_row_is_admitted_and_registered() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &release(&env.online, 1, KERNEL));
    let row = row();

    let admitted = client
        .admit_launch_set(execution("exe-1"), &row, components())
        .unwrap();
    let set = &admitted.admission;
    assert_eq!(admitted.execution, execution("exe-1"));
    assert_eq!(set.configuration(), row.key);
    assert_eq!(set.fingerprint(), row.fingerprint().unwrap());
    assert_eq!(set.basis(), basis(1));
    assert_eq!(set.assurance(), AssuranceProfile::Production);
    assert_eq!(
        set.components(),
        &BTreeMap::from([
            (ComponentKind::Runtime, key(RUNTIME)),
            (ComponentKind::GuestKernel, key(KERNEL)),
            (ComponentKind::GuestImage, key(IMAGE)),
        ])
    );
    // Each component was opened as its verified bytes and admitted at the boundary.
    assert_eq!(admitted.opened[&ComponentKind::GuestKernel].bytes(), KERNEL);
    assert_eq!(
        admitted.components[&ComponentKind::GuestImage].content_key,
        key(IMAGE)
    );
    assert_eq!(
        admitted.components[&ComponentKind::Runtime].name.as_str(),
        "runtime"
    );
    let serialized = serde_json::to_value(set).unwrap();
    assert_eq!(serialized["configuration"]["backend"], json!("firecracker"));
    assert_eq!(
        serialized["basis"],
        json!({"snapshot_version": 1, "targets_version": 1})
    );

    // Registered together under the execution, in kind order.
    let registered: Vec<LaunchAdmission> = admitted.components.values().cloned().collect();
    assert_eq!(
        client.running().admissions(&execution("exe-1")),
        registered.as_slice()
    );
    assert_eq!(client.running().len(), 1);
    assert_eq!(client.running().iter().count(), 3);
    assert_eq!(
        client.running().get(&execution("exe-1")),
        Some(&registered[0])
    );

    // The same targets through the check alone give the same admission.
    assert_eq!(
        check_launch_set(&row, &verified(&client), &client.revoked()),
        Ok(set.clone())
    );

    // An execution has one running launch, a set or a single artifact.
    assert_eq!(
        client.admit_launch_set(execution("exe-1"), &row, components()),
        Err(LaunchSetError::AlreadyRunning {
            execution: execution("exe-1")
        })
    );
    assert_eq!(
        client.admit_launch(
            execution("exe-1"),
            &admitted.opened[&ComponentKind::GuestKernel]
        ),
        Err(TrustRefusal::AlreadyRunning {
            execution: execution("exe-1")
        })
    );

    // Revoking any one component names the launch.
    let report = client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(IMAGE, "CVE-2026-0002")],
        ))
        .unwrap();
    assert_eq!(
        report.running,
        BTreeMap::from([(
            execution("exe-1"),
            RevokedLaunch {
                admission: admitted.components[&ComponentKind::GuestImage].clone(),
                reason: "CVE-2026-0002".to_owned(),
            }
        )])
    );

    // The launch ends with every admission it held.
    assert_eq!(client.end_launch_set(&execution("exe-1")), registered);
    assert!(client.running().is_empty());
    assert!(client.end_launch_set(&execution("exe-1")).is_empty());
}

#[test]
fn each_problem_of_a_launch_set_is_refused_with_its_own_type() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &release(&env.online, 1, KERNEL));
    let row = row();
    let none = BTreeMap::new();
    let all = verified(&client);
    let [runtime_target, kernel_target, image_target] =
        <[(ComponentKind, VerifiedTarget); 3]>::try_from(all.clone()).unwrap();
    let check =
        |set: &[(ComponentKind, VerifiedTarget)]| problems(check_launch_set(&row, set, &none));
    assert!(check_launch_set(&row, &all, &none).is_ok());

    // Missing, duplicated and unpinned components.
    assert_eq!(
        check(&[runtime_target.clone(), kernel_target.clone()]),
        [LaunchSetProblem::Missing {
            kind: ComponentKind::GuestImage
        }]
    );
    assert_eq!(
        check(&[
            runtime_target.clone(),
            kernel_target.clone(),
            kernel_target.clone(),
            image_target.clone(),
        ]),
        [LaunchSetProblem::Duplicate {
            kind: ComponentKind::GuestKernel,
            names: vec![kernel(), kernel()],
        }]
    );
    assert_eq!(
        check(&[
            runtime_target.clone(),
            kernel_target.clone(),
            image_target.clone(),
            (ComponentKind::Helper, kernel_target.1.clone()),
        ]),
        [LaunchSetProblem::Unpinned {
            kind: ComponentKind::Helper,
            name: kernel(),
        }]
    );

    // Other bytes than the row pins, or the pinned content key at another length.
    let mut other_kernel = row.clone();
    other_kernel.components.insert(
        ComponentKind::GuestKernel,
        pin(ComponentKind::GuestKernel, "6.1.0", OTHER),
    );
    assert_eq!(
        problems(check_launch_set(&other_kernel, &all, &none)),
        [LaunchSetProblem::PinMismatch {
            kind: ComponentKind::GuestKernel,
            name: kernel(),
            pinned_content_key: key(OTHER),
            pinned_length_bytes: length(OTHER),
            verified_content_key: key(KERNEL),
            verified_length_bytes: length(KERNEL),
        }]
    );
    let mut longer = row.clone();
    if let Some(image_pin) = longer.components.get_mut(&ComponentKind::GuestImage) {
        image_pin.length_bytes += 1;
    }
    assert_eq!(
        problems(check_launch_set(&longer, &all, &none)),
        [LaunchSetProblem::PinMismatch {
            kind: ComponentKind::GuestImage,
            name: image(),
            pinned_content_key: key(IMAGE),
            pinned_length_bytes: length(IMAGE) + 1,
            verified_content_key: key(IMAGE),
            verified_length_bytes: length(IMAGE),
        }]
    );

    // A revoked release.
    let revoked = BTreeMap::from([(key(KERNEL), "CVE-2026-0001".to_owned())]);
    let revoked_kernel = LaunchSetProblem::Revoked {
        kind: ComponentKind::GuestKernel,
        name: kernel(),
        content_key: key(KERNEL),
        reason: "CVE-2026-0001".to_owned(),
    };
    assert_eq!(
        problems(check_launch_set(&row, &all, &revoked)),
        [revoked_kernel.clone()]
    );

    // The image verified from the same release by a client under the developer profile:
    // the versions agree, the profiles do not.
    let fixture = Fixture::new();
    let mut developer = pinned_roots(trust_roots(&fixture.root_entries()), 2, developer_profile())
        .bootstrap(production_registry(), &fixture.root_file(1), NOW)
        .unwrap();
    let same = release(&env.online, 1, KERNEL);
    developer.update_timestamp(&same.timestamp, NOW).unwrap();
    developer.update_snapshot(&same.snapshot, NOW).unwrap();
    developer.update_targets(&same.targets, NOW).unwrap();
    let developer_image = developer
        .verify_target(&image(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    assert_eq!(developer_image.basis(), image_target.1.basis());
    let profiles = |image_profile: AssuranceProfile| LaunchSetProblem::MixedProfile {
        components: vec![
            ComponentProfile {
                kind: ComponentKind::Runtime,
                name: runtime(),
                assurance: AssuranceProfile::Production,
            },
            ComponentProfile {
                kind: ComponentKind::GuestKernel,
                name: kernel(),
                assurance: AssuranceProfile::Production,
            },
            ComponentProfile {
                kind: ComponentKind::GuestImage,
                name: image(),
                assurance: image_profile,
            },
        ],
    };
    assert_eq!(
        check(&[
            runtime_target.clone(),
            kernel_target.clone(),
            (ComponentKind::GuestImage, developer_image),
        ]),
        [profiles(AssuranceProfile::Developer)]
    );

    // An unsigned developer build of the pinned bytes was verified under no metadata.
    let unsigned = VerifiedTarget::developer_unsigned(
        developer_profile(),
        image(),
        ArtifactClass::GuestImage,
        key(IMAGE),
        length(IMAGE),
        ReleaseVersion::new("dev").unwrap(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        check(&[
            runtime_target.clone(),
            kernel_target.clone(),
            (ComponentKind::GuestImage, unsigned),
        ]),
        [
            LaunchSetProblem::Unsigned {
                kind: ComponentKind::GuestImage,
                name: image(),
            },
            profiles(AssuranceProfile::Developer),
        ]
    );

    // Every problem at once, in the fixed order: missing and duplicated kinds in kind
    // order, then each component's problems as presented.
    assert_eq!(
        problems(check_launch_set(
            &row,
            &[
                kernel_target.clone(),
                (ComponentKind::Helper, image_target.1.clone()),
                kernel_target.clone(),
            ],
            &revoked,
        )),
        [
            LaunchSetProblem::Missing {
                kind: ComponentKind::Runtime
            },
            LaunchSetProblem::Missing {
                kind: ComponentKind::GuestImage
            },
            LaunchSetProblem::Duplicate {
                kind: ComponentKind::GuestKernel,
                names: vec![kernel(), kernel()],
            },
            revoked_kernel.clone(),
            LaunchSetProblem::Unpinned {
                kind: ComponentKind::Helper,
                name: image(),
            },
            revoked_kernel,
        ]
    );

    // A row the matrix would refuse is refused before the components are looked at.
    let mut stray_firmware = row.clone();
    stray_firmware.components.insert(
        ComponentKind::Firmware,
        pin(ComponentKind::Firmware, "ovmf-2024.08", b"ovmf"),
    );
    assert_eq!(
        check_launch_set(&stray_firmware, &all, &none),
        Err(LaunchSetRefusal::Row {
            refusal: PinRefusal::FirmwareWithoutFirmwareBoot { key: row.key }
        })
    );

    // Refusals read as text and serialize with their type.
    let refusal = check_launch_set(&row, &[runtime_target], &none).unwrap_err();
    let text = refusal.to_string();
    assert!(text.contains("configuration linux/x86_64/firecracker"));
    assert!(text.contains("the row pins a guest_kernel and the launch presents none"));
    assert_eq!(
        serde_json::to_value(LaunchSetProblem::Missing {
            kind: ComponentKind::Firmware
        })
        .unwrap(),
        json!({"problem": "missing", "kind": "firmware"})
    );
}

#[test]
fn a_set_verified_across_a_targets_update_is_refused() {
    let env = Env::new();
    let mut client = env.open();
    let row = row();
    load(&mut client, &release(&env.online, 1, KERNEL));
    let kernel_before = client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();

    // Release 2 carries the same bytes; the other two are verified after it.
    load(&mut client, &release(&env.online, 2, KERNEL));
    let runtime_after = client
        .verify_target(&runtime(), ArtifactClass::GuestImage)
        .unwrap();
    let image_after = client
        .verify_target(&image(), ArtifactClass::GuestImage)
        .unwrap();
    let mixed = [
        (ComponentKind::Runtime, runtime_after),
        (ComponentKind::GuestKernel, kernel_before),
        (ComponentKind::GuestImage, image_after),
    ];
    let refused = problems(check_launch_set(&row, &mixed, &client.revoked()));
    assert_eq!(
        refused,
        [LaunchSetProblem::MixedVersions {
            components: vec![
                ComponentBasis {
                    kind: ComponentKind::Runtime,
                    name: runtime(),
                    basis: basis(2),
                },
                ComponentBasis {
                    kind: ComponentKind::GuestKernel,
                    name: kernel(),
                    basis: basis(1),
                },
                ComponentBasis {
                    kind: ComponentKind::GuestImage,
                    name: image(),
                    basis: basis(2),
                },
            ],
        }]
    );
    assert!(refused[0]
        .to_string()
        .contains("guest_kernel guest-kernel under snapshot 1 and targets 1"));

    // Verified in one pass through the persisted client, they are one release.
    let admitted = client
        .admit_launch_set(execution("exe-1"), &row, components())
        .unwrap();
    assert_eq!(admitted.admission.basis(), basis(2));
    assert_eq!(client.end_launch_set(&execution("exe-1")).len(), 3);

    // Release 3 replaces the kernel: one release, but no longer the pinned row.
    load(&mut client, &release(&env.online, 3, OTHER));
    assert_eq!(
        set_problems(client.admit_launch_set(execution("exe-2"), &row, components())),
        [LaunchSetProblem::PinMismatch {
            kind: ComponentKind::GuestKernel,
            name: kernel(),
            pinned_content_key: key(KERNEL),
            pinned_length_bytes: length(KERNEL),
            verified_content_key: key(OTHER),
            verified_length_bytes: length(OTHER),
        }]
    );
    assert!(client.running().is_empty());
}

#[test]
fn a_revoked_component_is_refused() {
    let env = Env::new();
    let mut client = env.open();
    let row = row();
    load(&mut client, &release(&env.online, 1, KERNEL));
    let before = verified(&client);
    client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(IMAGE, "CVE-2026-0002")],
        ))
        .unwrap();

    // Verified before the revocation, refused after it.
    assert_eq!(
        problems(check_launch_set(&row, &before, &client.revoked())),
        [LaunchSetProblem::Revoked {
            kind: ComponentKind::GuestImage,
            name: image(),
            content_key: key(IMAGE),
            reason: "CVE-2026-0002".to_owned(),
        }]
    );
    // Through the persisted client the image no longer verifies; nothing is registered.
    assert_eq!(
        client.admit_launch_set(execution("exe-1"), &row, components()),
        Err(LaunchSetError::Component {
            kind: ComponentKind::GuestImage,
            name: image(),
            reason: UpdateRefusal::RevokedRelease {
                content_key: key(IMAGE),
                reason: "CVE-2026-0002".to_owned(),
            },
        })
    );
    assert!(client.running().is_empty());
}

#[test]
fn a_release_kept_revoked_after_a_reload_is_refused_in_a_launch_set() {
    let env = Env::new();
    let mut client = env.open();
    // As `tests_persisted` does: root 2 replaces the online and revocation keys, signed
    // by root-0 and root-1; a list under it revokes OTHER.
    let rotated = Online::rotated();
    client
        .update_root(&root_signed_by(&env.fixture, &rotated, 2, &[0, 1]))
        .unwrap();
    load(&mut client, &release(&rotated, 1, KERNEL));
    client
        .update_revocation(&revocation_file(&rotated, 1, &[(OTHER, "CVE-2026-0001")]))
        .unwrap();
    // Root-0 is revoked and the roots reloaded: the list no longer verifies, and OTHER
    // stays revoked in the persisted client only.
    env.revoke_root_keys(&[0]);
    env.reload(&mut client).unwrap();
    client
        .update_root(&root_signed_by(&env.fixture, &rotated, 2, &[1, 2]))
        .unwrap();
    load(&mut client, &release(&rotated, 2, OTHER));
    assert!(!client.client().revoked().contains_key(&key(OTHER)));
    assert!(client.revoked().contains_key(&key(OTHER)));

    // A row pinning OTHER as its kernel verifies through the client, and the set is refused.
    let mut retired = row();
    retired.components.insert(
        ComponentKind::GuestKernel,
        pin(ComponentKind::GuestKernel, "6.1.0", OTHER),
    );
    let mut asked = components();
    asked[1].bytes = OTHER.to_vec();
    assert_eq!(
        set_problems(client.admit_launch_set(execution("exe-1"), &retired, asked)),
        [LaunchSetProblem::Revoked {
            kind: ComponentKind::GuestKernel,
            name: kernel(),
            content_key: key(OTHER),
            reason: "CVE-2026-0001".to_owned(),
        }]
    );
    assert!(client.running().is_empty());
}

#[test]
fn the_persisted_client_registers_nothing_it_refuses() {
    let env = Env::new();
    let mut client = env.open();
    let row = row();
    load(&mut client, &release(&env.online, 1, KERNEL));

    // A target the release does not carry, or one asked as another class.
    let jailer = TargetName::new("jailer").unwrap();
    let mut asked = components();
    asked[0].name = jailer.clone();
    assert_eq!(
        client.admit_launch_set(execution("exe-1"), &row, asked),
        Err(LaunchSetError::Component {
            kind: ComponentKind::Runtime,
            name: jailer.clone(),
            reason: UpdateRefusal::UnknownTarget { name: jailer },
        })
    );
    let mut asked = components();
    asked[0].class = ArtifactClass::RuntimeUpdate;
    let refused = client.admit_launch_set(execution("exe-1"), &row, asked);
    assert_eq!(
        refused,
        Err(LaunchSetError::Component {
            kind: ComponentKind::Runtime,
            name: runtime(),
            reason: UpdateRefusal::ClassMismatch {
                name: runtime(),
                declared: ArtifactClass::GuestImage,
                expected: ArtifactClass::RuntimeUpdate,
            },
        })
    );
    assert!(refused
        .unwrap_err()
        .to_string()
        .starts_with("the runtime (target runtime) was refused"));

    // Bytes of the right length that are not the verified bytes.
    let altered = b"rootfs-2026.10.1-yougorj";
    let mut asked = components();
    asked[2].bytes = altered.to_vec();
    assert_eq!(
        client.admit_launch_set(execution("exe-1"), &row, asked),
        Err(LaunchSetError::Open {
            kind: ComponentKind::GuestImage,
            name: image(),
            refusal: OpenRefusal::BytesDiffer {
                expected: key(IMAGE),
                found: key(altered),
            },
        })
    );
    assert!(client.running().is_empty());

    // A single launch holds the execution.
    let kernel_artifact = client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap()
        .open(KERNEL.to_vec())
        .unwrap();
    let single = client
        .admit_launch(execution("exe-1"), &kernel_artifact)
        .unwrap();
    assert_eq!(
        client.admit_launch_set(execution("exe-1"), &row, components()),
        Err(LaunchSetError::AlreadyRunning {
            execution: execution("exe-1")
        })
    );

    // A failed reload leaves the client trusted for nothing.
    env.revoke_root_keys(&[0, 1]);
    let refusal = env.reload(&mut client).unwrap_err();
    assert_eq!(
        client.admit_launch_set(execution("exe-2"), &row, components()),
        Err(LaunchSetError::Halted {
            halt: Halt::ReloadFailed { refusal },
        })
    );
    assert_eq!(client.running().len(), 1);
    assert_eq!(client.end_launch_set(&execution("exe-1")), [single]);
}
