//! CUDA IPC is exported, imported or opened only where the runtime profile's loader plan
//! from the CORE-01 gate enabled it, and only while the evidence behind that plan holds
//! (INT-06; T16's gap G6). Evidence alone never suffices.

use super::*;
use crate::foundation::evidence::{EvidenceRefusal, NotEnabled, Staleness};

const POSIX: ShareableHandle = ShareableHandle::PosixFileDescriptor;
const LEGACY: Optimization = Optimization::CudaIpcLegacy;
const VMM: Optimization = Optimization::CudaIpcVmmShareableHandle;

/// P1 holds artifact "a" in a published dedicated `cudaMalloc` allocation, and a host
/// probe shows legacy CUDA IPC in its runtime.
fn legacy_world() -> (World, MappingKey) {
    let mut world = World::new();
    world.show_legacy_ipc();
    let key = world
        .model
        .plan_legacy(P1, named("a"), content_of("a"), whole("a", 3 * MIB))
        .unwrap();
    world.fill(key, "a", 1);
    (world, key)
}

fn legacy_export(world: &mut World, key: MappingKey) -> Result<ExportId, VmmError> {
    world
        .model
        .legacy_export(&mut world.driver, &world.registry, key)
}

#[test]
fn legacy_ipc_needs_the_runtime_profile_to_permit_it() {
    let (mut world, key) = legacy_world();
    assert_eq!(
        legacy_export(&mut world, key),
        Err(VmmError::NoLoaderPlan { process: P1 }),
        "evidence alone never exports"
    );

    let refused = world.gate(P1, &[], &[LEGACY]);
    assert_eq!(refused.ordinary()[&LEGACY], NotEnabled::NotPermitted);
    world.model.set_loader_plan(P1, refused).unwrap();
    assert_eq!(
        legacy_export(&mut world, key),
        Err(VmmError::NotPermitted {
            process: P1,
            optimization: LEGACY,
            reason: Some(NotEnabled::NotPermitted),
        }),
        "the profile does not permit it, so the gate left it to the ordinary loader"
    );

    let unasked = world.gate(P1, &[LEGACY], &[]);
    world.model.set_loader_plan(P1, unasked).unwrap();
    assert_eq!(
        legacy_export(&mut world, key),
        Err(VmmError::NotPermitted {
            process: P1,
            optimization: LEGACY,
            reason: None,
        }),
        "a load that never asked for it does not get it"
    );
    assert_eq!(world.count_calls("cudaIpcGetMemHandle"), 0);

    world.permit(P1, &[LEGACY]);
    assert!(world.model.loader_plan(P1).unwrap().is_enabled(LEGACY));
    let export = legacy_export(&mut world, key).unwrap();
    assert_eq!(
        world
            .model
            .legacy_open(&mut world.driver, &world.registry, P2, export),
        Err(VmmError::NoLoaderPlan { process: P2 }),
        "the consumer's runtime profile must permit it too"
    );
    world.permit(P2, &[LEGACY]);
    world
        .model
        .legacy_open(&mut world.driver, &world.registry, P2, export)
        .unwrap();
    assert_eq!(world.count_calls("cudaIpcOpenMemHandle"), 1);
    world.assert_no_refusals();
}

#[test]
fn vmm_sharing_needs_the_runtime_profile_to_permit_it() {
    let mut world = World::new();
    world.show_vmm_handles(POSIX);
    world.show_legacy_ipc();
    let key = world.load(P1, "a", &[8 * MIB], posix());
    let physical = world.physical_of(key, 0);
    world.permit(P1, &[LEGACY]);
    assert_eq!(
        world.export(P1, physical, POSIX),
        Err(VmmError::NotPermitted {
            process: P1,
            optimization: VMM,
            reason: None,
        }),
        "a plan for legacy IPC never enables the other API family"
    );

    world.permit(P1, &[VMM]);
    let export = world.export(P1, physical, POSIX).unwrap();
    world.probe(P2, posix());
    let receiver = world
        .plan(P2, &layout("a", &[8 * MIB]), posix(), VmmOrigin::Import)
        .unwrap();
    assert_eq!(
        world.import(receiver, 0, export),
        Err(VmmError::NoLoaderPlan { process: P2 })
    );
    world.permit(P2, &[VMM]);
    world.import(receiver, 0, export).unwrap();
    assert_eq!(world.count_calls("cuMemImportFromShareableHandle"), 1);
    world.assert_no_refusals();
}

#[test]
fn a_plan_binds_to_the_process_runtime_and_configuration() {
    let (mut world, key) = legacy_world();
    world.add_other_runtime();
    let wsl_plan = world.gate(P1, &[LEGACY], &[LEGACY]);
    assert_eq!(
        world.model.set_loader_plan(P3, wsl_plan),
        Err(VmmError::LoaderPlanMismatch { process: P3 }),
        "a plan for another runtime never applies"
    );
    let plan = world.gate(P1, &[LEGACY], &[LEGACY]);
    assert_eq!(
        world.model.set_loader_plan(ProcessId(9), plan),
        Err(VmmError::UnknownProcess {
            process: ProcessId(9)
        })
    );

    world.permit(P1, &[LEGACY]);
    world
        .model
        .set_configuration(P1, configuration("581.0"))
        .unwrap();
    let subject = Subject::Runtime(runtime("wsl"));
    world.legacy_probe.respond(
        &subject,
        Observation::supported(configuration("581.0"), HOUR, SupportDetail::CudaIpcLegacy),
    );
    world
        .registry
        .refresh(Capability::CudaIpcLegacy, &subject)
        .unwrap();
    assert_eq!(
        legacy_export(&mut world, key),
        Err(VmmError::LoaderPlanMismatch { process: P1 }),
        "a plan made under the old configuration no longer applies"
    );
    world.permit(P1, &[LEGACY]);
    assert!(legacy_export(&mut world, key).is_ok());
}

#[test]
fn a_plan_lapses_with_its_evidence() {
    let (mut world, key) = legacy_world();
    world.permit(P1, &[LEGACY]);
    world.advance(MINUTE + Duration::from_secs(1));
    world.show_legacy_ipc();
    let refusal = legacy_export(&mut world, key).unwrap_err();
    assert!(
        matches!(
            refusal,
            VmmError::LoaderPlanLapsed {
                process: P1,
                optimization: LEGACY,
                refusal: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                },
            }
        ),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("plan the load again"));
    world.permit(P1, &[LEGACY]);
    assert!(legacy_export(&mut world, key).is_ok());
}
