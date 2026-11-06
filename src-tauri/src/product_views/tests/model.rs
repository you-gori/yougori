//! Model readiness, keep-ready preparation, residency and memory fit, converted from the
//! model-memory types and kept apart from sandbox evidence.

use std::collections::BTreeSet;

use serde_json::json;

use super::*;
use crate::foundation::ids::GpuDeviceKey;
use crate::foundation::product::{
    HostCopyShown, MemoryFit, ModelReadiness, ModelStatus, Preparation, Readiness, ReadyFor,
};
use crate::model_memory::placement::{
    Failure, FailureReason, GpuResidency, PlacementState, Rank, StateKind, SupportedShape,
    TransientStage, ValidationCheck,
};
use crate::model_memory::readiness::intent::{CancelReason, PrepareState, ReleaseReason};
use crate::model_memory::residency::host::{HostCopy, HostResidency};
use crate::model_memory::residency::vram::{VramBreakdown, VramEvaluation, VramPiece};
use crate::model_memory::residency::Interval;
use crate::product_views::from_models::residency;

#[test]
fn every_placement_state_has_one_readiness_and_only_serving_serves() {
    let expected = [
        (StateKind::Absent, Readiness::NotLoaded),
        (StateKind::Preparing, Readiness::Preparing),
        (StateKind::Materialized, Readiness::Loaded),
        (StateKind::Activating, Readiness::Activating),
        (StateKind::Serving, Readiness::Ready),
        (StateKind::Draining, Readiness::Draining),
        (StateKind::Parked, Readiness::Parked),
        (StateKind::Failed, Readiness::Failed),
    ];
    assert_eq!(expected.len(), StateKind::ALL.len());
    for (state, readiness) in expected {
        assert_eq!(Readiness::from(state), readiness);
        assert_eq!(readiness.serves_requests(), state == StateKind::Serving);
        assert_eq!(round_trip(&readiness), readiness);
    }
    let serving = ModelReadiness::from(&PlacementState::Serving);
    assert_eq!(serving.state(), Readiness::Ready);
    assert_eq!(serving.failure(), None);
}

#[test]
fn a_failed_model_says_why_and_only_a_failed_model_has_a_failure() {
    let failed = ModelReadiness::from(&PlacementState::Failed {
        failure: Failure {
            stage: TransientStage::Activating,
            reason: FailureReason::ValidationFailed {
                rank: Rank::new(0),
                check: ValidationCheck::Weights,
            },
            at: MonotonicTime::from_nanos(5),
        },
    });
    assert_eq!(failed.state(), Readiness::Failed);
    let why = failed.failure().unwrap().as_str();
    assert!(why.starts_with("failed while activating"), "{why}");
    assert_eq!(round_trip(&failed), failed);

    assert_eq!(failed.label(), "Failed");
    let ready_with_failure = refused::<ModelReadiness>(json!({
        "state": "ready", "label": "Ready", "failure": "it broke"
    }));
    assert!(
        ready_with_failure.contains("only a failed model"),
        "{ready_with_failure}"
    );
    let failed_silently = refused::<ModelReadiness>(json!({"state": "failed", "label": "Failed"}));
    assert!(failed_silently.contains("says why"), "{failed_silently}");
    let overclaimed = refused::<ModelReadiness>(json!({
        "state": "parked", "label": "Ready"
    }));
    assert!(overclaimed.contains("reads \"Parked\""), "{overclaimed}");
}

#[test]
fn keep_ready_preparations_convert_with_their_times_and_release_reasons() {
    let at = MonotonicTime::from_nanos;
    assert_eq!(
        Preparation::from(&PrepareState::Running { started_at: at(1) }),
        Preparation::Running { started_at: at(1) }
    );
    let ready = Preparation::from(&PrepareState::Ready {
        ready_at: at(2),
        expires_at: at(9),
    });
    assert_eq!(
        ready,
        Preparation::Ready {
            ready_at: at(2),
            expires_at: at(9)
        }
    );
    assert_eq!(
        Preparation::from(&PrepareState::Consumed { at: at(3) }),
        Preparation::Used { at: at(3) }
    );
    for (reason, words) in [
        (ReleaseReason::Expired, "keep-ready time ran out"),
        (ReleaseReason::DeadlineMissed, "not ready by its deadline"),
        (ReleaseReason::NotRequested, "another model"),
        (
            ReleaseReason::Cancelled {
                reason: CancelReason::Superseded,
            },
            "a newer request replaced it",
        ),
    ] {
        let Preparation::Released { reason, .. } =
            Preparation::from(&PrepareState::Released { at: at(4), reason })
        else {
            panic!("released");
        };
        assert!(reason.as_str().contains(words), "{reason}");
    }
    assert_eq!(round_trip(&ready), ready);
    let unit_extra = refused::<Preparation>(json!({
        "preparation": "used", "at": 3, "by": "someone"
    }));
    assert!(unit_extra.contains("unknown field"), "{unit_extra}");
}

#[test]
fn residency_counts_only_what_may_be_relied_on() {
    let gpu = GpuResidency {
        extents: 3,
        bytes: 9_000,
        allocations: BTreeSet::new(),
    };
    let pinned = HostCopy {
        bytes: 9_000,
        residency: HostResidency::Pinned,
    };
    let cached = HostCopy {
        bytes: 9_000,
        residency: HostResidency::Reclaimable {
            mincore_resident_bytes: Some(12_000),
        },
    };
    let on_gpu = residency(&gpu, Some(&pinned));
    assert!(on_gpu.is_on_gpu());
    assert_eq!(on_gpu.gpu_bytes(), 9_000);
    assert_eq!(on_gpu.host().unwrap().guaranteed_resident_bytes(), 9_000);
    let reclaimable = HostCopyShown::from(&cached);
    assert_eq!(reclaimable.guaranteed_resident_bytes(), 0);
    assert_eq!(reclaimable.advisory_resident_bytes(), Some(9_000));
    assert_eq!(round_trip(&on_gpu), on_gpu);

    let partial = refused::<HostCopyShown>(json!({
        "bytes": 9000, "guaranteed_resident_bytes": 4000
    }));
    assert!(partial.contains("whole"), "{partial}");
    let ghost = refused::<crate::foundation::product::Residency>(
        json!({"gpu_extents": 0, "gpu_bytes": 10}),
    );
    assert!(ghost.contains("GPU extents"), "{ghost}");
}

#[test]
fn memory_fit_is_the_peak_against_usable_memory() {
    let piece = |start, end, total_bytes| VramPiece {
        during: Interval::new(
            MonotonicTime::from_nanos(start),
            MonotonicTime::from_nanos(end),
        )
        .unwrap(),
        demand: VramBreakdown::default(),
        total_bytes,
    };
    let evaluation = VramEvaluation {
        device: GpuDeviceKey {
            machine: digest("yougori/test/product/machine/v1", &[b"m"]),
            device: digest("yougori/test/product/device/v1", &[b"d"]),
        },
        usable_vram_bytes: 20_000_000_000,
        pieces: vec![piece(0, 10, 12_000_000_000), piece(10, 20, 24_000_000_000)],
    };
    let fit = MemoryFit::from(&evaluation);
    assert_eq!(fit.peak_bytes(), 24_000_000_000);
    assert!(!fit.fits());
    assert!(fit.to_string().contains("does not fit"));
    assert_eq!(round_trip(&fit), fit);
    let mut json = serde_json::to_value(&fit).unwrap();
    json["fits"] = json!(true);
    assert!(refused::<MemoryFit>(json).contains("peak demand"));

    let status = ModelStatus {
        readiness: ModelReadiness::from(&PlacementState::Serving),
        preparation: None,
        residency: residency(&GpuResidency::default(), None),
        ready_for: Some(ReadyFor::from(SupportedShape {
            max_context_tokens: 32_768,
            max_batch_sequences: 4,
        })),
        memory: vec![fit],
    };
    assert_eq!(round_trip(&status), status);
    let mut json = serde_json::to_value(&status).unwrap();
    json["sandbox_verified"] = json!(true);
    assert!(refused::<ModelStatus>(json).contains("unknown field"));
}
