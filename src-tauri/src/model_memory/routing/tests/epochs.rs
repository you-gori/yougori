//! §4.8 line 736: in-flight requests finish on their original execution plan across the
//! pipeline-to-replica transition, and nothing from before a revocation is honoured.

use std::collections::BTreeMap;

use crate::foundation::ids::{
    AuthorizationEpoch, ContentKey, ModelActivationGeneration, OperationId,
};
use crate::model_memory::placement::{
    ActivationContent, Component, ExtentKey, Rank, WeightPosition,
};

use super::super::epochs::*;
use super::super::fixtures::{device, SyntheticFleet};

fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn generation(value: u64) -> ModelActivationGeneration {
    ModelActivationGeneration::new(value)
}

fn plans(synthetic: &SyntheticFleet) -> (PlanPublication, PlanPublication) {
    (
        PlanPublication {
            generation: generation(1),
            execution: synthetic.pipeline_execution().unwrap(),
            kind: PlanKind::Pipeline { stages: 2 },
        },
        PlanPublication {
            generation: generation(2),
            execution: synthetic.single_execution().unwrap(),
            kind: PlanKind::Replicas { nodes: 2 },
        },
    )
}

#[test]
fn in_flight_requests_finish_on_the_pipeline_while_new_ones_go_to_the_replicas() {
    let synthetic = SyntheticFleet::new().unwrap();
    let (pipeline, replicas) = plans(&synthetic);
    let mut epochs = PlanEpochs::new(
        synthetic.requested_single_or_pipeline().unwrap(),
        synthetic.epoch,
    );
    assert_eq!(epochs.publish(pipeline), Ok(None));
    let tickets: Vec<PlanTicket> = ["r1", "r2", "r3"]
        .iter()
        .map(|name| epochs.admit(op(name), synthetic.epoch).unwrap())
        .collect();
    assert!(tickets.iter().all(|ticket| ticket.plan == generation(1)));

    // The replicas publish in one step; the pipeline stops admitting and drains.
    assert_eq!(epochs.publish(replicas), Ok(Some(generation(1))));
    assert_eq!(epochs.state(generation(1)), Some(PlanState::Draining));
    let late = epochs.admit(op("r4"), synthetic.epoch).unwrap();
    assert_eq!(late.plan, generation(2));

    // An in-flight request never moves to the new plan.
    assert_eq!(
        epochs.run_on(&tickets[0], generation(2)),
        Err(EpochRefusal::PlanChanged {
            admitted: generation(1),
            offered: generation(2)
        })
    );
    assert_eq!(epochs.run_on(&tickets[0], generation(1)), Ok(()));
    // The pipeline is not retired under its requests, nor the current plan at all.
    assert_eq!(
        epochs.retire(generation(1)),
        Err(EpochRefusal::InFlight {
            plan: generation(1),
            requests: 3
        })
    );
    assert_eq!(
        epochs.retire(generation(2)),
        Err(EpochRefusal::StillCurrent {
            plan: generation(2)
        })
    );
    assert!(!epochs.finish(&tickets[0]).unwrap().drained);
    assert!(!epochs.finish(&tickets[1]).unwrap().drained);
    assert_eq!(
        epochs.finish(&tickets[2]),
        Ok(FinishReport {
            plan: generation(1),
            drained: true
        })
    );
    assert_eq!(epochs.retire(generation(1)), Ok(()));
    assert_eq!(epochs.state(generation(1)), Some(PlanState::Retired));
    assert_eq!(epochs.finish(&tickets[0]), Err(EpochRefusal::UnknownTicket));
    assert_eq!(epochs.in_flight(generation(2)), 1);
    assert!(!epochs.finish(&late).unwrap().drained);
}

#[test]
fn plans_publish_in_order_and_only_for_accepted_executions() {
    let synthetic = SyntheticFleet::new().unwrap();
    let (pipeline, replicas) = plans(&synthetic);
    let mut exact = PlanEpochs::new(synthetic.requested_single().unwrap(), synthetic.epoch);
    // The pipeline is another execution of the same logical model; an exact request for
    // the single-GPU execution does not accept it.
    assert_eq!(
        exact.publish(pipeline),
        Err(EpochRefusal::NotAccepted {
            execution: pipeline.execution
        })
    );
    let other = PlanPublication {
        execution: synthetic.other.identity().unwrap(),
        ..replicas
    };
    assert!(matches!(
        exact.publish(other),
        Err(EpochRefusal::NotAccepted { .. })
    ));
    assert_eq!(
        exact.admit(op("r1"), synthetic.epoch),
        Err(EpochRefusal::NoPlan)
    );
    assert_eq!(exact.publish(replicas), Ok(None));
    assert_eq!(
        exact.publish(replicas),
        Err(EpochRefusal::NotNewer {
            published: generation(2),
            latest: generation(2)
        })
    );
    exact.admit(op("r1"), synthetic.epoch).unwrap();
    assert_eq!(
        exact.admit(op("r1"), synthetic.epoch),
        Err(EpochRefusal::DuplicateRequest)
    );
    assert_eq!(
        exact.admit(op("r2"), AuthorizationEpoch::new(2)),
        Err(EpochRefusal::AuthorityMismatch {
            presented: AuthorizationEpoch::new(2),
            bound: synthetic.epoch
        })
    );
}

#[test]
fn a_revocation_cancels_every_in_flight_request_and_nothing_older_is_honoured() {
    let synthetic = SyntheticFleet::new().unwrap();
    let (pipeline, replicas) = plans(&synthetic);
    let mut epochs = PlanEpochs::new(
        synthetic.requested_single_or_pipeline().unwrap(),
        synthetic.epoch,
    );
    epochs.publish(pipeline).unwrap();
    let ticket = epochs.admit(op("r1"), synthetic.epoch).unwrap();
    epochs.publish(replicas).unwrap();
    let other = epochs.admit(op("r2"), synthetic.epoch).unwrap();
    let raised = AuthorizationEpoch::new(2);
    let mut cancelled = epochs.revoke(raised).unwrap();
    cancelled.sort();
    assert_eq!(cancelled, vec![op("r1"), op("r2")]);
    assert_eq!(epochs.current(), None);
    assert_eq!(epochs.state(generation(1)), Some(PlanState::Retired));
    assert_eq!(
        epochs.finish(&ticket),
        Err(EpochRefusal::Revoked {
            ticket: synthetic.epoch
        })
    );
    assert!(epochs.run_on(&other, generation(2)).is_err());
    assert_eq!(
        epochs.revoke(raised),
        Err(EpochRefusal::EpochNotRaised {
            bound: raised,
            offered: raised
        })
    );
    // Serving resumes only under a plan published again under the new epoch.
    let republished = PlanPublication {
        generation: generation(3),
        ..replicas
    };
    epochs.publish(republished).unwrap();
    assert_eq!(epochs.admit(op("r3"), raised).unwrap().plan, generation(3));
}

#[test]
fn a_plan_is_published_from_the_placement_slot_s_activation() {
    let synthetic = SyntheticFleet::new().unwrap();
    let content = ActivationContent {
        generation: generation(5),
        execution: synthetic.single_execution().unwrap(),
        artifact: synthetic.artifact,
        adapters: BTreeMap::new(),
        components: BTreeMap::from([(
            WeightPosition::new(Rank::new(0), Component::Layer(0)),
            ExtentKey {
                content: ContentKey::of(b"layer-0"),
                device: device("host-a", "gpu0"),
            },
        )]),
    };
    let publication = PlanPublication::from_activation(&content, PlanKind::Replicas { nodes: 1 });
    assert_eq!(publication.generation, generation(5));
    assert_eq!(publication.execution, content.execution);
    let mut epochs = PlanEpochs::new(synthetic.requested_single().unwrap(), synthetic.epoch);
    assert_eq!(epochs.publish(publication), Ok(None));
    assert_eq!(epochs.current(), Some(&publication));
}
