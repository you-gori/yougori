//! S3.1: placements and sessions bind to the parent execution and the VM authorization
//! epoch; activation and allocation generations are distinct, only move forward, and
//! changing one never refreshes another or resets session authority.

use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionCategory, GpuAllocationGeneration, ModelActivationGeneration,
};

use super::super::*;
use super::support::*;

#[test]
fn a_vm_binding_requires_its_authorization_epoch() {
    assert_eq!(
        AuthorityBinding::new(exe("exe-1"), ExecutionCategory::VmSandbox, None),
        Err(IdentityError::MissingAuthorizationEpoch)
    );
    let binding = vm_binding("exe-1", 7);
    assert_eq!(binding.parent(), &exe("exe-1"));
    assert_eq!(binding.category(), ExecutionCategory::VmSandbox);
    assert_eq!(binding.epoch(), Some(AuthorizationEpoch::new(7)));

    // A labelled runtime binds an epoch where it has one (S3.1 "where applicable").
    for category in ExecutionCategory::ALL
        .into_iter()
        .filter(|category| !category.is_vm_sandbox())
    {
        let without = AuthorityBinding::new(exe("exe-1"), category, None).unwrap();
        let with = AuthorityBinding::new(exe("exe-1"), category, Some(AuthorizationEpoch::new(2)))
            .unwrap();
        assert_ne!(without, with);
    }
}

#[test]
fn placements_and_sessions_bind_the_parent_execution_and_epoch() {
    let placement = placement_spec();
    let session = session_spec();
    for (name, authority) in [
        ("parent", vm_binding("exe-elsewhere", 3)),
        ("epoch", vm_binding("exe-parent", 4)),
    ] {
        let moved = PlacementSpec {
            authority: authority.clone(),
            ..placement.clone()
        };
        assert_ne!(moved.identity(), placement.identity(), "placement {name}");
    }
    for (name, authority) in [
        ("parent", vm_binding("exe-elsewhere", 3)),
        ("epoch", vm_binding("exe-session", 4)),
    ] {
        let moved = SessionSpec {
            authority,
            ..session.clone()
        };
        assert_ne!(moved.identity(), session.identity(), "session {name}");
    }
}

#[test]
fn reactivation_changes_the_placement_but_not_the_session_or_its_authority() {
    let placement = placement_spec();
    let session = session_spec();
    let session_identity = session.identity();
    let kv_key = kv_scope_spec().key();

    let next = placement.activation.next().unwrap();
    let reactivated = placement.with_activation(next).unwrap();

    assert_eq!(reactivated.activation, next);
    assert_ne!(reactivated.identity(), placement.identity());
    // Nothing else moved with it.
    assert_eq!(reactivated.allocation, placement.allocation);
    assert_eq!(reactivated.authority, placement.authority);
    assert_eq!(reactivated.leases, placement.leases);
    assert_eq!(reactivated.execution, placement.execution);

    // The session binds the execution identity, which is unchanged, so its identity, its
    // authority binding and its KV scope stay as they were: neither reset nor renewed.
    assert_eq!(session.execution, reactivated.execution);
    assert_eq!(session.identity(), session_identity);
    assert_eq!(session.authority, vm_binding("exe-session", 3));
    assert_eq!(kv_scope_spec().key(), kv_key);
    let enforced = enforced();
    assert_eq!(
        check_kv_reuse(&kv_scope_spec(), &kv_scope_spec(), &enforced),
        Ok(kv_key)
    );
}

#[test]
fn activation_and_allocation_generations_move_independently() {
    let placement = placement_spec();
    let reallocated = placement
        .with_allocation(placement.allocation.next().unwrap())
        .unwrap();
    assert_eq!(reallocated.activation, placement.activation);
    let reactivated = placement
        .with_activation(placement.activation.next().unwrap())
        .unwrap();
    assert_eq!(reactivated.allocation, placement.allocation);
    let both = reactivated
        .with_allocation(reactivated.allocation.next().unwrap())
        .unwrap();
    assert_all_distinct(&[
        ("placement", placement.identity()),
        ("reallocated", reallocated.identity()),
        ("reactivated", reactivated.identity()),
        ("both", both.identity()),
    ]);
}

#[test]
fn generations_never_stand_still_or_move_backwards() {
    let placement = placement_spec();
    assert_eq!(
        placement.with_activation(placement.activation),
        Err(IdentityError::GenerationNotAfter {
            field: "model activation",
            current: 5,
            proposed: 5,
        })
    );
    assert_eq!(
        placement.with_activation(ModelActivationGeneration::FIRST),
        Err(IdentityError::GenerationNotAfter {
            field: "model activation",
            current: 5,
            proposed: 1,
        })
    );
    assert_eq!(
        placement.with_allocation(placement.allocation),
        Err(IdentityError::GenerationNotAfter {
            field: "GPU allocation",
            current: 9,
            proposed: 9,
        })
    );
    assert_eq!(
        placement.with_allocation(GpuAllocationGeneration::new(8)),
        Err(IdentityError::GenerationNotAfter {
            field: "GPU allocation",
            current: 9,
            proposed: 8,
        })
    );
}

#[test]
fn a_raised_epoch_leaves_nothing_bound_to_the_old_one_matching() {
    let revoked = KvScopeSpec {
        authority: KvAuthority {
            session: vm_binding("exe-session", 4),
            ..kv_scope_spec().authority
        },
        ..kv_scope_spec()
    };
    let enforced = enforced();
    assert_eq!(
        check_kv_reuse(&kv_scope_spec(), &revoked, &enforced),
        Err(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::SessionAuthority],
        })
    );
    let session = SessionSpec {
        authority: vm_binding("exe-session", 4),
        ..session_spec()
    };
    assert_ne!(session.identity(), session_spec().identity());
}
