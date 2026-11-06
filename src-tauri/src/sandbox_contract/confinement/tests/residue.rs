//! Guest-root honesty: after guest root or a guest kernel compromise only host-side
//! boundaries remain, and every inner control is defense in depth (VM-P05, VM-R08,
//! VM-W07; §1.1, §1.2).

use std::collections::BTreeSet;

use super::*;

#[test]
fn only_host_side_boundaries_remain_after_any_guest_compromise() {
    for workload in WorkloadProfile::ALL {
        let profile = builtin(workload);
        for compromise in Compromise::ALL {
            let residue = after_compromise(&profile, compromise);
            assert_eq!(residue.compromise, compromise);
            assert_eq!(residue.profile, profile.digest());
            assert_eq!(residue.remaining, HostBoundary::ALL);
            let layers = residue.remaining_layers();
            assert!(layers.iter().all(|layer| layer.is_host_side()));
            for mechanism in Mechanism::ALL {
                let inner = ProtectionLayer::Inner(InnerControl::from_mechanism(mechanism));
                assert!(!layers.contains(&inner), "{mechanism} remains");
            }
            for control in InnerControl::ALL {
                assert!(!layers.contains(&ProtectionLayer::Inner(control)));
            }
        }
    }
}

#[test]
fn every_inner_control_of_the_profile_is_listed_as_defense_in_depth() {
    for workload in WorkloadProfile::ALL {
        let profile = builtin(workload);
        let residue = after_compromise(&profile, Compromise::GuestRoot);
        let listed: BTreeSet<InnerControl> = residue.defense_in_depth.iter().copied().collect();
        for mechanism in profile.mechanisms() {
            assert!(listed.contains(&InnerControl::from_mechanism(mechanism)));
        }
        for control in [
            InnerControl::NonRootUid,
            InnerControl::NoNewPrivs,
            InnerControl::CapabilityBoundingSet,
        ] {
            assert!(listed.contains(&control), "{control}");
        }
        assert_eq!(
            after_compromise(&profile, Compromise::GuestKernel).defense_in_depth,
            residue.defense_in_depth
        );
    }
    let strict = after_compromise(&strict(), Compromise::GuestKernel);
    for control in [
        InnerControl::KernelOptionsAbsent,
        InnerControl::SeccompFilter,
        InnerControl::ReadOnlyMounts,
        InnerControl::CredentialSeparation,
        InnerControl::LsmPolicy,
    ] {
        assert!(strict.defense_in_depth.contains(&control), "{control}");
    }
}

#[test]
fn no_label_or_record_claims_an_inner_control_survives_a_compromise() {
    for control in InnerControl::ALL {
        let label = control.label();
        assert!(label.contains("defense in depth"), "{label}");
        assert!(!label.contains("boundary"), "{label}");
        assert!(!label.contains("surviv"), "{label}");
    }
    for boundary in HostBoundary::ALL {
        assert!(boundary.label().contains("host side"));
    }
    let residue = after_compromise(&strict(), Compromise::GuestRoot);
    let value = serde_json::to_value(&residue).unwrap();
    let remaining: Vec<&str> = value["remaining"]
        .as_array()
        .unwrap()
        .iter()
        .map(|boundary| boundary.as_str().unwrap())
        .collect();
    assert_eq!(remaining, ["hypervisor", "host_perimeter", "broker"]);
    let text = value.to_string();
    assert!(!text.contains("surviv"));
    for mechanism in Mechanism::ALL {
        assert!(!remaining.contains(&mechanism.label()));
    }
}
