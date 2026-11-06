//! What a launch binds (VM-W16 row, line 2613; §8.1 line 2433): the sandbox and its
//! generations, the contract digest, the pinned artifacts, the device profile, the
//! required properties and the CORE-03 reservation the launch runs inside.

use serde::{Deserialize, Serialize};

use super::facets::{DeviceExposure, RequiredProperties};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{Digest, ExecutionId, TenantId};
use crate::foundation::ledger::ReservationId;

/// The artifacts a launch is pinned to, by identity (§1.3 evidence facet, line 1906;
/// §8.1 "backend and artifact versions"). The backend refuses to launch any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedArtifacts {
    /// The guest image, by its catalog identity.
    pub guest_image: Digest,
    /// The backend build, by its artifact identity.
    pub backend: Digest,
}

/// The versioned minimal device profile one VM is built with (§0.1 line 1825; VM-P02
/// line 2782). The measured inventory must match it exactly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    /// The identity of the approved profile.
    pub identity: Digest,
    pub devices: DeviceExposure,
}

/// A request to launch one boot of one sandbox (VM-W16; §8.1).
///
/// The backend interprets nothing here beyond what it needs to launch: the contract
/// digest is an opaque identity the policy layer owns, and the reservation was made by
/// the caller in the CORE-03 ledger before this request (S10: reserve before creating);
/// the backend never reserves for itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    /// The boot generation, policy epoch and authorization epoch of this launch (S3.1).
    pub generations: SandboxGenerations,
    /// The host machine, by the identity digest its host adapter derives (CORE-01
    /// subjects).
    pub machine: Digest,
    /// The host configuration in force now; evidence observed under any other
    /// configuration does not apply (CORE-01).
    pub configuration: ConfigurationFingerprint,
    /// The authority contract's digest: an integrity identifier, not a proof (§0.2 line
    /// 1663).
    pub contract: Digest,
    pub pinned: PinnedArtifacts,
    pub device_profile: DeviceProfile,
    pub required: RequiredProperties,
    /// The CORE-03 reservation the launch runs inside.
    pub reservation: ReservationId,
}

/// A request to the separate developer emulation facility (§1.3 line 1910). By
/// construction it carries no contract, no required properties, no tenant and no device
/// profile: an emulated VM is not a sandbox and gets no production sandbox credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmulationRequest {
    pub execution: ExecutionId,
    pub guest_image: Digest,
    /// Emulation still runs inside a reservation; host capacity is counted once
    /// (CORE-03).
    pub reservation: ReservationId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use std::time::Duration;

    fn reservation(number: u64) -> ReservationId {
        serde_json::from_value(number.into()).unwrap()
    }

    #[test]
    fn a_launch_request_round_trips_and_refuses_unknown_fields() {
        let request = LaunchRequest {
            execution: ExecutionId::new("exe-1").unwrap(),
            tenant: TenantId::new("tenant-1").unwrap(),
            generations: SandboxGenerations::FIRST,
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            configuration: ConfigurationFingerprint::from_settings([("kvm", "1")]).unwrap(),
            contract: digest("yougori/test/contract/v1", &[b"c"]),
            pinned: PinnedArtifacts {
                guest_image: digest("yougori/test/image/v1", &[b"i"]),
                backend: digest("yougori/test/backend/v1", &[b"b"]),
            },
            device_profile: DeviceProfile {
                identity: digest("yougori/test/profile/v1", &[b"minimal"]),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(Duration::from_secs(60)),
            reservation: reservation(4),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["reservation"], 4);
        assert_eq!(json["generations"]["boot"], 1);
        assert_eq!(
            serde_json::from_value::<LaunchRequest>(json.clone()).unwrap(),
            request
        );
        let mut extra = json;
        extra["accelerator"] = "kvm".into();
        assert!(serde_json::from_value::<LaunchRequest>(extra).is_err());
    }

    #[test]
    fn an_emulation_request_has_no_room_for_production_properties() {
        let json = serde_json::json!({
            "execution": "exe-1",
            "guest_image": digest("yougori/test/image/v1", &[b"i"]),
            "reservation": 1,
        });
        let request: EmulationRequest = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(request.execution.as_str(), "exe-1");
        for (field, value) in [
            ("required", serde_json::json!({})),
            ("contract", serde_json::json!("00")),
            ("tenant", serde_json::json!("tenant-1")),
        ] {
            let mut widened = json.clone();
            widened[field] = value;
            assert!(
                serde_json::from_value::<EmulationRequest>(widened).is_err(),
                "{field}"
            );
        }
    }
}
