//! The typed launch profile and the reservation seam (S2 CORE-03 and CORE-04 rows, lines
//! 40–41; VM part §8.1 launch records; the VB1 and VL1 integration notes of the rollout
//! plan: the backend's launch request carries a CORE-03 `ReservationId` while the
//! coordinator's boot request carries a CORE-04 `ReservationKey`).
//!
//! A [`LaunchProfile`] holds what the lifecycle's boot request does not carry and the
//! backend's launch request needs: the host configuration in force, the contract digest
//! of the policy plan (V01), the pinned artifacts, the device profile and the §1.3
//! required properties. A [`ReservationResolver`] maps the coordination reservation key
//! of a boot to the ledger reservation the backend binds; [`LedgerReservations`] does it
//! over the host's shared CORE-03 ledger.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{ReservationKey, SharedLedger};
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{Clock, Digest, ExecutionId};
use crate::foundation::ledger::{Requester, ReservationId, ReservationState};
use crate::sandbox::backend::{DeviceProfile, PinnedArtifacts, RequiredProperties};
use crate::sandbox_contract::policy::ContractIdentity;

/// What a launch of one execution binds beyond the coordinator's boot request (VM part
/// §8.1 line 2433: contract digest, backend and artifact versions, device profile and
/// required properties).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchProfile {
    /// The host configuration in force; evidence under another does not apply (CORE-01).
    pub configuration: ConfigurationFingerprint,
    /// The digest of the resolved contract the policy layer planned the launch under: an
    /// integrity identifier, never a proof (§0.2 line 1838).
    pub contract: Digest,
    pub pinned: PinnedArtifacts,
    pub device_profile: DeviceProfile,
    pub required: RequiredProperties,
}

impl LaunchProfile {
    /// A profile under the contract V01 planned; only its digest travels to the backend.
    pub fn new(
        configuration: ConfigurationFingerprint,
        contract: ContractIdentity,
        pinned: PinnedArtifacts,
        device_profile: DeviceProfile,
        required: RequiredProperties,
    ) -> Self {
        Self {
            configuration,
            contract: contract.digest(),
            pinned,
            device_profile,
            required,
        }
    }
}

/// Why a coordination reservation key names no ledger reservation the backend may bind.
/// It reads through `foundation::strict_serde`: a `refusal` that is not a string, or a key
/// repeated in one object, is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservationUnresolved {
    /// No open coordination reservation carries this key.
    NotOpen { key: ReservationKey },
    /// The reservation belongs to another execution.
    OtherExecution {
        key: ReservationKey,
        owner: ExecutionId,
    },
    /// The reservation is open but no longer reservable: it is releasing.
    NotReservable {
        key: ReservationKey,
        state: ReservationState,
    },
}

crate::foundation::strict_serde::strict_tag!(ReservationUnresolved, "refusal");

impl fmt::Display for ReservationUnresolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOpen { key } => {
                write!(f, "no open coordination reservation carries key {key}")
            }
            Self::OtherExecution { key, owner } => {
                write!(f, "reservation {key} belongs to execution {owner}")
            }
            Self::NotReservable { key, state } => {
                write!(f, "reservation {key} is {state:?}, not reservable")
            }
        }
    }
}

impl std::error::Error for ReservationUnresolved {}

/// Maps the coordination reservation of one boot to the CORE-03 reservation the backend
/// binds in its launch record (S10: reserve before creating; the launch runs inside it).
pub trait ReservationResolver {
    fn resolve(
        &self,
        execution: &ExecutionId,
        key: &ReservationKey,
    ) -> Result<ReservationId, ReservationUnresolved>;
}

/// The prefix of the operation identity a coordination reservation carries in the
/// ledger's provenance. It mirrors the convention of `foundation::coordination`'s ledger
/// adapter, which keys its reservations by operation identity so recovery can find them;
/// the scenario tests check the two agree end to end.
const COORDINATION_OPERATION_PREFIX: &str = "rsv-";

/// The resolver over the host's one CORE-03 ledger, shared with the coordinator's
/// capacity port through the same handle, so the backend binds the very reservation the
/// launch transaction made.
#[derive(Clone)]
pub struct LedgerReservations<C: Clock> {
    ledger: SharedLedger<C>,
}

impl<C: Clock> LedgerReservations<C> {
    pub fn new(ledger: SharedLedger<C>) -> Self {
        Self { ledger }
    }
}

impl<C: Clock> fmt::Debug for LedgerReservations<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LedgerReservations(shared ledger)")
    }
}

impl<C: Clock> ReservationResolver for LedgerReservations<C> {
    fn resolve(
        &self,
        execution: &ExecutionId,
        key: &ReservationKey,
    ) -> Result<ReservationId, ReservationUnresolved> {
        let wanted = format!("{COORDINATION_OPERATION_PREFIX}{}", key.digest().to_hex());
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = ledger
            .open_reservations()
            .find(|record| {
                let provenance = record.provenance();
                provenance.requester == Requester::Coordination
                    && provenance.operation.as_str() == wanted
            })
            .ok_or(ReservationUnresolved::NotOpen { key: *key })?;
        if &record.provenance().execution != execution {
            return Err(ReservationUnresolved::OtherExecution {
                key: *key,
                owner: record.provenance().execution.clone(),
            });
        }
        match record.state() {
            ReservationState::Granted | ReservationState::InUse => Ok(record.id()),
            state => Err(ReservationUnresolved::NotReservable { key: *key, state }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::sandbox::backend::DeviceExposure;
    use std::time::Duration;

    #[test]
    fn a_profile_carries_only_the_contract_digest_and_refuses_unknown_fields() {
        let profile = LaunchProfile::new(
            ConfigurationFingerprint::from_settings([("kvm", "1")]).unwrap(),
            serde_json::from_value(
                serde_json::to_value(digest("yougori/test/contract/v1", &[b"c"])).unwrap(),
            )
            .unwrap(),
            PinnedArtifacts {
                guest_image: digest("yougori/test/image/v1", &[b"i"]),
                backend: digest("yougori/test/backend/v1", &[b"b"]),
            },
            DeviceProfile {
                identity: digest("yougori/test/profile/v1", &[b"minimal"]),
                devices: DeviceExposure::cpu_only(),
            },
            RequiredProperties::strictest(Duration::from_secs(60)),
        );
        assert_eq!(
            profile.contract,
            digest("yougori/test/contract/v1", &[b"c"])
        );
        let json = serde_json::to_value(&profile).unwrap();
        assert_eq!(
            serde_json::from_value::<LaunchProfile>(json.clone()).unwrap(),
            profile
        );
        let mut extra = json;
        extra["enforced"] = true.into();
        assert!(serde_json::from_value::<LaunchProfile>(extra).is_err());
    }

    #[test]
    fn refusals_name_the_key() {
        let key = ReservationKey::derive(
            &ExecutionId::new("exe-1").unwrap(),
            &crate::foundation::coordination::ReservationPurpose::Sandbox {
                boot: crate::foundation::ids::SandboxBootGeneration::FIRST,
            },
        );
        let refusal = ReservationUnresolved::NotOpen { key };
        assert!(refusal.to_string().contains(&key.to_string()));
        let json = serde_json::to_value(&refusal).unwrap();
        assert_eq!(json["refusal"], "not_open");
        assert_eq!(
            serde_json::from_value::<ReservationUnresolved>(json).unwrap(),
            refusal
        );
        assert!(ReservationUnresolved::OtherExecution {
            key,
            owner: ExecutionId::new("exe-2").unwrap()
        }
        .to_string()
        .contains("exe-2"));
    }

    /// `foundation::strict_serde` (the S06 item "Strict tags of read-back tagged enums" of
    /// docs/combined-plan-leftover-tasks.md): every variant writes back unchanged and reads
    /// at the top level and nested, where serde buffers it, as a launch problem's refusal
    /// would be; a number for its tag or for the ledger state, and a repeated tag or field,
    /// are refused both ways.
    #[test]
    fn a_number_tag_or_a_repeated_key_is_refused() {
        #[derive(Debug, Deserialize)]
        #[serde(tag = "wrap", rename_all = "snake_case")]
        enum Wrapped {
            Inner { value: ReservationUnresolved },
        }
        let top = |text: &str| serde_json::from_str::<ReservationUnresolved>(text);
        let nested = |text: &str| {
            serde_json::from_str::<Wrapped>(&format!(r#"{{"wrap":"inner","value":{text}}}"#))
                .map(|Wrapped::Inner { value }| value)
        };
        let key = ReservationKey::derive(
            &ExecutionId::new("exe-1").unwrap(),
            &crate::foundation::coordination::ReservationPurpose::Sandbox {
                boot: crate::foundation::ids::SandboxBootGeneration::FIRST,
            },
        );
        let k = serde_json::to_string(&key).unwrap();
        let samples = [
            (
                "not_open",
                ReservationUnresolved::NotOpen { key },
                format!(r#"{{"refusal":"not_open","key":{k}}}"#),
            ),
            (
                "other_execution",
                ReservationUnresolved::OtherExecution {
                    key,
                    owner: ExecutionId::new("exe-2").unwrap(),
                },
                format!(r#"{{"refusal":"other_execution","key":{k},"owner":"exe-2"}}"#),
            ),
            (
                "not_reservable",
                ReservationUnresolved::NotReservable {
                    key,
                    state: ReservationState::Releasing,
                },
                format!(r#"{{"refusal":"not_reservable","key":{k},"state":"releasing"}}"#),
            ),
        ];
        for (index, (tag, refusal, text)) in samples.iter().enumerate() {
            assert_eq!(&serde_json::to_string(refusal).unwrap(), text);
            assert_eq!(&top(text).unwrap(), refusal);
            assert_eq!(&nested(text).unwrap(), refusal);
            let tag_field = format!(r#""refusal":"{tag}""#);
            let mut refused = vec![
                text.replacen(&tag_field, &format!(r#""refusal":{index}"#), 1),
                text.replacen(&tag_field, &format!("{tag_field},{tag_field}"), 1),
                text.replacen(r#","key":"#, &format!(r#","key":{k},"key":"#), 1),
            ];
            if text.contains(r#""state":"releasing""#) {
                // `releasing` is the third state.
                refused.push(text.replacen(r#""state":"releasing""#, r#""state":2"#, 1));
            }
            for text in &refused {
                assert!(top(text).is_err(), "{text}");
                assert!(nested(text).is_err(), "{text} nested");
            }
        }
    }
}
