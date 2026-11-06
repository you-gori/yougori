//! Durable enrollment state for the engine's shared SSH trust authority.
//! Restoring never enrolls a host or forgives a rejection; timestamps remain history.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownHostsState {
    version: u32,
    next: EnrollmentGeneration,
    active: Vec<HostEnrollment>,
    ever_enrolled: Vec<RemoteHostId>,
    rejections: Vec<HostKeyRejection>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::remote::fakes::{at, host_id, host_key};

    fn enrolled() -> (KnownHosts, HostEnrollment) {
        let mut known = KnownHosts::new();
        let key = host_key(1);
        let enrollment = known
            .enroll(
                host_id(1),
                &key,
                EnrollmentEvidence::OwnerPinned {
                    expected: key.fingerprint(),
                },
                EnrollmentPolicy::default(),
                at(1),
            )
            .unwrap();
        (known, enrollment)
    }

    #[test]
    fn recovery_keeps_rejections_and_retirement_and_never_resets_generation() {
        let (known, enrollment) = enrolled();
        known
            .record_rejection(
                &enrollment.host,
                enrollment.generation,
                RejectionObserver::ManagementSsh,
                RejectionEvidence::SshUnverified,
                at(2),
            )
            .unwrap();
        let bytes = serde_json::to_vec(&known.snapshot()).unwrap();
        let mut restored = KnownHosts::restore(serde_json::from_slice(&bytes).unwrap()).unwrap();
        assert_eq!(restored, known);
        assert!(matches!(
            restored.verify(&enrollment.host, &host_key(1)),
            Err(HostKeyRefusal::Rejected { .. })
        ));
        restored.retire(&enrollment.host);
        let mut restored = KnownHosts::restore(restored.snapshot()).unwrap();
        assert_eq!(
            restored.enroll(
                enrollment.host,
                &host_key(1),
                EnrollmentEvidence::FirstUse,
                EnrollmentPolicy {
                    allow_first_use: true
                },
                at(3)
            ),
            Err(EnrollmentRefusal::NotFirstUse {
                host: enrollment.host
            })
        );
        let new = restored
            .enroll(
                enrollment.host,
                &host_key(2),
                EnrollmentEvidence::OwnerPinned {
                    expected: host_key(2).fingerprint(),
                },
                EnrollmentPolicy::default(),
                at(3),
            )
            .unwrap();
        assert!(new.generation > enrollment.generation);
        assert!(restored
            .rejection(&enrollment.host, enrollment.generation)
            .is_some());
        assert!(restored.verify(&enrollment.host, &host_key(1)).is_err());
        assert!(restored.verify(&enrollment.host, &host_key(2)).is_ok());
    }

    #[test]
    fn inconsistent_restore_cannot_forget_history_or_upgrade_trust() {
        let (known, enrollment) = enrolled();
        let original = known.snapshot();
        let mut broken = original.clone();
        broken.next = enrollment.generation;
        assert_eq!(
            KnownHosts::restore(broken),
            Err(KnownHostsRestoreRefusal::Inconsistent)
        );
        let mut broken = original.clone();
        broken.ever_enrolled.clear();
        assert_eq!(
            KnownHosts::restore(broken),
            Err(KnownHostsRestoreRefusal::Inconsistent)
        );
        let mut broken = original.clone();
        broken.active[0].assumptions = BTreeSet::from([TrustAssumption::ProviderReportedKey]);
        assert_eq!(
            KnownHosts::restore(broken),
            Err(KnownHostsRestoreRefusal::Inconsistent)
        );
        let mut broken = original.clone();
        broken.active.push(enrollment);
        assert_eq!(
            KnownHosts::restore(broken),
            Err(KnownHostsRestoreRefusal::Inconsistent)
        );
        let mut value = serde_json::to_value(original).unwrap();
        value["ignore_rejections"] = serde_json::json!(true);
        assert!(serde_json::from_value::<KnownHostsState>(value).is_err());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownHostsRestoreRefusal {
    UnsupportedVersion,
    TooLarge,
    Inconsistent,
}

impl fmt::Display for KnownHostsRestoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "unsupported saved SSH enrollment version",
            Self::TooLarge => "saved SSH enrollments exceed their bound",
            Self::Inconsistent => {
                "saved SSH enrollments are inconsistent; re-enrollment is not automatic"
            }
        })
    }
}
impl std::error::Error for KnownHostsRestoreRefusal {}

impl KnownHosts {
    pub fn snapshot(&self) -> KnownHostsState {
        KnownHostsState {
            version: 1,
            next: self.next,
            active: self.active.values().cloned().collect(),
            ever_enrolled: self.ever_enrolled.iter().copied().collect(),
            rejections: self.rejections.all(),
        }
    }

    pub fn restore(state: KnownHostsState) -> Result<Self, KnownHostsRestoreRefusal> {
        use KnownHostsRestoreRefusal::*;
        if state.version != 1 {
            return Err(UnsupportedVersion);
        }
        if state.next < EnrollmentGeneration::FIRST {
            return Err(Inconsistent);
        }
        if state.active.len() > 1024
            || state.ever_enrolled.len() > 4096
            || state.rejections.len() > 4096
        {
            return Err(TooLarge);
        }
        let ever: BTreeSet<_> = state.ever_enrolled.iter().copied().collect();
        if ever.len() != state.ever_enrolled.len() {
            return Err(Inconsistent);
        }
        let mut generations = BTreeMap::new();
        for enrollment in state
            .active
            .iter()
            .chain(state.rejections.iter().map(|r| &r.enrollment))
        {
            let assumption = match enrollment.flow {
                EnrollmentFlow::InjectedAtProvisioning => TrustAssumption::ProviderDeliveredKey,
                EnrollmentFlow::ProviderApi | EnrollmentFlow::ProviderConsole => {
                    TrustAssumption::ProviderReportedKey
                }
                EnrollmentFlow::OwnerPinned => TrustAssumption::OwnerVerifiedKey,
                EnrollmentFlow::FirstUse => TrustAssumption::FirstUse,
            };
            if enrollment.generation < EnrollmentGeneration::FIRST
                || enrollment.generation >= state.next
                || !ever.contains(&enrollment.host)
                || enrollment.assumptions != BTreeSet::from([assumption])
            {
                return Err(Inconsistent);
            }
            if let Some(previous) = generations.insert(enrollment.generation, enrollment) {
                if previous != enrollment {
                    return Err(Inconsistent);
                }
            }
        }
        let active: BTreeMap<_, _> = state.active.iter().map(|e| (e.host, e.clone())).collect();
        if active.len() != state.active.len() {
            return Err(Inconsistent);
        }
        let rejections = RejectionBook::default();
        let mut rejected = BTreeSet::new();
        for rejection in state.rejections {
            if !rejected.insert((rejection.host(), rejection.generation())) {
                return Err(Inconsistent);
            }
            if active
                .get(&rejection.host())
                .is_some_and(|current| current.generation < rejection.generation())
            {
                return Err(Inconsistent);
            }
            rejections.insert_first(rejection);
        }
        Ok(Self {
            active,
            ever_enrolled: ever,
            next: state.next,
            rejections,
        })
    }
}
