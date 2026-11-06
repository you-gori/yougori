//! The serving facts FAST-02 needs, read from CORE-01 (S2 CORE-01; S13 FAST-02, line 242).
//!
//! Checkpoint compatibility, free GPU memory and peer topology are CORE-01 capabilities,
//! each judged by the probe registry under its own rules and in its own order: evidence
//! must exist for the exact subject, come from a source at least as strong as the policy
//! and the capability's floor ask for (free memory only from a host probe), be conclusive,
//! have been observed under the configuration in force, be fresh on the registry's clock
//! session, and show the capability supported. Only then is its measured detail used.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::settings::PeerTopology;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, GpuDeviceSubject,
    ModelCheckpointSubject, ProbeRegistry, Requirement, RuntimeSubject, Subject, SupportDetail,
};
use crate::foundation::ids::{Clock, Digest};

/// A fact FAST-02 needs as evidence (line 242).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingFact {
    /// What one checkpoint supports on one pinned engine and hardware class.
    CheckpointCompatibility,
    /// Free and total memory of each assigned GPU.
    FreeCapacity,
    /// Measured peer access between the runtime's GPUs.
    PeerTopology,
}

impl ServingFact {
    /// The CORE-01 capability the fact is evidence of.
    pub const fn capability(self) -> Capability {
        match self {
            Self::CheckpointCompatibility => Capability::CheckpointCompatibility,
            Self::FreeCapacity => Capability::GpuFreeMemory,
            Self::PeerTopology => Capability::PeerTopology,
        }
    }
}

impl fmt::Display for ServingFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CheckpointCompatibility => "checkpoint compatibility",
            Self::FreeCapacity => "free GPU capacity",
            Self::PeerTopology => "peer topology",
        })
    }
}

/// Why a serving fact cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gap", rename_all = "snake_case")]
pub enum EvidenceGap {
    /// CORE-01 refused the evidence, with the first of its refusals: missing, from too
    /// weak a source, inconclusive, observed under another configuration, stale or
    /// unsupported.
    Refused {
        fact: ServingFact,
        refusal: EvidenceRefusal,
    },
    /// The supported evidence carried another kind of detail than the fact. CORE-01 keeps
    /// only details that fit their capability, so its registry never yields this.
    OtherDetail { fact: ServingFact },
    /// The compatibility record given is not the one the evidence measured.
    OtherRecord { measured: Digest, given: Digest },
}

impl fmt::Display for EvidenceGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { fact, refusal } => {
                write!(f, "the {fact} evidence cannot be used: {refusal}")
            }
            Self::OtherDetail { fact } => {
                write!(f, "the {fact} evidence does not carry its measurement")
            }
            Self::OtherRecord { .. } => f.write_str(
                "the compatibility record is not the one that was measured; measure this one",
            ),
        }
    }
}

impl std::error::Error for EvidenceGap {}

/// The registry serving facts are read from, with the configuration in force.
pub(super) struct EvidenceSource<'a, C: Clock> {
    pub(super) registry: &'a ProbeRegistry<C>,
    pub(super) configuration: ConfigurationFingerprint,
}

impl<C: Clock> EvidenceSource<'_, C> {
    /// The supported detail of `fact` on `subject`, or the registry's first refusal.
    fn detail(
        &self,
        fact: ServingFact,
        subject: Subject,
        policy: EvidencePolicy,
    ) -> Result<SupportDetail, EvidenceGap> {
        let requirement = Requirement::new(
            fact.capability(),
            subject,
            policy.minimum_source,
            policy.max_age,
            self.configuration,
        );
        self.registry
            .evaluate(&requirement)
            .map(|satisfied| satisfied.detail().clone())
            .map_err(|refusal| EvidenceGap::Refused { fact, refusal })
    }

    /// Checks that `record`, by its digest, is the compatibility the registry measured
    /// for `subject`.
    pub(super) fn compatibility(
        &self,
        subject: ModelCheckpointSubject,
        record: Digest,
        policy: EvidencePolicy,
    ) -> Result<(), EvidenceGap> {
        let fact = ServingFact::CheckpointCompatibility;
        match self.detail(fact, Subject::ModelCheckpoint(subject), policy)? {
            SupportDetail::CheckpointCompatibility { record: measured } if measured == record => {
                Ok(())
            }
            SupportDetail::CheckpointCompatibility { record: measured } => {
                Err(EvidenceGap::OtherRecord {
                    measured,
                    given: record,
                })
            }
            _ => Err(EvidenceGap::OtherDetail { fact }),
        }
    }

    /// The free and total bytes the host measured on `device`.
    pub(super) fn free_memory(
        &self,
        device: GpuDeviceSubject,
        policy: EvidencePolicy,
    ) -> Result<(u64, u64), EvidenceGap> {
        let fact = ServingFact::FreeCapacity;
        match self.detail(fact, Subject::GpuDevice(device), policy)? {
            SupportDetail::GpuMemory {
                free_bytes,
                total_bytes,
            } => Ok((free_bytes, total_bytes.get())),
            _ => Err(EvidenceGap::OtherDetail { fact }),
        }
    }

    /// The peer topology measured for `runtime`'s GPUs.
    pub(super) fn topology(
        &self,
        runtime: &RuntimeSubject,
        policy: EvidencePolicy,
    ) -> Result<PeerTopology, EvidenceGap> {
        let fact = ServingFact::PeerTopology;
        match self.detail(fact, Subject::Runtime(runtime.clone()), policy)? {
            SupportDetail::PeerTopology {
                device_count,
                paths,
            } => Ok(PeerTopology {
                device_count: device_count.get(),
                paths,
            }),
            _ => Err(EvidenceGap::OtherDetail { fact }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::foundation::evidence::{SourceClass, Staleness};
    use crate::foundation::ids::ExecutionCategory;
    use crate::model_memory::profiles::selection::CheckpointCompatibility;
    use crate::model_memory::profiles::settings::PeerAccess;
    use crate::model_memory::profiles::testkit::{
        compatibility, compatibility_script, configuration, d, device, engine, free_memory_script,
        logical, registry_with, runtime, single_gpu, start_clock, topology_script,
        two_gpu_topology, GIB,
    };

    const MINUTE: Duration = Duration::from_secs(60);

    fn policy(minimum_source: SourceClass) -> EvidencePolicy {
        EvidencePolicy {
            minimum_source,
            max_age: MINUTE,
        }
    }

    #[test]
    fn each_fact_is_read_as_its_core_01_capability() {
        assert_eq!(
            ServingFact::CheckpointCompatibility.capability(),
            Capability::CheckpointCompatibility
        );
        assert_eq!(
            ServingFact::FreeCapacity.capability(),
            Capability::GpuFreeMemory
        );
        assert_eq!(
            ServingFact::PeerTopology.capability(),
            Capability::PeerTopology
        );
    }

    #[test]
    fn measured_values_are_read_from_the_registry() {
        let shared = runtime(ExecutionCategory::SharedKernelGpuRuntime);
        let topology = two_gpu_topology(PeerAccess::Verified);
        let registry = registry_with(
            start_clock(),
            &[
                compatibility_script(&single_gpu(), compatibility().digest()),
                free_memory_script(device(0), 20 * GIB, 24 * GIB),
                topology_script(shared.clone(), &topology),
            ],
        );
        let source = EvidenceSource {
            registry: &registry,
            configuration: configuration(),
        };
        let any = policy(SourceClass::Fixture);
        let subject = CheckpointCompatibility::subject(&logical(), &engine(), &single_gpu());
        assert_eq!(
            source.compatibility(subject.clone(), compatibility().digest(), any),
            Ok(())
        );
        assert_eq!(
            source.compatibility(subject, d("another record"), any),
            Err(EvidenceGap::OtherRecord {
                measured: compatibility().digest(),
                given: d("another record"),
            })
        );
        assert_eq!(source.free_memory(device(0), any), Ok((20 * GIB, 24 * GIB)));
        assert_eq!(source.topology(&shared, any), Ok(topology));
    }

    #[test]
    fn refusals_come_in_core_01_order() {
        // A guest's report of free memory, read after it went stale: a source too weak for
        // free memory is reported before staleness.
        let clock = start_clock();
        let mut guest = free_memory_script(device(0), 20 * GIB, 24 * GIB);
        guest.source = SourceClass::GuestReport;
        let registry = registry_with(clock.clone(), &[guest]);
        clock.advance(MINUTE * 2);
        let current = EvidenceSource {
            registry: &registry,
            configuration: configuration(),
        };
        assert!(matches!(
            current.free_memory(device(0), policy(SourceClass::GuestReport)),
            Err(EvidenceGap::Refused {
                fact: ServingFact::FreeCapacity,
                refusal: EvidenceRefusal::SourceTooWeak {
                    observed: SourceClass::GuestReport,
                    required: SourceClass::HostProbe,
                    ..
                }
            })
        ));
        // A host's measurement, stale and under a configuration since replaced: the
        // changed configuration is reported before staleness.
        let clock = start_clock();
        let registry = registry_with(
            clock.clone(),
            &[free_memory_script(device(0), 20 * GIB, 24 * GIB)],
        );
        clock.advance(MINUTE * 2);
        let replaced = EvidenceSource {
            registry: &registry,
            configuration: ConfigurationFingerprint::from_digest(d("new configuration")),
        };
        assert!(matches!(
            replaced.free_memory(device(0), policy(SourceClass::HostProbe)),
            Err(EvidenceGap::Refused {
                fact: ServingFact::FreeCapacity,
                refusal: EvidenceRefusal::FingerprintChanged { .. }
            })
        ));
        assert!(matches!(
            current_on(&registry).free_memory(device(0), policy(SourceClass::HostProbe)),
            Err(EvidenceGap::Refused {
                fact: ServingFact::FreeCapacity,
                refusal: EvidenceRefusal::Stale {
                    staleness: Staleness::TooOld { .. },
                    ..
                }
            })
        ));
        // Nothing observed for this GPU at all comes first of all.
        assert!(matches!(
            current_on(&registry).free_memory(device(1), policy(SourceClass::HostProbe)),
            Err(EvidenceGap::Refused {
                fact: ServingFact::FreeCapacity,
                refusal: EvidenceRefusal::Missing { .. }
            })
        ));
    }

    fn current_on<C: Clock>(registry: &ProbeRegistry<C>) -> EvidenceSource<'_, C> {
        EvidenceSource {
            registry,
            configuration: configuration(),
        }
    }
}
