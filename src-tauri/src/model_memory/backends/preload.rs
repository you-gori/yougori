//! Preloaded weights (GPU part §1.2 and §3.8, vLLM preloaded weights row). Upstream vLLM
//! 0.31.0 documents "a preload daemon sharing processed weights, configuration
//! fingerprints and fallback loading", and "Its IPC protocol is a trusted same-user,
//! same-node facility".
//!
//! A consumer attaches only on a runtime admitted to the preload pilot (the gate enabled
//! zero-copy preload, the evidence behind the runtime's plan still holds, nothing
//! conflicting such as sleep offload runs, and fresh CORE-01 evidence shows its CUDA
//! platform), as the daemon's own release, user and machine, and with the daemon's weights
//! configuration fingerprint; anything else loads through the ordinary loader. The pilot
//! is one daemon with one consumer: a further consumer is the row's later experiment,
//! "Controlled sharing across eligible local consumers", and needs its approval.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::declarations::Technique;
use super::runtime::{BackendRuntime, ExperimentApproval, TechniqueRefusal};
use crate::foundation::evidence::{
    BackendRelease, ConfigurationFingerprint, ProbeRegistry, Remedy, Subject,
};
use crate::foundation::ids::{Clock, Digest};

/// The machine and operating-system account a process runs as, named by digests so raw
/// names stay out of records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPrincipal {
    /// The machine.
    pub node: Digest,
    /// The operating-system account.
    pub user: Digest,
}

/// Why a consumer may not attach to a preload daemon's weights; it loads through the
/// ordinary loader instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PreloadRefusal {
    /// The consumer runtime is not admitted to the preload pilot, or the evidence behind
    /// its plan no longer holds.
    Technique { cause: TechniqueRefusal },
    /// The daemon runs another release.
    OtherRelease {
        daemon: BackendRelease,
        consumer: BackendRelease,
    },
    /// The IPC protocol is a same-node facility.
    OtherNode,
    /// The IPC protocol is trusted only within one user.
    OtherUser,
    /// The weights were processed under another configuration fingerprint.
    ConfigurationMismatch {
        daemon: ConfigurationFingerprint,
        consumer: ConfigurationFingerprint,
    },
    /// The daemon already serves a consumer, and sharing with more is a later experiment
    /// this consumer's runtime may not run.
    SharingNotApproved { cause: TechniqueRefusal },
}

impl PreloadRefusal {
    /// What follows: the ordinary loader, unless the runtime itself was refused.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::Technique { cause } => cause.remedy(),
            Self::OtherRelease { .. }
            | Self::OtherNode
            | Self::OtherUser
            | Self::ConfigurationMismatch { .. }
            | Self::SharingNotApproved { .. } => Remedy::UseOrdinaryLoader,
        }
    }
}

impl fmt::Display for PreloadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::Technique { cause } => write!(f, "{cause}"),
            Self::OtherRelease { daemon, consumer } => write!(
                f,
                "the preload daemon runs {daemon}, not the consumer's {consumer}; {remedy}"
            ),
            Self::OtherNode => write!(
                f,
                "preloaded weights are shared only on the daemon's own machine; {remedy}"
            ),
            Self::OtherUser => write!(
                f,
                "preloaded weights are shared only with the daemon's own user; {remedy}"
            ),
            Self::ConfigurationMismatch { .. } => write!(
                f,
                "the weights were processed under another configuration fingerprint; {remedy}"
            ),
            Self::SharingNotApproved { cause } => write!(
                f,
                "the daemon already serves a consumer, and sharing with more is not approved: \
                 {cause}"
            ),
        }
    }
}

impl std::error::Error for PreloadRefusal {}

/// A consumer attached to a daemon's weights. Only [`PreloadDaemon::attach`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreloadAttachment {
    consumer: Digest,
    release: BackendRelease,
}

impl PreloadAttachment {
    /// The identity of the consumer runtime.
    pub fn consumer(&self) -> Digest {
        self.consumer
    }

    /// The release both run.
    pub fn release(&self) -> &BackendRelease {
        &self.release
    }
}

/// A preload daemon sharing processed weights with local consumers (GPU part §1.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreloadDaemon {
    release: BackendRelease,
    principal: LocalPrincipal,
    weights_configuration: ConfigurationFingerprint,
    consumers: BTreeSet<Digest>,
}

impl PreloadDaemon {
    /// A daemon of `release` running as `principal`, holding weights processed under
    /// `weights_configuration`.
    pub fn new(
        release: BackendRelease,
        principal: LocalPrincipal,
        weights_configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            release,
            principal,
            weights_configuration,
            consumers: BTreeSet::new(),
        }
    }

    /// How many consumers are attached.
    pub fn consumers(&self) -> usize {
        self.consumers.len()
    }

    /// Attaches `consumer`, running as `principal` and wanting weights processed under
    /// `weights_configuration`, while the evidence behind the consumer's plan and its CUDA
    /// platform still holds in `registry`, the registry the plan was made with (T01: a plan
    /// expires at its earliest evidence expiry). Attaching an attached consumer again
    /// changes nothing.
    pub fn attach<C: Clock>(
        &mut self,
        consumer: &BackendRuntime,
        principal: LocalPrincipal,
        weights_configuration: ConfigurationFingerprint,
        approvals: &[ExperimentApproval],
        registry: &ProbeRegistry<C>,
    ) -> Result<PreloadAttachment, PreloadRefusal> {
        consumer
            .admit_with_evidence(Technique::PreloadDaemonPilot, &[], registry)
            .map_err(|cause| PreloadRefusal::Technique { cause })?;
        if *consumer.release() != self.release {
            return Err(PreloadRefusal::OtherRelease {
                daemon: self.release.clone(),
                consumer: consumer.release().clone(),
            });
        }
        if principal.node != self.principal.node {
            return Err(PreloadRefusal::OtherNode);
        }
        if principal.user != self.principal.user {
            return Err(PreloadRefusal::OtherUser);
        }
        if weights_configuration != self.weights_configuration {
            return Err(PreloadRefusal::ConfigurationMismatch {
                daemon: self.weights_configuration,
                consumer: weights_configuration,
            });
        }
        let identity = Subject::Runtime(consumer.plan().runtime().clone()).identity();
        if !self.consumers.is_empty() && !self.consumers.contains(&identity) {
            consumer
                .admit_with_evidence(Technique::ControlledLocalSharing, approvals, registry)
                .map_err(|cause| PreloadRefusal::SharingNotApproved { cause })?;
        }
        self.consumers.insert(identity);
        Ok(PreloadAttachment {
            consumer: identity,
            release: self.release.clone(),
        })
    }

    /// Detaches `consumer`; true if it was attached.
    pub fn detach(&mut self, consumer: &BackendRuntime) -> bool {
        let identity = Subject::Runtime(consumer.plan().runtime().clone()).identity();
        self.consumers.remove(&identity)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::platform::PlatformRefusal;
    use super::super::test_support::{vllm_0_29_0, vllm_0_31_0, Fixture, Loaded};
    use super::*;
    use crate::foundation::evidence::{EvidenceRefusal, ModeRefusal, Optimization, Staleness};
    use crate::foundation::ids::digest;

    fn principal(node: &str, user: &str) -> LocalPrincipal {
        LocalPrincipal {
            node: digest("yougori/test/node/v1", &[node.as_bytes()]),
            user: digest("yougori/test/user/v1", &[user.as_bytes()]),
        }
    }

    fn weights(model: &str) -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("model", model), ("dtype", "bf16")]).unwrap()
    }

    fn consumer(instance: &'static str) -> Loaded {
        Fixture::new(vllm_0_31_0())
            .instance(instance)
            .modes(&[Optimization::ZeroCopyPreload])
            .build()
            .unwrap()
    }

    fn daemon() -> PreloadDaemon {
        PreloadDaemon::new(vllm_0_31_0(), principal("m1", "alice"), weights("m"))
    }

    #[test]
    fn preloaded_weights_never_cross_users_or_machines() {
        let mut daemon = daemon();
        let consumer = consumer("a");
        for (other, refusal) in [
            (principal("m2", "alice"), PreloadRefusal::OtherNode),
            (principal("m1", "bob"), PreloadRefusal::OtherUser),
        ] {
            let refused = daemon
                .attach(&consumer, other, weights("m"), &[], &consumer.registry)
                .unwrap_err();
            assert_eq!(refused, refusal);
            assert_eq!(refused.remedy(), Remedy::UseOrdinaryLoader);
        }
        assert_eq!(daemon.consumers(), 0);
        let attached = daemon
            .attach(
                &consumer,
                principal("m1", "alice"),
                weights("m"),
                &[],
                &consumer.registry,
            )
            .unwrap();
        assert_eq!(attached.release(), &vllm_0_31_0());
        assert_eq!(daemon.consumers(), 1);
    }

    #[test]
    fn another_configuration_falls_back_to_loading() {
        let consumer = consumer("a");
        let refusal = daemon()
            .attach(
                &consumer,
                principal("m1", "alice"),
                weights("other"),
                &[],
                &consumer.registry,
            )
            .unwrap_err();
        assert_eq!(
            refusal,
            PreloadRefusal::ConfigurationMismatch {
                daemon: weights("m"),
                consumer: weights("other")
            }
        );
        assert_eq!(refusal.remedy(), Remedy::UseOrdinaryLoader);
        assert!(refusal.to_string().contains("ordinary loader"));
    }

    #[test]
    fn only_a_runtime_admitted_to_the_pilot_attaches() {
        let alice = principal("m1", "alice");
        let sleeping = Fixture::new(vllm_0_31_0())
            .modes(&[Optimization::SleepWeightOffload])
            .build()
            .unwrap();
        assert!(matches!(
            daemon().attach(&sleeping, alice, weights("m"), &[], &sleeping.registry),
            Err(PreloadRefusal::Technique {
                cause: TechniqueRefusal::Mode {
                    cause: ModeRefusal::DocumentedConflict { .. },
                    ..
                }
            })
        ));
        let pinned_today = Fixture::new(vllm_0_29_0())
            .modes(&[Optimization::ZeroCopyPreload])
            .build()
            .unwrap();
        assert!(matches!(
            daemon().attach(
                &pinned_today,
                alice,
                weights("m"),
                &[],
                &pinned_today.registry
            ),
            Err(PreloadRefusal::Technique {
                cause: TechniqueRefusal::Mode {
                    cause: ModeRefusal::UnknownRelease { .. },
                    ..
                }
            })
        ));
        let mut old_daemon = PreloadDaemon::new(vllm_0_29_0(), alice, weights("m"));
        let current = consumer("a");
        assert!(matches!(
            old_daemon.attach(&current, alice, weights("m"), &[], &current.registry),
            Err(PreloadRefusal::OtherRelease { .. })
        ));
    }

    #[test]
    fn a_consumer_never_attaches_on_stale_evidence() {
        // Review proof (R1-d): a consumer attached two hours after the 600-second evidence
        // behind its zero-copy preload went stale. Here the preload evidence has lapsed and
        // the platform's still holds.
        let alice = principal("m1", "alice");
        let mut daemon = daemon();
        let late = consumer("a");
        late.clock.advance(Duration::from_secs(601));
        assert!(late.plan().valid_until().unwrap() < late.clock.now());
        let refusal = daemon
            .attach(&late, alice, weights("m"), &[], &late.registry)
            .unwrap_err();
        assert!(matches!(
            &refusal,
            PreloadRefusal::Technique {
                cause: TechniqueRefusal::EvidenceNoLongerHolds {
                    cause: EvidenceRefusal::Stale {
                        staleness: Staleness::TooOld { .. },
                        ..
                    },
                    ..
                }
            }
        ));
        assert_eq!(refusal.remedy(), Remedy::RunCheckAgain);
        // Two hours on, as in the proof, the platform's evidence has lapsed too.
        late.clock.advance(Duration::from_secs(7_200));
        assert!(matches!(
            daemon.attach(&late, alice, weights("m"), &[], &late.registry),
            Err(PreloadRefusal::Technique {
                cause: TechniqueRefusal::PlatformNotShown {
                    cause: PlatformRefusal::Evidence { .. },
                    ..
                }
            })
        ));
        assert_eq!(daemon.consumers(), 0);

        // An attached consumer is not attached again once its evidence lapsed.
        let current = consumer("b");
        daemon
            .attach(&current, alice, weights("m"), &[], &current.registry)
            .unwrap();
        current.clock.advance(Duration::from_secs(601));
        assert!(daemon
            .attach(&current, alice, weights("m"), &[], &current.registry)
            .is_err());
        assert_eq!(daemon.consumers(), 1);
    }

    #[test]
    fn the_pilot_serves_one_consumer_and_more_need_the_sharing_experiment() {
        let alice = principal("m1", "alice");
        let mut daemon = daemon();
        let first = consumer("a");
        let second = consumer("b");
        daemon
            .attach(&first, alice, weights("m"), &[], &first.registry)
            .unwrap();
        assert!(daemon
            .attach(&first, alice, weights("m"), &[], &first.registry)
            .is_ok());
        assert_eq!(daemon.consumers(), 1);

        let refusal = daemon
            .attach(&second, alice, weights("m"), &[], &second.registry)
            .unwrap_err();
        assert!(matches!(
            refusal,
            PreloadRefusal::SharingNotApproved {
                cause: TechniqueRefusal::ExperimentNotApproved {
                    technique: Technique::ControlledLocalSharing,
                    ..
                }
            }
        ));
        let approval = ExperimentApproval {
            technique: Technique::ControlledLocalSharing,
            release: vllm_0_31_0(),
            record: digest("yougori/test/experiment/v1", &[b"sharing"]),
        };
        daemon
            .attach(&second, alice, weights("m"), &[approval], &second.registry)
            .unwrap();
        assert_eq!(daemon.consumers(), 2);
        assert!(daemon.detach(&first));
        assert!(!daemon.detach(&first));
        assert_eq!(daemon.consumers(), 1);
    }
}
