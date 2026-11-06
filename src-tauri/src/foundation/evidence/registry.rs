//! The probe registry: typed adapters registered under their capability, and the
//! latest envelope per capability and subject (CORE-01).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::envelope::{
    Capability, ClockReading, ClockSession, ConfigurationFingerprint, EvidenceEnvelope,
    Observation, SourceClass,
};
use super::requirement::{EvidenceRefusal, EvidenceStore, Requirement, Satisfied};
use super::subject::{Subject, SubjectKind};
use crate::foundation::ids::Clock;

/// Host state a probe could be tempted to change. Probes only observe: an adapter that
/// declares any of these is refused (S7, consumer hardware: never change global driver
/// settings, antivirus exclusions or power policy; S13: never auto-change device state,
/// global driver or power policy, host cache settings or machine-wide communication
/// settings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostChange {
    /// S7, S13.
    GlobalDriverSetting,
    /// S7; antivirus (Defender) exclusions are not rollout steps.
    AntivirusExclusion,
    /// S7, S13.
    PowerPolicy,
    /// S13.
    DeviceState,
    /// S13: global or host cache settings.
    HostCacheSetting,
    /// S13: a peer-access probe cannot justify machine-wide communication settings.
    MachineWideCommunicationSetting,
}

impl HostChange {
    pub const ALL: [Self; 6] = [
        Self::GlobalDriverSetting,
        Self::AntivirusExclusion,
        Self::PowerPolicy,
        Self::DeviceState,
        Self::HostCacheSetting,
        Self::MachineWideCommunicationSetting,
    ];
}

impl fmt::Display for HostChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GlobalDriverSetting => "a global driver setting",
            Self::AntivirusExclusion => "an antivirus exclusion",
            Self::PowerPolicy => "the power policy",
            Self::DeviceState => "device state",
            Self::HostCacheSetting => "a host cache setting",
            Self::MachineWideCommunicationSetting => "a machine-wide communication setting",
        })
    }
}

/// A typed check of one capability (CORE-01: each GPU, hypervisor, OS or provider check
/// is a typed adapter).
///
/// An adapter observes and never changes host state. Its source class is read once, when
/// it is registered, and every envelope it produces carries that class: a guest-report
/// adapter stays a guest report whatever it or the guest's payload claims later.
pub trait ProbeAdapter: Send + Sync {
    /// The capability the adapter is registered under.
    fn capability(&self) -> Capability;

    /// Where the adapter's observations come from; read only at registration.
    fn source(&self) -> SourceClass;

    /// Host state the adapter changes to observe; must be empty.
    fn host_changes(&self) -> Vec<HostChange>;

    /// Whether the adapter observes `subject`. A capability may have one adapter per
    /// source class, such as a host probe for local runtimes and a provider API check
    /// for pods; each subject must then be observed by exactly one of them.
    fn observes(&self, _subject: &Subject) -> bool {
        true
    }

    /// Observes the capability on `subject`. An adapter that cannot decide returns an
    /// unknown result rather than guessing.
    fn observe(&self, subject: &Subject) -> Observation;
}

impl<P: ProbeAdapter + ?Sized> ProbeAdapter for Arc<P> {
    fn capability(&self) -> Capability {
        (**self).capability()
    }

    fn source(&self) -> SourceClass {
        (**self).source()
    }

    fn host_changes(&self) -> Vec<HostChange> {
        (**self).host_changes()
    }

    fn observes(&self, subject: &Subject) -> bool {
        (**self).observes(subject)
    }

    fn observe(&self, subject: &Subject) -> Observation {
        (**self).observe(subject)
    }
}

/// Why the registry refused a registration or a refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// One adapter per capability and source class.
    AlreadyRegistered {
        capability: Capability,
        source: SourceClass,
    },
    /// The adapter would change host state (S7, S13).
    ChangesHostState {
        capability: Capability,
        changes: Vec<HostChange>,
    },
    /// No registered adapter observes this subject.
    NoAdapter { capability: Capability },
    /// Several adapters claim the subject, so its latest envelope would be ambiguous.
    AmbiguousAdapters {
        capability: Capability,
        sources: Vec<SourceClass>,
    },
    WrongSubjectKind {
        capability: Capability,
        expected: SubjectKind,
        found: SubjectKind,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRegistered { capability, source } => {
                write!(
                    f,
                    "a {capability} check from a {source} is already registered"
                )
            }
            Self::ChangesHostState {
                capability,
                changes,
            } => {
                write!(f, "the {capability} check would change ")?;
                for (index, change) in changes.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{change}")?;
                }
                f.write_str("; checks only observe and are not registered")
            }
            Self::NoAdapter { capability } => {
                write!(f, "no registered {capability} check observes this subject")
            }
            Self::AmbiguousAdapters {
                capability,
                sources,
            } => write!(
                f,
                "{} {capability} checks claim this subject; each subject needs exactly one",
                sources.len()
            ),
            Self::WrongSubjectKind {
                capability,
                expected,
                found,
            } => write!(
                f,
                "the {capability} check observes a {expected}, not a {found}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Typed probe adapters and the latest envelope each produced, per capability and
/// subject (CORE-01).
///
/// Time comes from the injected [`Clock`]; every envelope is stamped with this registry's
/// [`ClockSession`], so evidence from another clock never counts as fresh.
pub struct ProbeRegistry<C: Clock> {
    clock: C,
    session: ClockSession,
    /// Adapters keyed by capability and by the source class each had at registration.
    adapters: BTreeMap<(Capability, SourceClass), Box<dyn ProbeAdapter>>,
    evidence: EvidenceStore,
}

impl<C: Clock> ProbeRegistry<C> {
    /// A registry on `clock`, with a new random clock session that no other registry
    /// shares.
    pub fn new(clock: C) -> Self {
        Self {
            clock,
            session: ClockSession::generate(),
            adapters: BTreeMap::new(),
            evidence: EvidenceStore::default(),
        }
    }

    pub fn session(&self) -> ClockSession {
        self.session
    }

    /// The current time of this registry's clock session.
    pub fn now(&self) -> ClockReading {
        ClockReading::new(self.session, self.clock.now())
    }

    /// Registers `adapter` under its capability and its source class, which is read here
    /// and never again. Refused when that capability already has an adapter of that
    /// class, or when the adapter declares any host change.
    pub fn register(&mut self, adapter: Box<dyn ProbeAdapter>) -> Result<(), RegistryError> {
        let capability = adapter.capability();
        let source = adapter.source();
        let changes = adapter.host_changes();
        if !changes.is_empty() {
            return Err(RegistryError::ChangesHostState {
                capability,
                changes,
            });
        }
        if self.adapters.contains_key(&(capability, source)) {
            return Err(RegistryError::AlreadyRegistered { capability, source });
        }
        self.adapters.insert((capability, source), adapter);
        Ok(())
    }

    pub fn is_registered(&self, capability: Capability) -> bool {
        !self.sources(capability).is_empty()
    }

    /// The source classes of `capability`'s adapters, as fixed at registration.
    pub fn sources(&self, capability: Capability) -> Vec<SourceClass> {
        self.adapters
            .keys()
            .filter(|(registered, _)| *registered == capability)
            .map(|(_, source)| *source)
            .collect()
    }

    /// Observes `capability` on `subject` through the one adapter that observes it, and
    /// keeps the stamped envelope as the latest. The envelope carries the source class
    /// fixed at registration and the time the probe started, so a slow probe never makes
    /// its evidence look newer than it is. An adapter that now declares a host change is
    /// not called, and every envelope it produced is dropped.
    pub fn refresh(
        &mut self,
        capability: Capability,
        subject: &Subject,
    ) -> Result<&EvidenceEnvelope, RegistryError> {
        let expected = capability.subject_kind();
        if subject.kind() != expected {
            return Err(RegistryError::WrongSubjectKind {
                capability,
                expected,
                found: subject.kind(),
            });
        }
        let sources: Vec<SourceClass> = self
            .adapters
            .iter()
            .filter(|((registered, _), adapter)| {
                *registered == capability && adapter.observes(subject)
            })
            .map(|((_, source), _)| *source)
            .collect();
        let source = match sources.as_slice() {
            [] => return Err(RegistryError::NoAdapter { capability }),
            [source] => *source,
            _ => {
                return Err(RegistryError::AmbiguousAdapters {
                    capability,
                    sources,
                })
            }
        };
        let adapter = self
            .adapters
            .get(&(capability, source))
            .ok_or(RegistryError::NoAdapter { capability })?;
        let changes = adapter.host_changes();
        if !changes.is_empty() {
            self.evidence.remove_where(|envelope| {
                envelope.capability() == capability && envelope.source() == source
            });
            return Err(RegistryError::ChangesHostState {
                capability,
                changes,
            });
        }
        let started = self.now();
        let observation = adapter.observe(subject);
        let envelope =
            EvidenceEnvelope::stamp(capability, subject.clone(), source, observation, started);
        Ok(self.evidence.put(envelope))
    }

    /// The latest envelope for `capability` on `subject`, whatever its freshness.
    pub fn latest(&self, capability: Capability, subject: &Subject) -> Option<&EvidenceEnvelope> {
        self.evidence.latest(capability, subject)
    }

    /// Evaluates `requirement` against the latest evidence at this clock's current time.
    pub fn evaluate(&self, requirement: &Requirement) -> Result<Satisfied, EvidenceRefusal> {
        self.evidence.evaluate(requirement, self.now())
    }

    /// Drops the envelope for `capability` on `subject`; true if there was one.
    pub fn invalidate(&mut self, capability: Capability, subject: &Subject) -> bool {
        self.evidence
            .remove(capability, subject.identity())
            .is_some()
    }

    /// Drops every envelope about `subject`; returns how many.
    pub fn invalidate_subject(&mut self, subject: &Subject) -> usize {
        let identity = subject.identity();
        self.evidence
            .remove_where(|envelope| envelope.subject_identity() == identity)
    }

    /// Drops every envelope observed under `superseded` after that configuration changed
    /// (CORE-01: changed configurations invalidate relevant evidence); returns how many.
    pub fn invalidate_configuration(&mut self, superseded: ConfigurationFingerprint) -> usize {
        self.evidence
            .remove_where(|envelope| envelope.configuration() == superseded)
    }

    /// The stored evidence, for the optimization gate and for reports.
    pub fn evidence(&self) -> &EvidenceStore {
        &self.evidence
    }
}
