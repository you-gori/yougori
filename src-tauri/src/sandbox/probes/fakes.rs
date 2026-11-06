//! Test fakes: a scripted host runner, a CORE-01 registry on a manual clock, a guest end
//! that drives a real `sandbox::link` host link so guest outcomes come from genuine guest
//! reports, and guest-sourced probe adapters.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::catalog::{CheckId, Part};
use super::core01::HostCheckRunner;
use super::expect::{ExpectationId, Observed};
use super::outcome::{Observations, RunResult};
use super::rules::JudgeContext;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HostChange, Observation, OsKind, ProbeAdapter,
    ProbeRegistry, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, ManualClock, MonotonicTime, SandboxBootGeneration};
use crate::sandbox::link::{
    encode_frame, BootstrapSecret, GuestReport, Hello, HostLink, LinkBinding, LinkEvent,
    LinkLimits, LinkMessage, LinkName, ProbeOutcome as GuestVerdict, ProbeResult, Sender,
    PROTOCOL_VERSION,
};

pub const FRESH: Duration = Duration::from_secs(600);
pub const MAX_AGE: Duration = Duration::from_secs(300);

pub fn configuration(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub fn id(name: &str) -> ExpectationId {
    ExpectationId::named(name).unwrap_or_else(|| panic!("no expectation {name}"))
}

pub fn check_id(number: u8) -> CheckId {
    CheckId::new(number).unwrap()
}

pub fn observations(entries: &[(&str, Observed)]) -> Observations {
    entries
        .iter()
        .map(|(name, observed)| (id(name), observed.clone()))
        .collect()
}

pub fn refused() -> Observed {
    Observed::Attempt { refused: true }
}

pub fn succeeded() -> Observed {
    Observed::Attempt { refused: false }
}

pub fn absent() -> Observed {
    Observed::Presence { present: false }
}

pub fn present() -> Observed {
    Observed::Presence { present: true }
}

pub fn happened() -> Observed {
    Observed::Event { happened: true }
}

pub fn value(text: &str) -> Observed {
    Observed::Value {
        value: text.to_owned(),
    }
}

pub fn matching(name: &str) -> Observed {
    let reference = digest("yougori/test/probes/reference/v1", &[name.as_bytes()]);
    Observed::Comparison {
        observed: reference,
        reference,
    }
}

pub fn differing(name: &str) -> Observed {
    Observed::Comparison {
        observed: digest("yougori/test/probes/observed/v1", &[name.as_bytes()]),
        reference: digest("yougori/test/probes/reference/v1", &[name.as_bytes()]),
    }
}

pub fn distinct(count: u8) -> Observed {
    Observed::Identities {
        values: (0..count)
            .map(|index| digest("yougori/test/probes/identity/v1", &[&[index]]))
            .collect(),
    }
}

/// A CORE-01 registry on a manual clock.
pub fn registry() -> (ProbeRegistry<Arc<ManualClock>>, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000)));
    (ProbeRegistry::new(Arc::clone(&clock)), clock)
}

pub fn context(
    registry: &ProbeRegistry<Arc<ManualClock>>,
    configuration: ConfigurationFingerprint,
    os: OsKind,
) -> JudgeContext {
    JudgeContext {
        now: registry.now(),
        configuration,
        max_age: MAX_AGE,
        os,
    }
}

/// A host runner that answers each check and part from a script.
pub struct ScriptedRunner {
    configuration: ConfigurationFingerprint,
    os: OsKind,
    script: Mutex<BTreeMap<(CheckId, Part), RunResult>>,
    pub calls: Mutex<Vec<(CheckId, Part)>>,
}

impl ScriptedRunner {
    pub fn new(configuration: ConfigurationFingerprint, os: OsKind) -> Self {
        Self {
            configuration,
            os,
            script: Mutex::new(BTreeMap::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    pub fn answer(self, check: CheckId, part: Part, result: RunResult) -> Self {
        self.script.lock().unwrap().insert((check, part), result);
        self
    }
}

impl HostCheckRunner for ScriptedRunner {
    fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    fn fresh_for(&self) -> Duration {
        FRESH
    }

    fn os(&self) -> OsKind {
        self.os
    }

    fn run(&self, check: CheckId, part: Part, _subject: &Subject) -> RunResult {
        self.calls.lock().unwrap().push((check, part));
        self.script
            .lock()
            .unwrap()
            .get(&(check, part))
            .cloned()
            .unwrap_or(RunResult::Observed {
                observations: Observations::new(),
            })
    }
}

impl<R: HostCheckRunner> HostCheckRunner for Arc<R> {
    fn configuration(&self) -> ConfigurationFingerprint {
        (**self).configuration()
    }

    fn fresh_for(&self) -> Duration {
        (**self).fresh_for()
    }

    fn os(&self) -> OsKind {
        (**self).os()
    }

    fn run(&self, check: CheckId, part: Part, subject: &Subject) -> RunResult {
        (**self).run(check, part, subject)
    }
}

/// A probe adapter whose observations are guest reports: whatever it claims, the registry
/// stamps it with the guest source class it declared at registration.
pub struct GuestClaimedHypervisor {
    pub configuration: ConfigurationFingerprint,
}

impl ProbeAdapter for GuestClaimedHypervisor {
    fn capability(&self) -> Capability {
        Capability::HypervisorAvailable
    }

    fn source(&self) -> SourceClass {
        SourceClass::GuestReport
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let hypervisor = match subject {
            Subject::Hypervisor(target) => target.hypervisor,
            _ => crate::foundation::evidence::HypervisorKind::Kvm,
        };
        Observation::supported(
            self.configuration,
            FRESH,
            SupportDetail::Hypervisor { hypervisor },
        )
    }
}

/// A probe adapter for any capability whose observations are guest reports: it claims
/// `detail`, and the registry stamps it with the guest source class it declared.
pub struct GuestClaimed {
    pub capability: Capability,
    pub detail: SupportDetail,
    pub configuration: ConfigurationFingerprint,
}

impl ProbeAdapter for GuestClaimed {
    fn capability(&self) -> Capability {
        self.capability
    }

    fn source(&self) -> SourceClass {
        SourceClass::GuestReport
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observe(&self, _subject: &Subject) -> Observation {
        Observation::supported(self.configuration, FRESH, self.detail.clone())
    }
}

pub const BOOT: u64 = 4;

pub fn vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/test/probes/vm/v1", &[b"vm-under-test"]))
}

pub fn other_vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/test/probes/vm/v1", &[b"another-vm"]))
}

pub fn boot() -> SandboxBootGeneration {
    SandboxBootGeneration::new(BOOT)
}

fn secret() -> BootstrapSecret {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(3);
    }
    BootstrapSecret::new(&bytes).unwrap()
}

fn binding(instance: VmInstanceId) -> LinkBinding {
    LinkBinding::new(instance, boot(), secret())
}

/// The guest end of a real host link for `instance`: every message is sealed with the
/// guest's key and fed to the host link, which turns it into guest reports.
pub struct GuestEnd {
    instance: VmInstanceId,
    link: HostLink<Arc<ManualClock>>,
    sequence: u64,
}

impl GuestEnd {
    pub fn new(instance: VmInstanceId) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let link = HostLink::new(binding(instance), LinkLimits::default(), clock).unwrap();
        let mut end = Self {
            instance,
            link,
            sequence: 0,
        };
        let hello = LinkMessage::Hello(Hello {
            guest_version: PROTOCOL_VERSION,
            agent_build: digest("yougori/test/probes/agent/v1", &[b"agent"]),
            claimed_vm: None,
            claimed_boot: None,
        });
        let greeting = end.send(&hello);
        assert_eq!(greeting.len(), 1, "the hello is reported once");
        end
    }

    /// Sends `message` and returns the guest reports the host link produced.
    pub fn send(&mut self, message: &LinkMessage) -> Vec<GuestReport> {
        self.sequence += 1;
        let frame = encode_frame(
            &binding(self.instance),
            Sender::Guest,
            self.sequence,
            message,
        )
        .unwrap();
        self.link
            .receive(&frame)
            .into_iter()
            .filter_map(|event| match event {
                LinkEvent::Report(report) => Some(report),
                _ => None,
            })
            .collect()
    }

    /// The guest reports each probe result `(expectation, verdict)`.
    pub fn report(&mut self, results: &[(&str, GuestVerdict)]) -> Vec<GuestReport> {
        results
            .iter()
            .flat_map(|(name, outcome)| {
                self.send(&LinkMessage::ProbeResult(ProbeResult {
                    probe: LinkName::new(*name).unwrap(),
                    outcome: *outcome,
                    detail: "reported by the guest".to_owned(),
                }))
            })
            .collect()
    }
}
