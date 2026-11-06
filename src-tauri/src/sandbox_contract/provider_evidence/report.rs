//! The provider-report store (M11A item 1): what the provider's API reported about each
//! instance it runs for us, with when the call that produced it started, and the
//! [`ReportingPort`] that fills it through V12's provider port.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde::Serialize;

use crate::foundation::evidence::{
    ConfigurationFingerprint, FingerprintError, ProviderKind, Subject,
};
use crate::foundation::ids::{
    validate_identifier, Clock, Digest, ExecutionCategory, IdError, MonotonicTime,
};
use crate::sandbox_contract::remote::{
    AttemptId, BillingReport, LookupOutcome, OfferingKind, ProviderInstance, ProvisionOutcome,
    ProvisionRequest, RemoteProviderPort, TerminationOutcome,
};

/// The CUDA version an instance's NVIDIA driver supports, as the provider states it, such
/// as `12.4`. Compared exactly; only the ids.rs identifier grammar is checked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CudaVersion(String);

impl CudaVersion {
    /// Accepts the ids.rs identifier grammar: 1–128 letters, digits, '.', '_', ':' or '-',
    /// starting with a letter or digit.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// The version as the provider stated it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The accelerators the provider reports attached to an instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportedAccelerators {
    /// `count` NVIDIA GPUs, with the CUDA version their driver supports when the provider
    /// states one.
    NvidiaGpus {
        count: NonZeroU32,
        cuda: Option<CudaVersion>,
    },
    /// No accelerator: the provider reports a CPU-only instance.
    CpuOnly,
}

/// What one provider API call reported about one instance. A field the provider did not
/// report is `None`, and the adapters read it as not tested; nothing is filled in.
///
/// Reports are never read back: the call's start time is a point on this process's
/// clock and means nothing after a restart, so a report only ever comes from a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProviderReport {
    /// The instance as V12's provider port describes it: provider, region, offering, kind
    /// and the digest of the provider's instance identity.
    pub instance: ProviderInstance,
    /// Whether the provider runs the container under gVisor (VM-D5 hardening).
    pub gvisor: Option<bool>,
    /// Whether gVisor's GPU proxy, nvproxy, mediates the container's GPU access.
    pub nvproxy: Option<bool>,
    /// The accelerators attached to the instance.
    pub accelerators: Option<ReportedAccelerators>,
}

/// The value fingerprinted for a field the provider did not report.
const NOT_REPORTED: &str = "not_reported";

fn reported_flag(flag: Option<bool>) -> &'static str {
    match flag {
        Some(true) => "true",
        Some(false) => "false",
        None => NOT_REPORTED,
    }
}

impl ProviderReport {
    /// What V12's provider port reports: the instance alone. Hardening and accelerators
    /// were not reported.
    pub fn instance_only(instance: ProviderInstance) -> Self {
        Self {
            instance,
            gvisor: None,
            nvproxy: None,
            accelerators: None,
        }
    }

    /// The configuration observations from this report depend on: every reported field,
    /// and "not_reported" for each field that was not, so any change to the report
    /// changes it. The call's start time is not part of it: the same report from a later
    /// call is the same configuration, observed again.
    pub fn configuration(&self) -> Result<ConfigurationFingerprint, FingerprintError> {
        let instance = &self.instance;
        let digest = instance.instance.to_hex();
        let (accelerators, count, cuda) = match &self.accelerators {
            None => (NOT_REPORTED, NOT_REPORTED.to_owned(), NOT_REPORTED),
            Some(ReportedAccelerators::CpuOnly) => ("cpu_only", "0".to_owned(), NOT_REPORTED),
            Some(ReportedAccelerators::NvidiaGpus { count, cuda }) => (
                "nvidia_gpus",
                count.get().to_string(),
                cuda.as_ref().map_or(NOT_REPORTED, CudaVersion::as_str),
            ),
        };
        ConfigurationFingerprint::from_settings([
            ("provider", instance.provider.tag()),
            ("region", instance.region.as_str()),
            ("offering", instance.offering.as_str()),
            ("kind", instance.kind.tag()),
            ("instance", digest.as_str()),
            ("gvisor", reported_flag(self.gvisor)),
            ("nvproxy", reported_flag(self.nvproxy)),
            ("accelerators", accelerators),
            ("accelerators.count", count.as_str()),
            ("accelerators.cuda", cuda),
        ])
    }

    /// The execution category of the reported instance itself. A dedicated provider VM is
    /// the VM sandbox (§7.6); a provider container is the labelled provider-container
    /// runtime and never a VM sandbox (VM-D5). `None` for a bare-metal host or a host that
    /// launches per-sandbox VMs: the instance the provider reports is then the host, a
    /// host shell and never the sandbox, which only management evidence shows (V12).
    pub fn instance_category(&self) -> Option<ExecutionCategory> {
        match self.instance.kind {
            OfferingKind::DedicatedVm => Some(ExecutionCategory::VmSandbox),
            OfferingKind::ProviderContainer => Some(ExecutionCategory::ProviderContainerRuntime),
            OfferingKind::BareMetal | OfferingKind::PerSandboxVmHost => None,
        }
    }
}

/// A report as recorded: the report, when the call that produced it started, and its
/// configuration fingerprint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecordedReport {
    report: ProviderReport,
    started_at: MonotonicTime,
    configuration: ConfigurationFingerprint,
}

impl RecordedReport {
    /// What the provider reported.
    pub fn report(&self) -> &ProviderReport {
        &self.report
    }

    /// When the call that produced the report started, on the store's clock; freshness
    /// counts from here.
    pub fn started_at(&self) -> MonotonicTime {
        self.started_at
    }

    /// The fingerprint of the report, which observations from it are made under.
    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }
}

/// What recording a report did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RecordOutcome {
    /// The first report about this instance.
    New {
        configuration: ConfigurationFingerprint,
    },
    /// The same report from a later call: only its freshness moved.
    Refreshed {
        configuration: ConfigurationFingerprint,
    },
    /// The report changed. Evidence observed under `previous` no longer applies; the
    /// owner of the registry drops it with `invalidate_configuration(previous)`.
    Changed {
        previous: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    /// The call started before the report in force; it was not recorded.
    Superseded { in_force_started_at: MonotonicTime },
}

/// Why a report was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// The call is dated after the store's current time, which a call timed on this clock
    /// never is.
    StartedAfterNow {
        started_at: MonotonicTime,
        now: MonotonicTime,
    },
    /// Another provider already reported this instance; a provider never changes
    /// silently (V12).
    ProviderChanged {
        recorded: ProviderKind,
        reported: ProviderKind,
    },
    /// The report could not be fingerprinted.
    Fingerprint { error: FingerprintError },
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartedAfterNow { .. } => {
                f.write_str("the provider call is dated after the current time; not recorded")
            }
            Self::ProviderChanged { recorded, reported } => write!(
                f,
                "{reported} reported an instance {recorded} already reported; a provider never \
                 changes silently, so the report is refused"
            ),
            Self::Fingerprint { error } => write!(f, "the report cannot be fingerprinted: {error}"),
        }
    }
}

impl std::error::Error for ReportError {}

/// Whether a provider can run a runtime of `category`: a VM sandbox (a dedicated provider
/// VM) or a provider container (VM-D5). The WSL CUDA runtime (VM-D4) and the native Metal
/// runner (VM-D6) are local and never observed here.
fn provider_category(category: ExecutionCategory) -> bool {
    matches!(
        category,
        ExecutionCategory::VmSandbox | ExecutionCategory::ProviderContainerRuntime
    )
}

/// The store of provider reports, by the digest of the provider's instance identity
/// (M11A).
///
/// It must share the clock of the registry its adapters are registered in, so a report's
/// age is measured on the clock the registry stamps envelopes with. Only the latest
/// report per instance is kept: a call that started before it is superseded.
pub struct ProviderReports<C: Clock> {
    clock: Arc<C>,
    reports: RwLock<BTreeMap<Digest, RecordedReport>>,
}

impl<C: Clock> ProviderReports<C> {
    /// An empty store on `clock`, the registry's clock.
    pub fn new(clock: Arc<C>) -> Self {
        Self {
            clock,
            reports: RwLock::new(BTreeMap::new()),
        }
    }

    /// The time on the store's clock. Read it before a provider call starts and record
    /// the call's report with it.
    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    // Writers only insert or remove whole entries, so a panic while holding the lock left
    // nothing half written and the map is still usable.
    fn read(&self) -> RwLockReadGuard<'_, BTreeMap<Digest, RecordedReport>> {
        self.reports.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, BTreeMap<Digest, RecordedReport>> {
        self.reports.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records what a call that started at `started_at` reported. Refused when the call
    /// is dated after now or another provider already reported the instance; not recorded
    /// when it started before the report in force.
    pub fn record(
        &self,
        report: ProviderReport,
        started_at: MonotonicTime,
    ) -> Result<RecordOutcome, ReportError> {
        let configuration = report
            .configuration()
            .map_err(|error| ReportError::Fingerprint { error })?;
        let now = self.clock.now();
        if started_at > now {
            return Err(ReportError::StartedAfterNow { started_at, now });
        }
        let instance = report.instance.instance;
        let mut reports = self.write();
        let outcome = match reports.get(&instance) {
            None => RecordOutcome::New { configuration },
            Some(current) if current.report.instance.provider != report.instance.provider => {
                return Err(ReportError::ProviderChanged {
                    recorded: current.report.instance.provider,
                    reported: report.instance.provider,
                })
            }
            Some(current) if started_at < current.started_at => {
                return Ok(RecordOutcome::Superseded {
                    in_force_started_at: current.started_at,
                })
            }
            Some(current) if current.configuration == configuration => {
                RecordOutcome::Refreshed { configuration }
            }
            Some(current) => RecordOutcome::Changed {
                previous: current.configuration,
                current: configuration,
            },
        };
        reports.insert(
            instance,
            RecordedReport {
                report,
                started_at,
                configuration,
            },
        );
        Ok(outcome)
    }

    /// Drops the report about `instance`, such as after the provider confirmed its
    /// termination, and returns the configuration it was recorded under, whose evidence
    /// the owner of the registry drops. Its subjects then have no provider adapter.
    pub fn forget(&self, instance: &Digest) -> Option<ConfigurationFingerprint> {
        self.write()
            .remove(instance)
            .map(|recorded| recorded.configuration)
    }

    /// The latest report about `instance`.
    pub fn get(&self, instance: &Digest) -> Option<RecordedReport> {
        self.read().get(instance).cloned()
    }

    /// Every recorded report, by instance digest.
    pub fn all(&self) -> Vec<RecordedReport> {
        self.read().values().cloned().collect()
    }

    /// The report `subject` is observed from, when this module owns the subject: a
    /// provider resource the same provider reported, or a VM sandbox or provider
    /// container whose instance is a reported provider instance.
    pub fn about(&self, subject: &Subject) -> Option<RecordedReport> {
        let reports = self.read();
        match subject {
            Subject::Runtime(runtime) if provider_category(runtime.category) => {
                reports.get(&runtime.instance).cloned()
            }
            Subject::Provider(resource) => reports
                .get(&resource.resource)
                .filter(|recorded| recorded.report.instance.provider == resource.provider)
                .cloned(),
            _ => None,
        }
    }

    /// The configuration in force for `subject`: the fingerprint of the latest report it
    /// is observed from.
    pub fn configuration(&self, subject: &Subject) -> Option<ConfigurationFingerprint> {
        self.about(subject).map(|recorded| recorded.configuration)
    }
}

/// What a [`ReportingPort`] did with one provider answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortRecord {
    /// The provider reported `instance`, and the store recorded or superseded it.
    Recorded {
        instance: Digest,
        outcome: RecordOutcome,
    },
    /// The store refused what the provider reported about `instance`.
    Refused {
        instance: Digest,
        error: ReportError,
    },
    /// The provider confirmed `instance` is gone, and its report was dropped; evidence
    /// observed under `configuration` no longer applies.
    Forgotten {
        instance: Digest,
        configuration: ConfigurationFingerprint,
    },
}

/// V12's provider port with every answer recorded in a [`ProviderReports`] (M11A: the
/// store is filled through V12's provider port).
///
/// The time is read before each call, so a slow call never makes its report look newer
/// than it is. A created or found instance is recorded as the port reports it, instance
/// only; a confirmed termination, or the provider confirming the instance is already gone,
/// drops its report. Every other answer leaves the store unchanged.
pub struct ReportingPort<'a, P: RemoteProviderPort + ?Sized, C: Clock> {
    port: &'a mut P,
    reports: &'a ProviderReports<C>,
    log: Vec<PortRecord>,
}

impl<'a, P: RemoteProviderPort + ?Sized, C: Clock> ReportingPort<'a, P, C> {
    /// Wraps `port`, recording into `reports`.
    pub fn new(port: &'a mut P, reports: &'a ProviderReports<C>) -> Self {
        Self {
            port,
            reports,
            log: Vec::new(),
        }
    }

    /// What each recorded answer did, in call order.
    pub fn log(&self) -> &[PortRecord] {
        &self.log
    }

    fn note(&mut self, instance: &ProviderInstance, started_at: MonotonicTime) {
        let digest = instance.instance;
        let record = match self
            .reports
            .record(ProviderReport::instance_only(instance.clone()), started_at)
        {
            Ok(outcome) => PortRecord::Recorded {
                instance: digest,
                outcome,
            },
            Err(error) => PortRecord::Refused {
                instance: digest,
                error,
            },
        };
        self.log.push(record);
    }
}

impl<P: RemoteProviderPort + ?Sized, C: Clock> RemoteProviderPort for ReportingPort<'_, P, C> {
    fn provision(&mut self, request: &ProvisionRequest) -> ProvisionOutcome {
        let started_at = self.reports.now();
        let outcome = self.port.provision(request);
        if let ProvisionOutcome::Created { instance } = &outcome {
            self.note(instance, started_at);
        }
        outcome
    }

    fn terminate(&mut self, instance: &ProviderInstance) -> TerminationOutcome {
        let outcome = self.port.terminate(instance);
        if matches!(
            outcome,
            TerminationOutcome::Confirmed | TerminationOutcome::AlreadyGone
        ) {
            if let Some(configuration) = self.reports.forget(&instance.instance) {
                self.log.push(PortRecord::Forgotten {
                    instance: instance.instance,
                    configuration,
                });
            }
        }
        outcome
    }

    fn find(&mut self, request: &ProvisionRequest) -> LookupOutcome {
        let started_at = self.reports.now();
        let outcome = self.port.find(request);
        if let LookupOutcome::Found { instance } = &outcome {
            self.note(instance, started_at);
        }
        outcome
    }

    fn final_bill(&mut self, attempt: &AttemptId) -> BillingReport {
        self.port.final_bill(attempt)
    }
}
