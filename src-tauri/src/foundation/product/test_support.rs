//! Test support shared by the contract's own tests and by the conversion tests of the
//! engine's `product_views` module: a CORE-01 registry with fake probes on a manual clock,
//! a CORE-06 hub that records a progress state, and JSON helpers. Nothing here starts a
//! runtime or probes a host.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use crate::foundation::events::{
    CancellationBoundary, EventContext, EventEnvelope, EventHub, HubConfig, MetricsConfig, Phase,
    ProducerId, ProducerIncarnation, ProgressConfig, ProgressUpdate, QueueReason, ResourceKind,
    RevocationConfig, TrackedResourceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ClockReading, ConfigurationFingerprint, Observation,
    ProbeRegistry, Requirement, RuntimeOffer, RuntimeSubject, Satisfied, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{digest, ExecutionCategory, ManualClock, MonotonicTime, OperationId};

pub(crate) const HOUR: Duration = Duration::from_secs(3_600);

pub(crate) fn config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", "a")]).unwrap()
}

pub(crate) fn other_config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", "b")]).unwrap()
}

pub(crate) fn runtime(category: ExecutionCategory) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest(
            "yougori/test/product/instance/v1",
            &[category.label().as_bytes()],
        ),
    }
}

/// A CORE-01 registry on a manual clock whose runtime-category adapter reports from
/// `source`.
pub(crate) struct Probes {
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) registry: ProbeRegistry<Arc<ManualClock>>,
    category: Arc<FakeProbe>,
}

impl Probes {
    pub(crate) fn new(source: SourceClass) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(source));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        Self {
            clock,
            registry,
            category,
        }
    }

    pub(crate) fn now(&self) -> ClockReading {
        self.registry.now()
    }

    pub(crate) fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// An offer of `category`, confirmed by this registry's adapter, fresh for an hour.
    pub(crate) fn offer(&mut self, category: ExecutionCategory) -> RuntimeOffer {
        let subject = runtime(category);
        let wrapped = Subject::Runtime(subject.clone());
        self.category.respond(
            &wrapped,
            Observation::supported(config(), HOUR, SupportDetail::RuntimeCategory { category }),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &wrapped)
            .unwrap();
        RuntimeOffer::observe(&self.registry, subject, HOUR, config()).unwrap()
    }

    /// CORE-01 evidence of `category`'s runtime category from this registry's source.
    pub(crate) fn satisfied(&mut self, category: ExecutionCategory) -> Satisfied {
        self.offer(category).evidence().clone()
    }

    /// The requirement that `category`'s runtime category is known from at least `minimum`.
    pub(crate) fn requirement(category: ExecutionCategory, minimum: SourceClass) -> Requirement {
        Requirement::new(
            Capability::RuntimeCategory,
            Subject::Runtime(runtime(category)),
            minimum,
            HOUR,
            config(),
        )
    }
}

/// Round-trips `value` through JSON.
pub(crate) fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    serde_json::from_value(serde_json::to_value(value).unwrap()).unwrap()
}

/// The error reading `json` as `T` gives, which the test expects.
pub(crate) fn refused<T>(json: serde_json::Value) -> String
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
{
    serde_json::from_value::<T>(json).unwrap_err().to_string()
}

fn hub(clock: Arc<ManualClock>) -> EventHub<Arc<ManualClock>> {
    EventHub::new(
        clock,
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 8,
                sample_above_events: 8,
                keep_one_in: NonZeroU32::MIN,
                retention: HOUR,
                max_series: 4,
            },
            progress: ProgressConfig {
                max_tracked: 8,
                terminal_retention: HOUR,
            },
            revocation: RevocationConfig {
                max_pending_executions: 4,
            },
            first_incarnation: ProducerIncarnation::FIRST,
        },
    )
    .unwrap()
}

/// The catalog identity of the weights the progress tests load.
pub(crate) fn weights() -> TrackedResourceId {
    TrackedResourceId::new(digest("yougori/test/product/weights/v1", &[b"weights"]))
}

/// The progress state a real hub records for `update` in `phase`.
pub(crate) fn recorded(phase: Phase, update: ProgressUpdate) -> EventEnvelope<ProgressUpdate> {
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let mut hub = hub(clock);
    let mut producer = hub
        .register_progress(
            ProducerId::new("model-loader").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    hub.emit_progress(
        &mut producer,
        EventContext::new(OperationId::new("op-load-1").unwrap(), phase),
        update,
    )
    .unwrap();
    hub.progress_snapshot().states.remove(0)
}

/// Weights queued for 4 GB of GPU memory.
pub(crate) fn queued_for_memory() -> ProgressUpdate {
    ProgressUpdate::new(
        weights(),
        ResourceKind::Weights,
        0,
        Some(4_000_000_000),
        0,
        CancellationBoundary::Anytime,
    )
    .queued_for(QueueReason::GpuMemory {
        needed_bytes: 4_000_000_000,
    })
}
