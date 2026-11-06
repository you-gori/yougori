//! Tests for the CORE-07 product contract on its own, one file per area, on the real
//! CORE-01 registry with fake probes on a manual clock, the real CORE-06 hub and the real
//! CORE-04 coordinator. The conversions from domain packages are tested in the engine's
//! `product_views` module. Nothing here starts a runtime or probes a host.

mod endpoint;
mod evidence;
mod execution;
mod grants;
mod migration;
mod progress;
mod refusal;
mod version;

use std::time::Duration;

use super::test_support::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ClockReading, Observation, ProbeRegistry, Requirement, SourceClass, Subject,
    SupportDetail,
};
use crate::foundation::ids::{digest, ExecutionCategory, ManualClock, MonotonicTime};
