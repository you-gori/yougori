//! Tests for the conversions into the CORE-07 contract, one file per area, on the real
//! CORE-01 registry with fake probes on a manual clock, the real CORE-06 hub, V17's labels,
//! V01's tier migration, model-memory types, the serving protocol's rows and runs and the
//! setup crate's own types, with the contract's shared test support. Nothing here starts a
//! runtime or probes a host.

mod endpoint;
mod golden;
mod migration;
mod model;
mod progress;
mod refusal;
mod sandbox;

use std::sync::Arc;
use std::time::Duration;

use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ClockReading, Observation, Requirement, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, ExecutionCategory, MonotonicTime};
use crate::foundation::product::test_support::*;
