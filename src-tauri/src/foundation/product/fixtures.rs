//! Golden fixtures pinning the product contract's wire shape (CORE-07: "UI and CLI resolve
//! the same state"), one folder per contract version.
//!
//! Each fixture is a whole [`ProductView`](super::ProductView) built by the conversions
//! from typed sources, written as indented JSON. The engine API, the CLI and the desktop's
//! generated TypeScript mirror test against the same files. Within a version a fixture
//! changes only when a source rewords a sentence; any change to a field, code, remedy or
//! category bumps [`PRODUCT_CONTRACT_VERSION`](super::PRODUCT_CONTRACT_VERSION) and adds a
//! folder, and the older folders stay, because every older version this build reads must
//! still read them. Version 2 pins version 1's four documents again, exactly as version
//! 1's reader upgrades them, and adds a model's declared agent endpoint and a sandbox's
//! grant records.

/// One golden fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldenFixture {
    /// The contract version it was written under.
    pub version: u32,
    pub name: &'static str,
    pub json: &'static str,
}

/// Every golden fixture of every version.
pub const GOLDEN_FIXTURES: &[GoldenFixture] = &[
    GoldenFixture {
        version: 1,
        name: "vm_sandbox_ready",
        json: include_str!("fixtures/v1/vm_sandbox_ready.json"),
    },
    GoldenFixture {
        version: 1,
        name: "labelled_runtime_refused",
        json: include_str!("fixtures/v1/labelled_runtime_refused.json"),
    },
    GoldenFixture {
        version: 1,
        name: "model_preparing",
        json: include_str!("fixtures/v1/model_preparing.json"),
    },
    GoldenFixture {
        version: 1,
        name: "migration_needs_decision",
        json: include_str!("fixtures/v1/migration_needs_decision.json"),
    },
    GoldenFixture {
        version: 2,
        name: "vm_sandbox_ready",
        json: include_str!("fixtures/v2/vm_sandbox_ready.json"),
    },
    GoldenFixture {
        version: 2,
        name: "labelled_runtime_refused",
        json: include_str!("fixtures/v2/labelled_runtime_refused.json"),
    },
    GoldenFixture {
        version: 2,
        name: "model_preparing",
        json: include_str!("fixtures/v2/model_preparing.json"),
    },
    GoldenFixture {
        version: 2,
        name: "migration_needs_decision",
        json: include_str!("fixtures/v2/migration_needs_decision.json"),
    },
    GoldenFixture {
        version: 2,
        name: "agent_endpoint_declared",
        json: include_str!("fixtures/v2/agent_endpoint_declared.json"),
    },
    GoldenFixture {
        version: 2,
        name: "execution_grants",
        json: include_str!("fixtures/v2/execution_grants.json"),
    },
];
