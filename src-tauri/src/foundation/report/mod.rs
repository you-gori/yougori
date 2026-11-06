//! CORE-08 measurement contract: the shared report schema and statistics of the combined
//! GPU memory and VM sandbox plan (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2
//! CORE-08, S7–S12, S13 FAST-01 and quality evidence, GPU §1.1, §1.3 and §2.1).
//!
//! - [`RunRecord`]: the raw run record of S8, redacted by construction, with explicit
//!   "not measured" cells ([`Measured`]) and monotonic events ([`RecordedEvent`]); a
//!   reasoning-family attempt carries its [`ReasoningCheck`] (S13 FAST-05).
//!   [`RunRecord::from_json`] refuses a record of another [`SCHEMA_VERSION`] with a typed
//!   error.
//! - The five S8 clocks and the §2.1 boundaries as named intervals ([`IntervalKind`],
//!   [`Timeline`]), refused across clocks or runs or when reversed.
//! - Outcomes over every initial attempt, with retries linked to their first attempt
//!   ([`AttemptLedger`]).
//! - Statistics: [`SuccessRate`], untrimmed [`LatencySummary`], the Wilson interval, a
//!   resolution rule, the exact McNemar test and ratios with denominators.
//! - Both S8 cost equations ([`accelerator_only_cost_per_million_output_tokens`],
//!   [`total_cost_per_successful_agent_task`]).
//! - Comparison discipline ([`ComparisonReport`], [`assess`], [`ImprovementClaim`]) and
//!   provenance ([`Provenance`]); a fake-substrate run validates schema and comparisons
//!   and backs no release or performance claim (S12 G0).
//! - BENCH-01–BENCH-13 ([`BenchId`], [`ApplicabilityMatrix`]) and the BENCH-13
//!   [`ReproducibilityRecord`].
//!
//! Pure and synchronous: time comes from [`crate::foundation::ids::Clock`], and calendar
//! times (price observations, publication dates) are supplied by the caller. These are
//! evaluation records, not production services (S11).

/// `foundation::strict_serde`'s [`strict_tagged_enum!`](crate::foundation::strict_serde::strict_tagged_enum),
/// in this module's textual scope for the enums its child files declare with it.
macro_rules! strict_tagged_enum {
    ($($tokens:tt)*) => {
        $crate::foundation::strict_serde::strict_tagged_enum! { $($tokens)* }
    };
}

mod bench;
mod claims;
mod compare;
mod cost;
mod error;
mod events;
mod fidelity;
#[cfg(test)]
mod fixtures;
mod ledger;
mod measured;
mod record;
mod stats;
mod text;

pub use bench::*;
pub use claims::*;
pub use compare::*;
pub use cost::*;
pub use error::*;
pub use events::*;
pub use fidelity::*;
pub use ledger::*;
pub use measured::*;
pub use record::*;
pub use stats::*;
pub use text::*;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The report schema version. Bump it on any change to the serialized form of
/// [`RunRecord`] or the records that embed it (the BENCH-13 [`ReproducibilityRecord`]),
/// and replace the golden sample with one for the new version. A record of another
/// version is refused when read, never reinterpreted. Version 2 adds the declared
/// [`ClaimComparison`] of a reproduced third-party claim; version 3 adds the reasoning
/// fixture family and its [`ReasoningCheck`].
pub const SCHEMA_VERSION: u32 = 3;

/// A complete [`RunRecord`] in the current format, pinned by tests so the format cannot
/// drift silently. It is also the exported example of the format.
pub const RUN_RECORD_SAMPLE_JSON: &str = include_str!("golden_run_record_v3.json");

/// The `schema_version` field: serializes as [`SCHEMA_VERSION`] and refuses any other
/// version when read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchemaVersion;

impl SchemaVersion {
    pub const fn get(self) -> u32 {
        SCHEMA_VERSION
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(SCHEMA_VERSION)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let found = u64::deserialize(deserializer)?;
        if found == u64::from(SCHEMA_VERSION) {
            Ok(Self)
        } else {
            Err(D::Error::custom(ReportError::UnsupportedSchemaVersion {
                found,
            }))
        }
    }
}

/// Refuses a JSON document written under another schema version with the typed
/// [`ReportError::UnsupportedSchemaVersion`] before anything else in it is read, so an
/// old record is refused rather than reinterpreted (the typed path of
/// [`RunRecord::from_json`] and [`ReproducibilityRecord::from_json`]).
fn check_schema_version(json: &str) -> Result<(), ReportError> {
    #[derive(Deserialize)]
    struct Versioned {
        schema_version: u64,
    }
    let Versioned {
        schema_version: found,
    } = serde_json::from_str(json).map_err(malformed)?;
    if found == u64::from(SCHEMA_VERSION) {
        Ok(())
    } else {
        Err(ReportError::UnsupportedSchemaVersion { found })
    }
}

/// [`ReportError::Malformed`] at the parser's position, without its message.
fn malformed(error: serde_json::Error) -> ReportError {
    ReportError::Malformed {
        line: error.line(),
        column: error.column(),
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{
        golden_record, label, real_serving_records, reasoning_record, reproduction, vendor_claim,
    };
    use super::*;
    use crate::foundation::ids::digest;

    /// The schema version and the digest of the golden record's compact JSON. When a
    /// format change makes this fail, bump [`SCHEMA_VERSION`], add a new golden file and
    /// record the new pair here; never just replace the digest.
    const PINNED_GOLDEN: (u32, &str) = (
        3,
        "00ce461c4a39acaa2ce86b565f5287035fd0c0a682cae2fbcdb8dd7a07ff8941",
    );

    fn sample_text() -> String {
        RUN_RECORD_SAMPLE_JSON
            .replace("\r\n", "\n")
            .trim_end()
            .to_string()
    }

    #[test]
    fn the_golden_sample_is_the_golden_record() {
        let record = golden_record();
        record.validate().unwrap();
        let generated = serde_json::to_string_pretty(&record).unwrap();
        assert_eq!(generated, sample_text(), "the serialized format changed");
        let parsed: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
        assert_eq!(parsed, record);
        parsed.validate().unwrap();
    }

    #[test]
    fn the_golden_sample_is_pinned_to_the_schema_version() {
        let compact = serde_json::to_vec(&golden_record()).unwrap();
        let pinned = digest("yougori/report/golden/v1", &[&compact]).to_hex();
        assert_eq!(
            (SCHEMA_VERSION, pinned.as_str()),
            PINNED_GOLDEN,
            "the report format changed: bump SCHEMA_VERSION and add a new golden sample"
        );
    }

    #[test]
    fn another_schema_version_is_refused() {
        let json = serde_json::to_value(golden_record()).unwrap();
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        // The previous version and the next one are both refused, not reinterpreted.
        for other in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
            let mut versioned = json.clone();
            versioned["schema_version"] = other.into();
            let error = serde_json::from_value::<RunRecord>(versioned).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("report schema version {other}")),
                "{error}"
            );
        }
        assert_eq!(SchemaVersion.get(), SCHEMA_VERSION);

        // The typed path reads the current version and refuses every other one as such,
        // before the body is read: a version 2 record has no reasoning check, and is
        // refused for its version, not for the missing field.
        assert_eq!(
            RunRecord::from_json(RUN_RECORD_SAMPLE_JSON),
            Ok(golden_record())
        );
        let mut older = json.clone();
        older["schema_version"] = 2.into();
        older["measurements"]
            .as_object_mut()
            .unwrap()
            .remove("reasoning");
        for (other, document) in [
            (1, {
                let mut first = older.clone();
                first["schema_version"] = 1.into();
                first
            }),
            (2, older),
            (u64::from(SCHEMA_VERSION) + 1, {
                let mut next = json.clone();
                next["schema_version"] = (SCHEMA_VERSION + 1).into();
                next
            }),
        ] {
            assert_eq!(
                RunRecord::from_json(&document.to_string()),
                Err(ReportError::UnsupportedSchemaVersion { found: other })
            );
        }
        // Text that does not parse is located, never quoted (S8).
        for text in [
            "a prompt, not a record",
            r#"{"schema_version": 3, "attempt": "a private prompt"}"#,
        ] {
            let error = RunRecord::from_json(text).unwrap_err();
            assert!(
                matches!(error, ReportError::Malformed { line: 1, .. }),
                "{error}"
            );
            assert!(!error.to_string().contains("prompt"), "{error}");
        }
        // A record that parses is still validated.
        let mut invalid = golden_record();
        invalid.attempt.role = AttemptRole::Retry {
            first_attempt: invalid.attempt.operation.clone(),
            retry_number: 1,
        };
        assert_eq!(
            RunRecord::from_json(&serde_json::to_string(&invalid).unwrap()),
            Err(ReportError::InvalidRetry)
        );
    }

    /// The schema version and the digest of a BENCH-13 record reproducing a third-party
    /// claim, so the record's format cannot drift silently either.
    const PINNED_REPRODUCTION: (u32, &str) = (
        3,
        "d1e1195d35efb2de65bab96ff08eda06112ea692b3bb6f7e9769531052c7be29",
    );

    #[test]
    fn the_reproducibility_record_format_is_pinned_to_the_schema_version() {
        let claim = vendor_claim(ClaimConfiguration::Declared {
            entries: vec![ConfigurationEntry {
                key: label("model"),
                value: label("llama-3.1-8b"),
            }],
        });
        let comparison = ClaimComparison {
            statistic: RecordStatistic::Percentile {
                interval: IntervalKind::TimeToFirstToken,
                quantile: Quantile::P50,
            },
            unit: ClaimUnit::Milliseconds,
            relative_tolerance: NonNegative::new(0.1).unwrap(),
        };
        let record = reproduction(
            ClaimUnderTest::ThirdParty {
                bench: BenchId::Bench01,
                claim,
                comparison,
            },
            real_serving_records(30, |index| 88 + index as u64 % 5),
        )
        .unwrap();
        let pinned = record.digest().unwrap().to_hex();
        assert_eq!(
            (SCHEMA_VERSION, pinned.as_str()),
            PINNED_REPRODUCTION,
            "the BENCH-13 record format changed: bump SCHEMA_VERSION and re-pin"
        );
        // The record reads back as itself, with its declared comparison.
        let text = serde_json::to_string(&record).unwrap();
        let read: ReproducibilityRecord = serde_json::from_str(&text).unwrap();
        assert_eq!(read, record);
        assert_eq!(ReproducibilityRecord::from_json(&text), Ok(record.clone()));
        // A record of an earlier version is refused for its version, typed.
        let mut older: serde_json::Value = serde_json::from_str(&text).unwrap();
        older["schema_version"] = 2.into();
        assert_eq!(
            ReproducibilityRecord::from_json(&older.to_string()),
            Err(ReportError::UnsupportedSchemaVersion { found: 2 })
        );
        // A refusal of its contents keeps its own typed error.
        let mut trimmed: serde_json::Value = serde_json::from_str(&text).unwrap();
        trimmed["fixture_digests"] = serde_json::Value::Array(Vec::new());
        assert_eq!(
            ReproducibilityRecord::from_json(&trimmed.to_string()),
            Err(ReportError::InconsistentRecord)
        );
    }

    /// The schema version and the digest of a reasoning attempt, so the reasoning check's
    /// format cannot drift silently.
    const PINNED_REASONING: (u32, &str) = (
        3,
        "cd352802e47f03bf6f7733fece07a8261b5c3321c86fc5938682f2481b217843",
    );

    #[test]
    fn the_reasoning_record_format_is_pinned_to_the_schema_version() {
        let record = reasoning_record("op-reasoning", 300);
        record.validate().unwrap();
        let compact = serde_json::to_vec(&record).unwrap();
        let pinned = digest("yougori/report/golden/v1", &[&compact]).to_hex();
        assert_eq!(
            (SCHEMA_VERSION, pinned.as_str()),
            PINNED_REASONING,
            "the reasoning record format changed: bump SCHEMA_VERSION and re-pin"
        );
    }

    #[test]
    fn the_golden_sample_has_every_s8_and_fast01_field() {
        let json: serde_json::Value = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
        for field in [
            "schema_version",
            "attempt",
            "scenario",
            "substrate",
            "build",
            "execution_category",
            "model",
            "precision",
            "engine",
            "host",
            "workload",
            "client",
            "load",
            "state",
            "launch",
            "price",
            "measurements",
            "events",
            "outcome",
        ] {
            assert!(json.get(field).is_some(), "{field}");
        }
        for field in [
            "output_tokens",
            "prefill_tokens_per_second",
            "aggregate_decode_tokens_per_second",
            "speculative",
            "peak_gpu_memory_bytes",
            "retained_gpu_memory_bytes",
            "energy_joules",
            "reasoning",
        ] {
            assert!(json["measurements"].get(field).is_some(), "{field}");
        }
        // A tool request has no reasoning check, and says so.
        assert_eq!(
            json["measurements"]["reasoning"]["reason"],
            "not_applicable"
        );
        assert_eq!(json["host"]["gpu_power_clock"]["status"], "not_measured");
        assert_eq!(json["execution_category"], "shared_kernel_gpu_runtime");
        // No path separators, spaces or line breaks anywhere in the values.
        let compact = serde_json::to_string(&json).unwrap();
        assert!(!compact.contains(['/', '\\', ' ']));
    }
}
