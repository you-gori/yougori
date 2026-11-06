//! Attestation checks (VM part §7.6 line 2249; VM-P41; VM-CP-32 "attestation fixtures
//! with a stale nonce, wrong measurement, debug flag or unsupported security version are
//! refused; a valid fixture report is accepted and recorded"; §1.3 facets, not a score).

use std::collections::BTreeSet;
use std::time::Duration;

use super::attestation::{
    report_data, AttestationBook, AttestationChallenge, AttestationNonce, AttestationPolicy,
    AttestationRecord, AttestationRefusal, AttestationReport, AttestationUse, ChainRejection,
    CheckName, CheckOutcome, CpuCoverage, FacetVerdict, GpuProblem, MemoryCoverage, Portion,
    ReportOrigin, TcbStatus, TeePlatform,
};
use super::fakes::{
    chip, component, gpu_measurement, identity, policy, resign, resign_gpu, session, session_key,
    target, valid_gpu_report, valid_report, volume, workload, FakeVendor, RepeatingNonces,
    SeededNonces, SeededRng, GIB, MIB,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, Digest, MonotonicTime};
use crate::sandbox_contract::policy::DeploymentFacet;

struct Bench {
    book: AttestationBook,
    nonces: SeededNonces,
    vendor: FakeVendor,
    clock: ClockSession,
    now: MonotonicTime,
}

impl Bench {
    fn new() -> Self {
        Self {
            book: AttestationBook::new(),
            nonces: SeededNonces(SeededRng::new(41)),
            vendor: FakeVendor::new(),
            clock: session(7),
            now: MonotonicTime::from_nanos(5_000_000_000_000),
        }
    }

    fn challenge(&mut self) -> AttestationChallenge {
        self.book
            .challenge(
                &mut self.nonces,
                identity(1).digest(),
                session_key(1),
                workload(),
                target(),
                self.clock,
                self.now,
            )
            .unwrap()
    }

    fn verify_with(
        &mut self,
        report: &AttestationReport,
        policy: &AttestationPolicy,
    ) -> AttestationRecord {
        self.book
            .verify(report, policy, &self.vendor, self.clock, self.now)
    }

    fn verify(&mut self, report: &AttestationReport) -> AttestationRecord {
        self.verify_with(report, &policy())
    }
}

fn refusals(record: &AttestationRecord) -> Vec<AttestationRefusal> {
    match &record.result.verdict {
        FacetVerdict::Verified => Vec::new(),
        FacetVerdict::Refused { refusals } => refusals.clone(),
    }
}

fn failed(record: &AttestationRecord, check: CheckName) -> Vec<AttestationRefusal> {
    match record.result.outcome(check) {
        Some(CheckOutcome::Failed { refusals }) => refusals.clone(),
        other => panic!("{check:?} did not fail: {other:?}"),
    }
}

/// A refused report covers nothing, whatever its claims say.
fn covers_nothing(record: &AttestationRecord) {
    let coverage = &record.result.coverage;
    assert_eq!(coverage.cpu.protected_vcpus, 0);
    assert_eq!(coverage.memory.private_bytes, 0);
    assert!(coverage.storage.encrypted.is_empty());
    assert!(coverage.gpu.attested.is_empty());
}

#[test]
fn a_valid_fixture_report_is_accepted_and_recorded() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let report = valid_report(&challenge);
    let record = bench.verify(&report);
    assert!(record.result.is_accepted(), "{:?}", refusals(&record));
    assert_eq!(bench.book.records(), &[record.clone()]);
    assert_eq!(record.report, report.digest());
    assert_eq!(record.result.challenge, Some(challenge.id()));
    assert_eq!(record.result.identity, Some(identity(1).digest()));
    assert_eq!(record.result.session_key, Some(session_key(1)));
    assert_eq!(record.result.workload, Some(workload()));
    assert_eq!(
        record.result.facet,
        DeploymentFacet::OperatorConfidentiality
    );
    let checks: Vec<CheckName> = record
        .result
        .checks
        .iter()
        .map(|verdict| verdict.check)
        .collect();
    assert_eq!(checks, CheckName::ALL.to_vec());
    for verdict in &record.result.checks {
        let expected = if verdict.check == CheckName::GpuEvidence {
            CheckOutcome::NotApplicable
        } else {
            CheckOutcome::Passed
        };
        assert_eq!(verdict.outcome, expected, "{:?}", verdict.check);
    }
    // Exactly which portions are covered: all 8 vCPUs, the private memory (the 64 MiB
    // shared I/O window is listed and not covered), both volumes, and not the GPU, which
    // sent no report of its own.
    let coverage = &record.result.coverage;
    assert_eq!(
        coverage.cpu,
        CpuCoverage {
            protected_vcpus: 8,
            total_vcpus: 8
        }
    );
    assert_eq!(
        coverage.memory,
        MemoryCoverage {
            private_bytes: 32 * GIB - 64 * MIB,
            shared_bytes: 64 * MIB,
            total_bytes: 32 * GIB
        }
    );
    assert_eq!(
        coverage.storage.encrypted,
        BTreeSet::from([volume("root"), volume("data")])
    );
    assert!(coverage.storage.not_covered.is_empty());
    assert!(coverage.gpu.attested.is_empty());
    assert_eq!(coverage.gpu.not_covered, BTreeSet::from([0]));
}

fn keys(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                found.push(key.clone());
                keys(inner, found);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|inner| keys(inner, found)),
        _ => {}
    }
}

#[test]
fn results_are_facets_with_verdicts_never_a_score() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let record = bench.verify(&valid_report(&challenge));
    let json = serde_json::to_value(&record).unwrap();
    let mut found = Vec::new();
    keys(&json, &mut found);
    for key in &found {
        let lower = key.to_lowercase();
        assert!(
            !lower.contains("score") && !lower.contains("level") && !lower.contains("tier"),
            "{key}"
        );
    }
    assert_eq!(json["result"]["facet"], "operator_confidentiality");
    assert_eq!(json["result"]["verdict"]["verdict"], "verified");
    let back: AttestationRecord = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back, record);
    let mut extra = json;
    extra["result"]["score"] = serde_json::json!(97);
    assert!(serde_json::from_value::<AttestationRecord>(extra).is_err());
}

#[test]
fn a_stale_nonce_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let report = valid_report(&challenge);
    assert!(bench.verify(&report).result.is_accepted());
    // The same report again: its challenge was answered, so the nonce is stale.
    let replay = bench.verify(&report);
    assert!(!replay.result.is_accepted());
    assert_eq!(
        failed(&replay, CheckName::Nonce),
        vec![AttestationRefusal::StaleNonce]
    );
    assert_eq!(
        replay.result.outcome(CheckName::SessionKeyBinding),
        Some(&CheckOutcome::NotEvaluated {
            because: CheckName::Nonce
        })
    );
    assert_eq!(
        replay.result.outcome(CheckName::Freshness),
        Some(&CheckOutcome::NotEvaluated {
            because: CheckName::Nonce
        })
    );
    assert_eq!(replay.result.challenge, None);
    // A nonce never issued is stale too.
    let mut forged = valid_report(&challenge);
    forged.body.bound_nonce = AttestationNonce::new([9; 32]);
    forged.body.report_data = report_data(
        &forged.body.bound_nonce,
        &forged.body.bound_session_key,
        &forged.body.bound_workload,
    );
    resign(&mut forged);
    let record = bench.verify(&forged);
    assert_eq!(
        failed(&record, CheckName::Nonce),
        vec![AttestationRefusal::StaleNonce]
    );
    covers_nothing(&record);
}

#[test]
fn a_report_refused_once_cannot_be_answered_again() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut bad = valid_report(&challenge);
    bad.body.debug_enabled = true;
    resign(&mut bad);
    assert!(!bench.verify(&bad).result.is_accepted());
    // The good report for the same challenge now finds it answered.
    let record = bench.verify(&valid_report(&challenge));
    assert_eq!(
        failed(&record, CheckName::Nonce),
        vec![AttestationRefusal::StaleNonce]
    );
}

#[test]
fn a_wrong_measurement_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    let other = digest("yougori/test/measurement/v1", &[b"unreviewed"]);
    report.body.measurement = other;
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(
        failed(&record, CheckName::Measurement),
        vec![AttestationRefusal::MeasurementNotAllowed { measurement: other }]
    );
    assert!(!record.result.is_accepted());
    covers_nothing(&record);
}

#[test]
fn a_debug_flag_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.debug_enabled = true;
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(
        failed(&record, CheckName::DebugState),
        vec![AttestationRefusal::DebugEnabled]
    );
    assert!(!record.result.is_accepted());
    covers_nothing(&record);
}

#[test]
fn an_unsupported_or_too_old_security_version_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.security_versions.insert(component("snp"), 7);
    report
        .body
        .security_versions
        .remove(&component("microcode"));
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(
        failed(&record, CheckName::SecurityVersion),
        vec![
            AttestationRefusal::SecurityVersionBelowMinimum {
                component: component("microcode"),
                found: None,
                minimum: 200
            },
            AttestationRefusal::SecurityVersionBelowMinimum {
                component: component("snp"),
                found: Some(7),
                minimum: 8
            },
        ]
    );
    // Exactly at the minimum passes.
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.security_versions.insert(component("snp"), 8);
    report
        .body
        .security_versions
        .insert(component("microcode"), 200);
    resign(&mut report);
    assert!(bench.verify(&report).result.is_accepted());
}

#[test]
fn a_revoked_or_unsupported_tcb_is_refused_and_out_of_date_only_when_allowed() {
    for (status, refusal) in [
        (TcbStatus::Revoked, AttestationRefusal::TcbRevoked),
        (TcbStatus::Unsupported, AttestationRefusal::TcbUnsupported),
        (TcbStatus::OutOfDate, AttestationRefusal::TcbOutOfDate),
    ] {
        let mut bench = Bench::new();
        bench.vendor.tcb.insert(chip(), status);
        let challenge = bench.challenge();
        let record = bench.verify(&valid_report(&challenge));
        assert_eq!(failed(&record, CheckName::TcbStatus), vec![refusal]);
        assert!(!record.result.is_accepted());
    }
    let mut bench = Bench::new();
    bench.vendor.tcb.insert(chip(), TcbStatus::OutOfDate);
    let allowing = AttestationPolicy {
        allow_out_of_date_tcb: true,
        ..policy()
    };
    let challenge = bench.challenge();
    assert!(bench
        .verify_with(&valid_report(&challenge), &allowing)
        .result
        .is_accepted());
    for status in [TcbStatus::Revoked, TcbStatus::Unsupported] {
        bench.vendor.tcb.insert(chip(), status);
        let challenge = bench.challenge();
        assert!(!bench
            .verify_with(&valid_report(&challenge), &allowing)
            .result
            .is_accepted());
    }
}

#[test]
fn an_unbound_session_key_or_workload_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    // A report produced for another channel, consistently signed.
    report.body.bound_session_key = session_key(2);
    report.body.report_data = report_data(&challenge.nonce, &session_key(2), &workload());
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(
        failed(&record, CheckName::SessionKeyBinding),
        vec![AttestationRefusal::UnboundSessionKey]
    );
    assert_eq!(
        record.result.outcome(CheckName::ReportData),
        Some(&CheckOutcome::Passed)
    );

    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    let other = digest("yougori/test/workload/v1", &[b"something-else"]);
    report.body.bound_workload = other;
    report.body.report_data = report_data(&challenge.nonce, &session_key(1), &other);
    resign(&mut report);
    assert_eq!(
        failed(&bench.verify(&report), CheckName::WorkloadBinding),
        vec![AttestationRefusal::UnboundWorkload]
    );

    // Report data that is not the binding of its claimed fields.
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.report_data = digest("yougori/test/report-data/v1", &[b"x"]);
    resign(&mut report);
    assert_eq!(
        failed(&bench.verify(&report), CheckName::ReportData),
        vec![AttestationRefusal::ReportDataMismatch]
    );
}

#[test]
fn a_self_reported_measurement_or_a_vtpm_alone_never_satisfies_the_profile() {
    for (origin, refusal) in [
        (
            ReportOrigin::SelfReported,
            AttestationRefusal::SelfReportedMeasurement,
        ),
        (ReportOrigin::VtpmQuote, AttestationRefusal::VtpmAlone),
    ] {
        let mut bench = Bench::new();
        let challenge = bench.challenge();
        let mut report = valid_report(&challenge);
        report.body.origin = origin;
        // Even with a signature the fake vendor accepts.
        resign(&mut report);
        let record = bench.verify(&report);
        assert_eq!(failed(&record, CheckName::ReportOrigin), vec![refusal]);
        assert_eq!(
            record.result.outcome(CheckName::Measurement),
            Some(&CheckOutcome::NotEvaluated {
                because: CheckName::ReportOrigin
            })
        );
        assert!(!record.result.is_accepted());
        covers_nothing(&record);
    }
}

#[test]
fn a_rejected_or_unverifiable_vendor_chain_leaves_every_claim_unevaluated() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut unknown_root = valid_report(&challenge);
    unknown_root.chain = vec![digest("yougori/test/vendor-root/v1", &[b"self-signed"])];
    let record = bench.verify(&unknown_root);
    assert_eq!(
        failed(&record, CheckName::VendorChain),
        vec![AttestationRefusal::ChainRejected {
            reason: ChainRejection::UnknownRoot
        }]
    );
    for check in [
        CheckName::TcbStatus,
        CheckName::Nonce,
        CheckName::Measurement,
        CheckName::DebugState,
        CheckName::SessionKeyBinding,
    ] {
        assert_eq!(
            record.result.outcome(check),
            Some(&CheckOutcome::NotEvaluated {
                because: CheckName::VendorChain
            })
        );
    }
    covers_nothing(&record);

    let challenge = bench.challenge();
    let mut tampered = valid_report(&challenge);
    tampered.body.protected_vcpus = 64;
    assert_eq!(
        failed(&bench.verify(&tampered), CheckName::VendorChain),
        vec![AttestationRefusal::ChainRejected {
            reason: ChainRejection::BadSignature
        }]
    );

    let challenge = bench.challenge();
    let mut empty = valid_report(&challenge);
    empty.chain.clear();
    assert_eq!(
        failed(&bench.verify(&empty), CheckName::VendorChain),
        vec![AttestationRefusal::ChainRejected {
            reason: ChainRejection::EmptyChain
        }]
    );

    bench.vendor.available = false;
    let challenge = bench.challenge();
    assert_eq!(
        failed(
            &bench.verify(&valid_report(&challenge)),
            CheckName::VendorChain
        ),
        vec![AttestationRefusal::VerifierUnavailable]
    );
}

#[test]
fn a_late_report_or_one_from_another_clock_session_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    bench.now = MonotonicTime::from_nanos(bench.now.as_nanos() + 61_000_000_000);
    let record = bench.verify(&valid_report(&challenge));
    assert_eq!(
        failed(&record, CheckName::Freshness),
        vec![AttestationRefusal::StaleReport {
            age_nanos: 61_000_000_000,
            max_nanos: 60_000_000_000
        }]
    );
    // Exactly at the limit is still fresh.
    let challenge = bench.challenge();
    bench.now = MonotonicTime::from_nanos(bench.now.as_nanos() + 60_000_000_000);
    assert!(bench.verify(&valid_report(&challenge)).result.is_accepted());

    let challenge = bench.challenge();
    bench.clock = session(8);
    assert_eq!(
        failed(
            &bench.verify(&valid_report(&challenge)),
            CheckName::Freshness
        ),
        vec![AttestationRefusal::OtherClock]
    );
}

#[test]
fn a_report_from_another_platform_is_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.platform = TeePlatform::IntelTdx;
    resign(&mut report);
    assert_eq!(
        failed(&bench.verify(&report), CheckName::Platform),
        vec![AttestationRefusal::PlatformMismatch {
            expected: TeePlatform::AmdSevSnp,
            found: TeePlatform::IntelTdx
        }]
    );
}

#[test]
fn gpu_coverage_needs_a_verified_bound_confidential_mode_report() {
    let requiring_gpu = AttestationPolicy {
        required: BTreeSet::from([Portion::Cpu, Portion::Memory, Portion::Gpu]),
        ..policy()
    };
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let record = bench.verify_with(&valid_report(&challenge), &requiring_gpu);
    assert_eq!(
        failed(&record, CheckName::Coverage),
        vec![AttestationRefusal::PortionNotCovered {
            portion: Portion::Gpu
        }]
    );

    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.gpus.push(valid_gpu_report(&challenge, 0));
    let record = bench.verify_with(&report, &requiring_gpu);
    assert!(record.result.is_accepted(), "{:?}", refusals(&record));
    assert_eq!(record.result.coverage.gpu.attested, BTreeSet::from([0]));
    assert!(record.result.coverage.gpu.not_covered.is_empty());

    type Mutation = fn(&mut super::attestation::GpuReport, &AttestationChallenge);
    let cases: [(Mutation, GpuProblem); 6] = [
        (
            |gpu, _| gpu.body.bound_nonce = AttestationNonce::new([3; 32]),
            GpuProblem::StaleNonce,
        ),
        (
            |gpu, _| gpu.body.bound_session_key = session_key(9),
            GpuProblem::UnboundSessionKey,
        ),
        (
            |gpu, _| gpu.body.confidential_mode = false,
            GpuProblem::NotConfidentialMode,
        ),
        (
            |gpu, _| gpu.body.debug_enabled = true,
            GpuProblem::DebugEnabled,
        ),
        (
            |gpu, _| gpu.body.measurement = digest("yougori/test/gpu-measurement/v1", &[b"x"]),
            GpuProblem::MeasurementNotAllowed,
        ),
        (|gpu, _| gpu.body.device = 5, GpuProblem::UnexpectedDevice),
    ];
    for (mutate, problem) in cases {
        let challenge = bench.challenge();
        let mut report = valid_report(&challenge);
        let mut gpu = valid_gpu_report(&challenge, 0);
        mutate(&mut gpu, &challenge);
        resign_gpu(&mut gpu);
        let device = gpu.body.device;
        report.gpus.push(gpu);
        let record = bench.verify_with(&report, &requiring_gpu);
        assert_eq!(
            failed(&record, CheckName::GpuEvidence),
            vec![AttestationRefusal::GpuReportRefused { device, problem }]
        );
        assert!(record.result.coverage.gpu.attested.is_empty());
        assert!(!record.result.is_accepted());
    }
    assert_eq!(
        gpu_measurement(),
        policy().gpu_measurements.into_iter().next().unwrap()
    );
}

#[test]
fn a_gpu_report_on_its_own_does_not_cover_the_cpu_and_a_bad_one_refuses() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    let mut gpu = valid_gpu_report(&challenge, 0);
    gpu.chain = vec![digest("yougori/test/vendor-root/v1", &[b"unknown"])];
    report.gpus.push(gpu);
    let record = bench.verify(&report);
    assert_eq!(
        failed(&record, CheckName::GpuEvidence),
        vec![AttestationRefusal::GpuReportRefused {
            device: 0,
            problem: GpuProblem::ChainRejected {
                reason: ChainRejection::UnknownRoot
            }
        }]
    );
    assert!(!record.result.is_accepted());
}

#[test]
fn storage_coverage_names_exactly_the_volumes_the_measured_image_does_not_encrypt() {
    let mut bench = Bench::new();
    let mut nonces = SeededNonces(SeededRng::new(5));
    let mut wider = target();
    wider.volumes.insert(volume("scratch"));
    let challenge = bench
        .book
        .challenge(
            &mut nonces,
            identity(1).digest(),
            session_key(1),
            workload(),
            wider,
            bench.clock,
            bench.now,
        )
        .unwrap();
    let requiring_storage = AttestationPolicy {
        required: BTreeSet::from([Portion::Cpu, Portion::Memory, Portion::Storage]),
        ..policy()
    };
    let record = bench.verify_with(&valid_report(&challenge), &requiring_storage);
    assert_eq!(
        record.result.coverage.storage.not_covered,
        BTreeSet::from([volume("scratch")])
    );
    assert_eq!(
        record.result.coverage.storage.encrypted,
        BTreeSet::from([volume("root"), volume("data")])
    );
    assert_eq!(
        failed(&record, CheckName::Coverage),
        vec![AttestationRefusal::PortionNotCovered {
            portion: Portion::Storage
        }]
    );
}

#[test]
fn partial_cpu_and_oversized_shared_memory_are_stated_and_refused() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.protected_vcpus = 6;
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(
        record.result.coverage.cpu,
        CpuCoverage {
            protected_vcpus: 6,
            total_vcpus: 8
        }
    );
    assert_eq!(
        failed(&record, CheckName::Coverage),
        vec![AttestationRefusal::PortionNotCovered {
            portion: Portion::Cpu
        }]
    );

    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.shared_memory_bytes = 128 * MIB;
    report.body.private_memory_bytes = 32 * GIB - 128 * MIB;
    resign(&mut report);
    let record = bench.verify(&report);
    assert_eq!(record.result.coverage.memory.shared_bytes, 128 * MIB);
    assert_eq!(
        failed(&record, CheckName::Coverage),
        vec![AttestationRefusal::PortionNotCovered {
            portion: Portion::Memory
        }]
    );

    // Memory that does not add up to the instance's total is not covered either.
    let challenge = bench.challenge();
    let mut report = valid_report(&challenge);
    report.body.private_memory_bytes = 16 * GIB;
    resign(&mut report);
    assert_eq!(
        failed(&bench.verify(&report), CheckName::Coverage),
        vec![AttestationRefusal::PortionNotCovered {
            portion: Portion::Memory
        }]
    );
}

#[test]
fn every_vm_p41_failure_refuses_the_claimed_confidential_profile() {
    type Mutation = fn(&mut AttestationReport);
    let mutations: [(&str, Mutation); 6] = [
        ("wrong measurement", |report| {
            report.body.measurement = digest("yougori/test/measurement/v1", &[b"bad"])
        }),
        ("debug mode", |report| report.body.debug_enabled = true),
        ("old security version", |report| {
            report.body.security_versions.insert(component("snp"), 1);
        }),
        ("unbound session key", |report| {
            report.body.bound_session_key = session_key(3);
            report.body.report_data = report_data(
                &report.body.bound_nonce,
                &session_key(3),
                &report.body.bound_workload,
            );
        }),
        ("self-reported", |report| {
            report.body.origin = ReportOrigin::SelfReported
        }),
        ("vTPM only", |report| {
            report.body.origin = ReportOrigin::VtpmQuote
        }),
    ];
    for (name, mutate) in mutations {
        let mut bench = Bench::new();
        let challenge = bench.challenge();
        let mut report = valid_report(&challenge);
        mutate(&mut report);
        resign(&mut report);
        let record = bench.verify(&report);
        assert!(!record.result.is_accepted(), "{name}");
        assert!(!refusals(&record).is_empty(), "{name}");
        covers_nothing(&record);
    }
    for status in [TcbStatus::Revoked, TcbStatus::Unsupported] {
        let mut bench = Bench::new();
        bench.vendor.tcb.insert(chip(), status);
        let challenge = bench.challenge();
        assert!(!bench.verify(&valid_report(&challenge)).result.is_accepted());
    }
}

#[test]
fn a_repeating_nonce_source_is_refused() {
    let mut book = AttestationBook::new();
    let mut nonces = RepeatingNonces;
    let mut ask = |book: &mut AttestationBook| {
        book.challenge(
            &mut nonces,
            identity(1).digest(),
            session_key(1),
            workload(),
            target(),
            session(1),
            MonotonicTime::ZERO,
        )
    };
    assert!(ask(&mut book).is_ok());
    assert_eq!(ask(&mut book), Err(AttestationRefusal::NonceReused));
}

#[test]
fn the_report_data_binds_nonce_session_key_and_workload() {
    let nonce = AttestationNonce::new([1; 32]);
    let base = report_data(&nonce, &session_key(1), &workload());
    assert_ne!(
        base,
        report_data(
            &AttestationNonce::new([2; 32]),
            &session_key(1),
            &workload()
        )
    );
    assert_ne!(base, report_data(&nonce, &session_key(2), &workload()));
    assert_ne!(
        base,
        report_data(&nonce, &session_key(1), &Digest::from_bytes([0; 32]))
    );
    let json = serde_json::to_value(nonce).unwrap();
    assert_eq!(json, serde_json::json!("01".repeat(32)));
    assert_eq!(
        serde_json::from_value::<AttestationNonce>(json).unwrap(),
        nonce
    );
}

#[test]
fn a_record_backs_a_launch_only_for_its_identity_session_workload_and_age() {
    let mut bench = Bench::new();
    let challenge = bench.challenge();
    let record = bench.verify(&valid_report(&challenge));
    let now = bench.now;
    let max = Duration::from_secs(300);
    let ok = |record: &AttestationRecord| {
        record.usable_for(
            identity(1).digest(),
            session_key(1),
            workload(),
            session(7),
            now,
            max,
        )
    };
    assert_eq!(ok(&record), Ok(()));
    assert_eq!(
        record.usable_for(
            identity(2).digest(),
            session_key(1),
            workload(),
            session(7),
            now,
            max
        ),
        Err(AttestationUse::OtherIdentity)
    );
    assert_eq!(
        record.usable_for(
            identity(1).digest(),
            session_key(2),
            workload(),
            session(7),
            now,
            max
        ),
        Err(AttestationUse::OtherSessionKey)
    );
    assert_eq!(
        record.usable_for(
            identity(1).digest(),
            session_key(1),
            digest("yougori/test/workload/v1", &[b"other"]),
            session(7),
            now,
            max
        ),
        Err(AttestationUse::OtherWorkload)
    );
    assert_eq!(
        record.usable_for(
            identity(1).digest(),
            session_key(1),
            workload(),
            session(8),
            now,
            max
        ),
        Err(AttestationUse::OtherClock)
    );
    let later = MonotonicTime::from_nanos(now.as_nanos() + 301_000_000_000);
    assert!(matches!(
        record.usable_for(
            identity(1).digest(),
            session_key(1),
            workload(),
            session(7),
            later,
            max
        ),
        Err(AttestationUse::Stale { .. })
    ));
    let challenge = bench.challenge();
    let mut bad = valid_report(&challenge);
    bad.body.debug_enabled = true;
    resign(&mut bad);
    let refused = bench.verify(&bad);
    assert_eq!(ok(&refused), Err(AttestationUse::NotAccepted));
}

#[test]
fn tagged_records_refuse_unknown_fields_on_every_variant() {
    use super::adapter::BillingOutcome;
    use super::attestation::VendorVerdict;
    use super::control::{ControlBody, SessionState};
    use super::ssh::HostKeyProblem;
    fn refuses<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        value: T,
    ) {
        let mut json = serde_json::to_value(&value).unwrap();
        assert_eq!(serde_json::from_value::<T>(json.clone()).unwrap(), value);
        json["smuggled"] = serde_json::json!(true);
        assert!(serde_json::from_value::<T>(json).is_err(), "{value:?}");
    }
    refuses(BillingOutcome::Settled {
        charged_microunits: 1,
    });
    refuses(SessionState::Live);
    refuses(HostKeyProblem::Empty);
    refuses(ControlBody::Heartbeat);
    refuses(ControlBody::Stop);
    refuses(VendorVerdict::Unavailable);
    refuses(CheckOutcome::Passed);
    refuses(CheckOutcome::NotApplicable);
    refuses(FacetVerdict::Verified);
    refuses(AttestationUse::NotAccepted);
}
