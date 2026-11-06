//! The deliberately vulnerable fixture through the whole path: the three report formats,
//! the mapping onto trust findings, coverage, and the gate across an exception's expiry
//! (VM-W47, line 2670: "Deliberately vulnerable fixture exercises the gate; expiring
//! exceptions cannot become permanent silent bypasses; false-positive review
//! documented"; line 2459).

use std::collections::BTreeSet;
use std::time::Duration;

use super::fixture::{
    clock, configuration, governance, inventory, runs, runtime_version, DAY, NOW,
};
use super::*;
use crate::sandbox::trust::{
    AdvisoryId, Applicability, BlockReason, ComponentKind, ConfigurationMatrix, Disposition,
    Exception, ExceptionId, FalsePositiveReview, Finding, GateOutcome, GovernanceError,
    KnownVulnerabilityDecision, Mitigation, Owner, Reachability, Remediation, Severity, TrustClock,
    UnixSeconds,
};

const SMALLVEC_ADVISORIES: [&str; 3] = ["RUSTSEC-2021-0003", "RUSTSEC-2021-0003", "CVE-2021-25900"];

fn advisory(id: &str) -> AdvisoryId {
    AdvisoryId::new(id).unwrap()
}

/// Every fixture report taken in at the fixture's clock, each with fresh sightings.
fn records(clock: &TrustClock) -> Vec<ScanRecord> {
    let inventory = inventory();
    runs()
        .into_iter()
        .map(|(run, report)| {
            intake(
                &inventory,
                &run,
                report.as_bytes(),
                &ReachabilityStatements::none(),
                &mut Sightings::new(),
                clock,
            )
            .unwrap()
        })
        .collect()
}

fn smallvec(record: &ScanRecord) -> &MappedFinding {
    record
        .findings
        .iter()
        .find(|mapped| mapped.package.name.as_str() == "smallvec")
        .unwrap()
}

fn disposition<'a>(outcome: &'a GateOutcome, id: &str) -> &'a Disposition {
    &outcome
        .dispositions
        .iter()
        .find(|(advisory, _)| advisory.as_str() == id)
        .unwrap()
        .1
}

fn exception(id: &str, advisory_id: &str, granted_at: u64, days: u64) -> Exception {
    Exception {
        id: ExceptionId::new(id).unwrap(),
        advisory: advisory(advisory_id),
        component: ComponentKind::Runtime,
        component_version: runtime_version(),
        owner: Owner::new("runtime-owner").unwrap(),
        justification:
            "insert_many is not called by the runtime; the 0.1.1 build pins smallvec 1.6.1"
                .to_owned(),
        granted_at: UnixSeconds::new(granted_at),
        expires_at: UnixSeconds::new(granted_at + days * DAY),
    }
}

#[test]
fn the_three_formats_report_the_vulnerable_component() {
    let (_, clock) = clock();
    let records = records(&clock);
    let expected_published = [1_610_064_000, 1_610_107_200, 1_611_684_960];
    for ((record, id), published) in records
        .iter()
        .zip(SMALLVEC_ADVISORIES)
        .zip(expected_published)
    {
        let mapped = smallvec(record);
        assert_eq!(
            mapped.finding,
            Finding {
                advisory: advisory(id),
                component: ComponentKind::Runtime,
                component_version: runtime_version(),
                severity: Severity::Critical,
                applicability: Applicability::Applicable,
                reachability: Reachability::Undetermined,
                remediation: mapped.finding.remediation.clone(),
                reported_at: UnixSeconds::new(published),
                signal: mapped.finding.signal.clone(),
            },
            "{}",
            record.scanner
        );
        assert!(matches!(
            mapped.finding.remediation,
            Remediation::PackageFixAvailable { .. }
        ));
        assert_eq!(mapped.reported_at_basis, ReportedAtBasis::AdvisoryPublished);
        assert_eq!(mapped.package.to_string(), "crates_io smallvec 1.6.0");
        assert_eq!(record.covered, BTreeSet::from([ComponentKind::Runtime]));
        assert_eq!(
            record.not_covered,
            BTreeSet::from([ComponentKind::GuestKernel, ComponentKind::GuestImage])
        );
        assert_eq!(record.configuration, configuration().key);
        assert_eq!(record.scanned_at, UnixSeconds::new(NOW - 3_600));
    }
    // Each format's own severity basis and fix statements are kept.
    assert_eq!(
        records[0].findings[0].severity_basis,
        SeverityBasis::ComputedScore {
            version: CvssVersion::V3_1,
            score: CvssScore::from_tenths(98).unwrap()
        }
    );
    assert_eq!(
        smallvec(&records[1]).severity_basis,
        SeverityBasis::ReportedScore {
            score: CvssScore::from_tenths(98).unwrap()
        }
    );
    assert_eq!(
        smallvec(&records[2]).severity_basis,
        SeverityBasis::ScannerLabel {
            label: ScannerLabel::Critical
        }
    );
    let fixes = |record: &ScanRecord| -> Vec<String> {
        smallvec(record)
            .fixes
            .iter()
            .map(|fix| fix.as_str().to_owned())
            .collect()
    };
    assert_eq!(fixes(&records[0]), [">=0.6.14, <1.0.0", ">=1.6.1"]);
    assert_eq!(fixes(&records[1]), ["0.6.14", "1.6.1"]);
    assert_eq!(fixes(&records[2]), ["0.6.14", "1.6.1"]);
    assert_eq!(
        smallvec(&records[0]).aliases,
        BTreeSet::from([advisory("CVE-2021-25900")])
    );
    let counts: Vec<usize> = runs()
        .iter()
        .map(|(run, report)| {
            run.scanner
                .parse(report.as_bytes())
                .unwrap()
                .vulnerability_count()
        })
        .collect();
    assert_eq!(counts, [2, 1, 2]);
    // Trivy's configuration result is skipped visibly.
    assert_eq!(records[2].skipped.len(), 1);
    assert_eq!(records[2].skipped[0].class, "config");
}

#[test]
fn the_gate_blocks_the_vulnerable_fixture() {
    let (_, clock) = clock();
    let governance = governance();
    let configuration = configuration();
    for (record, id) in records(&clock).iter().zip(SMALLVEC_ADVISORIES) {
        let outcome = record
            .gate(&governance, &configuration, clock.now())
            .unwrap();
        assert!(outcome.has_blocker(), "{}", record.scanner);
        assert!(outcome.blocking.contains(&advisory(id)));
        // Critical has a two-day window from publication, long past.
        assert_eq!(
            disposition(&outcome, id),
            &Disposition::Blocked {
                reason: BlockReason::PastDeadline {
                    deadline: smallvec(record).finding.reported_at.plus_seconds(2 * DAY)
                }
            }
        );
        assert_eq!(
            outcome.not_scanned,
            BTreeSet::from([ComponentKind::GuestKernel, ComponentKind::GuestImage])
        );
    }
}

#[test]
fn a_finding_outside_the_configuration_is_recorded_not_dropped() {
    let (_, clock) = clock();
    let records = records(&clock);
    let audit = &records[0];
    assert_eq!(audit.findings.len(), 2);
    let helper = &audit.findings[1];
    assert_eq!(helper.finding.advisory, advisory("RUSTSEC-0000-0000"));
    assert_eq!(
        helper.finding.applicability,
        Applicability::NotApplicable {
            reason: "the inventory of runtime fixture-runtime-0.1.0 lists no crates_io fixture-build-helper 0.3.0"
                .to_owned()
        }
    );
    assert_eq!(helper.finding.remediation, Remediation::NoFix);
    let outcome = audit
        .gate(&governance(), &configuration(), clock.now())
        .unwrap();
    assert_eq!(outcome.dispositions.len(), 2);
    assert!(matches!(
        disposition(&outcome, "RUSTSEC-0000-0000"),
        Disposition::NotApplicable { .. }
    ));
    assert!(!outcome.blocking.contains(&advisory("RUSTSEC-0000-0000")));
}

#[test]
fn an_owned_exception_lets_the_fixture_pass_until_expiry_then_it_blocks_again() {
    let (manual, clock) = clock();
    let configuration = configuration();
    let mut governance = governance();
    governance
        .grant_exception(exception(
            "exc-smallvec-rustsec",
            "RUSTSEC-2021-0003",
            NOW,
            14,
        ))
        .unwrap();
    governance
        .grant_exception(exception("exc-smallvec-cve", "CVE-2021-25900", NOW, 14))
        .unwrap();
    let records = records(&clock);
    let expiry = UnixSeconds::new(NOW + 14 * DAY);

    for (record, id) in records.iter().zip(SMALLVEC_ADVISORIES) {
        let outcome = record
            .gate(&governance, &configuration, clock.now())
            .unwrap();
        assert_eq!(
            disposition(&outcome, id),
            &Disposition::Excused {
                exception: ExceptionId::new(if id == "CVE-2021-25900" {
                    "exc-smallvec-cve"
                } else {
                    "exc-smallvec-rustsec"
                })
                .unwrap(),
                owner: Owner::new("runtime-owner").unwrap(),
                until: expiry,
            }
        );
    }
    // cargo audit and OSV-Scanner have nothing else that blocks; Trivy's other finding
    // still does until it is reviewed.
    assert!(!records[0]
        .gate(&governance, &configuration, clock.now())
        .unwrap()
        .has_blocker());
    assert!(!records[1]
        .gate(&governance, &configuration, clock.now())
        .unwrap()
        .has_blocker());

    // One second before expiry the exception still excuses.
    manual.advance(Duration::from_secs(14 * DAY - 1));
    assert!(!records[0]
        .gate(&governance, &configuration, clock.now())
        .unwrap()
        .has_blocker());

    // At expiry it excuses nothing, and the finding blocks with the expiry named.
    manual.advance(Duration::from_secs(1));
    assert_eq!(clock.now(), expiry);
    for (record, id) in records.iter().zip(SMALLVEC_ADVISORIES) {
        let outcome = record
            .gate(&governance, &configuration, clock.now())
            .unwrap();
        assert!(matches!(
            disposition(&outcome, id),
            Disposition::Blocked {
                reason: BlockReason::ExceptionExpired { expired_at, .. }
            } if *expired_at == expiry
        ));
    }

    // Scanning again after expiry does not revive it.
    let rescanned = {
        let inventory = inventory();
        let (mut run, report) = runs().remove(0);
        run.scanned_at = clock.now();
        intake(
            &inventory,
            &run,
            report.as_bytes(),
            &ReachabilityStatements::none(),
            &mut Sightings::new(),
            &clock,
        )
        .unwrap()
    };
    assert!(rescanned
        .gate(&governance, &configuration, clock.now())
        .unwrap()
        .has_blocker());

    // The expired exception cannot be extended in place or replaced by a longer one.
    assert_eq!(
        governance.grant_exception(exception(
            "exc-smallvec-rustsec",
            "RUSTSEC-2021-0003",
            NOW + 14 * DAY,
            14
        )),
        Err(GovernanceError::DuplicateException {
            id: ExceptionId::new("exc-smallvec-rustsec").unwrap()
        })
    );
    assert!(matches!(
        governance.grant_exception(exception(
            "exc-smallvec-forever",
            "RUSTSEC-2021-0003",
            NOW + 14 * DAY,
            3650
        )),
        Err(GovernanceError::ExceptionTooLong { .. })
    ));
    assert!(records[0]
        .gate(&governance, &configuration, clock.now())
        .unwrap()
        .has_blocker());
}

#[test]
fn a_false_positive_review_is_recorded_and_applies_to_its_finding() {
    let (_, clock) = clock();
    let configuration = configuration();
    let mut governance = governance();
    governance
        .grant_exception(exception("exc-smallvec-cve", "CVE-2021-25900", NOW, 14))
        .unwrap();
    let trivy = records(&clock).remove(2);
    let before = trivy
        .gate(&governance, &configuration, clock.now())
        .unwrap();
    assert_eq!(
        disposition(&before, "FIXTURE-2026-0001"),
        &Disposition::Blocked {
            reason: BlockReason::NoFixWithoutException
        }
    );
    assert_eq!(before.blocking, vec![advisory("FIXTURE-2026-0001")]);

    let review = FalsePositiveReview {
        advisory: advisory("FIXTURE-2026-0001"),
        component: ComponentKind::Runtime,
        component_version: runtime_version(),
        reviewer: Owner::new("runtime-owner").unwrap(),
        reason:
            "Trivy matched the crate name; fixture-codec 2.1.0 does not contain the flagged decoder"
                .to_owned(),
        reviewed_at: UnixSeconds::new(NOW),
    };
    governance.record_review(review).unwrap();
    let after = trivy
        .gate(&governance, &configuration, clock.now())
        .unwrap();
    assert_eq!(
        disposition(&after, "FIXTURE-2026-0001"),
        &Disposition::ReviewedFalsePositive {
            reviewer: Owner::new("runtime-owner").unwrap(),
            reviewed_at: UnixSeconds::new(NOW)
        }
    );
    assert!(!after.has_blocker());
    // The review is about one finding; it does not excuse the vulnerable crate.
    assert!(matches!(
        disposition(&after, "CVE-2021-25900"),
        Disposition::Excused { .. }
    ));
    let json = serde_json::to_value(&after).unwrap();
    assert!(json.to_string().contains("reviewed_false_positive"));
    // An undocumented review is refused.
    assert_eq!(
        governance.record_review(FalsePositiveReview {
            advisory: advisory("CVE-2021-25900"),
            component: ComponentKind::Runtime,
            component_version: runtime_version(),
            reviewer: Owner::new("runtime-owner").unwrap(),
            reason: String::new(),
            reviewed_at: UnixSeconds::new(NOW),
        }),
        Err(GovernanceError::BadText { field: "reason" })
    );
}

#[test]
fn the_fixture_configuration_carries_its_known_vulnerability_decision() {
    let mut matrix = ConfigurationMatrix::new();
    matrix.pin(configuration()).unwrap();
    let key = configuration().key;
    matrix
        .record_decision(KnownVulnerabilityDecision {
            advisory: advisory("RUSTSEC-2021-0003"),
            affected: key,
            component: ComponentKind::Runtime,
            component_version: runtime_version(),
            mitigation: Mitigation::Excepted {
                exception: ExceptionId::new("exc-smallvec-rustsec").unwrap(),
            },
            owner: Owner::new("runtime-owner").unwrap(),
            decided_at: UnixSeconds::new(NOW),
        })
        .unwrap();
    assert_eq!(matrix.decisions_for(&key).len(), 1);
    assert_eq!(matrix.lookup(&key).unwrap(), &configuration());
    assert_eq!(
        inventory().fingerprint(),
        configuration().fingerprint().unwrap()
    );
}

#[test]
fn the_three_formats_combine_into_one_decision() {
    let (_, clock) = clock();
    let records = records(&clock);
    let inventory = inventory();
    let configuration = configuration();
    let mut governance = governance();

    // Each format says what it can about the runtime's packages.
    let runtime = |record: &ScanRecord| record.completeness[&ComponentKind::Runtime].clone();
    assert_eq!(
        runtime(&records[0]),
        PackageCompleteness::Counted {
            inventoried: 3,
            counted: 4,
            fewer_than_inventoried: false
        }
    );
    assert!(matches!(
        runtime(&records[1]),
        PackageCompleteness::CannotTell {
            why: NotTellable::NamesFindingsOnly,
            ..
        }
    ));
    assert!(matches!(
        runtime(&records[2]),
        PackageCompleteness::CannotTell {
            why: NotTellable::NoPackageList,
            ..
        }
    ));

    let gate = combine(&inventory, &records, &governance, clock.now()).unwrap();
    // The vulnerable crate is one issue in three reports, joined by the alias cargo audit
    // and OSV-Scanner state; Trivy reports it under the CVE alone.
    assert_eq!(gate.findings.len(), 3);
    let smallvec = &gate.findings[0];
    assert_eq!(
        smallvec.advisories,
        BTreeSet::from([advisory("CVE-2021-25900"), advisory("RUSTSEC-2021-0003")])
    );
    assert_eq!(smallvec.reports.len(), 3);
    assert!(smallvec.disposition.blocks());
    assert!(matches!(
        &gate.findings[1].disposition,
        Disposition::NotApplicable { .. }
    ));
    assert_eq!(
        gate.blocking,
        vec![advisory("RUSTSEC-2021-0003"), advisory("FIXTURE-2026-0001")]
    );
    assert_eq!(
        gate.not_scanned,
        BTreeSet::from([ComponentKind::GuestKernel, ComponentKind::GuestImage])
    );
    let coverage = &gate.coverage[&ComponentKind::Runtime];
    assert_eq!(coverage.covered_by, gate.scans);
    match &coverage.completeness {
        CombinedCompleteness::Joined {
            not_listed,
            undetermined_by,
            ..
        } => {
            // OSV-Scanner named smallvec; nothing names the other two crates, and no
            // format here can tell whether it read them.
            let names: Vec<String> = not_listed.iter().map(ToString::to_string).collect();
            assert_eq!(
                names,
                ["crates_io fixture-codec 2.1.0", "crates_io serde 1.0.210"]
            );
            assert_eq!(undetermined_by, &gate.scans);
        }
        other => panic!("not joined: {other:?}"),
    }

    // An exception for one identifier leaves the report under the other blocking.
    governance
        .grant_exception(exception(
            "exc-smallvec-rustsec",
            "RUSTSEC-2021-0003",
            NOW,
            14,
        ))
        .unwrap();
    let gate = combine(&inventory, &records, &governance, clock.now()).unwrap();
    assert!(gate.findings[0].disposition.blocks());
    assert_eq!(
        gate.findings[0].deciding_advisory(),
        Some(&advisory("CVE-2021-25900"))
    );
    governance
        .grant_exception(exception("exc-smallvec-cve", "CVE-2021-25900", NOW, 14))
        .unwrap();
    let gate = combine(&inventory, &records, &governance, clock.now()).unwrap();
    assert!(matches!(
        gate.findings[0].disposition,
        Disposition::Excused { .. }
    ));
    assert_eq!(gate.blocking, vec![advisory("FIXTURE-2026-0001")]);
    assert_eq!(gate.outcome().dispositions.len(), gate.findings.len());
    // The one decision agrees with gating each record alone.
    for record in &records {
        let alone = record
            .gate(&governance, &configuration, clock.now())
            .unwrap();
        for blocked in &alone.blocking {
            assert!(gate.findings.iter().any(
                |finding| finding.advisories.contains(blocked) && finding.disposition.blocks()
            ));
        }
    }
}
