//! Assembling the evidence row of one backend on one host from the evidence that exists
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §7.1, lines 2356–2364; VM-W23, line
//! 2622; §8.1, lines 2433–2439; VM-W04, line 2589).
//!
//! The row reads only what was handed in: the doctor's examination of the host
//! (`sandbox::doctor`), the sealed launch records of the backend (`sandbox::backend`),
//! the verified guest image release (`sandbox::guest_image`) and the stamped V15 verdict
//! for VM-CP-05 (`sandbox::probes`). Nothing is run, observed or stamped again. A record's
//! guest assertions are never read.
//!
//! Before anything is read, the parts must be about one combination, or the row is
//! refused: the reading is about the doctor's host; the backend is one the doctor
//! examined; every record is of that backend, of one build, observed the doctor's host
//! build and is given once; every record the doctor read results from is given; the
//! image's architecture is the host's; every record pinned and booted the same root
//! image, the manifest's when one is given; records agree on every combination field; the
//! verdict's profile is one the image installs for its workload; and the doctor's VM-CP-05
//! result, when the doctor judged one, is the status the verdict gives.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::field::{Field, Freshness, RowField, Source, Unavailable};
use super::row::{
    label_of, BackendPart, ConfinementPart, DevicePart, GuestConfinement, HostPart, ImagePart,
    LabelBasis, LaunchPath, LifecyclePart, LifecycleResult, MatrixRow, NetworkPart,
    PerimeterEnforcement, SignedImage, COMBINATION_DOMAIN, LIFECYCLE_CHECKS, ROW_NOTICE,
};
use crate::foundation::evidence::{OsKind, UnknownReason};
use crate::foundation::ids::{digest, ContentKey, Digest};
use crate::sandbox::backend::{
    Accelerator, Architecture as HostArchitecture, BackendIdentity, BackendKind,
    ConfinementControl, DeviceProfile, FactName, HostBuild, HostFact, HostObserved, LaunchRecord,
    NetworkAuthority, PerimeterRequirement,
};
use crate::sandbox::doctor::{CandidateReport, DoctorReport};
use crate::sandbox::guest_image::VerifiedImage;
use crate::sandbox::probes::{
    status_of_verdict, CheckRefusal, CheckStatus, JudgeContext, RunProfile, Vm05Evaluation,
};
use crate::sandbox::trust::{Architecture as ImageArchitecture, UnixSeconds};
use crate::sandbox_contract::confinement::WorkloadProfile;

/// The evidence one row is assembled from.
#[derive(Clone, Copy, Debug)]
pub struct RowSources<'a> {
    /// The doctor's examination of the host.
    pub doctor: &'a DoctorReport,
    /// The candidate backend the row is about.
    pub backend: BackendKind,
    /// Sealed launch records of that backend on that host, oldest first; none is allowed.
    pub records: &'a [LaunchRecord],
    /// The verified release the launches booted, if known.
    pub image: Option<&'a VerifiedImage>,
    /// The stamped V15 verdict for VM-CP-05, if one was evaluated.
    pub confinement: Option<&'a Vm05Evaluation>,
}

/// When and under what the row is read: the evidence clock's reading, the configuration
/// in force, the oldest evidence accepted and the host's operating system, and the
/// calendar time (from `sandbox::trust::TrustClock`) the manifest's validity is judged at.
#[derive(Clone, Copy, Debug)]
pub struct Reading {
    pub context: JudgeContext,
    pub calendar: UnixSeconds,
}

/// Why a row was not assembled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RowError {
    /// The reading is about another host operating system than the doctor's report.
    ReadingOfOtherHost {
        host: OsKind,
        reading: OsKind,
    },
    /// The doctor did not examine this backend on this host.
    NotExamined {
        backend: BackendKind,
    },
    /// A launch record was given twice.
    DuplicateRecord {
        record: Digest,
    },
    /// A launch record was sealed by another kind of backend.
    OtherBackend {
        record: Digest,
        examined: BackendKind,
        found: BackendKind,
    },
    /// A launch record was sealed by another build than the first record's.
    OtherBackendBuild {
        record: Digest,
    },
    /// A launch record does not show the doctor's host build as observed.
    OtherHost {
        record: Digest,
    },
    /// The doctor read results from a launch record that was not given.
    DoctorRecordMissing {
        record: Digest,
    },
    /// The guest image is built for another architecture than the host's.
    ImageArchitecture {
        host: HostArchitecture,
        image: ImageArchitecture,
    },
    /// A launch record pinned or booted another root image than expected: the manifest's,
    /// or without one the first record's.
    OtherImage {
        record: Digest,
        expected: Digest,
        found: Digest,
    },
    /// A launch record disagrees with an earlier one about a field of the combination.
    Disagree {
        field: RowField,
        record: Digest,
    },
    /// The verdict is for a confinement profile the image does not install for its
    /// workload.
    ProfileNotInstalled {
        workload: WorkloadProfile,
        profile: Digest,
    },
    /// The doctor judged VM-CP-05 otherwise than the verdict given would.
    VerdictDisagrees {
        doctor: CheckStatus,
        verdict: CheckStatus,
    },
    Unserializable {
        detail: String,
    },
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadingOfOtherHost { host, reading } => write!(
                f,
                "the doctor examined a {host} host, and the row is read for a {reading} host"
            ),
            Self::NotExamined { backend } => {
                write!(f, "the doctor did not examine {backend} on this host")
            }
            Self::DuplicateRecord { record } => {
                write!(f, "launch record {record} was given twice")
            }
            Self::OtherBackend {
                record,
                examined,
                found,
            } => write!(
                f,
                "launch record {record} was sealed by {found}, and the row is about {examined}"
            ),
            Self::OtherBackendBuild { record } => write!(
                f,
                "launch record {record} was sealed by another backend build than the first record"
            ),
            Self::OtherHost { record } => write!(
                f,
                "launch record {record} does not show the examined host build as observed"
            ),
            Self::DoctorRecordMissing { record } => write!(
                f,
                "the doctor read results from launch record {record}, which was not given"
            ),
            Self::ImageArchitecture { host, image } => write!(
                f,
                "the guest image is built for {image}, and the host is {}",
                host.tag()
            ),
            Self::OtherImage {
                record,
                expected,
                found,
            } => write!(
                f,
                "launch record {record} pinned or booted root image {found}, not {expected}"
            ),
            Self::Disagree { field, record } => write!(
                f,
                "launch record {record} disagrees with an earlier record about the {field}"
            ),
            Self::ProfileNotInstalled { workload, profile } => write!(
                f,
                "the image does not install confinement profile {profile} for the {} workload",
                workload.label()
            ),
            Self::VerdictDisagrees { doctor, verdict } => write!(
                f,
                "the doctor judged VM-CP-05 {doctor}, and the verdict given reads {verdict}"
            ),
            Self::Unserializable { detail } => {
                write!(f, "the combination could not be serialized: {detail}")
            }
        }
    }
}

impl std::error::Error for RowError {}

/// Whether a host of `host` runs an image built for `image`.
fn same_architecture(host: HostArchitecture, image: ImageArchitecture) -> bool {
    matches!(
        (host, image),
        (HostArchitecture::X86_64, ImageArchitecture::X86_64)
            | (HostArchitecture::Aarch64, ImageArchitecture::Aarch64)
    )
}

/// The combination a row is about, as its identity is computed. An element nobody
/// observed is written as null.
#[derive(Serialize)]
struct Combination<'a> {
    host: &'a HostBuild,
    backend: BackendKind,
    profiles: &'a BTreeSet<RunProfile>,
    build: Option<&'a BackendIdentity>,
    manifest: Option<ContentKey>,
    root_image: Option<Digest>,
    accelerator: Option<&'a Accelerator>,
    hypervisor_confinement: Option<&'a BTreeSet<ConfinementControl>>,
    guest_confinement: Option<(WorkloadProfile, Digest)>,
    device_profile: Option<&'a DeviceProfile>,
    network: Option<&'a NetworkAuthority>,
    perimeter: Option<&'a PerimeterRequirement>,
    lifecycle: Option<&'a BTreeSet<LaunchPath>>,
}

/// Assembles the evidence row of `sources.backend` on the doctor's host at `reading`,
/// after checking that every part is about one combination (module documentation).
pub fn assemble(sources: &RowSources<'_>, reading: &Reading) -> Result<MatrixRow, RowError> {
    let context = &reading.context;
    let doctor = sources.doctor;
    let host = &doctor.host;
    if context.os != host.os {
        return Err(RowError::ReadingOfOtherHost {
            host: host.os,
            reading: context.os,
        });
    }
    let candidate = doctor
        .candidates
        .iter()
        .find(|candidate| candidate.candidate.backend == sources.backend)
        .ok_or(RowError::NotExamined {
            backend: sources.backend,
        })?;
    let records = sources.records;
    check_records(records, sources.backend, host, candidate)?;
    let root_image = check_image(sources, host)?;
    check_confinement(sources, candidate)?;

    let report = &candidate.report;
    let report_check = report.current_at(context.now, context.max_age, context.configuration);
    let report_problem = report_check.err();
    let from_doctor = DoctorSource {
        report: report.identity(),
        freshness: Freshness::of_check(report_check),
    };
    let lifecycle_checks = report
        .entries()
        .iter()
        .filter(|entry| LIFECYCLE_CHECKS.contains(&entry.check.number()))
        .map(|entry| LifecycleResult {
            check: entry.check,
            applicability: entry.applicability,
            status: entry.status.clone(),
        })
        .collect();

    let mut row = MatrixRow {
        notice: ROW_NOTICE,
        combination: Digest::from_bytes([0; 32]),
        label: candidate.label,
        basis: LabelBasis::Doctor,
        host: HostPart {
            examined: from_doctor.field(host.clone()),
            observed: observed(
                records,
                FactName::Host,
                RowField::HostObserved,
                context,
                |r| host_fact(&r.host_observed().host),
            )?,
        },
        backend: BackendPart {
            candidate: from_doctor.field(candidate.candidate),
            build: sealed(records, RowField::BackendBuild, context, |r| {
                r.backend().clone()
            })?,
        },
        guest_image: ImagePart {
            manifest: manifest(sources.image, reading.calendar),
            pinned: sealed(records, RowField::ImagePinned, context, |r| {
                r.pinned().guest_image
            })?,
            booted: observed(
                records,
                FactName::GuestImage,
                RowField::ImageBooted,
                context,
                |r| host_fact(&r.host_observed().guest_image),
            )?,
        },
        accelerator: observed(
            records,
            FactName::Accelerator,
            RowField::Accelerator,
            context,
            |r| Ok(r.accelerator()),
        )?,
        confinement: ConfinementPart {
            hypervisor: observed(
                records,
                FactName::Confinement,
                RowField::HypervisorConfinement,
                context,
                |r| host_fact(&r.host_observed().confinement),
            )?,
            guest: guest_confinement(sources.confinement, context),
        },
        devices: DevicePart {
            profile: sealed(records, RowField::DeviceProfile, context, |r| {
                r.device_profile().clone()
            })?,
            measured: observed(
                records,
                FactName::Devices,
                RowField::DeviceInventory,
                context,
                |r| host_fact(&r.host_observed().devices),
            )?,
        },
        network: NetworkPart {
            enforced: observed(
                records,
                FactName::Network,
                RowField::NetworkEnforcement,
                context,
                |r| host_fact(&r.host_observed().network),
            )?,
            perimeter: perimeter(records, context)?,
        },
        lifecycle: LifecyclePart {
            paths: paths(records, context),
            checks: from_doctor.field(lifecycle_checks),
        },
        result: from_doctor.field(candidate.clone()),
    };

    let combination = Combination {
        host,
        backend: sources.backend,
        profiles: &doctor.profiles,
        build: row.backend.build.value(),
        manifest: row.guest_image.manifest.value().map(|image| image.manifest),
        root_image,
        accelerator: row.accelerator.value(),
        hypervisor_confinement: row.confinement.hypervisor.value(),
        guest_confinement: row
            .confinement
            .guest
            .value()
            .map(|guest| (guest.workload, guest.profile)),
        device_profile: row.devices.profile.value(),
        network: row.network.enforced.value(),
        perimeter: row
            .network
            .perimeter
            .value()
            .map(|perimeter| &perimeter.requirement),
        lifecycle: row.lifecycle.paths.value(),
    };
    let bytes = serde_json::to_vec(&combination).map_err(|error| RowError::Unserializable {
        detail: error.to_string(),
    })?;
    row.combination = digest(COMBINATION_DOMAIN, &[&bytes]);

    let states: Vec<_> = RowField::ALL
        .into_iter()
        .map(|field| (field, row.state(field)))
        .collect();
    let (label, basis) = label_of(candidate.label, report_problem, &states);
    row.label = label;
    row.basis = basis;
    Ok(row)
}

/// The doctor's report as the source of a field.
struct DoctorSource {
    report: Digest,
    freshness: Freshness,
}

impl DoctorSource {
    fn field<T>(&self, value: T) -> Field<T> {
        Field::Known {
            value,
            source: Source::Doctor {
                report: self.report,
            },
            freshness: self.freshness,
        }
    }
}

fn check_records(
    records: &[LaunchRecord],
    backend: BackendKind,
    host: &HostBuild,
    candidate: &CandidateReport,
) -> Result<(), RowError> {
    let mut seen = BTreeSet::new();
    for record in records {
        let identity = record.identity();
        if !seen.insert(identity) {
            return Err(RowError::DuplicateRecord { record: identity });
        }
        let kind = record.backend().kind;
        if kind != backend {
            return Err(RowError::OtherBackend {
                record: identity,
                examined: backend,
                found: kind,
            });
        }
        if records
            .first()
            .is_some_and(|first| first.backend() != record.backend())
        {
            return Err(RowError::OtherBackendBuild { record: identity });
        }
        if record.host_observed().host.value() != Some(host) {
            return Err(RowError::OtherHost { record: identity });
        }
    }
    for result in &candidate.from_launch_records {
        if let Some(record) = result.records.iter().find(|record| !seen.contains(*record)) {
            return Err(RowError::DoctorRecordMissing { record: *record });
        }
    }
    Ok(())
}

/// Checks the image against the host and the records, and gives the root image of the
/// combination: the manifest's, or without one the records'.
fn check_image(sources: &RowSources<'_>, host: &HostBuild) -> Result<Option<Digest>, RowError> {
    let expected = match sources.image {
        Some(image) => {
            let architecture = image.manifest().document().architecture;
            if !same_architecture(host.architecture, architecture) {
                return Err(RowError::ImageArchitecture {
                    host: host.architecture,
                    image: architecture,
                });
            }
            Some(image.manifest().root_image())
        }
        None => sources
            .records
            .first()
            .map(|record| record.pinned().guest_image),
    };
    let Some(expected) = expected else {
        return Ok(None);
    };
    for record in sources.records {
        let pinned = record.pinned().guest_image;
        let booted = record.host_observed().guest_image.value().copied();
        if let Some(found) = [Some(pinned), booted]
            .into_iter()
            .flatten()
            .find(|found| *found != expected)
        {
            return Err(RowError::OtherImage {
                record: record.identity(),
                expected,
                found,
            });
        }
    }
    Ok(Some(expected))
}

/// Checks the verdict against the image, which must install its profile for its
/// workload, and against the doctor's VM-CP-05 result, which must be the status the
/// verdict gives unless the doctor did not judge one: not tested, or not current.
fn check_confinement(
    sources: &RowSources<'_>,
    candidate: &CandidateReport,
) -> Result<(), RowError> {
    let Some(evaluation) = sources.confinement else {
        return Ok(());
    };
    let verdict = evaluation.verdict();
    if let Some(image) = sources.image {
        let installed = image
            .manifest()
            .workload(verdict.workload)
            .is_some_and(|feature| feature.confinement_profile == verdict.profile);
        if !installed {
            return Err(RowError::ProfileNotInstalled {
                workload: verdict.workload,
                profile: verdict.profile,
            });
        }
    }
    let judged = candidate
        .report
        .entries()
        .iter()
        .find(|entry| entry.check.number() == VM_CP_05)
        .map(|entry| &entry.status);
    let given = status_of_verdict(verdict);
    match judged {
        None
        | Some(CheckStatus::NotTested { .. })
        | Some(CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent { .. },
        }) => Ok(()),
        Some(doctor) if *doctor == given => Ok(()),
        Some(doctor) => Err(RowError::VerdictDisagrees {
            doctor: doctor.clone(),
            verdict: given,
        }),
    }
}

/// The check the V15 verdict decides.
const VM_CP_05: u8 = 5;

/// A host fact as an observation, or what the record stated when it had none.
fn host_fact<T>(fact: &HostFact<T>) -> Result<&HostObserved<T>, UnknownReason> {
    match fact {
        HostFact::Observed { observation } => Ok(observation),
        HostFact::Unavailable { reason } => Err(*reason),
    }
}

/// The host observation of `fact` in `records`: unavailable without records or when no
/// record observed it; otherwise the value every observation agrees on, from the records
/// that observed it, with the freshness of the freshest observation. A record whose
/// observation differs from an earlier one's is refused.
fn observed<'r, T: Clone + PartialEq + 'r>(
    records: &'r [LaunchRecord],
    fact: FactName,
    field: RowField,
    context: &JudgeContext,
    get: impl Fn(&'r LaunchRecord) -> Result<&'r HostObserved<T>, UnknownReason>,
) -> Result<Field<T>, RowError> {
    if records.is_empty() {
        return Ok(Field::unavailable(Unavailable::NoLaunchRecord));
    }
    let mut value: Option<&T> = None;
    let mut read_from = Vec::new();
    let mut best: Option<(Freshness, &HostObserved<T>)> = None;
    let mut reason = UnknownReason::NotTested;
    for record in records {
        let observation = match get(record) {
            Ok(observation) => observation,
            Err(why) => {
                reason = why;
                continue;
            }
        };
        match value {
            Some(agreed) if agreed != observation.value() => {
                return Err(RowError::Disagree {
                    field,
                    record: record.identity(),
                })
            }
            Some(_) => {}
            None => value = Some(observation.value()),
        }
        read_from.push(record.identity());
        let freshness = Freshness::of_stamp(
            observation.configuration(),
            observation.clock(),
            observation.observed_at(),
            observation.fresh_for(),
            context,
        );
        if best
            .as_ref()
            .is_none_or(|(kept, _)| freshness.preferred_over(kept))
        {
            best = Some((freshness, observation));
        }
    }
    Ok(match (value, best) {
        (Some(value), Some((freshness, observation))) => Field::Known {
            value: value.clone(),
            source: Source::HostObserved {
                fact,
                how: observation.source(),
                records: read_from,
            },
            freshness,
        },
        _ => Field::unavailable(Unavailable::NotObserved { fact, reason }),
    })
}

/// How fresh what a record binds is: a fact stamped when the record was sealed, under the
/// record's configuration, with no bound of its own, so the reader's maximum age decides.
fn seal_freshness(record: &LaunchRecord, context: &JudgeContext) -> Freshness {
    Freshness::of_stamp(
        record.configuration(),
        record.clock(),
        record.recorded_at(),
        Duration::MAX,
        context,
    )
}

fn identities(records: &[LaunchRecord]) -> Vec<Digest> {
    records.iter().map(LaunchRecord::identity).collect()
}

/// What `records` bind for `field`: the value every record agrees on, with the freshness
/// of the freshest seal. A record that binds another value than an earlier one is refused.
fn sealed<T: PartialEq>(
    records: &[LaunchRecord],
    field: RowField,
    context: &JudgeContext,
    get: impl Fn(&LaunchRecord) -> T,
) -> Result<Field<T>, RowError> {
    let mut agreed: Option<(T, Freshness)> = None;
    for record in records {
        let value = get(record);
        let freshness = seal_freshness(record, context);
        agreed = Some(match agreed {
            None => (value, freshness),
            Some((kept, _)) if kept != value => {
                return Err(RowError::Disagree {
                    field,
                    record: record.identity(),
                })
            }
            Some((kept, best)) if !freshness.preferred_over(&best) => (kept, best),
            Some((kept, _)) => (kept, freshness),
        });
    }
    Ok(match agreed {
        None => Field::unavailable(Unavailable::NoLaunchRecord),
        Some((value, freshness)) => Field::Known {
            value,
            source: Source::SealedRecords {
                records: identities(records),
            },
            freshness,
        },
    })
}

/// The perimeter the records asked for, which they must agree on, with how many block
/// rules have CORE-01 evidence in the freshest record. A record with perimeter evidence
/// is as fresh as its least fresh rule evidence; one without is as fresh as its seal.
fn perimeter(
    records: &[LaunchRecord],
    context: &JudgeContext,
) -> Result<Field<PerimeterEnforcement>, RowError> {
    let mut chosen: Option<(Freshness, usize)> = None;
    for record in records {
        if records
            .first()
            .is_some_and(|first| first.required().perimeter != record.required().perimeter)
        {
            return Err(RowError::Disagree {
                field: RowField::Perimeter,
                record: record.identity(),
            });
        }
        let evidence = record.perimeter_evidence();
        let mut freshness: Option<Freshness> = None;
        for satisfied in evidence {
            let rule = Freshness::of_stamp(
                satisfied.configuration(),
                record.clock(),
                satisfied.observed_at(),
                satisfied
                    .fresh_until()
                    .saturating_duration_since(satisfied.observed_at()),
                context,
            );
            if freshness.as_ref().is_none_or(|kept| rule.worse_than(kept)) {
                freshness = Some(rule);
            }
        }
        let freshness = freshness.unwrap_or_else(|| seal_freshness(record, context));
        if chosen
            .as_ref()
            .is_none_or(|(kept, _)| freshness.preferred_over(kept))
        {
            chosen = Some((freshness, evidence.len()));
        }
    }
    Ok(match (records.first(), chosen) {
        (Some(first), Some((freshness, evidenced_rules))) => Field::Known {
            value: PerimeterEnforcement {
                requirement: first.required().perimeter.clone(),
                evidenced_rules,
            },
            source: Source::SealedRecords {
                records: identities(records),
            },
            freshness,
        },
        _ => Field::unavailable(Unavailable::NoLaunchRecord),
    })
}

/// The launch paths the records exercised. Each path is as fresh as the freshest seal of
/// a record that took it, and the set as the least fresh of its paths.
fn paths(records: &[LaunchRecord], context: &JudgeContext) -> Field<BTreeSet<LaunchPath>> {
    let mut by_path: BTreeMap<LaunchPath, Freshness> = BTreeMap::new();
    for record in records {
        let path = if record.restored_from().is_some() {
            LaunchPath::Restore
        } else {
            LaunchPath::ColdBoot
        };
        let freshness = seal_freshness(record, context);
        let kept = by_path.entry(path).or_insert(freshness);
        if freshness.preferred_over(kept) {
            *kept = freshness;
        }
    }
    let mut worst: Option<Freshness> = None;
    for freshness in by_path.values() {
        if worst.as_ref().is_none_or(|kept| freshness.worse_than(kept)) {
            worst = Some(*freshness);
        }
    }
    match worst {
        None => Field::unavailable(Unavailable::NoLaunchRecord),
        Some(freshness) => Field::Known {
            value: by_path.into_keys().collect(),
            source: Source::SealedRecords {
                records: identities(records),
            },
            freshness,
        },
    }
}

fn manifest(image: Option<&VerifiedImage>, calendar: UnixSeconds) -> Field<SignedImage> {
    let Some(image) = image else {
        return Field::unavailable(Unavailable::NoSignedManifest);
    };
    let manifest = image.manifest();
    let document = manifest.document();
    Field::Known {
        value: SignedImage {
            image: manifest.image().clone(),
            release: manifest.release(),
            manifest: manifest.content_key(),
            build_record: document.build_record,
            root_image: manifest.root_image(),
            architecture: document.architecture,
        },
        source: Source::SignedManifest {
            manifest: manifest.content_key(),
            key: image.key().clone(),
        },
        freshness: Freshness::of_validity(document.issued_at, document.expires_at, calendar),
    }
}

/// The guest's confinement from the stamped verdict: as fresh as the verdict's own
/// currency check says, which refuses a verdict evaluated under another configuration,
/// on another clock or too long ago.
fn guest_confinement(
    evaluation: Option<&Vm05Evaluation>,
    context: &JudgeContext,
) -> Field<GuestConfinement> {
    let Some(evaluation) = evaluation else {
        return Field::unavailable(Unavailable::NoConfinementVerdict);
    };
    let verdict = evaluation.verdict();
    let freshness = match evaluation.status(context) {
        CheckStatus::Refused {
            refusal: CheckRefusal::NotCurrent { problem, .. },
        } => Freshness::NotCurrent { problem },
        _ => Freshness::CurrentAgeNotExposed,
    };
    Field::Known {
        value: GuestConfinement {
            workload: verdict.workload,
            profile: verdict.profile,
            outcome: verdict.outcome,
        },
        source: Source::ConfinementVerdict {
            profile: verdict.profile,
        },
        freshness,
    }
}
