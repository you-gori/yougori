//! The isolated research realm.
//!
//! A research realm is an ordinary [`Core`] created with `RealmKind::Research`, so it already has
//! its own database file, its own key and fingerprint, its own people and computers, its own
//! history and an offline network policy, and `Capability::allowed_in` already refuses to put
//! research and the company's three capabilities in one realm. Nothing is inherited because there
//! is nothing to inherit from: the two realms are two files holding two keys.
//!
//! This file adds what research needs on top of that. What may be studied and under what limits;
//! what was explicitly let in and which agreement let it in; what material was acquired and what
//! it hashed to; what a run produced; who looked at it; and the one document that leaves. All of
//! it is metadata. No source byte and no artifact byte reaches this code, and there is no column
//! anywhere in the profile that could hold one.
//!
//! Three things are worth reading before the code.
//!
//! **This is a code and trust separation, and nothing else.** Nothing here weakens, bypasses or
//! disables any model's safety behaviour. There is no model invocation in this file, no prompt, no
//! system message, no setting that reaches a runtime's behaviour and no field whose contents could
//! become one. Every control added here is containment: an approval, an offline default, a scope
//! with limits, an artifact somebody looked at, a one-way document out. Where a model declines
//! work, that decision stands. A guard test in this module's tests reads this file and the V6
//! schema and fails if a setting of that sort ever appears; it proves the words are absent, which
//! is not the same as proving a model is safe, and it is not offered as that.
//!
//! **Agreement goes through `approval.rs` and nowhere else.** Admitting anything, freezing a
//! scope's authorisation and reviewing a finding are all ordinary `Core::ask` requests for
//! `Action::ApproveResearch`, decided by `Core::decide`. Every one of them is marked `every_time`,
//! so `approval::decide` already refuses to turn one into a standing allowance and no blanket
//! permission can ever cover admitting anything to a research realm. `research_reviews` is a link
//! row naming the request; it holds no verdict of its own.
//!
//! **The core holds no process.** Isolated execution is the [`Enclosure`] seam: the core writes
//! the plan, the limits and the record, and the engine builds the container, microVM, virtual
//! machine or GPU sandbox from the runtime it already has. A stop here moves rows and takes
//! permissions away; stopping the enclosure itself is the engine's half, and the product text
//! should say so rather than implying the core reaches into a running machine.
use super::{
    approval::{Approval, State},
    audit::{Decision, Entry},
    capability::Claims,
    identity::Action,
    realm::{Capability, NetworkPolicy, RealmKind},
    store::Stale,
    work::{GpuIsolation, Kind, Lease, Resources, Stage, Workload, TRIES},
    Core,
};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// The longest a research run may hold a computer, whatever a scope asks for.
pub const MAX_RUN_SECONDS: i64 = 6 * 60 * 60;
/// The most scopes one research realm keeps. A number, so a mistake in a loop cannot fill a disk.
pub const MAX_SCOPES: usize = 64;
/// The most files one acquired source may have its manifest listed in one call.
pub const MAX_MANIFEST: usize = 20_000;

// ---- What may be researched ----

/// Where material came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Origin {
    Upload,
    Repository,
    Archive,
}

impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Origin::Upload => "upload",
            Origin::Repository => "repository",
            Origin::Archive => "archive",
        }
    }
}

/// How sensitive the material is. A workload names this before it starts, through its scope, and
/// it is carried into the plan the engine builds from, so an enclosure is never built without the
/// classification of what is going into it being on the record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Classification {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
}

impl Classification {
    pub fn name(self) -> &'static str {
        match self {
            Classification::Public => "public",
            Classification::Internal => "internal",
            Classification::Confidential => "confidential",
            Classification::Restricted => "restricted",
        }
    }
}

/// What a scope holds every piece of work to.
///
/// The computers are expressed with the core's own `Resources`, so the scheduler needs nothing new
/// to honour cpu, memory, disk, gpu and vram. The rest are the limits `Resources` has no word for:
/// how long, how many files, how many artifacts, how many bytes, how long any of it is kept, and
/// whether anything may leave at all.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// The most one run may ask for. Checked when it is placed, and again by the host's free room.
    pub resources: Resources,
    /// How long one run may hold its reservation.
    pub runtime_seconds: i64,
    /// How many artifacts one run may leave behind.
    pub maximum_artifacts: u32,
    /// How many files one acquired source may hold.
    pub maximum_files: u64,
    /// The most bytes one run may leave behind, across all its artifacts.
    pub maximum_bytes: u64,
    /// How long an artifact or a source is kept before somebody should dispose of it.
    pub retain_seconds: i64,
    /// Whether any destination may be admitted for this scope at all. False means none may.
    pub outbound: bool,
    /// How a card must be isolated before research may have one. `Unknown` is never enough.
    pub gpu_isolation: GpuIsolation,
}

impl Limits {
    /// The careful default: four cores, eight gigabytes, forty of disk, no card, one hour, nothing
    /// leaves, kept for thirty days.
    pub fn careful() -> Limits {
        Limits {
            resources: Resources { cpu: 4.0, memory_gb: 8.0, disk_gb: 40.0, gpu: false, vram_gb: 0.0 },
            runtime_seconds: 60 * 60,
            maximum_artifacts: 64,
            maximum_files: 20_000,
            maximum_bytes: 2 * 1024 * 1024 * 1024,
            retain_seconds: 30 * 24 * 60 * 60,
            outbound: false,
            gpu_isolation: GpuIsolation::Exclusive,
        }
    }

    /// Whether these limits are ones a person could have meant.
    pub fn checked(self) -> Result<Limits, String> {
        if self.resources.cpu <= 0.0 || self.resources.memory_gb <= 0.0 || self.resources.disk_gb <= 0.0 {
            return Err("A research scope says how much cpu, memory and disk one run may have".into());
        }
        if self.runtime_seconds < 30 || self.runtime_seconds > MAX_RUN_SECONDS {
            return Err(format!("A research run lasts between 30 seconds and {} hours", MAX_RUN_SECONDS / 3_600));
        }
        if self.maximum_artifacts == 0 || self.maximum_files == 0 || self.maximum_bytes == 0 {
            return Err("A research scope allows at least one file, one artifact and one byte".into());
        }
        if self.retain_seconds < 0 {
            return Err("A research scope keeps what it produced for a length of time, never a negative one".into());
        }
        Ok(self)
    }

    /// Whether a run asking for `wanted` fits inside what the scope allows.
    pub fn fit(&self, wanted: &Resources) -> Result<(), String> {
        if wanted.gpu && !self.resources.gpu {
            return Err("This scope does not allow research to have a card".into());
        }
        if !self.resources.covers(wanted) {
            return Err(format!(
                "This scope allows {} cpu, {} GB of memory and {} GB of disk, and this run asks for {} cpu, {} GB and {} GB",
                self.resources.cpu, self.resources.memory_gb, self.resources.disk_gb, wanted.cpu, wanted.memory_gb, wanted.disk_gb
            ));
        }
        Ok(())
    }
}

/// What may be researched, in the material owner's own words, under those limits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    pub id: String,
    pub realm_id: String,
    pub name: String,
    pub purpose: String,
    /// Exactly what the person who owns the material wrote.
    pub authorisation: String,
    /// A digest of those words, so a changed authorisation is a different scope.
    pub authorisation_digest: String,
    /// The granted request a second approver decided over that digest. Empty while a draft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorisation_approval_id: Option<String>,
    pub classification: Classification,
    pub limits: Limits,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Set when the scope is frozen; a frozen scope is never edited again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Rises whenever what this scope allows narrows. A permission minted under an older one is
    /// refused at its next use by `check_capability`, so nothing has to be hunted down.
    #[serde(default = "one")]
    pub generation: u64,
    pub created_by: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub closed_reason: String,
}

fn one() -> u64 {
    1
}

impl Scope {
    /// A draft scope. Nothing may be placed under it until it is frozen.
    pub fn draft(realm_id: &str, name: &str, purpose: &str, authorisation: &str, classification: Classification, limits: Limits, created_by: &str, now: i64) -> Result<Scope, String> {
        let name = crate::label(name, "scope name")?;
        let purpose = sentence(purpose, "purpose")?;
        let authorisation = words(authorisation)?;
        let limits = limits.checked()?;
        Ok(Scope {
            id: format!("scope-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            name,
            purpose,
            authorisation_digest: crate::digest("research-authorisation", &authorisation),
            authorisation,
            authorisation_approval_id: None,
            classification,
            limits,
            version: 1,
            supersedes: None,
            digest: None,
            generation: 1,
            created_by: created_by.to_owned(),
            created_at: now,
            frozen_at: None,
            closed_at: None,
            closed_reason: String::new(),
        })
    }

    /// The digest over everything that was agreed to: the name, the purpose, the authorisation,
    /// how sensitive the material is, the limits and which version this is.
    pub fn compute_digest(&self) -> String {
        crate::digest(
            "research-scope",
            &serde_json::json!({
                "name": self.name,
                "purpose": self.purpose,
                "authorisationDigest": self.authorisation_digest,
                "classification": self.classification,
                "limits": self.limits,
                "version": self.version,
            })
            .to_string(),
        )
    }

    pub fn frozen(&self) -> bool {
        self.frozen_at.is_some()
    }

    /// Whether work may be placed under this scope now.
    pub fn open(&self) -> bool {
        self.frozen() && self.closed_at.is_none()
    }
}

// ---- What was let in ----

/// What may be let into a research realm, one kind per thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Admission {
    Source,
    Destination,
    Repository,
    Tool,
    Participant,
}

impl Admission {
    pub fn name(self) -> &'static str {
        match self {
            Admission::Source => "source",
            Admission::Destination => "destination",
            Admission::Repository => "repository",
            Admission::Tool => "tool",
            Admission::Participant => "participant",
        }
    }

    /// Every one of them needs an approver every time. No standing allowance covers any of them,
    /// which `approval::decide` enforces rather than this.
    pub fn every_time(self) -> bool {
        true
    }
}

/// Something explicitly let in, and the agreement it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Admitted {
    pub id: String,
    pub realm_id: String,
    pub scope_id: String,
    pub kind: Admission,
    /// What was let in: an address, a repository, a tool's name, a person's id.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub approval_id: String,
    pub admitted_by: String,
    pub admitted_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub withdrawn_reason: String,
}

impl Admitted {
    /// Whether this admission still stands at `now`.
    pub fn live(&self, now: i64) -> bool {
        self.withdrawn_at.is_none() && self.expires_at.is_none_or(|lapses| now < lapses)
    }

    /// Whether this admission covers reaching `subject` that way at `now`. An admission narrowed
    /// to a method or a path covers only that one.
    pub fn covers(&self, subject: &str, method: Option<&str>, path: Option<&str>, now: i64) -> bool {
        self.live(now)
            && self.subject == subject
            && self.method.as_deref().is_none_or(|allowed| method.map(str::to_ascii_uppercase).as_deref() == Some(allowed))
            && self.path.as_deref().is_none_or(|allowed| path.is_some_and(|asked| asked == allowed || asked.starts_with(&format!("{allowed}/"))))
    }
}

// ---- Material ----

/// One file in a source, as it was when it was acquired.
///
/// This is not `bounty::SourceFile`, which carries the file's bytes as base64: no byte of source
/// reaches the core and there is nowhere here to put one. What is shared with the bounty hub is
/// the rules, not a second copy of them: `safe_path` and `secret_name` below are that hub's own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// The digest over a whole manifest, in sorted path order.
///
/// It is taken over what the caller reported, which is the honest description of it: the component
/// that read the files and hashed them is the trusted part, and this notices a change made by
/// anything other than that component, or a change made after it looked. It does not notice a
/// caller that controls the hashing and reports a match.
pub fn manifest_digest(files: &[SourceFile]) -> String {
    let mut sorted: Vec<&SourceFile> = files.iter().collect();
    sorted.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let body: String = sorted.iter().map(|file| format!("{}\n{}\n{}\n", file.path, file.sha256, file.bytes)).collect();
    crate::digest("research-manifest", &body)
}

/// Whether a manifest is one this realm will record: safe paths, no duplicates, no credential
/// files, and digests that are digests.
///
/// The path rule and the credential rule are `crate::bounty_project`'s, called rather than copied,
/// because a second copy of a path safety rule drifts from the one the bounty hub enforces.
pub fn checked_manifest(files: &[SourceFile], maximum: u64) -> Result<(), String> {
    if files.is_empty() {
        return Err("A source has at least one file".into());
    }
    if files.len() > MAX_MANIFEST {
        return Err(format!("A manifest lists at most {MAX_MANIFEST} files"));
    }
    if files.len() as u64 > maximum {
        return Err(format!("This scope allows {maximum} files in a source and this one has {}", files.len()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for file in files {
        if !crate::bounty_project::safe_path(&file.path) {
            return Err(format!("{} is not a path this grid will record", file.path));
        }
        let name = file.path.rsplit('/').next().unwrap_or(&file.path);
        if crate::bounty_project::secret_name(name) {
            return Err(format!("{} holds credentials rather than source; it is not acquired", file.path));
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|letter| letter.is_ascii_hexdigit()) {
            return Err(format!("{} has no digest; a manifest says what each file hashed to", file.path));
        }
        if !seen.insert(file.path.to_ascii_lowercase()) {
            return Err(format!("{} is listed twice", file.path));
        }
    }
    Ok(())
}

/// Material acquired for a scope. The bytes are not in this type and not in the database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub id: String,
    pub realm_id: String,
    pub scope_id: String,
    /// The admission that let this origin in, which names the agreement it came from.
    pub admission_id: String,
    pub origin: Origin,
    /// An address or a name. Never a credential.
    pub reference: String,
    #[serde(default)]
    pub revision: String,
    pub digest: String,
    pub bytes: u64,
    pub file_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_until: Option<i64>,
    pub acquired_by: String,
    pub acquired_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl Source {
    /// Whether work may still be placed against this source.
    pub fn usable(&self) -> bool {
        self.quarantined_at.is_none() && self.disposed_at.is_none()
    }
}

/// Where a dependency check got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Dependency {
    Declared,
    Verified,
    Mismatched,
    Missing,
}

impl Dependency {
    pub fn name(self) -> &'static str {
        match self {
            Dependency::Declared => "declared",
            Dependency::Verified => "verified",
            Dependency::Mismatched => "mismatched",
            Dependency::Missing => "missing",
        }
    }

    /// Whether a dependency in this state is a reason to stop rather than a note to go past.
    pub fn stops_the_work(self) -> bool {
        matches!(self, Dependency::Mismatched | Dependency::Missing)
    }
}

/// What the source says it depends on, and what actually arrived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    pub id: String,
    pub source_id: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// What the lock file said it should hash to.
    pub expected: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<String>,
    pub state: Dependency,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
}

impl Package {
    pub fn new(source_id: &str, ecosystem: &str, name: &str, version: &str, expected: &str, seen: Option<&str>, now: i64) -> Result<Package, String> {
        if expected.len() != 64 || !expected.bytes().all(|letter| letter.is_ascii_hexdigit()) {
            return Err(format!("{name} has no expected digest; a lock file says what each package should hash to"));
        }
        let state = match seen {
            None => Dependency::Missing,
            Some(seen) if seen == expected => Dependency::Verified,
            Some(_) => Dependency::Mismatched,
        };
        Ok(Package {
            id: format!("package-{}", &crate::token()[..16]),
            source_id: source_id.to_owned(),
            ecosystem: crate::label(ecosystem, "ecosystem")?,
            name: crate::label(name, "package name")?,
            version: crate::label(version, "package version")?,
            expected: expected.to_owned(),
            seen: seen.map(str::to_owned),
            state,
            checked_at: Some(now),
        })
    }
}

// ---- What a run produced ----

/// What somebody said about an artifact. The grid does not scan anything, and this is the record
/// of a verdict rather than evidence that the grid detected anything itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scan {
    /// Nobody has looked yet.
    #[default]
    Pending,
    Clean,
    Flagged,
    Quarantined,
}

impl Scan {
    pub fn name(self) -> &'static str {
        match self {
            Scan::Pending => "pending",
            Scan::Clean => "clean",
            Scan::Flagged => "flagged",
            Scan::Quarantined => "quarantined",
        }
    }
}

/// Something a run produced. The bytes are on the computer that ran the enclosure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: String,
    pub realm_id: String,
    pub scope_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub workload_id: String,
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_until: Option<i64>,
    pub produced_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disposed_reason: String,
}

/// Who looked at an artifact and what they said. Written once; a change of mind is another row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Look {
    pub id: String,
    pub realm_id: String,
    pub artifact_id: String,
    pub verdict: Scan,
    /// The person in this grid who recorded it. Never "the grid".
    pub looked_by: String,
    /// The tool they are reporting, with its version where there is one. Empty when a person
    /// looked themselves.
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub reason: String,
    pub sequence: u64,
    pub looked_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingState {
    Draft,
    Submitted,
    Accepted,
    Rejected,
    Sealed,
}

impl FindingState {
    pub fn name(self) -> &'static str {
        match self {
            FindingState::Draft => "draft",
            FindingState::Submitted => "submitted",
            FindingState::Accepted => "accepted",
            FindingState::Rejected => "rejected",
            FindingState::Sealed => "sealed",
        }
    }
}

/// A finding, as the research realm records it, naming the exact source it was found against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub realm_id: String,
    pub scope_id: String,
    pub source_id: String,
    pub workload_id: String,
    pub title: String,
    #[serde(default)]
    pub component: String,
    #[serde(default)]
    pub summary: String,
    pub severity: Severity,
    pub state: FindingState,
    /// The artifacts this finding rests on, by artifact id.
    #[serde(default)]
    pub artifacts: Vec<String>,
    pub reported_by: String,
    pub created_at: i64,
    pub updated_at: i64,
}

// ---- The one document that leaves ----

/// One artifact as the crossing names it: what it is called, what it hashes to, how large it is
/// and what the last person to look at it said. Never its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRecord {
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub bytes: u64,
    pub scan: Scan,
}

/// One review, as the crossing carries it: the request, the verdict, who gave it and whether they
/// were the person who asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecord {
    pub request_id: String,
    pub granted: bool,
    pub decided_by: String,
    pub decided_at: i64,
    pub self_issued: bool,
    #[serde(default)]
    pub reason: String,
}

/// The one document that leaves a research realm.
///
/// It carries no key, no permission, no account secret and no source byte. The company realm
/// recomputes `digest` over the body and refuses anything that does not match.
///
/// Two things about it must never be overstated. `digest` is a keyless hash, so it catches
/// corruption and transcription error and not an adversary, who recomputes it along with the edit.
/// And `seal` is taken with the research realm's own key, which the company realm does not hold
/// and must never be given, so the company realm cannot check it and does not try: the seal is
/// there for the research realm and its own auditor. What actually makes an import is a named
/// person in the company realm deciding, with a second approver, written as that realm's own row
/// under its own key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Crossing {
    pub bundle_version: u32,
    pub from_realm_id: String,
    pub from_realm_name: String,
    /// The fingerprint of the research realm's key, so an auditor can tell one realm from another.
    /// It is not a proof of anything to the company realm.
    pub from_key_fingerprint: String,
    pub scope_name: String,
    pub scope_version: u32,
    pub scope_digest: String,
    pub authorisation_digest: String,
    pub classification: Classification,
    pub source_origin: Origin,
    pub source_reference: String,
    pub source_revision: String,
    pub source_digest: String,
    pub finding: Finding,
    pub artifacts: Vec<ArtifactRecord>,
    pub reviews: Vec<ReviewRecord>,
    pub sealed_by: String,
    pub sealed_at: i64,
    pub digest: String,
    pub seal: String,
}

impl Crossing {
    /// What the digest and the seal are taken over: every field except those two.
    pub fn body(&self) -> String {
        serde_json::json!({
            "bundleVersion": self.bundle_version,
            "fromRealmId": self.from_realm_id,
            "fromRealmName": self.from_realm_name,
            "fromKeyFingerprint": self.from_key_fingerprint,
            "scopeName": self.scope_name,
            "scopeVersion": self.scope_version,
            "scopeDigest": self.scope_digest,
            "authorisationDigest": self.authorisation_digest,
            "classification": self.classification,
            "sourceOrigin": self.source_origin,
            "sourceReference": self.source_reference,
            "sourceRevision": self.source_revision,
            "sourceDigest": self.source_digest,
            "finding": self.finding,
            "artifacts": self.artifacts,
            "reviews": self.reviews,
            "sealedBy": self.sealed_by,
            "sealedAt": self.sealed_at,
        })
        .to_string()
    }

    pub fn compute_digest(&self) -> String {
        crate::digest("research-crossing", &self.body())
    }

    /// Whether the document is whole. Anyone can run this and it needs no key, which is also the
    /// limit of it: it catches a bundle that was damaged or copied out wrong, never one that was
    /// edited by somebody who could run this too.
    pub fn intact(&self) -> Result<(), String> {
        if self.bundle_version != 1 {
            return Err(format!("This document was written by another version of Yougori (bundle {})", self.bundle_version));
        }
        if self.digest != self.compute_digest() {
            return Err("This document does not match its own digest; it was damaged or copied out wrong".into());
        }
        if self.artifacts.is_empty() {
            return Err("This document rests on no evidence".into());
        }
        if !self.reviews.iter().any(|review| review.granted) {
            return Err("Nobody in the research grid accepted this finding".into());
        }
        Ok(())
    }

    /// Whether the research realm's own seal still holds. Only the research realm can run this,
    /// because only it holds the key; the company realm neither can nor should.
    pub fn sealed_by_key(&self, research_key: &str) -> bool {
        crate::desks::same_hash(&self.seal, &seal_with(research_key, &self.body()))
    }
}

/// A seal over a document, with the realm's own key. The same shape the audit chain uses.
fn seal_with(key: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// What a company grid wrote down when it accepted a crossing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Import {
    pub id: String,
    pub realm_id: String,
    pub crossing_digest: String,
    pub from_realm_id: String,
    pub from_realm_name: String,
    pub from_key_fingerprint: String,
    pub scope_digest: String,
    pub source_digest: String,
    pub title: String,
    pub severity: Severity,
    pub artifacts: u32,
    pub reviews: u32,
    /// The agreement in this grid that let it in. Not the research grid's reviews.
    pub approval_id: String,
    pub accepted_by: String,
    pub accepted_at: i64,
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub withdrawn_reason: String,
}

impl Import {
    /// Whether this acceptance still stands.
    pub fn stands(&self) -> bool {
        self.withdrawn_at.is_none()
    }
}

/// A sealed crossing as the research realm's own database keeps it: the counts taken from the
/// rows at the moment it was sealed, and whether it is still good.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedCrossing {
    pub id: String,
    pub realm_id: String,
    pub finding_id: String,
    pub digest: String,
    pub seal: String,
    pub bundle_version: u32,
    pub reviews: u32,
    pub artifacts: u32,
    pub scope_digest: String,
    pub source_digest: String,
    pub sealed_by: String,
    pub sealed_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub withdrawn_reason: String,
}

/// A sealed crossing the research realm has since marked as no longer good, for somebody to carry
/// to the company realm. Changing the source or the scope behind a result invalidates acceptance,
/// and this is how the research realm says so to a realm it cannot reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notice {
    pub crossing_digest: String,
    pub reason: String,
    pub at: i64,
}

// ---- The enclosure seam ----

/// How isolated a run must be. The engine maps these onto the runtime it already has: an
/// unprivileged OCI container, a microVM whose one shared interface the host filters, a full
/// virtual machine, or a machine with a card attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Isolation {
    Container,
    MicroVm,
    Vm,
    GpuSandbox,
}

impl Isolation {
    pub fn name(self) -> &'static str {
        match self {
            Isolation::Container => "container",
            Isolation::MicroVm => "microVM",
            Isolation::Vm => "virtual machine",
            Isolation::GpuSandbox => "GPU sandbox",
        }
    }
}

/// Which research activity a piece of work is, which decides the `work::Kind` it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Activity {
    /// Fetching the material that was admitted.
    Acquire,
    /// Reading the repository without running it.
    Inspect,
    /// Running it inside an enclosure.
    Execute,
    /// Taking the artifacts out of the enclosure.
    Collect,
    /// Writing up what was found.
    Report,
}

impl Activity {
    pub fn name(self) -> &'static str {
        match self {
            Activity::Acquire => "acquire",
            Activity::Inspect => "inspect",
            Activity::Execute => "execute",
            Activity::Collect => "collect",
            Activity::Report => "report",
        }
    }

    /// Which kind of work this is to the core's one lifecycle.
    pub fn kind(self) -> Kind {
        match self {
            Activity::Acquire | Activity::Collect => Kind::ArtifactTransfer,
            _ => Kind::Research,
        }
    }
}

/// Everything the engine needs to build one isolated place, and nothing it does not.
///
/// There is no field here that reaches a model, and there cannot be: a plan says how much of a
/// computer a run may have, how long, what it may reach and where its material is, and says
/// nothing at all about what any model may be asked or how it must answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    pub realm_id: String,
    pub scope_id: String,
    pub scope_generation: u64,
    pub workload_id: String,
    pub lease_id: String,
    pub isolation: Isolation,
    pub classification: Classification,
    pub resources: Resources,
    pub gpu_isolation: GpuIsolation,
    /// Exactly what this run may reach. Offline is the normal case and means no interface at all.
    pub network: NetworkPolicy,
    pub runtime_seconds: i64,
    pub maximum_files: u64,
    pub maximum_bytes: u64,
    pub maximum_artifacts: u32,
    /// The source the enclosure is filled with, by digest. The engine finds it; the core hands
    /// over no bytes.
    #[serde(default)]
    pub source_digest: String,
    /// Where artifacts are collected from inside the enclosure.
    pub artifact_path: String,
}

/// What the engine must be able to do with a plan.
///
/// The core holds no implementation of this and never will. It is here so that the plan, the
/// limits and the record have one shape, and so that the research profile can be proven without
/// a container, a machine or a worker: the tests hand a recording stub a plan and check what it
/// was handed.
pub trait Enclosure {
    /// Builds a stopped enclosure and returns the engine's own name for it.
    fn build(&self, plan: &Plan) -> Result<String, String>;
    fn start(&self, id: &str) -> Result<(), String>;
    /// Stops it and leaves everything inside, so a quarantine keeps its evidence.
    fn stop(&self, id: &str) -> Result<(), String>;
    /// What it produced: name, type, digest and size. Never the bytes.
    fn collected(&self, id: &str) -> Result<Vec<ArtifactRecord>, String>;
    /// Destroys it, after collection and after a quarantine has been dealt with.
    fn discard(&self, id: &str) -> Result<(), String>;
}

// ---- Where a research realm may and may not reach ----

/// Whether an address can only ever mean a machine near us.
///
/// `crate::net::private` answers a different question: it is the LAN-sharing rule that decides who
/// may join a grid, and it stops at fc00::/7. Research asks its own question here rather than
/// widening that one, because widening it would also make plain `http://` acceptable to the
/// forwarder for these addresses, which is the opposite of what is wanted.
///
/// Several families are named here that the LAN rule says nothing about. The unspecified
/// addresses, 0.0.0.0 and `::`, reach the computer the enclosure is running on, on Windows and on
/// Linux alike. IPv6 link-local, fe80::/10, only ever means a machine on the same link, and the
/// deprecated site-local range beside it, fec0::/10, only ever meant a machine on the same site.
/// The deprecated IPv4-compatible form `::a.b.c.d` is an ordinary address written a second way and
/// is never a real destination. Broadcast, multicast and the rest of 0.0.0.0/8 are not
/// destinations either.
///
/// A mapped address is judged as the IPv4 address it wraps, so `::ffff:10.0.0.8` is refused for
/// being 10.0.0.8 and not for being written differently.
fn near_us(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(a) => crate::net::private(address) || a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.octets()[0] == 0,
        std::net::IpAddr::V6(a) => {
            crate::net::private(address)
                || a.is_unspecified()
                || a.is_multicast()
                // fe80::/9: link-local and the deprecated site-local range above it. Neither has a
                // test on this toolchain that is stable, so the prefix is masked by hand.
                || a.segments()[0] & 0xff80 == 0xfe80
                || a.to_ipv4_mapped().is_some_and(|mapped| near_us(mapped.into()))
                // What is left of ::/96 once the mapped form is accounted for is ::a.b.c.d.
                || (a.to_ipv4().is_some() && a.to_ipv4_mapped().is_none())
        }
    }
}

/// Whether a destination may be admitted to a research realm at all.
///
/// The gate is "the research realm cannot address the company's computers", so every address that
/// can only mean a machine near us is refused outright, by the rule `near_us` writes down, along
/// with the names that only ever mean a machine on the same network, and plain `http://`, which
/// the forwarder otherwise allows for a private address and which would be the way back in.
///
/// What this cannot do is said plainly rather than implied: the core does no name lookup, so a
/// public name that resolves to an address inside the company is not caught here, and neither is a
/// host written as a bare decimal such as `2130706433`, which is a name as far as this is
/// concerned. What holds then is the enclosure's own network filter, which is the engine's half of
/// this and is why `Plan` carries the policy rather than the core trusting its own list.
pub fn addressable(destination: &str) -> Result<String, String> {
    let place = crate::access::forward::destination(destination)?;
    let rest = place.strip_prefix("https://").or_else(|| place.strip_prefix("http://")).unwrap_or(&place);
    let authority = rest.split('/').next().unwrap_or_default();
    // An address in brackets is one host, colons and all; anything else loses a trailing port.
    let host = match authority.strip_prefix('[').and_then(|inside| inside.split_once(']')).map(|(address, _)| address) {
        Some(address) => address.to_ascii_lowercase(),
        None => match authority.rsplit_once(':') {
            Some((name, port)) if !port.is_empty() && port.bytes().all(|digit| digit.is_ascii_digit()) => name.to_ascii_lowercase(),
            _ => authority.to_ascii_lowercase(),
        },
    };
    if host.parse::<std::net::IpAddr>().is_ok_and(near_us)
        || host == "localhost"
        || ["local", "internal", "lan", "intranet", "localdomain", "home.arpa"].iter().any(|ending| host.ends_with(&format!(".{ending}")))
    {
        return Err("A research grid cannot address the company's own computers".into());
    }
    if !place.starts_with("https://") {
        return Err("A research grid reaches a destination over https:// only".into());
    }
    Ok(place)
}

/// A purpose or a reason in words: printable, one paragraph, bounded.
fn sentence(text: &str, what: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > 500 || text.chars().any(|letter| letter.is_control() && letter != '\n') {
        return Err(format!("The {what} is 1 to 500 printable characters"));
    }
    Ok(text.to_owned())
}

/// The material owner's own authorisation, kept exactly as they wrote it.
fn words(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.chars().count() > 4_000 {
        return Err("An authorisation is the material owner's own words, 1 to 4000 characters".into());
    }
    if text.chars().any(|letter| letter.is_control() && letter != '\n' && letter != '\t') {
        return Err("An authorisation is printable text".into());
    }
    if super::credential::looks_like_a_secret(text) {
        return Err("An authorisation is words, not a credential. Nothing in a research grid holds a value.".into());
    }
    Ok(text.to_owned())
}

/// A name of something admitted: an address, a repository, a tool, a person's id.
fn subject_of(kind: Admission, subject: &str) -> Result<String, String> {
    let subject = subject.trim();
    if subject.is_empty() || subject.chars().count() > 2_048 || subject.chars().any(char::is_control) {
        return Err("What is let in is named in 1 to 2048 printable characters".into());
    }
    if super::credential::looks_like_a_secret(subject) {
        return Err("What is let in is named, never held. Nothing in a research grid holds a value.".into());
    }
    match kind {
        Admission::Destination => addressable(subject),
        _ => Ok(subject.to_owned()),
    }
}

impl Core {
    // ---- Scopes ----

    /// Writes a draft scope. Nothing may be placed under it until it has been frozen, which takes
    /// a second person's decision over the authorisation.
    pub fn add_scope(&mut self, by: &str, name: &str, purpose: &str, authorisation: &str, classification: Classification, limits: Limits, now: i64) -> Result<Scope, String> {
        let person = self.research_person(by, Action::DoResearch)?;
        if self.store.scope_count()? >= MAX_SCOPES {
            return Err(format!("A research grid holds at most {MAX_SCOPES} scopes"));
        }
        let scope = Scope::draft(&self.realm.id, name, purpose, authorisation, classification, limits, &person, now)?;
        self.store.put_scope(&scope)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.scope.drafted", Decision::Allowed)
                .about(Capability::Research, &scope.id)
                .because(&format!("{}, {} material", scope.name, scope.classification.name())),
            now,
        )?;
        Ok(scope)
    }

    pub fn scope(&self, id: &str) -> Result<Option<Scope>, String> {
        self.store.scope(id)
    }

    pub fn scopes(&self) -> Result<Vec<Scope>, String> {
        self.store.scopes()
    }

    /// Asks for someone else's agreement to the authorisation behind a scope, over its digest.
    ///
    /// The request is `every_time`, so no standing allowance can ever cover it and nobody can
    /// agree in advance to whatever a researcher writes next.
    pub fn ask_to_freeze(&mut self, by: &str, scope_id: &str, seconds: i64, now: i64) -> Result<Approval, String> {
        self.research_person(by, Action::DoResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        if scope.frozen() {
            return Err("This scope has already been frozen".into());
        }
        self.ask(by, Action::ApproveResearch, &freezing(&scope), None, true, seconds, now)
    }

    /// Fixes a scope's digest, on a second approver's granted decision over the authorisation.
    ///
    /// A researcher must not write their own authorisation and freeze it alone. Where a realm has
    /// exactly one person who could decide, `approval::decide` already records that as self-issued
    /// rather than passing it off as somebody else's agreement, and this refuses it only when
    /// somebody else could have decided and the author decided anyway.
    pub fn freeze_scope(&mut self, by: &str, scope_id: &str, approval_id: &str, now: i64) -> Result<Scope, String> {
        self.research_person(by, Action::DoResearch)?;
        let mut scope = self.scope_or_fail(scope_id)?;
        if scope.frozen() {
            return Err("This scope has already been frozen".into());
        }
        let request = self.store.request(approval_id)?.ok_or("No such request is in this grid")?;
        if !request.asked_to(Action::ApproveResearch) {
            return Err("That agreement was given for something other than research".into());
        }
        if request.resource_id != freezing(&scope) {
            return Err("That agreement was given for another scope or for other words".into());
        }
        if !request.stands(now) {
            return Err("Nobody has agreed to this scope's authorisation yet".into());
        }
        let decided_by = request.decided_by.clone().ok_or("Nobody has agreed to this scope's authorisation yet")?;
        let alone = !self.store.another_holder_of(&super::approval::approving_roles(Action::ApproveResearch), &scope.created_by)?;
        if decided_by == scope.created_by && !alone {
            return Err("Somebody other than the person who wrote the authorisation has to agree to it".into());
        }
        scope.authorisation_approval_id = Some(request.id.clone());
        scope.digest = Some(scope.compute_digest());
        scope.frozen_at = Some(now);
        self.store.put_scope(&scope)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.scope.frozen", Decision::Allowed)
                .about(Capability::Research, &scope.id)
                .because(&format!("agreed by {decided_by}; {}", scope.digest.clone().unwrap_or_default())),
            now,
        )?;
        Ok(scope)
    }

    /// Makes the next version of a scope, leaving the one it replaces frozen and closed.
    ///
    /// Changing the scope invalidates acceptance: version N is closed, its unfinished work is
    /// stopped, its admissions are withdrawn, its generation rises so every permission it issued
    /// is refused at its next use, and every crossing sealed under it is marked no longer good so
    /// somebody can carry that word to the company realm. The new version starts as a draft and
    /// needs its own agreement before anything runs under it.
    pub fn revise_scope(&mut self, by: &str, scope_id: &str, purpose: &str, authorisation: &str, classification: Classification, limits: Limits, now: i64) -> Result<Scope, String> {
        let person = self.research_person(by, Action::DoResearch)?;
        let before = self.scope_or_fail(scope_id)?;
        if !before.frozen() {
            return Err("A draft scope is edited, not replaced; freeze it first".into());
        }
        let mut next = Scope::draft(&self.realm.id, &before.name, purpose, authorisation, classification, limits, &person, now)?;
        next.version = before.version + 1;
        next.supersedes = Some(before.id.clone());
        self.store.put_scope(&next)?;
        self.close_scope(by, &before, &format!("replaced by version {}", next.version), now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.scope.revised", Decision::Allowed)
                .about(Capability::Research, &next.id)
                .because(&format!("version {} replaces version {}", next.version, before.version)),
            now,
        )?;
        Ok(next)
    }

    /// The whole-scope stop: nothing more runs, nothing more is reachable, and the evidence stays.
    ///
    /// Work that is already under way is quarantined rather than cancelled, because `Stage` refuses
    /// to take draining work to cancelled and because a stop that cannot reach what is running is
    /// not a stop. Nothing is deleted. The core moves rows and withdraws permissions; stopping the
    /// enclosure itself is the engine's half.
    pub fn halt_scope(&mut self, by: &str, scope_id: &str, reason: &str, now: i64) -> Result<usize, String> {
        self.may_stop_research(by)?;
        let scope = self.scope_or_fail(scope_id)?;
        let stopped = self.close_scope(by, &scope, reason, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.scope.halted", Decision::Allowed)
                .about(Capability::Research, scope_id)
                .because(&format!("{reason}; {stopped} pieces of work stopped")),
            now,
        )?;
        Ok(stopped)
    }

    /// The one path behind closing a scope, whether it was halted or replaced by a new version.
    fn close_scope(&mut self, by: &str, scope: &Scope, reason: &str, now: i64) -> Result<usize, String> {
        let mut stopped = 0;
        for work in self.store.unfinished_noted(&research_note(&scope.id))? {
            self.stop_research_work(by, work, reason, now)?;
            stopped += 1;
        }
        for admission in self.store.admissions(&scope.id)?.into_iter().filter(|admission| admission.live(now)) {
            self.store.withdraw_admission(&admission.id, reason, now)?;
        }
        self.store.close_scope(&scope.id, reason, now)?;
        // Everything this scope issued stops at its next use, without anything being hunted down.
        self.store.raise_scope_generation(&scope.id, now)?;
        self.narrow_network(now)?;
        for crossing in self.store.crossings()?.into_iter().filter(|crossing| crossing.withdrawn_at.is_none()) {
            if self.store.finding(&crossing.finding_id)?.is_some_and(|finding| finding.scope_id == scope.id) {
                self.store.withdraw_crossing(&crossing.digest, &format!("the scope changed: {reason}"), now)?;
            }
        }
        Ok(stopped)
    }

    /// Stops one piece of research work, keeping everything it produced.
    ///
    /// Work that has begun is quarantined, which `Stage` treats as terminal from preparing,
    /// running and draining; work that has not is cancelled. Either way the reservation goes back
    /// and every row stays where it is.
    fn stop_research_work(&mut self, by: &str, work: Workload, reason: &str, now: i64) -> Result<Stage, String> {
        let mut work = work;
        self.store.release_for(&work.id, now)?;
        let next = if work.stage.may_become(Stage::Quarantined) { Stage::Quarantined } else { Stage::Cancelled };
        work.advance(next, now)?;
        self.store.put_workload(&work)?;
        self.note(
            Entry::new(&self.realm.id, by, if next == Stage::Quarantined { "research.work.quarantined" } else { "research.work.cancelled" }, Decision::Allowed)
                .about(Capability::Research, &work.id)
                .for_work(&work.id)
                .because(reason),
            now,
        )?;
        Ok(next)
    }

    /// Stops one piece of research work and keeps everything it produced, by hand.
    pub fn quarantine_work(&mut self, by: &str, workload_id: &str, reason: &str, now: i64) -> Result<Stage, String> {
        self.may_stop_research(by)?;
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.capability != Capability::Research {
            return Err("That is not research work".into());
        }
        if work.stage.finished() {
            return Err("This work has already finished".into());
        }
        self.stop_research_work(by, work, &sentence(reason, "reason")?, now)
    }

    // ---- What is let in ----

    /// Asks for someone else's agreement to let one thing into a research scope.
    ///
    /// `about` narrows a destination to one method and one path prefix. Every one of these is
    /// `every_time`, so `approval::decide` refuses to turn it into a standing allowance: no
    /// blanket permission can ever cover admitting a source, a destination, a repository, a tool
    /// or a person to a research realm.
    pub fn ask_to_admit(&mut self, by: &str, scope_id: &str, kind: Admission, subject: &str, about: Option<(&str, &str)>, seconds: i64, now: i64) -> Result<Approval, String> {
        self.research_person(by, Action::DoResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        let subject = subject_of(kind, subject)?;
        if kind == Admission::Destination && !scope.limits.outbound {
            return Err("This scope does not allow anything to leave, so no destination can be admitted to it".into());
        }
        self.ask(by, Action::ApproveResearch, &admitting(scope_id, kind, &subject), about, kind.every_time(), seconds, now)
    }

    /// Lets one thing into a scope, on a granted agreement that named exactly it.
    ///
    /// A destination is also written into the realm's own network policy here, in the same change,
    /// so the policy a workload is judged against and the list of what was admitted are one thing
    /// rather than two that can disagree.
    pub fn admit_to_scope(&mut self, by: &str, scope_id: &str, kind: Admission, subject: &str, approval_id: &str, expires_at: Option<i64>, now: i64) -> Result<Admitted, String> {
        let person = self.research_person(by, Action::ApproveResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        let subject = subject_of(kind, subject)?;
        if kind == Admission::Destination && !scope.limits.outbound {
            return Err("This scope does not allow anything to leave, so no destination can be admitted to it".into());
        }
        let request = self.store.request(approval_id)?.ok_or("No such request is in this grid")?;
        if !request.asked_to(Action::ApproveResearch) {
            return Err("That agreement was given for something other than research".into());
        }
        if request.resource_id != admitting(scope_id, kind, &subject) {
            return Err("That agreement was given for something else".into());
        }
        if !request.stands(now) {
            return Err("Somebody has to agree to this before it is let in".into());
        }
        let admitted = Admitted {
            id: format!("admission-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            scope_id: scope_id.to_owned(),
            kind,
            subject: subject.clone(),
            method: request.method.clone(),
            path: request.path.clone(),
            approval_id: request.id.clone(),
            admitted_by: person,
            admitted_at: now,
            expires_at,
            withdrawn_at: None,
            withdrawn_reason: String::new(),
        };
        self.store.put_admission(&admitted)?;
        if kind == Admission::Destination {
            self.widen_network(&subject)?;
        }
        self.note(
            Entry::new(&self.realm.id, by, "research.admitted", Decision::Allowed)
                .about(Capability::Research, scope_id)
                .because(&format!("{}: {subject}", kind.name())),
            now,
        )?;
        Ok(admitted)
    }

    /// Takes something back out of a scope.
    ///
    /// The scope's generation rises, so every permission minted under it is refused at its next
    /// use. That is narrower than raising the realm's policy version, which would stop every
    /// permission in the realm including ones about other scopes.
    pub fn withdraw_admission(&mut self, by: &str, admission_id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.research_person(by, Action::ApproveResearch)?;
        let admitted = self.store.admission(admission_id)?.ok_or("No such admission is in this grid")?;
        let reason = sentence(reason, "reason")?;
        self.store.withdraw_admission(admission_id, &reason, now)?;
        self.narrow_network(now)?;
        self.store.raise_scope_generation(&admitted.scope_id, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.admission.withdrawn", Decision::Allowed)
                .about(Capability::Research, &admitted.scope_id)
                .because(&format!("{}: {}; {reason}", admitted.kind.name(), admitted.subject)),
            now,
        )
    }

    /// Everything of one kind that is live for a scope now.
    pub fn admitted(&self, scope_id: &str, kind: Admission, now: i64) -> Result<Vec<Admitted>, String> {
        Ok(self.store.admissions(scope_id)?.into_iter().filter(|admitted| admitted.kind == kind && admitted.live(now)).collect())
    }

    /// Everything ever let into a scope, live or not.
    pub fn admissions(&self, scope_id: &str) -> Result<Vec<Admitted>, String> {
        self.store.admissions(scope_id)
    }

    /// Withdraws the admissions that have simply lapsed, and narrows the realm's network policy to
    /// match. Called beside `expire` and `expire_approvals`: without it a destination whose
    /// admission ran out would still be in the stated policy, and the policy and the admissions
    /// would disagree about what may be reached.
    pub fn expire_admissions(&mut self, now: i64) -> usize {
        let Ok(scopes) = self.store.scopes() else { return 0 };
        let mut lapsed = 0;
        for scope in scopes {
            let Ok(admissions) = self.store.admissions(&scope.id) else { continue };
            for admitted in admissions.into_iter().filter(|admitted| admitted.withdrawn_at.is_none() && admitted.expires_at.is_some_and(|at| now >= at)) {
                if self.store.withdraw_admission(&admitted.id, "it ran out", now).is_ok() {
                    let _ = self.store.raise_scope_generation(&admitted.scope_id, now);
                    lapsed += 1;
                }
            }
        }
        if lapsed > 0 {
            let _ = self.narrow_network(now);
        }
        lapsed
    }

    // ---- The realm's own network policy ----

    /// Sets what this realm's workloads may reach.
    ///
    /// In a research realm every destination has to be one a live admission already covers, and an
    /// empty list with outbound on is refused outright: `NetworkPolicy::allows` reads an empty list
    /// as any destination, so one admitted destination and an empty list would open the realm to
    /// everything.
    ///
    /// Narrowing the realm this way raises the policy version, because an administrator closing
    /// the realm's network is a realm-wide act and every permission in it should stop at its next
    /// use. Withdrawing one admission does not come through here; it raises that scope's
    /// generation instead, which is the narrow thing to do.
    pub fn set_network(&mut self, by: &str, network: NetworkPolicy, now: i64) -> Result<(), String> {
        self.allowed(by, Action::ManageSecurity)?;
        let network = self.checked_network(network, now)?;
        // Narrower when outbound is turned off, when a list replaces "anywhere", or when a
        // destination that was on the list has gone. An empty list with outbound on means
        // anywhere, so going to one is never a narrowing.
        let was_anywhere = self.realm.network.outbound && self.realm.network.destinations.is_empty();
        let now_anywhere = network.outbound && network.destinations.is_empty();
        let narrower = (self.realm.network.outbound && !network.outbound)
            || (was_anywhere && network.outbound && !now_anywhere)
            || (!was_anywhere && !now_anywhere && self.realm.network.destinations.iter().any(|before| !network.destinations.contains(before)));
        self.store.set_network(&network)?;
        self.realm.network = network.clone();
        if narrower {
            self.store.raise_policy()?;
        }
        self.note(
            Entry::new(&self.realm.id, by, "realm.network", Decision::Allowed).because(&if network.outbound {
                format!("{} destinations", network.destinations.len())
            } else {
                "nothing leaves".to_owned()
            }),
            now,
        )
    }

    /// Whether a policy is one this realm may have. A company realm is unchanged; a research realm
    /// is held to its admissions.
    ///
    /// Reachable from the broker's own door onto the same policy, because there is one set of
    /// rules about what a realm may reach and a second way in would be a way around them.
    pub(super) fn checked_network(&self, network: NetworkPolicy, now: i64) -> Result<NetworkPolicy, String> {
        if self.realm.kind != RealmKind::Research {
            return Ok(network);
        }
        if network.published {
            return Err("A research grid is not published; nothing reaches it from outside".into());
        }
        if !network.outbound {
            return Ok(NetworkPolicy::offline());
        }
        if network.destinations.is_empty() {
            return Err("A research grid names every destination it may reach; an empty list would mean anywhere".into());
        }
        let live = self.live_destinations(now)?;
        let mut checked = Vec::new();
        for destination in &network.destinations {
            let place = addressable(destination)?;
            if !live.contains(&place) {
                return Err(format!("{place} has not been admitted to any open scope in this grid"));
            }
            if !checked.contains(&place) {
                checked.push(place);
            }
        }
        Ok(NetworkPolicy { outbound: true, destinations: checked, published: false })
    }

    /// Every destination a live admission on an open scope covers now.
    fn live_destinations(&self, now: i64) -> Result<Vec<String>, String> {
        let mut places = Vec::new();
        for scope in self.store.scopes()?.into_iter().filter(|scope| scope.closed_at.is_none()) {
            for admitted in self.store.admissions(&scope.id)?.into_iter().filter(|admitted| admitted.kind == Admission::Destination && admitted.live(now)) {
                if !places.contains(&admitted.subject) {
                    places.push(admitted.subject);
                }
            }
        }
        Ok(places)
    }

    /// Adds one admitted destination to the realm's policy, in the same change as the admission.
    /// The list is never left empty with outbound on, because an empty list means anywhere.
    fn widen_network(&mut self, destination: &str) -> Result<(), String> {
        let mut network = self.store.realm()?.network;
        network.outbound = true;
        network.published = false;
        if !network.destinations.iter().any(|place| place == destination) {
            network.destinations.push(destination.to_owned());
        }
        self.store.set_network(&network)?;
        self.realm.network = network;
        Ok(())
    }

    /// Puts the realm's policy back to exactly what is still admitted. With nothing admitted the
    /// realm is offline again, which is where it started.
    fn narrow_network(&mut self, now: i64) -> Result<(), String> {
        let live = self.live_destinations(now)?;
        let network = if live.is_empty() { NetworkPolicy::offline() } else { NetworkPolicy { outbound: true, destinations: live, published: false } };
        self.store.set_network(&network)?;
        self.realm.network = network;
        Ok(())
    }

    // ---- Material ----

    /// Records what was acquired and its manifest, in one change.
    ///
    /// No byte is passed in and none is stored. What is recorded is where it came from, which
    /// admission let that origin in, what each file hashed to and what the whole manifest hashes
    /// to, so a change made afterwards by anything other than the component that hashed it is
    /// noticed rather than worked on.
    pub fn acquire_source(
        &mut self,
        by: &str,
        scope_id: &str,
        origin: Origin,
        reference: &str,
        revision: &str,
        files: &[SourceFile],
        admission_id: &str,
        now: i64,
    ) -> Result<Source, String> {
        let person = self.research_person(by, Action::DoResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        if !scope.open() {
            return Err("This scope is not open; freeze it before acquiring anything under it".into());
        }
        let reference = subject_of(Admission::Source, reference)?;
        let admitted = self.store.admission(admission_id)?.ok_or("No such admission is in this grid")?;
        if admitted.scope_id != scope_id || !matches!(admitted.kind, Admission::Source | Admission::Repository) {
            return Err("That admission does not let any source into this scope".into());
        }
        if !admitted.covers(&reference, None, None, now) {
            return Err(format!("{reference} has not been admitted to this scope"));
        }
        checked_manifest(files, scope.limits.maximum_files)?;
        let source = Source {
            id: format!("source-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            scope_id: scope_id.to_owned(),
            admission_id: admitted.id.clone(),
            origin,
            reference: reference.clone(),
            revision: revision.trim().chars().filter(|letter| !letter.is_control()).take(128).collect(),
            digest: manifest_digest(files),
            bytes: files.iter().map(|file| file.bytes).sum(),
            file_count: files.len() as u64,
            retain_until: retain_until(&scope, now),
            acquired_by: person,
            acquired_at: now,
            verified_at: None,
            quarantined_at: None,
            disposed_at: None,
            reason: String::new(),
        };
        self.store.put_source(&source, files)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.source.acquired", Decision::Allowed)
                .about(Capability::Research, &source.id)
                .because(&format!("{} from {reference}, {} files, {}", origin.name(), source.file_count, source.digest)),
            now,
        )?;
        Ok(source)
    }

    pub fn source(&self, id: &str) -> Result<Option<Source>, String> {
        self.store.source(id)
    }

    pub fn sources(&self, scope_id: &str) -> Result<Vec<Source>, String> {
        self.store.sources(scope_id)
    }

    pub fn source_files(&self, source_id: &str) -> Result<Vec<SourceFile>, String> {
        self.store.source_files(source_id)
    }

    /// Compares a freshly hashed manifest with what was recorded.
    ///
    /// A match sets `verified_at`. A difference quarantines the source and names the first path
    /// that differs, so a change made after acquisition stops the work instead of being researched
    /// under. Both manifests are what the caller reported; what this catches is a change made by
    /// something other than the component that hashes, not a caller that controls the hashing.
    pub fn verify_source(&mut self, by: &str, source_id: &str, seen: &[SourceFile], now: i64) -> Result<(), String> {
        self.research_person(by, Action::DoResearch)?;
        let source = self.store.source(source_id)?.ok_or("No such source is in this grid")?;
        let before = self.store.source_files(source_id)?;
        let difference = first_difference(&before, seen);
        match difference {
            None => {
                self.store.verified_source(source_id, now)?;
                self.note(
                    Entry::new(&self.realm.id, by, "research.source.verified", Decision::Allowed).about(Capability::Research, source_id).because(&source.digest),
                    now,
                )
            }
            Some(path) => {
                let why = format!("{path} is not what was acquired");
                self.quarantine_source(by, source_id, &why, now)?;
                Err(format!("This source changed after it was acquired: {why}"))
            }
        }
    }

    /// Writes what a source says it depends on and what arrived. Any row left mismatched or
    /// missing makes `submit_research` refuse, so a substituted package stops the work.
    pub fn record_dependencies(&mut self, by: &str, source_id: &str, packages: &[Package], now: i64) -> Result<usize, String> {
        self.research_person(by, Action::DoResearch)?;
        self.store.source(source_id)?.ok_or("No such source is in this grid")?;
        if packages.iter().any(|package| package.source_id != source_id) {
            return Err("These dependencies belong to another source".into());
        }
        self.store.put_dependencies(packages)?;
        let trouble = packages.iter().filter(|package| package.state.stops_the_work()).count();
        self.note(
            Entry::new(&self.realm.id, by, "research.dependencies.recorded", Decision::Allowed)
                .about(Capability::Research, source_id)
                .because(&format!("{} declared, {trouble} that do not match", packages.len())),
            now,
        )?;
        Ok(packages.len())
    }

    pub fn dependencies(&self, source_id: &str) -> Result<Vec<Package>, String> {
        self.store.dependencies(source_id)
    }

    /// Takes a source out of use without deleting it, and stops the unfinished work that used it.
    pub fn quarantine_source(&mut self, by: &str, source_id: &str, reason: &str, now: i64) -> Result<usize, String> {
        self.research_person(by, Action::DoResearch)?;
        let source = self.store.source(source_id)?.ok_or("No such source is in this grid")?;
        let reason = sentence(reason, "reason")?;
        self.store.quarantine_source(source_id, &reason, now)?;
        let mut stopped = 0;
        for finding in self.store.findings(&source.scope_id)?.into_iter().filter(|finding| finding.source_id == source_id) {
            for crossing in self.store.crossings()?.into_iter().filter(|crossing| crossing.finding_id == finding.id && crossing.withdrawn_at.is_none()) {
                self.store.withdraw_crossing(&crossing.digest, &format!("the source changed: {reason}"), now)?;
            }
        }
        for unfinished in self.store.unfinished_noted(&research_note(&source.scope_id))? {
            if unfinished.kind == Kind::Research || self.store.artifacts_of_work(&unfinished.id)?.iter().any(|artifact| artifact.source_id.as_deref() == Some(source_id)) {
                self.stop_research_work(by, unfinished, &reason, now)?;
                stopped += 1;
            }
        }
        self.note(
            Entry::new(&self.realm.id, by, "research.source.quarantined", Decision::Allowed).about(Capability::Research, source_id).because(&reason),
            now,
        )?;
        Ok(stopped)
    }

    // ---- Work ----

    /// Puts one piece of research work in the queue, under its scope's limits.
    pub fn submit_research(&mut self, principal_id: &str, device_id: &str, scope_id: &str, source_id: Option<&str>, activity: Activity, needs: Resources, now: i64) -> Result<Workload, String> {
        self.research_person(principal_id, Action::DoResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        if !scope.open() {
            return Err("This scope is not open to work; freeze it, and do not place work under a closed one".into());
        }
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        if device.principal_id != principal_id {
            return Err("That computer belongs to someone else".into());
        }
        scope.limits.fit(&needs)?;
        if let Some(source_id) = source_id {
            let source = self.store.source(source_id)?.ok_or("No such source is in this grid")?;
            if source.scope_id != scope_id {
                return Err("That source belongs to another scope".into());
            }
            if !source.usable() {
                return Err("This source is quarantined; nothing more is researched against it".into());
            }
            if source.verified_at.is_none() {
                return Err("This source has not been checked against its manifest yet".into());
            }
            if let Some(package) = self.store.dependencies(source_id)?.into_iter().find(|package| package.state.stops_the_work()) {
                return Err(format!("{} {} is {}; a dependency that does not match its lock file stops the work", package.name, package.version, package.state.name()));
            }
        }
        let mut work = Workload::new(&self.realm.id, Capability::Research, activity.kind(), principal_id, device_id, needs, self.store.policy_version()?, now);
        work.note = Some(research_note(scope_id));
        work.expires_at = Some(now + scope.limits.runtime_seconds.min(MAX_RUN_SECONDS));
        let work = self.submit(work, now)?;
        self.note(
            Entry::new(&self.realm.id, principal_id, "research.work.queued", Decision::Allowed)
                .about(Capability::Research, scope_id)
                .from(device_id)
                .for_work(&work.id)
                .because(activity.name()),
            now,
        )?;
        Ok(work)
    }

    /// Reserves a computer for research work, held to the scope's limits.
    ///
    /// A card is handed to research only where its isolation is good enough for the scope. The
    /// ordinary rule in `grant_lease` refuses only to share a card somebody else already holds, so
    /// an idle card whose isolation nobody has ever recorded would otherwise go to research with
    /// no refusal at all. Nothing attests that isolation; it is what an administrator asserted
    /// through `set_gpu_isolation`, and `Unknown` is never enough.
    pub fn grant_research_lease(&mut self, workload_id: &str, now: i64) -> Result<Lease, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.capability != Capability::Research || work.stage != Stage::Queued {
            return Err("Only queued research work is given a computer this way".into());
        }
        let scope_id = work.note.as_deref().and_then(|note| note.strip_prefix("research:")).ok_or("This piece of work names no research scope")?.to_owned();
        let scope = self.scope_or_fail(&scope_id)?;
        if !scope.open() {
            return Err("This scope is closed; no computer is given to it".into());
        }
        scope.limits.fit(&work.needs)?;
        let tried = self.tried(workload_id)?;
        if tried.len() as u64 >= TRIES {
            return Err(format!("This research run has already been tried on {TRIES} computers"));
        }
        let leases = self.store.live_leases(now)?;
        let free_room = self.free_everywhere(now)?;
        let still_here = self.store.active_devices()?;
        let mut best: Option<(String, f64)> = None;
        let mut refused_for_the_card = false;
        for host in self.store.hosts()?.iter().filter(|host| host.takes_work() && !tried.contains(&host.id)) {
            if !still_here.contains(&host.device_id) {
                continue;
            }
            let Some(free) = free_room.get(&host.id).copied() else { continue };
            if !free.covers(&work.needs) {
                continue;
            }
            if work.needs.gpu {
                // Good enough for the scope, and not already held by somebody else.
                if host.gpu_isolation == GpuIsolation::Unknown || !enough_isolation(host.gpu_isolation, scope.limits.gpu_isolation) {
                    refused_for_the_card = true;
                    continue;
                }
                if !host.gpu_isolation.shareable() && leases.iter().any(|lease| lease.host_id == host.id && lease.resources.gpu) {
                    continue;
                }
            }
            if best.as_ref().is_none_or(|(_, most)| free.memory_gb > *most) {
                best = Some((host.id.clone(), free.memory_gb));
            }
        }
        let Some((host_id, _)) = best else {
            return Err(if refused_for_the_card {
                "No computer in this grid has a card isolated well enough for this scope".to_owned()
            } else {
                "No computer in this grid has room for this research run".to_owned()
            });
        };
        let seconds = scope.limits.runtime_seconds.min(MAX_RUN_SECONDS);
        let lease = Lease {
            id: format!("lease-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            host_id,
            workload_id: workload_id.to_owned(),
            resources: work.needs,
            generation: tried.len() as u64 + 1,
            granted_at: now,
            expires_at: now + seconds.clamp(30, MAX_RUN_SECONDS),
            released_at: None,
        };
        let mut work = work;
        work.lease_id = Some(lease.id.clone());
        work.advance(Stage::Leased, now)?;
        self.store.put_workload(&work)?;
        self.store.put_lease(&lease)?;
        self.note(
            Entry::new(&self.realm.id, &work.principal_id, "research.work.leased", Decision::Allowed)
                .about(Capability::Research, &lease.host_id)
                .for_work(workload_id),
            now,
        )?;
        Ok(lease)
    }

    /// Turns a leased research run into the plan the engine builds an enclosure from.
    ///
    /// With no admitted destination the plan carries `NetworkPolicy::offline()`, which the engine
    /// builds as an enclosure with no network interface at all. The core never starts anything.
    pub fn plan_for(&self, workload_id: &str, isolation: Isolation, artifact_path: &str, now: i64) -> Result<Plan, String> {
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.capability != Capability::Research {
            return Err("That is not research work".into());
        }
        let scope_id = work.note.as_deref().and_then(|note| note.strip_prefix("research:")).ok_or("This piece of work names no research scope")?;
        let scope = self.scope_or_fail(scope_id)?;
        let lease_id = work.lease_id.clone().ok_or("This work holds no computer yet")?;
        let lease = self.store.lease(&lease_id)?.filter(|lease| lease.holds(now)).ok_or("This work no longer holds a computer")?;
        // Only what this scope itself was allowed to reach. The realm's policy is the union of
        // every open scope's admissions, and a run under one scope has no business reaching what
        // was admitted to another.
        let places: Vec<String> = self.admitted(scope_id, Admission::Destination, now)?.into_iter().map(|admitted| admitted.subject).collect();
        let network = if scope.limits.outbound && !places.is_empty() { NetworkPolicy { outbound: true, destinations: places, published: false } } else { NetworkPolicy::offline() };
        let source_digest = self
            .store
            .sources(scope_id)?
            .into_iter()
            .filter(|source| source.usable() && source.verified_at.is_some())
            .max_by_key(|source| source.acquired_at)
            .map(|source| source.digest)
            .unwrap_or_default();
        Ok(Plan {
            realm_id: self.realm.id.clone(),
            scope_id: scope_id.to_owned(),
            scope_generation: scope.generation,
            workload_id: workload_id.to_owned(),
            lease_id: lease.id,
            isolation,
            classification: scope.classification,
            resources: work.needs,
            gpu_isolation: scope.limits.gpu_isolation,
            network,
            runtime_seconds: scope.limits.runtime_seconds.min(MAX_RUN_SECONDS),
            maximum_files: scope.limits.maximum_files,
            maximum_bytes: scope.limits.maximum_bytes,
            maximum_artifacts: scope.limits.maximum_artifacts,
            source_digest,
            artifact_path: artifact_path.trim().to_owned(),
        })
    }

    /// Mints a permission for one outbound request from a research run.
    ///
    /// The permission names the scope, so the scope's generation is written into it and withdrawing
    /// an admission refuses it at its next use through the one mechanism that refuses a suspended
    /// account. Everything it is narrowed to is checked again in `accept`.
    pub fn mint_research(&mut self, scope_id: &str, principal_id: &str, device_id: &str, workload_id: &str, destination: &str, method: &str, path: &str, seconds: i64, now: i64) -> Result<String, String> {
        self.research_person(principal_id, Action::DoResearch)?;
        let scope = self.scope_or_fail(scope_id)?;
        if !scope.open() {
            return Err("This scope is closed; it reaches nothing".into());
        }
        if !scope.limits.outbound {
            return Err("This scope does not allow anything to leave".into());
        }
        let place = addressable(destination)?;
        let method = method.trim().to_ascii_uppercase();
        if !self.store.realm()?.network.allows(&place) {
            return Err(format!("This grid's network policy does not allow {place}"));
        }
        if !self.admitted(scope_id, Admission::Destination, now)?.iter().any(|admitted| admitted.covers(&place, Some(&method), Some(path), now)) {
            return Err(format!("{place} has not been admitted to this scope that way"));
        }
        let claims = Claims::new(&self.realm.id, Capability::Research, principal_id, device_id, workload_id, scope_id, now, seconds.min(scope.limits.runtime_seconds))
            .bound_to(&place, &method, path, scope.limits.maximum_bytes);
        self.mint(&claims)
    }

    // ---- Artifacts ----

    /// Records one artifact a run produced, inside what the scope allows.
    pub fn record_artifact(&mut self, by: &str, workload_id: &str, source_id: Option<&str>, name: &str, media_type: &str, sha256: &str, bytes: u64, now: i64) -> Result<Artifact, String> {
        self.research_person(by, Action::DoResearch)?;
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        if work.capability != Capability::Research {
            return Err("That is not research work".into());
        }
        let scope_id = work.note.as_deref().and_then(|note| note.strip_prefix("research:")).ok_or("This piece of work names no research scope")?.to_owned();
        let scope = self.scope_or_fail(&scope_id)?;
        if sha256.len() != 64 || !sha256.bytes().all(|letter| letter.is_ascii_hexdigit()) {
            return Err("An artifact is recorded with what it hashed to".into());
        }
        let already = self.store.artifacts_of_work(workload_id)?;
        if already.len() as u32 >= scope.limits.maximum_artifacts {
            return Err(format!("This scope allows {} artifacts from one run", scope.limits.maximum_artifacts));
        }
        let total: u64 = already.iter().map(|artifact| artifact.bytes).sum::<u64>() + bytes;
        if total > scope.limits.maximum_bytes {
            return Err(format!("This scope allows {} bytes from one run and these would be {total}", scope.limits.maximum_bytes));
        }
        let artifact = Artifact {
            id: format!("artifact-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            scope_id: scope_id.clone(),
            source_id: source_id.map(str::to_owned),
            workload_id: workload_id.to_owned(),
            name: crate::label(name, "artifact name")?,
            media_type: media_type.trim().chars().filter(|letter| !letter.is_control()).take(128).collect(),
            sha256: sha256.to_ascii_lowercase(),
            bytes,
            retain_until: retain_until(&scope, now),
            produced_at: now,
            disposed_at: None,
            disposed_reason: String::new(),
        };
        self.store.put_artifact_record(&artifact)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.artifact.recorded", Decision::Allowed)
                .about(Capability::Research, &artifact.id)
                .for_work(workload_id)
                .because(&format!("{} bytes, {}", artifact.bytes, artifact.sha256)),
            now,
        )?;
        Ok(artifact)
    }

    /// Records who looked at an artifact and what they concluded.
    ///
    /// This grid does not scan anything. There is no scanner in this repository, and this method
    /// writes down somebody's verdict and the tool they are reporting. It must never be presented
    /// as the grid having detected anything itself.
    pub fn record_look(&mut self, by: &str, artifact_id: &str, verdict: Scan, tool: &str, reason: &str, now: i64) -> Result<Look, String> {
        // Either side may write one down. The person who produced the artifact should be able to
        // say what they saw in it, and so should the person who will be asked to agree that it
        // may cross; refusing one of them would push the other into speaking for both.
        let person = self.research_person(by, Action::DoResearch).or_else(|_| self.research_person(by, Action::ApproveResearch))?;
        let artifact = self.store.artifact_record(artifact_id)?.ok_or("No such artifact is in this grid")?;
        let look = Look {
            id: format!("look-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            artifact_id: artifact_id.to_owned(),
            verdict,
            looked_by: person,
            tool: tool.trim().chars().filter(|letter| !letter.is_control()).take(128).collect(),
            reason: reason.trim().chars().filter(|letter| !letter.is_control()).take(500).collect(),
            sequence: self.store.next_look(artifact_id)?,
            looked_at: now,
        };
        self.store.put_look(&look)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.artifact.looked at", Decision::Allowed)
                .about(Capability::Research, &artifact.id)
                .because(&format!("{} by {}", verdict.name(), if look.tool.is_empty() { "a person" } else { &look.tool })),
            now,
        )?;
        Ok(look)
    }

    pub fn artifact_record(&self, id: &str) -> Result<Option<Artifact>, String> {
        self.store.artifact_record(id)
    }

    pub fn research_artifacts(&self, scope_id: &str) -> Result<Vec<Artifact>, String> {
        self.store.artifacts_of_scope(scope_id)
    }

    pub fn looks(&self, artifact_id: &str) -> Result<Vec<Look>, String> {
        self.store.looks(artifact_id)
    }

    /// What the last person to look at this artifact said.
    pub fn scan_of(&self, artifact_id: &str) -> Result<Scan, String> {
        Ok(self.store.looks(artifact_id)?.last().map(|look| look.verdict).unwrap_or(Scan::Pending))
    }

    /// Lets go of an artifact, with the reason written down. The row stays, so what was produced
    /// and what became of it are both readable afterwards.
    pub fn dispose_artifact(&mut self, by: &str, artifact_id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.research_person(by, Action::DoResearch)?;
        let reason = sentence(reason, "reason")?;
        self.store.dispose_artifact(artifact_id, &reason, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.artifact.disposed", Decision::Allowed).about(Capability::Research, artifact_id).because(&reason),
            now,
        )
    }

    /// Lets go of a source, with the reason written down. The row and its manifest stay, so what
    /// was studied and what became of it are both readable afterwards.
    pub fn dispose_source(&mut self, by: &str, source_id: &str, reason: &str, now: i64) -> Result<(), String> {
        self.research_person(by, Action::DoResearch)?;
        let reason = sentence(reason, "reason")?;
        self.store.source(source_id)?.ok_or("No such source is in this grid")?;
        self.store.dispose_source(source_id, &reason, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.source.disposed", Decision::Allowed).about(Capability::Research, source_id).because(&reason),
            now,
        )
    }

    /// The artifacts and sources whose retention has run out, so somebody can dispose of them.
    /// Nothing is dropped on a timer: disposal is a decision somebody makes and a row they write.
    pub fn due_for_disposal(&self, now: i64) -> Result<(Vec<Artifact>, Vec<Source>), String> {
        let mut artifacts = Vec::new();
        let mut sources = Vec::new();
        for scope in self.store.scopes()? {
            artifacts.extend(self.store.artifacts_of_scope(&scope.id)?.into_iter().filter(|artifact| artifact.disposed_at.is_none() && artifact.retain_until.is_some_and(|until| now >= until)));
            sources.extend(self.store.sources(&scope.id)?.into_iter().filter(|source| source.disposed_at.is_none() && source.retain_until.is_some_and(|until| now >= until)));
        }
        Ok((artifacts, sources))
    }

    // ---- Findings ----

    /// Writes a finding, naming the source it was found against and the artifacts it rests on.
    pub fn record_finding(&mut self, by: &str, workload_id: &str, source_id: &str, title: &str, component: &str, summary: &str, severity: Severity, artifacts: &[String], now: i64) -> Result<Finding, String> {
        let person = self.research_person(by, Action::DoResearch)?;
        let work = self.store.workload(workload_id)?.ok_or("No such work")?;
        let scope_id = work.note.as_deref().and_then(|note| note.strip_prefix("research:")).ok_or("This piece of work names no research scope")?.to_owned();
        let source = self.store.source(source_id)?.ok_or("No such source is in this grid")?;
        if source.scope_id != scope_id {
            return Err("That source belongs to another scope".into());
        }
        if artifacts.is_empty() {
            return Err("A finding names the artifacts it rests on; nothing rests on an assertion alone".into());
        }
        for artifact_id in artifacts {
            let artifact = self.store.artifact_record(artifact_id)?.ok_or("No such artifact is in this grid")?;
            if artifact.scope_id != scope_id {
                return Err("That artifact belongs to another scope".into());
            }
        }
        let finding = Finding {
            id: format!("finding-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            scope_id,
            source_id: source_id.to_owned(),
            workload_id: workload_id.to_owned(),
            title: crate::label(title, "finding title")?,
            component: component.trim().chars().filter(|letter| !letter.is_control()).take(128).collect(),
            summary: sentence(if summary.trim().is_empty() { "No summary was written" } else { summary }, "summary")?,
            severity,
            state: FindingState::Draft,
            artifacts: artifacts.to_vec(),
            reported_by: person,
            created_at: now,
            updated_at: now,
        };
        self.store.put_finding(&finding)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.finding.recorded", Decision::Allowed)
                .about(Capability::Research, &finding.id)
                .for_work(workload_id)
                .because(&format!("{}, {}", finding.title, severity.name())),
            now,
        )?;
        Ok(finding)
    }

    /// Puts a finding up for review.
    pub fn submit_finding(&mut self, by: &str, finding_id: &str, now: i64) -> Result<Finding, String> {
        self.research_person(by, Action::DoResearch)?;
        let mut finding = self.store.finding(finding_id)?.ok_or("No such finding is in this grid")?;
        if finding.state != FindingState::Draft {
            return Err(format!("This finding is {} and is not a draft", finding.state.name()));
        }
        finding.state = FindingState::Submitted;
        finding.updated_at = now;
        self.store.put_finding(&finding)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.finding.submitted", Decision::Allowed).about(Capability::Research, finding_id),
            now,
        )?;
        Ok(finding)
    }

    /// Asks for somebody to review a finding.
    ///
    /// This is the ordinary approval machinery and nothing else: the request lives in `requests`,
    /// the verdict in `decisions`, and `approval::decide` already refuses a person deciding their
    /// own while anybody else could, refuses a second decision and refuses an edit to one. The row
    /// this writes only says which request belongs to which finding.
    pub fn ask_to_review(&mut self, by: &str, finding_id: &str, seconds: i64, now: i64) -> Result<Approval, String> {
        self.research_person(by, Action::DoResearch)?;
        let finding = self.store.finding(finding_id)?.ok_or("No such finding is in this grid")?;
        if finding.state != FindingState::Submitted {
            return Err("A finding is put up for review before anybody is asked to look at it".into());
        }
        let request = self.ask(by, Action::ApproveResearch, finding_id, None, true, seconds, now)?;
        self.store.put_review(finding_id, &request.id, now)?;
        Ok(request)
    }

    /// The review requests asked about a finding, with whatever each of them was decided.
    pub fn reviews_of(&self, finding_id: &str) -> Result<Vec<Approval>, String> {
        self.store.reviews_of(finding_id)
    }

    /// Moves a finding on to what its reviews decided.
    pub fn settle_finding(&mut self, by: &str, finding_id: &str, now: i64) -> Result<FindingState, String> {
        self.research_person(by, Action::DoResearch)?;
        let mut finding = self.store.finding(finding_id)?.ok_or("No such finding is in this grid")?;
        if finding.state != FindingState::Submitted {
            return Err(format!("This finding is {} and is not waiting on a review", finding.state.name()));
        }
        // A verdict about a finding is not a permission to act, so it is read as the state it was
        // decided into rather than as something that lapses. `stands` is for an agreement somebody
        // is about to spend; this is a decision that was made and stays made.
        let reviews = self.store.reviews_of(finding_id)?;
        let next = if reviews.iter().any(|review| review.state == State::Granted) {
            FindingState::Accepted
        } else if !reviews.is_empty() && reviews.iter().all(|review| review.state == State::Refused) {
            FindingState::Rejected
        } else {
            return Err("Nobody has decided about this finding yet".into());
        };
        finding.state = next;
        finding.updated_at = now;
        self.store.put_finding(&finding)?;
        self.note(
            Entry::new(&self.realm.id, by, &format!("research.finding.{}", next.name()), Decision::Allowed).about(Capability::Research, finding_id),
            now,
        )?;
        Ok(next)
    }

    pub fn finding(&self, id: &str) -> Result<Option<Finding>, String> {
        self.store.finding(id)
    }

    pub fn findings(&self, scope_id: &str) -> Result<Vec<Finding>, String> {
        self.store.findings(scope_id)
    }

    // ---- The crossing ----

    /// Seals the one document that leaves this realm.
    ///
    /// Nothing is sent anywhere: the caller is handed the document to carry. The database refuses
    /// the row unless the finding rests on at least one artifact and the last person to look at
    /// each of them called it clean, and this refuses it unless somebody accepted the finding.
    pub fn seal_for_crossing(&mut self, by: &str, finding_id: &str, now: i64) -> Result<Crossing, String> {
        let person = self.research_person(by, Action::DoResearch)?;
        let mut finding = self.store.finding(finding_id)?.ok_or("No such finding is in this grid")?;
        if finding.state == FindingState::Sealed {
            return Err("This finding has already been sealed".into());
        }
        if finding.state != FindingState::Accepted {
            return Err("A finding crosses once somebody else has accepted it".into());
        }
        let scope = self.scope_or_fail(&finding.scope_id)?;
        let source = self.store.source(&finding.source_id)?.ok_or("No such source is in this grid")?;
        if !source.usable() {
            return Err("The source behind this finding is quarantined; nothing crosses on it".into());
        }
        let mut artifacts = Vec::new();
        for artifact_id in &finding.artifacts {
            let artifact = self.store.artifact_record(artifact_id)?.ok_or("No such artifact is in this grid")?;
            artifacts.push(ArtifactRecord {
                name: artifact.name,
                media_type: artifact.media_type,
                sha256: artifact.sha256,
                bytes: artifact.bytes,
                scan: self.scan_of(artifact_id)?,
            });
        }
        let reviews: Vec<ReviewRecord> = self
            .store
            .reviews_of(finding_id)?
            .into_iter()
            .filter(|review| review.decided_by.is_some())
            .map(|review| ReviewRecord {
                request_id: review.id,
                granted: review.state == State::Granted,
                decided_by: review.decided_by.unwrap_or_default(),
                decided_at: review.decided_at.unwrap_or_default(),
                self_issued: review.self_issued,
                reason: review.reason,
            })
            .collect();
        if !reviews.iter().any(|review| review.granted) {
            return Err("A finding crosses once somebody else has accepted it".into());
        }
        finding.state = FindingState::Sealed;
        finding.updated_at = now;
        let mut crossing = Crossing {
            bundle_version: 1,
            from_realm_id: self.realm.id.clone(),
            from_realm_name: self.realm.name.clone(),
            from_key_fingerprint: self.realm.key_fingerprint.clone(),
            scope_name: scope.name.clone(),
            scope_version: scope.version,
            scope_digest: scope.digest.clone().unwrap_or_default(),
            authorisation_digest: scope.authorisation_digest.clone(),
            classification: scope.classification,
            source_origin: source.origin,
            source_reference: source.reference.clone(),
            source_revision: source.revision.clone(),
            source_digest: source.digest.clone(),
            finding: finding.clone(),
            artifacts,
            reviews,
            sealed_by: person,
            sealed_at: now,
            digest: String::new(),
            seal: String::new(),
        };
        crossing.digest = crossing.compute_digest();
        crossing.seal = seal_with(&self.key, &crossing.body());
        self.store.put_crossing(&crossing, &finding)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.crossing.sealed", Decision::Allowed)
                .about(Capability::Research, finding_id)
                .because(&format!("{} artifacts, {} reviews, {}", crossing.artifacts.len(), crossing.reviews.len(), crossing.digest)),
            now,
        )?;
        Ok(crossing)
    }

    /// Every sealed crossing this realm has written, and whether it is still good.
    pub fn crossings(&self) -> Result<Vec<SealedCrossing>, String> {
        self.store.crossings()
    }

    /// The crossings this realm has since marked as no longer good, for somebody to carry to the
    /// company realm. There is no connection between the two realms and there is not meant to be.
    pub fn notices(&self) -> Result<Vec<Notice>, String> {
        Ok(self
            .store
            .crossings()?
            .into_iter()
            .filter_map(|crossing| crossing.withdrawn_at.map(|at| Notice { crossing_digest: crossing.digest, reason: crossing.withdrawn_reason, at }))
            .collect())
    }

    /// Accepts a research result into a company realm, on this realm's own decision.
    ///
    /// Called on the company realm's `Core`, never the research one. It recomputes the document's
    /// digest, which catches damage in carrying it rather than an adversary. It does not verify the
    /// research realm's seal and must not: that seal is taken with a key this realm does not hold
    /// and must never be given. What makes this row is a named person here deciding, with somebody
    /// else agreeing, written under this realm's own key. Nothing of the research realm's people,
    /// computers or permissions comes across, because nothing here writes any of those.
    pub fn accept_crossing(&mut self, by: &str, crossing: &Crossing, approval_id: &str, note: &str, now: i64) -> Result<Import, String> {
        let person = self.person(by)?;
        self.allowed(by, Action::ManageSecurity)?;
        if self.realm.kind != RealmKind::Primary {
            return Err("A research result is accepted by a company grid".into());
        }
        if crossing.from_realm_id == self.realm.id {
            return Err("That document came from this grid; a crossing is a document from another".into());
        }
        crossing.intact()?;
        let request = self.store.request(approval_id)?.ok_or("No such request is in this grid")?;
        if !request.asked_to(Action::ApproveResearch) {
            return Err("That agreement was given for something other than research".into());
        }
        if request.resource_id != crossing.digest {
            return Err("That agreement was given for another document".into());
        }
        if !request.stands(now) {
            return Err("Somebody in this grid has to agree before a research result is accepted".into());
        }
        let decided_by = request.decided_by.clone().ok_or("Somebody in this grid has to agree before a research result is accepted")?;
        if decided_by == person.id && !request.self_issued {
            return Err("Somebody other than the person accepting it has to agree".into());
        }
        let import = Import {
            id: format!("import-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            crossing_digest: crossing.digest.clone(),
            from_realm_id: crossing.from_realm_id.clone(),
            from_realm_name: crossing.from_realm_name.clone(),
            from_key_fingerprint: crossing.from_key_fingerprint.clone(),
            scope_digest: crossing.scope_digest.clone(),
            source_digest: crossing.source_digest.clone(),
            title: crossing.finding.title.clone(),
            severity: crossing.finding.severity,
            artifacts: crossing.artifacts.len() as u32,
            reviews: crossing.reviews.iter().filter(|review| review.granted).count() as u32,
            approval_id: request.id.clone(),
            accepted_by: person.id.clone(),
            accepted_at: now,
            note: sentence(if note.trim().is_empty() { "No note was written" } else { note }, "note")?,
            withdrawn_at: None,
            withdrawn_reason: String::new(),
        };
        self.store.put_import(&import)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.result.accepted", Decision::Allowed)
                .about(Capability::Research, &import.crossing_digest)
                .because(&format!("{} from {}, agreed by {decided_by}", import.title, import.from_realm_name)),
            now,
        )?;
        Ok(import)
    }

    /// Marks an accepted research result as no longer good, because the source or the scope behind
    /// it changed. The acceptance stands as it was made; this is the second row beside it.
    pub fn retract_import(&mut self, by: &str, crossing_digest: &str, reason: &str, now: i64) -> Result<(), String> {
        self.person(by)?;
        self.allowed(by, Action::ManageSecurity)?;
        let reason = sentence(reason, "reason")?;
        self.store.withdraw_import(crossing_digest, &reason, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "research.result.retracted", Decision::Allowed).about(Capability::Research, crossing_digest).because(&reason),
            now,
        )
    }

    pub fn imports(&self) -> Result<Vec<Import>, String> {
        self.store.imports()
    }

    // ---- Shared ----

    /// The person doing this, refused in words rather than on a foreign key.
    ///
    /// `Core::allowed` lets the literal "owner" through, because a realm is created before anybody
    /// is in it. Every research method writes a principal id into a row that references
    /// `principals`, so "owner" would pass the permission check and then fail on a foreign key
    /// with a database error nobody can act on. This refuses it as a sentence instead.
    fn research_person(&self, by: &str, action: Action) -> Result<String, String> {
        if by == "owner" {
            return Err("Research is done by a named person in this grid, not by the grid's owner".into());
        }
        let person = self.person(by)?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        if !person.may(action) {
            return Err(format!("{} may not {}", person.name, action.name()));
        }
        if self.realm.kind != RealmKind::Research {
            return Err("Research runs in a research grid of its own".into());
        }
        if !self.realm.can(Capability::Research) {
            return Err("This grid does not run authorised research".into());
        }
        Ok(person.id)
    }

    /// Who may stop research: the people doing it, and the person who holds the realm's stop
    /// switches. A security administrator who could not stop a research run would be holding a
    /// stop switch that does not reach the one thing it is most for.
    fn may_stop_research(&self, by: &str) -> Result<String, String> {
        self.research_person(by, Action::DoResearch).or_else(|_| self.research_person(by, Action::ManageSecurity))
    }

    fn scope_or_fail(&self, scope_id: &str) -> Result<Scope, String> {
        self.store.scope(scope_id)?.ok_or_else(|| "No such research scope is in this grid".to_owned())
    }

    /// The research half of `accept`: a permission bound to a destination is judged against the
    /// realm's policy and the admissions as they are at the moment it is used, not as they were
    /// when it was minted.
    pub(super) fn research_destination_still_allowed(&self, claims: &Claims, now: i64) -> Option<Stale> {
        let destination = claims.destination.as_deref()?;
        let allowed = self.store.realm().ok()?.network.allows(destination);
        let admitted = self
            .admitted(&claims.resource_id, Admission::Destination, now)
            .ok()?
            .iter()
            .any(|admitted| admitted.covers(destination, claims.method.as_deref(), claims.path.as_deref(), now));
        if allowed && admitted {
            None
        } else {
            Some(Stale::Withdrawn)
        }
    }
}

/// What a scope's work carries as its note, which is what makes a piece of work research work.
fn research_note(scope_id: &str) -> String {
    format!("research:{scope_id}")
}

/// The resource a request to freeze a scope's authorisation names.
fn freezing(scope: &Scope) -> String {
    format!("{}:authorisation:{}", scope.id, scope.authorisation_digest)
}

/// The resource a request to admit something names.
fn admitting(scope_id: &str, kind: Admission, subject: &str) -> String {
    format!("{scope_id}:{}:{subject}", kind.name())
}

/// When something produced under this scope may be let go of.
fn retain_until(scope: &Scope, now: i64) -> Option<i64> {
    if scope.limits.retain_seconds > 0 {
        Some(now + scope.limits.retain_seconds)
    } else {
        None
    }
}

/// Whether a host's card is isolated at least as well as a scope asks for. `Unknown` never is,
/// whatever the scope says, because nothing attested it and a card that is merely visible is not
/// thereby a card that is safely shared.
fn enough_isolation(host: GpuIsolation, wanted: GpuIsolation) -> bool {
    if host == GpuIsolation::Unknown {
        return false;
    }
    match wanted {
        // The scope asked for a hardware boundary between tenants.
        GpuIsolation::Partitioned | GpuIsolation::Virtual => host.shareable(),
        // The scope asked for the whole card, or for one passed through to one machine. Time
        // slicing puts no boundary between tenants and is never either of those.
        GpuIsolation::Exclusive | GpuIsolation::Passthrough => host != GpuIsolation::TimeSliced,
        // The scope named the weakest of them, or named nothing in particular. A card somebody
        // has recorded the isolation of is enough; one nobody has is refused above.
        GpuIsolation::TimeSliced | GpuIsolation::Unknown => true,
    }
}

/// The first path where two manifests disagree, which is what a person needs to be told.
fn first_difference(before: &[SourceFile], seen: &[SourceFile]) -> Option<String> {
    let mut sorted: Vec<&SourceFile> = seen.iter().collect();
    sorted.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let mut was: Vec<&SourceFile> = before.iter().collect();
    was.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    for (old, new) in was.iter().zip(sorted.iter()) {
        if old.path != new.path {
            return Some(new.path.clone());
        }
        if old.sha256 != new.sha256 || old.bytes != new.bytes {
            return Some(new.path.clone());
        }
    }
    if was.len() != sorted.len() {
        return Some(if was.len() > sorted.len() { was[sorted.len()].path.clone() } else { sorted[was.len()].path.clone() });
    }
    None
}
