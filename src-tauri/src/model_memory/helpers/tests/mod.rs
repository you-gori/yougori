//! Tests of helper bundles, their admission through a temporary catalog under keys
//! generated here, the rollout on fake admissibility, and runner pins. Each acceptance
//! item of G08 is named in the test that checks it.

mod admission;
mod journal;
mod manifest;
mod rollout;
mod runners;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, Catalog, CatalogConfig, ImportControl, ObjectId, PublisherId, Scope,
    TrustRevision, Uninterrupted, VerifierRegistry,
};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{
    digest, ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId,
};
use crate::foundation::report::{
    Label, Provenance, RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON,
};
use crate::foundation::signing::{Ed25519PublicKey, SharedTrustRoots, TrustCalendar, TrustRoots};

const ENTRY_SOURCE: &[u8] = b"def load(host):\n    return host.register('gpu-optimizer')\n";
const UTIL_SOURCE: &[u8] = b"LIMIT = 4096\n";

fn helper_id() -> HelperId {
    HelperId::new("gpu-optimizer").unwrap()
}

fn path(text: &str) -> HelperPath {
    HelperPath::new(text).unwrap()
}

fn label(text: &str) -> Label {
    Label::new(text).unwrap()
}

fn version(major: u32, minor: u32, patch: u32) -> HelperVersion {
    HelperVersion::new(major, minor, patch)
}

fn vllm() -> BackendRelease {
    BackendRelease::new(Backend::Vllm, "0.29.0").unwrap()
}

fn vllm_next() -> BackendRelease {
    BackendRelease::new(Backend::Vllm, "0.31.0").unwrap()
}

fn llama() -> BackendRelease {
    BackendRelease::new(Backend::LlamaCpp, "b11425").unwrap()
}

/// The gpu-optimizer bundle at `at` for ABI `abi`, supporting vLLM 0.29.0 and llama.cpp
/// b11425, with an entry point and one library file.
fn bundle_at(at: HelperVersion, abi: HelperAbi) -> HelperBundle {
    HelperBundle::build(
        helper_id(),
        at,
        abi,
        vec![vllm(), llama()],
        path("gpu_optimizer.py"),
        vec![
            (path("lib/util.py"), UTIL_SOURCE.to_vec()),
            (path("gpu_optimizer.py"), ENTRY_SOURCE.to_vec()),
        ],
    )
    .unwrap()
}

fn encoded(at: HelperVersion, abi: HelperAbi) -> Vec<u8> {
    bundle_at(at, abi).encode().unwrap()
}

// Keys and trust roots.

fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

fn publisher(seed: u8) -> PublisherId {
    public(seed).publisher_id()
}

/// `seed`'s signature over the bundle statement of `bytes` as `publisher(seed)`.
fn signature(seed: u8, bytes: &[u8]) -> Vec<u8> {
    let statement = bundle_statement(&publisher(seed), bytes);
    pair(seed).sign(statement.as_bytes()).as_ref().to_vec()
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

fn key(name: &str, seed: u8, classes: &[&str], from: &str, until: &str) -> Value {
    json!({
        "id": name,
        "algorithm": "ed25519",
        "public_key": public(seed).to_hex(),
        "classes": classes,
        "valid_from": format!("{from}T00:00:00Z"),
        "valid_until": format!("{until}T00:00:00Z"),
    })
}

/// Helper key 1 (2026), runtime-update key 2, revoked helper key 3 and helper key 4, the
/// rotation of key 1 from December 2026.
fn root_keys() -> Vec<Value> {
    let mut compromised = key(
        "helpers-compromised",
        3,
        &["model_helper"],
        "2026-01-01",
        "2027-01-01",
    );
    compromised["revoked"] = json!({ "reason": "key-compromise" });
    let mut rotated = key(
        "helpers-2027",
        4,
        &["model_helper"],
        "2026-12-01",
        "2028-01-01",
    );
    rotated["replaces"] = json!("helpers-2026");
    vec![
        key(
            "helpers-2026",
            1,
            &["model_helper"],
            "2026-01-01",
            "2027-01-01",
        ),
        key(
            "release-2026",
            2,
            &["runtime_update"],
            "2026-01-01",
            "2027-01-01",
        ),
        compromised,
        rotated,
    ]
}

fn roots_from(keys: Vec<Value>) -> TrustRoots {
    TrustRoots::from_json(&json!({ "format": 1, "keys": keys }).to_string()).unwrap()
}

struct FixedCalendar(Mutex<DateTime<Utc>>);

impl FixedCalendar {
    fn at(text: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(at(text))))
    }

    fn set(&self, text: &str) {
        *self.0.lock().unwrap() = at(text);
    }
}

impl TrustCalendar for FixedCalendar {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

/// Committed catalog files are read-only; make them writable so the temporary root goes.
#[allow(clippy::permissions_set_readonly_false)]
fn make_tree_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_tree_writable(&entry.path());
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

fn execution() -> ExecutionId {
    ExecutionId::new("exe-helpers").unwrap()
}

/// A temporary catalog whose `model_helper` class is verified by [`helper_verifier`] and
/// trusted by [`helper_policy`] of the shared roots, with an admission for `host`.
struct Fixture {
    catalog: Catalog,
    admission: HelperAdmission,
    roots: SharedTrustRoots,
    calendar: Arc<FixedCalendar>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_abi(HostHelperAbi::single(HelperAbi::new(1, 0)))
    }

    fn with_abi(host: HostHelperAbi) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let roots = SharedTrustRoots::new(roots_from(root_keys()));
        let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
        let mut verifiers = VerifierRegistry::new();
        verifiers
            .register(Box::new(helper_verifier(roots.clone(), calendar.clone())))
            .unwrap();
        let config = CatalogConfig::new(Duration::from_secs(60))
            .with_quota(Scope::Host, 1 << 26)
            .with_trust(HELPER_CLASS, helper_policy(&roots.current()));
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)));
        let catalog = Catalog::open(dir.path(), config, verifiers, clock)
            .unwrap()
            .0;
        let admission = HelperAdmission::new(host, roots.clone(), calendar.clone());
        Self {
            catalog,
            admission,
            roots,
            calendar,
            dir,
        }
    }

    fn admit_with(
        &mut self,
        bytes: &[u8],
        signed: Option<(PublisherId, Vec<u8>)>,
        control: &mut dyn ImportControl,
    ) -> Result<AdmittedHelper, HelperRefusal> {
        let offer = HelperOffer {
            bundle: bytes.to_vec(),
            signature: signed.map(|(publisher, signature)| HelperSignature {
                publisher,
                signature,
            }),
            operation: OperationId::new("op-helper-admit").unwrap(),
            execution: execution(),
        };
        self.admission.admit(&mut self.catalog, offer, control)
    }

    /// Admits `bytes` signed by `seed`'s key as its own publisher, or unsigned.
    fn admit(&mut self, bytes: &[u8], seed: Option<u8>) -> Result<AdmittedHelper, HelperRefusal> {
        let signed = seed.map(|seed| (publisher(seed), signature(seed, bytes)));
        self.admit_with(bytes, signed, &mut Uninterrupted)
    }

    fn open(&mut self, pin: &HelperPin) -> Result<HelperBundle, HelperRefusal> {
        self.admission.open(
            &mut self.catalog,
            pin,
            &execution(),
            Duration::from_secs(30),
        )
    }

    /// The owner revokes helper key 1: the shared roots are replaced and the class policy
    /// set from them.
    fn revoke_key_one(&mut self) -> TrustRevision {
        let mut keys = root_keys();
        keys[0]["revoked"] = json!({ "reason": "key-compromise" });
        self.roots.replace(roots_from(keys));
        self.catalog
            .set_trust_policy(HELPER_CLASS, helper_policy(&self.roots.current()))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        make_tree_writable(self.dir.path());
    }
}

// Rollout fakes.

/// A pin to a bundle that was never imported, for the pure rollout tests.
fn fake_pin(at: HelperVersion, runners: &[BackendRelease]) -> HelperPin {
    let bundle = ContentKey::of(format!("gpu-optimizer bundle {at}").as_bytes());
    HelperPin {
        helper: helper_id(),
        version: at,
        abi: HelperAbi::new(1, 0),
        runners: runners.iter().cloned().collect::<BTreeSet<_>>(),
        object: ObjectId::new(&Scope::Host, ArtifactClass::ModelHelper, bundle),
        bundle,
        length_bytes: 4096,
        publisher: PublisherId::from_key_fingerprint(digest(
            "yougori/test/helpers/publisher/v1",
            &[b"p1"],
        )),
    }
}

fn fake_pin_at(major: u32, minor: u32, patch: u32) -> HelperPin {
    fake_pin(version(major, minor, patch), &[vllm(), llama()])
}

/// Admits every pin except those refused.
#[derive(Debug, Default)]
struct FakePins {
    refused: BTreeMap<HelperPinId, PinRefusal>,
}

impl FakePins {
    fn refuse(&mut self, pin: &HelperPin, refusal: PinRefusal) {
        self.refused.insert(pin.id(), refusal);
    }
}

impl PinAdmissibility for FakePins {
    fn check(&self, pin: &HelperPin) -> Result<(), PinRefusal> {
        match self.refused.get(&pin.id()) {
            Some(refusal) => Err(refusal.clone()),
            None => Ok(()),
        }
    }
}

// CORE-08 evidence.

/// CORE-08's golden run record, run on `substrate`.
fn run_record(substrate: RunSubstrate) -> RunRecord {
    let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    record.substrate = substrate;
    record
}

/// A Yougori measurement in an authorized disposable environment.
fn measured() -> Provenance {
    Provenance::of_records(&[run_record(RunSubstrate::AuthorizedDisposable {
        authorization: label("disposable-test-host"),
    })])
    .unwrap()
}

/// A fake, time-controlled run.
fn simulated() -> Provenance {
    Provenance::of_records(&[run_record(RunSubstrate::FakeTimeControlled)]).unwrap()
}

fn trial(
    pin: &HelperPin,
    runner: &BackendRelease,
    stage: RolloutStage,
    verdict: TrialVerdict,
    provenance: Provenance,
) -> RolloutEvidence {
    RolloutEvidence {
        pin: pin.id(),
        runner: runner.clone(),
        stage,
        verdict,
        provenance,
    }
}

/// A measured pass of `pin` on vLLM 0.29.0 at `stage`.
fn pass(pin: &HelperPin, stage: RolloutStage) -> RolloutEvidence {
    trial(pin, &vllm(), stage, TrialVerdict::Passed, measured())
}

/// A measured failure of `pin` on vLLM 0.29.0 at `stage`.
fn fail(pin: &HelperPin, stage: RolloutStage) -> RolloutEvidence {
    trial(
        pin,
        &vllm(),
        stage,
        TrialVerdict::Failed {
            reason: label("shadow-mismatch"),
        },
        measured(),
    )
}

/// Takes `pin` through shadow and opt-in to the vLLM default on measured passes.
fn make_default(rollouts: &mut HelperRollouts, pin: &HelperPin, admissible: &dyn PinAdmissibility) {
    let helper = pin.helper.clone();
    rollouts
        .propose(pin.clone(), Backend::Vllm, admissible)
        .unwrap();
    rollouts
        .record(pass(pin, RolloutStage::Shadow), admissible)
        .unwrap();
    rollouts
        .promote(&helper, Backend::Vllm, admissible)
        .unwrap();
    rollouts
        .record(pass(pin, RolloutStage::OptIn), admissible)
        .unwrap();
    rollouts
        .promote(&helper, Backend::Vllm, admissible)
        .unwrap();
}
