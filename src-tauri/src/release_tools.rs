//! Explicit maintainer-only signing entrypoint (S08/VM-W45). Uses the existing
//! catalog statements and sandbox metadata, without starting the engine. The build
//! operations produce and re-verify CORE-08 `SignedBuildIdentity` records (S08, E05)
//! from public inputs only; they never sign and never read a private key.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::{ContentHasher, ContentKey, Digest};
use crate::foundation::report::{BuildIdentity, Label};
use crate::foundation::signing::{
    content_statement, RootKeyId, SignedBuildIdentity, SignedComponent, SigningKey, SystemCalendar,
    TrustCalendar, TrustRoots, MAX_PRIVATE_KEY_BYTES, MAX_SIGNED_COMPONENTS,
};
use crate::sandbox::trust::{
    verify_threshold, HexBytes, MetadataFile, PublicKey, RevocationMetadata, Role, RootMetadata,
    SchemeKind, SchemeRegistry, Signature, SnapshotMetadata, TargetsMetadata, TimestampMetadata,
    UnixSeconds,
};
use crate::sandbox_contract::trust_adapter::Ed25519Scheme;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 64;
/// Largest detached signature file read; `sign_artifact` writes about 230 bytes.
const MAX_SIGNATURE_FILE_BYTES: usize = 4096;
/// The classes whose responsible verifier checks [`content_statement`] over the
/// artifact's actual bytes, the statement `sign_artifact` signs: guest image manifests
/// (`guest_image::signing_statement`) and helper bundles (`helpers::bundle_statement`).
/// The other classes' verifiers check another statement (OCI layers), a metadata chain
/// (runtime updates) or none yet, so a content signature is not their identity.
const CONTENT_SIGNED_CLASSES: [ArtifactClass; 2] =
    [ArtifactClass::GuestImage, ArtifactClass::ModelHelper];
type Result<T, E = String> = std::result::Result<T, E>;

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    deny_unknown_fields,
    remote = "Self"
)]
enum Request {
    PublicKey,
    /// Builds a helper bundle (G08) from files on disk: the manifest (helper, version, the
    /// loader ABI it needs, the exact runner releases it supports, the entry file) and the
    /// files, written as one YGHELPER file at `output`. No key: the bundle is signed by
    /// `sign_artifact` with class `model_helper`.
    BuildHelperBundle {
        helper: String,
        version: String,
        abi: HelperAbiInput,
        runners: Vec<RunnerInput>,
        entry: String,
        files: Vec<HelperFileInput>,
        output: PathBuf,
    },
    TrustRoots {
        #[serde(deserialize_with = "root_key_id")]
        id: RootKeyId,
        classes: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    SignArtifact {
        #[serde(deserialize_with = "artifact_class")]
        class: ArtifactClass,
        artifact: PathBuf,
    },
    VerifyArtifact {
        #[serde(deserialize_with = "artifact_class")]
        class: ArtifactClass,
        artifact: PathBuf,
        attestation: Attestation,
        trust_roots: Value,
        at: DateTime<Utc>,
    },
    SignMetadata {
        role: String,
        document: MetadataFile,
        at: UnixSeconds,
    },
    VerifyMetadata {
        role: String,
        document: MetadataFile,
        trusted_root: RootMetadata,
        at: UnixSeconds,
    },
    IdentifyBuild {
        trust_roots_file: PathBuf,
        build: BuildInput,
        components: Vec<ComponentInput>,
    },
    VerifyBuild {
        trust_roots_file: PathBuf,
        record_file: PathBuf,
        artifact_files: Vec<PathBuf>,
        signature_files: Vec<PathBuf>,
    },
}
crate::foundation::strict_serde::strict_tag!(Request, "operation", deserialize);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    publisher: PublisherId,
    signature: HexBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperAbiInput {
    major: u16,
    minor: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerInput {
    backend: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperFileInput {
    /// The path inside the bundle.
    path: String,
    /// The file on disk, relative to the request.
    source: PathBuf,
}

/// The build a [`SignedBuildIdentity`] names, as the report's [`BuildIdentity`] holds
/// it. The runner build is given either as a digest or as a file whose SHA-256 it is.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildInput {
    plan: Digest,
    runner_build: Option<Digest>,
    runner_build_file: Option<PathBuf>,
    runner_version: Label,
}

/// One component of a build: an actual file and its detached signature file in
/// `sign_artifact`'s output format.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentInput {
    #[serde(deserialize_with = "artifact_class")]
    class: ArtifactClass,
    publisher: PublisherId,
    artifact: PathBuf,
    signature_file: PathBuf,
}

fn artifact_class<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<ArtifactClass, D::Error> {
    let name = String::deserialize(d)?;
    serde_json::from_value(Value::String(name)).map_err(serde::de::Error::custom)
}

fn root_key_id<'de, D: Deserializer<'de>>(d: D) -> Result<RootKeyId, D::Error> {
    RootKeyId::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read bounded input".to_owned())?;
    if bytes.len() > limit {
        return Err("input exceeds its byte limit".to_owned());
    }
    Ok(bytes)
}

fn signing_key(reader: &mut impl Read) -> Result<SigningKey> {
    // Keep the allocation here so partial reads and oversized inputs are also
    // cleared on refusal, rather than dropping a buffer from `bounded` unseen.
    let mut bytes = Vec::with_capacity(MAX_PRIVATE_KEY_BYTES + 1);
    let key = reader
        .take(MAX_PRIVATE_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read private signing input".to_owned())
        .and_then(|_| SigningKey::from_pkcs8(&bytes).map_err(|error| error.to_string()));
    bytes.fill(0);
    key
}

fn regular_file(path: &Path) -> Result<File> {
    let file = File::open(path).map_err(|_| "could not open input file".to_owned())?;
    if !file
        .metadata()
        .map_err(|_| "could not inspect input file")?
        .is_file()
    {
        return Err("input must be a regular file".to_owned());
    }
    Ok(file)
}

/// Streams the actual bytes of the regular file at `path` with a fixed buffer into the
/// hasher `start` makes for its length, refusing truncation, growth and observed
/// mutation while they are read.
fn read_stable<H>(
    path: &Path,
    start: impl FnOnce(u64) -> H,
    mut update: impl FnMut(&mut H, &[u8]) -> Result<()>,
) -> Result<(H, u64)> {
    let mut file = regular_file(path)?;
    let before = file.metadata().map_err(|_| "could not inspect artifact")?;
    let mut hasher = start(before.len());
    let mut remaining = before.len();
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])
            .map_err(|_| "artifact changed or could not be read")?;
        update(&mut hasher, &buffer[..count])?;
        remaining -= count as u64;
    }
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|_| "could not finish reading artifact")?
        != 0
    {
        return Err("artifact grew while being read".to_owned());
    }
    let after = file.metadata().map_err(|_| "could not inspect artifact")?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err("artifact changed while being read".to_owned());
    }
    Ok((hasher, before.len()))
}

/// Hash the actual bytes, streaming with a fixed buffer. Never accept a caller's
/// checksum as proof of the file supplied for signing or verification.
fn identify(path: &Path) -> Result<(ContentKey, u64)> {
    let (hasher, length) = read_stable(
        path,
        ContentHasher::new,
        |hasher: &mut ContentHasher, chunk: &[u8]| {
            hasher
                .update(chunk)
                .map_err(|_| "artifact length changed".to_owned())
        },
    )?;
    Ok((
        hasher.finish().map_err(|_| "artifact length changed")?,
        length,
    ))
}

/// The plain SHA-256 of the file's actual bytes, the value common file-hash tools print.
fn sha256_file(path: &Path) -> Result<Digest> {
    let (hasher, _) = read_stable(
        path,
        |_| Sha256::new(),
        |hasher: &mut Sha256, chunk: &[u8]| {
            hasher.update(chunk);
            Ok(())
        },
    )?;
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

/// The statement `publisher` signs for the actual file at `path` as an artifact of
/// `class`: [`content_statement`] over its content key and length, the statement
/// `sign_artifact` signs (`SigningKey::sign_content`).
fn file_statement(
    publisher: &PublisherId,
    class: ArtifactClass,
    path: &Path,
) -> Result<(Digest, ContentKey, u64)> {
    let (content, length) = identify(path)?;
    Ok((
        content_statement(publisher, class, &content, length),
        content,
        length,
    ))
}

/// A detached signature file in `sign_artifact`'s output format.
fn attestation(path: &Path) -> Result<Attestation> {
    let bytes = bounded(regular_file(path)?, MAX_SIGNATURE_FILE_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid detached signature file".to_owned())
}

/// The owner's trust-root file, read and checked by the engine's own loader.
fn load_trust_roots(path: &Path) -> Result<TrustRoots> {
    TrustRoots::load(path).map_err(|error| format!("trust roots refused: {error}"))
}

impl BuildInput {
    fn identity(&self, base: &Path) -> Result<BuildIdentity> {
        let runner_build = match (&self.runner_build, &self.runner_build_file) {
            (Some(digest), None) => *digest,
            (None, Some(file)) => sha256_file(&base.join(file))?,
            _ => return Err("give exactly one of runner_build and runner_build_file".to_owned()),
        };
        Ok(BuildIdentity {
            plan: self.plan,
            runner_build,
            runner_version: self.runner_version.clone(),
        })
    }
}

impl ComponentInput {
    /// Verifies the signature over the statement the class's verifier checks, at `at`,
    /// and records the outcome, a refusal included. Input that yields no such statement
    /// (another class, an unreadable file, another publisher's signature file) is an
    /// error, so nothing is left out of the record silently.
    fn check(&self, base: &Path, roots: &TrustRoots, at: DateTime<Utc>) -> Result<SignedComponent> {
        if !CONTENT_SIGNED_CLASSES.contains(&self.class) {
            return Err(format!(
                "no {} verifier checks a content statement; supported: guest_image, model_helper",
                self.class
            ));
        }
        let attestation = attestation(&base.join(&self.signature_file))?;
        if attestation.publisher != self.publisher {
            return Err("the signature file names another publisher".to_owned());
        }
        let (statement, _, _) =
            file_statement(&self.publisher, self.class, &base.join(&self.artifact))?;
        Ok(SignedComponent::check(
            roots,
            self.class,
            &self.publisher,
            statement,
            attestation.signature.as_bytes(),
            at,
        ))
    }
}

/// The CORE-08 record of `build` with each component verified under the trust roots at
/// `at`. A refused component is recorded with its typed outcome, never dropped; a
/// duplicate component refuses the record.
fn identify_build(
    base: &Path,
    trust_roots_file: &Path,
    build: &BuildInput,
    components: &[ComponentInput],
    at: DateTime<Utc>,
) -> Result<Value> {
    if components.is_empty() || components.len() > MAX_SIGNED_COMPONENTS {
        return Err(format!(
            "a build identity lists 1 to {MAX_SIGNED_COMPONENTS} components"
        ));
    }
    let roots = load_trust_roots(&base.join(trust_roots_file))?;
    let build = build.identity(base)?;
    let components = components
        .iter()
        .enumerate()
        .map(|(index, component)| {
            component
                .check(base, &roots, at)
                .map_err(|error| format!("component {index}: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let record = SignedBuildIdentity::new(build, components)
        .map_err(|error| format!("build identity refused: {error}"))?;
    serde_json::to_value(record).map_err(|_| "could not encode the build identity".to_owned())
}

/// Reads a [`SignedBuildIdentity`] back, binds each recorded statement to the actual
/// artifact bytes, class and publisher, and verifies its detached signature under the
/// trust roots at `at`. Build labels remain unsigned caller-supplied metadata.
fn verify_build(
    base: &Path,
    trust_roots_file: &Path,
    record_file: &Path,
    artifact_files: &[PathBuf],
    signature_files: &[PathBuf],
    at: DateTime<Utc>,
) -> Result<Value> {
    let roots = load_trust_roots(&base.join(trust_roots_file))?;
    let text = String::from_utf8(bounded(
        regular_file(&base.join(record_file))?,
        MAX_REQUEST_BYTES,
    )?)
    .map_err(|_| "the build identity is not UTF-8 text")?;
    let record = SignedBuildIdentity::from_json(&text)
        .map_err(|error| format!("build identity refused: {error}"))?;
    let components = record.components();
    if components.is_empty() {
        return Err("the build identity lists no component".to_owned());
    }
    if signature_files.len() != components.len() || artifact_files.len() != components.len() {
        return Err(format!(
            "the build identity lists {} components; give one artifact and signature file for each, in order",
            components.len()
        ));
    }
    let mut all_verified = true;
    let mut outcomes = Vec::with_capacity(components.len());
    for (index, (component, file)) in components.iter().zip(signature_files).enumerate() {
        if !CONTENT_SIGNED_CLASSES.contains(&component.class()) {
            return Err(format!(
                "component {index}: unsupported content-signed artifact class"
            ));
        }
        let (statement, _, _) = file_statement(
            component.publisher(),
            component.class(),
            &base.join(&artifact_files[index]),
        )?;
        if &statement != component.statement() {
            return Err(format!("component {index}: artifact bytes, class or publisher do not match the recorded statement"));
        }
        let attestation =
            attestation(&base.join(file)).map_err(|error| format!("component {index}: {error}"))?;
        if attestation.publisher != *component.publisher() {
            return Err(format!(
                "component {index}: the signature file names another publisher"
            ));
        }
        let now = component.reverify(&roots, attestation.signature.as_bytes(), at);
        all_verified &= now.is_verified();
        outcomes.push(
            json!({"class":component.class(), "publisher":component.publisher(),
            "statement":component.statement(), "recorded_at":component.checked_at(),
            "recorded":component.verification(), "reverified":now.verification()}),
        );
    }
    Ok(
        json!({"verification":"signed_build_reverified", "build":record.build(), "checked_at":at,
        "all_verified":all_verified, "artifact_files_checked":true,
        "build_authenticated":false, "components":outcomes}),
    )
}

fn role(name: &str) -> Result<Role> {
    serde_json::from_value(Value::String(name.to_owned()))
        .map_err(|_| "unknown metadata role".to_owned())
}

fn check_metadata(document: &MetadataFile, role: Role, at: UnixSeconds) -> Result<()> {
    if document
        .declared_role()
        .map_err(|_| "metadata has no valid role")?
        != role
    {
        return Err("metadata role does not match the request".to_owned());
    }
    if document.signatures().len() > MAX_SIGNATURES
        || document
            .signatures()
            .iter()
            .any(|s| s.signature.as_bytes().len() != 64)
    {
        return Err("metadata signature list is invalid or too large".to_owned());
    }
    let expires = match role {
        Role::Root => {
            let value: RootMetadata = document.parse().map_err(|_| "invalid root metadata")?;
            check_root(&value, at)?;
            value.expires
        }
        Role::Timestamp => {
            let value: TimestampMetadata =
                document.parse().map_err(|_| "invalid timestamp metadata")?;
            value.check().map_err(|_| "invalid timestamp metadata")?;
            value.expires
        }
        Role::Snapshot => {
            let value: SnapshotMetadata =
                document.parse().map_err(|_| "invalid snapshot metadata")?;
            value.check().map_err(|_| "invalid snapshot metadata")?;
            value.expires
        }
        Role::Targets => {
            let value: TargetsMetadata =
                document.parse().map_err(|_| "invalid targets metadata")?;
            value.check().map_err(|_| "invalid targets metadata")?;
            value.expires
        }
        Role::Revocation => {
            let value: RevocationMetadata = document
                .parse()
                .map_err(|_| "invalid revocation metadata")?;
            value.check().map_err(|_| "invalid revocation metadata")?;
            return if value.issued <= at {
                Ok(())
            } else {
                Err("revocation is issued in the future".to_owned())
            };
        }
    };
    if at >= expires {
        Err("metadata has expired".to_owned())
    } else {
        Ok(())
    }
}

fn check_root(root: &RootMetadata, at: UnixSeconds) -> Result<()> {
    root.check().map_err(|_| "invalid trusted metadata root")?;
    if at >= root.expires {
        return Err("trusted metadata root has expired".to_owned());
    }
    for key in root.keys.values() {
        if key.scheme != SchemeKind::Ed25519
            || crate::foundation::signing::Ed25519PublicKey::from_bytes(key.material.as_bytes())
                .is_err()
        {
            return Err("metadata root must use valid Ed25519 keys".to_owned());
        }
    }
    Ok(())
}

fn execute(request: Request, base: &Path, private_input: &mut impl Read) -> Result<Value> {
    execute_at(request, base, private_input, &SystemCalendar)
}

/// Runs `request`. The build operations judge key windows at `calendar`'s time: the
/// system's calendar in the binary ([`execute`]); only tests fix it.
fn execute_at(
    request: Request,
    base: &Path,
    private_input: &mut impl Read,
    calendar: &dyn TrustCalendar,
) -> Result<Value> {
    match request {
        Request::PublicKey => {
            let key = signing_key(private_input)?.public_key();
            let metadata = PublicKey::new(SchemeKind::Ed25519, key.as_bytes().to_vec());
            Ok(
                json!({"algorithm":"ed25519", "public_key":key, "publisher":key.publisher_id(),
                "metadata_key_id":metadata.key_id(), "metadata_key":metadata}),
            )
        }
        Request::TrustRoots {
            id,
            classes,
            valid_from,
            valid_until,
        } => {
            if classes.is_empty()
                || classes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != classes.len()
            {
                return Err("artifact classes must be nonempty and distinct".to_owned());
            }
            let public = signing_key(private_input)?.public_key();
            let document = json!({"format":1,"keys":[{"id":id,"algorithm":"ed25519",
                "public_key":public,"classes":classes,"valid_from":valid_from,"valid_until":valid_until}]});
            TrustRoots::from_json(&document.to_string())
                .map_err(|_| "invalid artifact trust-root declaration")?;
            Ok(document)
        }
        Request::BuildHelperBundle {
            helper,
            version,
            abi,
            runners,
            entry,
            files,
            output,
        } => {
            use crate::foundation::evidence::{Backend, BackendRelease};
            use crate::model_memory::helpers::{
                HelperAbi, HelperBundle, HelperId, HelperPath, HelperVersion,
            };
            let helper =
                HelperId::new(helper).map_err(|error| format!("invalid helper id: {error}"))?;
            let version = HelperVersion::parse(&version)
                .map_err(|error| format!("invalid helper version: {error}"))?;
            let runners = runners
                .into_iter()
                .map(|runner| {
                    let backend = match runner.backend.as_str() {
                        "transformers" => Backend::Transformers,
                        "vllm" => Backend::Vllm,
                        "llama_cpp" => Backend::LlamaCpp,
                        other => return Err(format!("unknown runner backend '{other}'")),
                    };
                    BackendRelease::new(backend, &runner.version)
                        .map_err(|error| format!("invalid runner release: {error}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let entry =
                HelperPath::new(entry).map_err(|error| format!("invalid entry path: {error}"))?;
            if files.len() > 256 {
                return Err("too many files for a helper bundle".into());
            }
            let mut contents = Vec::with_capacity(files.len());
            for file in files {
                let path = HelperPath::new(file.path)
                    .map_err(|error| format!("invalid file path: {error}"))?;
                let bytes = bounded(regular_file(&base.join(&file.source))?, 16 << 20)?;
                contents.push((path, bytes));
            }
            let bundle = HelperBundle::build(
                helper,
                version,
                HelperAbi::new(abi.major, abi.minor),
                runners,
                entry,
                contents,
            )
            .map_err(|error| format!("the bundle could not be built: {error}"))?;
            let encoded = bundle
                .encode()
                .map_err(|error| format!("the bundle could not be encoded: {error}"))?;
            let destination = base.join(&output);
            std::fs::write(&destination, &encoded)
                .map_err(|error| format!("could not write {}: {error}", destination.display()))?;
            let (content, length) = identify(&destination)?;
            Ok(
                json!({"built":"helper_bundle","output":destination.display().to_string(),"content_key":content,"length_bytes":length,
                "helper":bundle.manifest().helper().as_str(),"version":bundle.manifest().version().to_string(),"files":bundle.manifest().files().len()}),
            )
        }
        Request::SignArtifact { class, artifact } => {
            let key = signing_key(private_input)?;
            let (content, length) = identify(&base.join(artifact))?;
            Ok(json!(Attestation {
                publisher: key.public_key().publisher_id(),
                signature: HexBytes::new(key.sign_content(class, &content, length).to_vec())
            }))
        }
        Request::VerifyArtifact {
            class,
            artifact,
            attestation,
            trust_roots,
            at,
        } => {
            let roots = TrustRoots::from_json(&trust_roots.to_string())
                .map_err(|_| "invalid artifact trust roots")?;
            let (statement, content, length) =
                file_statement(&attestation.publisher, class, &base.join(artifact))?;
            let key = roots
                .verify_statement(
                    &attestation.publisher,
                    class,
                    &statement,
                    attestation.signature.as_bytes(),
                    at,
                )
                .map_err(|error| format!("artifact refused: {error}"))?;
            Ok(
                json!({"verification":"artifact_signature", "key":key.id(), "class":class,
                "content_key":content,"length_bytes":length,"publisher":attestation.publisher}),
            )
        }
        Request::SignMetadata {
            role: name,
            mut document,
            at,
        } => {
            let role = role(&name)?;
            check_metadata(&document, role, at)?;
            let key = signing_key(private_input)?;
            let public = PublicKey::new(SchemeKind::Ed25519, key.public_key().as_bytes().to_vec());
            if document.signatures().len() >= MAX_SIGNATURES
                || document
                    .signatures()
                    .iter()
                    .any(|s| s.key_id == public.key_id())
            {
                return Err(
                    "metadata already has this signer or has too many signatures".to_owned(),
                );
            }
            let statement = Digest::from_bytes(
                document
                    .message(role)
                    .map_err(|_| "invalid metadata statement")?,
            );
            document.add_signature(Signature {
                key_id: public.key_id(),
                signature: HexBytes::new(key.sign_statement(&statement).to_vec()),
            });
            serde_json::to_value(document).map_err(|_| "could not encode metadata".to_owned())
        }
        Request::VerifyMetadata {
            role: name,
            document,
            trusted_root,
            at,
        } => {
            let role = role(&name)?;
            check_root(&trusted_root, at)?;
            check_metadata(&document, role, at)?;
            let mut schemes = SchemeRegistry::new();
            schemes
                .register(Box::new(Ed25519Scheme))
                .map_err(|_| "could not register signature scheme")?;
            let keys = trusted_root
                .role_keys(role)
                .map_err(|_| "root has no requested role")?;
            let witness = verify_threshold(&document, role, &trusted_root.keys, keys, &schemes)
                .map_err(|error| format!("metadata refused: {error}"))?;
            Ok(json!({"verification":"metadata_threshold_only", "witness":witness}))
        }
        Request::IdentifyBuild {
            trust_roots_file,
            build,
            components,
        } => identify_build(base, &trust_roots_file, &build, &components, calendar.now()),
        Request::VerifyBuild {
            trust_roots_file,
            record_file,
            artifact_files,
            signature_files,
        } => verify_build(
            base,
            &trust_roots_file,
            &record_file,
            &artifact_files,
            &signature_files,
            calendar.now(),
        ),
    }
}

fn run(
    args: Vec<std::ffi::OsString>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<()> {
    if args.len() != 2 || args[0] != "--request" {
        return Err(
            "usage: yougori-sign --request PUBLIC_REQUEST.json; signing key: PKCS#8 DER on stdin"
                .to_owned(),
        );
    }
    let request_path = Path::new(&args[1]);
    let encoded = bounded(regular_file(request_path)?, MAX_REQUEST_BYTES)?;
    // Strict tagged decoding also refuses duplicate keys anywhere in nested JSON.
    let request: Request =
        serde_json::from_slice(&encoded).map_err(|_| "invalid public signing request")?;
    let result = execute(
        request,
        request_path.parent().unwrap_or(Path::new(".")),
        input,
    )?;
    let encoded = serde_json::to_vec(&result).map_err(|_| "could not encode public result")?;
    if encoded.len() > MAX_REQUEST_BYTES * 2 {
        return Err("public result exceeds its byte limit".to_owned());
    }
    output
        .write_all(&encoded)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|_| "could not write public result".to_owned())
}

/// Maintainer binary entrypoint. Reads no engine settings and starts no runtime.
pub fn main() -> ExitCode {
    match run(
        std::env::args_os().skip(1).collect(),
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "release_tools/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "release_tools/tests_build.rs"]
mod tests_build;
