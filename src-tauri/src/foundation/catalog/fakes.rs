//! Fakes for the catalog tests: an in-memory source that can corrupt or fail
//! deliveries, a scripted control and class verifiers. They touch nothing outside the
//! test's temporary root.

use std::collections::BTreeMap;

use super::identity::{ArtifactClass, PublisherId, SourceIdentity};
use super::import::{Checkpoint, ImportControl, ImportSource, ImportStage, Proceed, SourceError};
use super::trust::{ArtifactVerifier, ContentDescriptor, ObjectBytes, VerifierRejection};
use crate::foundation::ids::{digest, ContentKey, Digest};

/// An in-memory source that counts reads per offset.
pub struct FakeSource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
    reads: BTreeMap<u64, u32>,
    corrupt: BTreeMap<u64, u32>,
    fail_from: Option<u64>,
    reported_length: Option<u64>,
    chunk: Option<usize>,
}

impl FakeSource {
    pub fn new(locator: &str, bytes: &[u8]) -> Self {
        Self {
            identity: SourceIdentity::describe("test", locator),
            bytes: bytes.to_vec(),
            reads: BTreeMap::new(),
            corrupt: BTreeMap::new(),
            fail_from: None,
            reported_length: None,
            chunk: None,
        }
    }

    /// The next `deliveries` reads at `offset` arrive with their first byte flipped.
    pub fn corrupt_at(&mut self, offset: u64, deliveries: u32) {
        self.corrupt.insert(offset, deliveries);
    }

    /// Reads at or after `offset` fail.
    pub fn fail_from(&mut self, offset: u64) {
        self.fail_from = Some(offset);
    }

    pub fn heal(&mut self) {
        self.corrupt.clear();
        self.fail_from = None;
    }

    pub fn report_length(&mut self, length: u64) {
        self.reported_length = Some(length);
    }

    /// Delivers at most `chunk` bytes per read.
    pub fn chunked(mut self, chunk: usize) -> Self {
        self.chunk = Some(chunk);
        self
    }

    pub fn reads(&self) -> u32 {
        self.reads.values().sum()
    }

    pub fn reads_at(&self, offset: u64) -> u32 {
        self.reads.get(&offset).copied().unwrap_or(0)
    }

    pub fn reset_reads(&mut self) {
        self.reads.clear();
    }
}

impl ImportSource for FakeSource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.reported_length.unwrap_or(self.bytes.len() as u64))
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        *self.reads.entry(offset_bytes).or_default() += 1;
        if self.fail_from.is_some_and(|from| offset_bytes >= from) {
            return Err(SourceError {
                detail: "connection reset".to_owned(),
            });
        }
        let available = self.bytes.get(offset_bytes as usize..).unwrap_or(&[]);
        let mut count = available.len().min(buffer.len());
        if let Some(chunk) = self.chunk {
            count = count.min(chunk);
        }
        buffer[..count].copy_from_slice(&available[..count]);
        if let Some(remaining) = self.corrupt.get_mut(&offset_bytes) {
            if *remaining > 0 && count > 0 {
                *remaining -= 1;
                buffer[0] ^= 0xff;
            }
        }
        Ok(count)
    }
}

/// Interrupts at one checkpoint and records every checkpoint it saw.
pub struct StopAt {
    at: Checkpoint,
    pub seen: Vec<Checkpoint>,
}

impl StopAt {
    pub fn stage(stage: ImportStage) -> Self {
        Self {
            at: Checkpoint::Stage { stage },
            seen: Vec::new(),
        }
    }

    pub fn extent(extent: u32) -> Self {
        Self {
            at: Checkpoint::Extent { extent },
            seen: Vec::new(),
        }
    }
}

impl ImportControl for StopAt {
    fn proceed(&mut self, at: Checkpoint) -> Proceed {
        self.seen.push(at);
        if at == self.at {
            Proceed::Interrupt
        } else {
            Proceed::Continue
        }
    }
}

/// The magic of the fake structured format a header verifier checks.
pub const HEADER_MAGIC: &[u8; 4] = b"YGOB";

/// An object in the fake structured format: magic, payload length, payload.
pub fn header_object(payload: &[u8]) -> Vec<u8> {
    let mut object = HEADER_MAGIC.to_vec();
    object.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    object.extend_from_slice(payload);
    object
}

/// The fake publisher signature: a digest binding publisher, class and content key.
pub fn attestation(publisher: &PublisherId, class: ArtifactClass, content: ContentKey) -> Vec<u8> {
    digest(
        "yougori/test/attestation/v1",
        &[
            publisher.digest().as_bytes(),
            class.tag().as_bytes(),
            content.digest().as_bytes(),
        ],
    )
    .as_bytes()
    .to_vec()
}

/// A fake publisher signature over the whole manifest, extent table included.
pub fn manifest_attestation(
    publisher: &PublisherId,
    class: ArtifactClass,
    manifest: Digest,
) -> Vec<u8> {
    digest(
        "yougori/test/manifest-attestation/v1",
        &[
            publisher.digest().as_bytes(),
            class.tag().as_bytes(),
            manifest.as_bytes(),
        ],
    )
    .as_bytes()
    .to_vec()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Structure {
    Any,
    Header,
}

/// A class verifier: checks fake attestations and, for structured classes, the header.
pub struct FakeVerifier {
    class: ArtifactClass,
    structure: Structure,
    accept_any_attestation: bool,
    binds_manifest: bool,
}

impl FakeVerifier {
    pub fn new(class: ArtifactClass) -> Self {
        Self {
            class,
            structure: Structure::Any,
            accept_any_attestation: false,
            binds_manifest: false,
        }
    }

    /// A verifier whose attestations sign the whole manifest.
    pub fn manifest_bound(class: ArtifactClass) -> Self {
        Self {
            binds_manifest: true,
            ..Self::new(class)
        }
    }

    pub fn header(class: ArtifactClass) -> Self {
        Self {
            structure: Structure::Header,
            ..Self::new(class)
        }
    }

    /// A broken verifier that accepts every attestation.
    pub fn permissive(class: ArtifactClass) -> Self {
        Self {
            accept_any_attestation: true,
            ..Self::new(class)
        }
    }
}

impl ArtifactVerifier for FakeVerifier {
    fn class(&self) -> ArtifactClass {
        self.class
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation_bytes: &[u8],
    ) -> Result<(), VerifierRejection> {
        let expected = if self.binds_manifest {
            manifest_attestation(publisher, content.class, content.manifest_digest)
        } else {
            attestation(publisher, content.class, content.content_key)
        };
        if self.accept_any_attestation || attestation_bytes == expected {
            Ok(())
        } else {
            Err(VerifierRejection::AttestationInvalid)
        }
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        if self.structure == Structure::Any {
            return Ok(());
        }
        let length = bytes.length_bytes();
        if length < 12 {
            return Err(VerifierRejection::CorruptStructure {
                detail: "shorter than its header".to_owned(),
            });
        }
        let mut header = [0u8; 12];
        bytes
            .read_exact_at(0, &mut header)
            .map_err(|error| VerifierRejection::Unreadable {
                detail: error.to_string(),
            })?;
        if &header[..4] != HEADER_MAGIC {
            return Err(VerifierRejection::WrongFormat {
                detail: "no header magic".to_owned(),
            });
        }
        let mut declared = [0u8; 8];
        declared.copy_from_slice(&header[4..]);
        if u64::from_be_bytes(declared) != length - 12 {
            return Err(VerifierRejection::CorruptStructure {
                detail: "the header's payload length is wrong".to_owned(),
            });
        }
        Ok(())
    }
}
