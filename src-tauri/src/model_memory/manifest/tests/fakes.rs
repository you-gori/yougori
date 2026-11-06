//! Fakes of the catalog (T05), identity (T07) and extent (T06) ports, an in-memory source
//! that counts its reads, and codec stand-ins. They hold everything in memory and touch
//! nothing outside temp dirs.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::super::*;
use crate::foundation::ids::{Digest, DigestBuilder};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Integrity extents of a fixed size with a true-length tail, as T06 will plan them.
pub struct FixedExtents;

impl ExtentPlanner for FixedExtents {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<ExtentSpan>, ExtentPlanError> {
        if integrity_extent_bytes == 0 {
            return Err(ExtentPlanError::Refused);
        }
        let mut spans = Vec::new();
        let mut offset_bytes = 0;
        while offset_bytes < logical_length_bytes {
            let true_length_bytes = integrity_extent_bytes.min(logical_length_bytes - offset_bytes);
            spans.push(ExtentSpan {
                offset_bytes,
                true_length_bytes,
            });
            offset_bytes += true_length_bytes;
        }
        Ok(spans)
    }
}

/// A broken planner whose spans overlap.
pub struct OverlappingExtents;

impl ExtentPlanner for OverlappingExtents {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        _integrity_extent_bytes: u64,
    ) -> Result<Vec<ExtentSpan>, ExtentPlanError> {
        let whole = ExtentSpan {
            offset_bytes: 0,
            true_length_bytes: logical_length_bytes.max(1),
        };
        Ok(vec![whole, whole])
    }
}

/// Plans like [`FixedExtents`] but cancels `token` on its `cancel_on_call`-th call.
pub struct CancellingExtents {
    pub token: CancellationToken,
    pub cancel_on_call: usize,
    pub calls: AtomicUsize,
}

impl ExtentPlanner for CancellingExtents {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<ExtentSpan>, ExtentPlanError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.cancel_on_call {
            self.token.cancel();
        }
        FixedExtents.integrity_extents(logical_length_bytes, integrity_extent_bytes)
    }
}

/// Identities computed from the fields T07 binds, under test domains.
pub struct FakeIdentities;

impl FakeIdentities {
    pub fn source_for(listing: &SourceListing) -> SourceIdentity {
        let files = listing.sorted_files();
        let builder = DigestBuilder::new("yougori/test/source-identity/v1")
            .str(&format!("{:?}", listing.origin))
            .str(&format!("{:?}", listing.revision))
            .u64(files.len() as u64);
        SourceIdentity(
            files
                .iter()
                .fold(builder, |builder, file| {
                    builder
                        .str(file.path.as_str())
                        .u64(file.length_bytes)
                        .digest(file.content.digest())
                })
                .finish(),
        )
    }

    pub fn execution_for(
        source: &SourceIdentity,
        abi: &ExecutionAbi,
        distribution: &Distribution,
    ) -> ExecutionIdentity {
        ExecutionIdentity(
            DigestBuilder::new("yougori/test/execution-identity/v1")
                .digest(&source.0)
                .str(abi.runner.backend.tag())
                .str(abi.runner.version.as_str())
                .str(abi.layout.as_str())
                .u64(distribution.tensor_parallel_size.into())
                .u64(distribution.pipeline_parallel_size.into())
                .u64(distribution.expert_parallel_size.into())
                .u64(distribution.expert_count.into())
                .finish(),
        )
    }

    pub fn artifact_for(manifest: &ManifestDigest) -> ArtifactIdentity {
        ArtifactIdentity(
            DigestBuilder::new("yougori/test/artifact-identity/v1")
                .digest(&manifest.digest())
                .finish(),
        )
    }
}

impl ModelIdentities for FakeIdentities {
    type Context = ();

    fn source_identity(
        &self,
        listing: &SourceListing,
        _configuration: &Digest,
        _context: &(),
    ) -> Result<SourceIdentity, IdentityError> {
        Ok(Self::source_for(listing))
    }

    fn execution_identity(
        &self,
        source: &SourceIdentity,
        manifest: &ValidatedManifest,
        _context: &(),
    ) -> Result<ExecutionIdentity, IdentityError> {
        let manifest = manifest.manifest();
        Ok(Self::execution_for(
            source,
            &manifest.execution_abi,
            &manifest.distribution,
        ))
    }

    fn artifact_identity(&self, manifest: &ManifestDigest) -> ArtifactIdentity {
        Self::artifact_for(manifest)
    }
}

/// A temporary area of the fake catalog.
#[derive(Clone, Debug)]
pub struct Staged {
    pub key: ImportKey,
    pub reserved_bytes: u64,
    pub bytes: Vec<u8>,
    pub record: Option<PublishedArtifact>,
    pub committed: bool,
}

/// What the fake catalog saw and holds.
#[derive(Default)]
pub struct CatalogState {
    pub calls: Vec<&'static str>,
    pub next_staging: u64,
    pub staged: BTreeMap<StagingId, Staged>,
    pub published: BTreeMap<ImportKey, PublishedArtifact>,
    pub discarded: Vec<StagingId>,
    pub corrupt_read_back: bool,
    pub refuse_reservation: bool,
    pub fail_discard: bool,
}

/// Lets a test hold an import inside `begin_staging`.
pub struct Gate {
    pub entered: Sender<()>,
    pub release: Receiver<()>,
}

type Hook = Box<dyn FnOnce() + Send>;

/// An in-memory catalog that records every call, with hooks that run when a named call
/// arrives.
#[derive(Default)]
pub struct FakeCatalog {
    state: Mutex<CatalogState>,
    hooks: Mutex<Vec<(&'static str, Hook)>>,
    gate: Mutex<Option<Gate>>,
}

impl FakeCatalog {
    pub fn state(&self) -> MutexGuard<'_, CatalogState> {
        lock(&self.state)
    }

    /// Runs `action` once, when `call` next arrives.
    pub fn on(&self, call: &'static str, action: impl FnOnce() + Send + 'static) {
        lock(&self.hooks).push((call, Box::new(action)));
    }

    /// Cancels `token` when `call` arrives, after the call itself succeeds.
    pub fn cancel_on(&self, call: &'static str, token: &CancellationToken) {
        let token = token.clone();
        self.on(call, move || token.cancel());
    }

    pub fn hold_next_staging(&self, gate: Gate) {
        *lock(&self.gate) = Some(gate);
    }

    fn record(&self, call: &'static str) {
        self.state().calls.push(call);
        let mut due = Vec::new();
        {
            let mut hooks = lock(&self.hooks);
            let mut index = 0;
            while index < hooks.len() {
                if hooks[index].0 == call {
                    due.push(hooks.remove(index).1);
                } else {
                    index += 1;
                }
            }
        }
        for action in due {
            action();
        }
    }
}

impl ArtifactCatalog for FakeCatalog {
    type Context = ();

    fn published(
        &self,
        key: &ImportKey,
        _context: &(),
    ) -> Result<Option<PublishedArtifact>, CatalogError> {
        self.record("published");
        Ok(self.state().published.get(key).copied())
    }

    fn begin_staging(
        &self,
        key: &ImportKey,
        reserved_bytes: u64,
        _context: &(),
    ) -> Result<StagingId, CatalogError> {
        let gate = lock(&self.gate).take();
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.release.recv().unwrap();
        }
        let mut state = self.state();
        if state.refuse_reservation {
            drop(state);
            self.record("begin_staging");
            return Err(CatalogError::ReservationRefused {
                requested_bytes: reserved_bytes,
            });
        }
        state.next_staging += 1;
        let staging = StagingId(state.next_staging);
        state.staged.insert(
            staging,
            Staged {
                key: *key,
                reserved_bytes,
                bytes: Vec::new(),
                record: None,
                committed: false,
            },
        );
        drop(state);
        self.record("begin_staging");
        Ok(staging)
    }

    fn write_staged(
        &self,
        staging: StagingId,
        sidecar: &[u8],
        artifact: &PublishedArtifact,
    ) -> Result<(), CatalogError> {
        {
            let mut state = self.state();
            let staged = state
                .staged
                .get_mut(&staging)
                .ok_or(CatalogError::UnknownStaging)?;
            if sidecar.len() as u64 > staged.reserved_bytes {
                return Err(CatalogError::ReservationExceeded {
                    reserved_bytes: staged.reserved_bytes,
                    requested_bytes: sidecar.len() as u64,
                });
            }
            staged.bytes = sidecar.to_vec();
            staged.record = Some(*artifact);
        }
        self.record("write_staged");
        Ok(())
    }

    fn read_staged(&self, staging: StagingId, max_bytes: u64) -> Result<Vec<u8>, CatalogError> {
        let bytes = {
            let state = self.state();
            let staged = state
                .staged
                .get(&staging)
                .ok_or(CatalogError::UnknownStaging)?;
            let mut bytes = staged.bytes.clone();
            if state.corrupt_read_back {
                if let Some(last) = bytes.last_mut() {
                    *last ^= 1;
                }
            }
            bytes.truncate(max_bytes as usize);
            bytes
        };
        self.record("read_staged");
        Ok(bytes)
    }

    fn commit(&self, staging: StagingId) -> Result<(), CatalogError> {
        {
            let mut state = self.state();
            let staged = state
                .staged
                .get_mut(&staging)
                .ok_or(CatalogError::UnknownStaging)?;
            staged.committed = true;
        }
        self.record("commit");
        Ok(())
    }

    fn publish(&self, staging: StagingId) -> Result<PublishedArtifact, CatalogError> {
        let published = {
            let mut state = self.state();
            let staged = state
                .staged
                .get(&staging)
                .ok_or(CatalogError::UnknownStaging)?;
            let record = match staged.record {
                Some(record) if staged.committed && record.key == staged.key => record,
                _ => return Err(CatalogError::UnknownStaging),
            };
            if state.published.contains_key(&record.key) {
                return Err(CatalogError::Conflict);
            }
            state.published.insert(record.key, record);
            record
        };
        self.record("publish");
        Ok(published)
    }

    fn discard(&self, staging: StagingId) -> Result<(), CatalogError> {
        let result = {
            let mut state = self.state();
            if state.fail_discard {
                Err(CatalogError::Storage {
                    kind: std::io::ErrorKind::Other,
                })
            } else {
                state.staged.remove(&staging);
                state.discarded.push(staging);
                Ok(())
            }
        };
        self.record("discard");
        result
    }
}

/// How a [`CountingSource`] misreports a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Misreport {
    /// Delivers one byte more than the length it reports.
    Longer,
    /// Delivers one byte fewer than the length it reports.
    Shorter,
}

/// Source files in memory that count every open and every byte delivered, per path.
#[derive(Default)]
pub struct CountingSource {
    files: BTreeMap<String, Vec<u8>>,
    misreport: BTreeMap<String, Misreport>,
    opens: Mutex<BTreeMap<String, usize>>,
    bytes_read: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl CountingSource {
    pub fn new(files: &BTreeMap<String, Vec<u8>>) -> Self {
        Self {
            files: files.clone(),
            ..Self::default()
        }
    }

    pub fn misreport(mut self, path: &str, misreport: Misreport) -> Self {
        self.misreport.insert(path.to_owned(), misreport);
        self
    }

    pub fn opens(&self, path: &str) -> usize {
        lock(&self.opens).get(path).copied().unwrap_or(0)
    }

    pub fn bytes_read(&self, path: &str) -> u64 {
        lock(&self.bytes_read).get(path).copied().unwrap_or(0)
    }
}

struct CountingReader {
    path: String,
    bytes: Vec<u8>,
    position: usize,
    counter: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let rest = &self.bytes[self.position..];
        let read = rest.len().min(buffer.len());
        buffer[..read].copy_from_slice(&rest[..read]);
        self.position += read;
        *lock(&self.counter).entry(self.path.clone()).or_default() += read as u64;
        Ok(read)
    }
}

impl SourceFiles for CountingSource {
    fn open(&self, path: &RelativePath) -> Result<(Box<dyn Read + '_>, u64), SourceError> {
        let key = path.as_str().to_owned();
        let bytes = self
            .files
            .get(&key)
            .ok_or_else(|| SourceError::MissingFile { path: path.clone() })?;
        *lock(&self.opens).entry(key.clone()).or_default() += 1;
        let length_bytes = bytes.len() as u64;
        let delivered = match self.misreport.get(&key) {
            None => bytes.clone(),
            Some(Misreport::Longer) => [&bytes[..], b"!"].concat(),
            Some(Misreport::Shorter) => bytes[..bytes.len() - 1].to_vec(),
        };
        Ok((
            Box::new(CountingReader {
                path: key,
                bytes: delivered,
                position: 0,
                counter: Arc::clone(&self.bytes_read),
            }),
            length_bytes,
        ))
    }
}

/// Stands in for a zstd decoder of [`CodecVersion::ZstdRfc8878`]: the encoding is (count,
/// byte) pairs. The manifest code depends only on the decoder trait, the bound and the
/// digests, not on the codec. It records the declared format of every call.
#[derive(Default)]
pub struct RunLengthStandIn {
    pub calls: AtomicUsize,
    pub formats: Mutex<Vec<CodecFormat>>,
}

impl RunLengthStandIn {
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        let mut rest = data;
        while let Some(&byte) = rest.first() {
            let run = rest
                .iter()
                .take(255)
                .take_while(|candidate| **candidate == byte)
                .count();
            encoded.push(run as u8);
            encoded.push(byte);
            rest = &rest[run..];
        }
        encoded
    }
}

impl ExtentDecoder for RunLengthStandIn {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[CodecVersion::ZstdRfc8878]
    }

    fn decode(
        &self,
        format: &CodecFormat,
        encoded: &[u8],
        _dictionary: Option<&[u8]>,
        output: &mut BoundedOutput,
    ) -> Result<(), DecodeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.formats).push(*format);
        if !encoded.len().is_multiple_of(2) {
            return Err(DecodeError::Corrupt);
        }
        for pair in encoded.chunks_exact(2) {
            output.write(&vec![pair[1]; pair[0] as usize])?;
        }
        Ok(())
    }
}

/// Writes without end in 7-byte pieces, as a decompression bomb would; it records the
/// most it managed to write.
#[derive(Default)]
pub struct BombDecoder {
    pub written_bytes: AtomicUsize,
}

impl ExtentDecoder for BombDecoder {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &CodecVersion::ALL
    }

    fn decode(
        &self,
        _format: &CodecFormat,
        _encoded: &[u8],
        _dictionary: Option<&[u8]>,
        output: &mut BoundedOutput,
    ) -> Result<(), DecodeError> {
        loop {
            let result = output.write(&[0u8; 7]);
            self.written_bytes
                .store(output.written_bytes(), Ordering::SeqCst);
            result?;
        }
    }
}

/// Produces fewer bytes than declared.
pub struct ShortDecoder;

impl ExtentDecoder for ShortDecoder {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &CodecVersion::ALL
    }

    fn decode(
        &self,
        _format: &CodecFormat,
        _encoded: &[u8],
        _dictionary: Option<&[u8]>,
        output: &mut BoundedOutput,
    ) -> Result<(), DecodeError> {
        output.write(&[1u8])
    }
}

/// A zstd decoder that declares no version, as one built for another stream format
/// would; it counts the calls that reach it.
#[derive(Default)]
pub struct VersionlessDecoder {
    pub calls: AtomicUsize,
}

impl ExtentDecoder for VersionlessDecoder {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[]
    }

    fn decode(
        &self,
        _format: &CodecFormat,
        _encoded: &[u8],
        _dictionary: Option<&[u8]>,
        _output: &mut BoundedOutput,
    ) -> Result<(), DecodeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(DecodeError::Corrupt)
    }
}
