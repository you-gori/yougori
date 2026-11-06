//! Test fixtures: one launch's named locations written into a temporary directory, the
//! fixture credentials, runner settings and a reader that injects faults into
//! [`HostFiles`]. Nothing here reads outside its temporary directory.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::fixture::FixtureCredential;
use super::plan::{LocationRole, NamedLocation, ScanPlan};
use super::port::{EntryKind, HostFiles, ScanReader};
use super::runner::{CredentialScanRunner, ScanSettings};
use super::scan::ScanLimits;
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind, SandboxBootSubject, Subject};
use crate::foundation::ids::{digest, SandboxBootGeneration};
use crate::sandbox::host_checks::fixtures::FRESH;
use crate::sandbox::host_checks::reader::ReadError;

/// The fixture credential of the tests: unreserved characters only, so its
/// percent-encoding is its exact bytes.
pub const FIXTURE: &str = "yg-fixture-7Q2xN9pLm4Rv8KtZ";

/// A fixture with reserved characters, whose percent-encodings differ from it, and with
/// `?~?`, whose base64 differs between the two alphabets at every alignment.
pub const RESERVED_FIXTURE: &str = "fx+Q2/xN9?~?=pLm4:Rv8@KtZ!w";

pub fn fixture() -> FixtureCredential {
    FixtureCredential::new(FIXTURE).unwrap()
}

pub fn reserved_fixture() -> FixtureCredential {
    FixtureCredential::new(RESERVED_FIXTURE).unwrap()
}

pub fn launch_subject() -> SandboxBootSubject {
    launch_of(b"vm-a", 1)
}

pub fn launch_of(vm: &[u8], boot: u64) -> SandboxBootSubject {
    SandboxBootSubject {
        machine: digest("yougori/test/host-checks/machine/v1", &[b"machine"]),
        vm: digest("yougori/test/host-checks/vm/v1", &[vm]),
        boot: SandboxBootGeneration::new(boot),
    }
}

pub fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("profile", "strict"), ("relay", "test")]).unwrap()
}

pub fn settings(limits: ScanLimits) -> ScanSettings {
    ScanSettings {
        os: OsKind::Linux,
        configuration: configuration(),
        fresh_for: FRESH,
        limits,
    }
}

/// The request the executor sent, with the fixture in its `Authorization` header at
/// [`REQUEST_OFFSET`].
pub fn executor_request() -> String {
    format!("POST /v1/messages HTTP/1.1\nhost: provider.test\nauthorization: Bearer {FIXTURE}\n\n{{}}\n")
}

pub const REQUEST_OFFSET: u64 = 69;

/// One launch's named locations in a temporary directory:
///
/// - `launch/specification.json`: the launch specification (a file);
/// - `relay/inputs/` and `relay/logs/`: the relay's inputs and logs (two directories);
/// - `audit/`: the audit (a directory, with a nested day directory);
/// - `provider/echo.json`: the fake provider's echoed response (a file);
/// - `executor/request.http`: the executor's outbound request (a file).
pub struct Launch {
    dir: tempfile::TempDir,
}

impl Launch {
    /// The passing case: the fixture only in the executor's request.
    pub fn clean() -> Self {
        let launch = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        launch.write(
            "launch/specification.json",
            b"{\"image\":\"guest-1\",\"env\":{\"PROVIDER_KEY\":\"placeholder-1\"}}\n",
        );
        launch.write(
            "relay/inputs/0001.http",
            b"POST /v1/messages HTTP/1.1\nauthorization: Bearer placeholder-1\n\n{}\n",
        );
        launch.write("relay/logs/relay.log", b"accepted 0001 route=provider\n");
        launch.write(
            "audit/2026-10-29/events.jsonl",
            b"{\"event\":\"launch\"}\n{\"event\":\"executor_call\",\"route\":\"provider\"}\n",
        );
        launch.write("audit/index.json", b"{\"days\":[\"2026-10-29\"]}\n");
        launch.write(
            "provider/echo.json",
            b"{\"echo\":{\"authorization\":\"[stripped]\"}}\n",
        );
        launch.write("executor/request.http", executor_request().as_bytes());
        launch
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.root().to_path_buf(), |path, name| path.join(name))
    }

    pub fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    pub fn remove(&self, relative: &str) {
        let path = self.path(relative);
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }

    pub fn locations(&self) -> Vec<NamedLocation> {
        vec![
            NamedLocation::new(
                LocationRole::LaunchSpecification,
                self.path("launch/specification.json"),
            ),
            NamedLocation::new(LocationRole::RelayInputsAndLogs, self.path("relay/inputs")),
            NamedLocation::new(LocationRole::RelayInputsAndLogs, self.path("relay/logs")),
            NamedLocation::new(LocationRole::Audit, self.path("audit")),
            NamedLocation::new(
                LocationRole::EchoedResponse,
                self.path("provider/echo.json"),
            ),
            NamedLocation::new(
                LocationRole::ExecutorRequest,
                self.path("executor/request.http"),
            ),
        ]
    }

    pub fn plan(&self) -> ScanPlan {
        ScanPlan::new(launch_subject(), fixture(), self.locations()).unwrap()
    }

    pub fn subject(&self) -> Subject {
        Subject::CredentialScan(self.plan().subject())
    }

    pub fn runner(&self) -> CredentialScanRunner<HostFiles> {
        CredentialScanRunner::new(
            HostFiles,
            settings(ScanLimits::default()),
            vec![self.plan()],
        )
        .unwrap()
    }

    pub fn runner_with<R: ScanReader>(&self, reader: R) -> CredentialScanRunner<R> {
        CredentialScanRunner::new(reader, settings(ScanLimits::default()), vec![self.plan()])
            .unwrap()
    }
}

/// The relative file of each place that must not hold the fixture.
pub fn place_files() -> [(LocationRole, &'static str); 4] {
    [
        (
            LocationRole::LaunchSpecification,
            "launch/specification.json",
        ),
        (LocationRole::RelayInputsAndLogs, "relay/logs/relay.log"),
        (LocationRole::Audit, "audit/2026-10-29/events.jsonl"),
        (LocationRole::EchoedResponse, "provider/echo.json"),
    ]
}

/// Faults a [`FaultyFiles`] injects, by path.
#[derive(Clone, Debug, Default)]
pub struct Faults {
    /// What `entry` reports instead of the host's answer.
    pub entry: BTreeMap<PathBuf, Result<EntryKind, ReadError>>,
    /// Directories whose listing fails.
    pub list: BTreeMap<PathBuf, ReadError>,
    /// Names added to a directory's listing.
    pub names: BTreeMap<PathBuf, Vec<String>>,
    /// Files whose open fails.
    pub open: BTreeMap<PathBuf, ReadError>,
    /// Files whose read fails after this many bytes.
    pub fail_after: BTreeMap<PathBuf, u64>,
    /// The most bytes one read returns, to split forms across reads.
    pub chunk: Option<usize>,
}

/// [`HostFiles`] with injected faults, counting every call of the port.
pub struct FaultyFiles {
    pub faults: Faults,
    pub calls: Arc<AtomicUsize>,
}

impl FaultyFiles {
    pub fn new(faults: Faults) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                faults,
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    fn count(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

pub struct FaultyFile {
    inner: File,
    chunk: Option<usize>,
    fail_after: Option<u64>,
    read: u64,
}

impl Read for FaultyFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.fail_after.is_some_and(|after| self.read >= after) {
            return Err(io::Error::other("injected read fault"));
        }
        let mut room = buffer.len();
        if let Some(chunk) = self.chunk {
            room = room.min(chunk);
        }
        if let Some(after) = self.fail_after {
            room = room.min(usize::try_from(after - self.read).unwrap());
        }
        let read = self.inner.read(&mut buffer[..room])?;
        self.read += read as u64;
        Ok(read)
    }
}

impl ScanReader for FaultyFiles {
    type File = FaultyFile;

    fn entry(&self, path: &Path) -> Result<EntryKind, ReadError> {
        self.count();
        match self.faults.entry.get(path) {
            Some(answer) => *answer,
            None => HostFiles.entry(path),
        }
    }

    fn list(&self, path: &Path, limit: usize) -> Result<Vec<String>, ReadError> {
        self.count();
        if let Some(error) = self.faults.list.get(path) {
            return Err(*error);
        }
        let mut names = HostFiles.list(path, limit)?;
        if let Some(extra) = self.faults.names.get(path) {
            names.extend(extra.iter().cloned());
            names.sort();
        }
        Ok(names)
    }

    fn open(&self, path: &Path) -> Result<FaultyFile, ReadError> {
        self.count();
        if let Some(error) = self.faults.open.get(path) {
            return Err(*error);
        }
        Ok(FaultyFile {
            inner: HostFiles.open(path)?,
            chunk: self.faults.chunk,
            fail_after: self.faults.fail_after.get(path).copied(),
            read: 0,
        })
    }
}
