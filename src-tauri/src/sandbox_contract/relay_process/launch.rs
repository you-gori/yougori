//! The confined launch of a relay on Windows (M09E; VM part §3.1: the relay is its own
//! confined process with no provider secret, no host path and no lifecycle privilege;
//! VM-W11; VM part §6.4: stable process handles; VM-R17).
//!
//! [`launch_relay`], in order:
//!
//! 1. creates the sandbox's AppContainer profile, with no capabilities (no
//!    `internetClient`, `privateNetworkClient` or any other), so its processes have no
//!    network, no access to the user's files and low integrity. Its name is derived from
//!    the sandbox; one left by a relay that did not end cleanly is deleted and made again;
//! 2. grants the AppContainer read and execute on the relay executable, and nothing else;
//! 3. starts the relay through PX1 ([`HostProcess::spawn_confined`]): suspended, in a
//!    kill-on-close job with no breakaway, in the AppContainer, bound to
//!    [`ProcessRole::GuestRelay`]. It inherits no handle and its standard handles are null,
//!    so no handle of this process is made inheritable for it, and no other start in this
//!    process (`std::process::Command::spawn` on another thread included) can catch one.
//!    Its environment is `SystemRoot` and [`LOCALAPPDATA_PLACEHOLDER`], plus the `TEMP` and
//!    `TMP` Windows derives from the placeholder for an AppContainer start: no `PATH`,
//!    user path or anything else of this process's, so the relay must need none of them
//!    (it reads no file and runs no program). Its working directory is the system
//!    directory;
//! 4. creates the relay's link pipe for that AppContainer
//!    ([`RelayPipeListener::create_for_container`]), named after the relay's PX1 identity
//!    ([`RelayPipeName::for_relay`]), which the relay derives itself and waits for;
//! 5. makes the handoff: a fresh 32-byte link key, the binding with the relay's own PX1
//!    identity and a fresh link session, this process's identity as the broker, the route
//!    table and the reader limits.
//!
//! The [`LaunchedRelay`] admits the relay on the pipe by PX1 identity and only then
//! writes the handoff to it, ahead of the link ([`LaunchedRelay::accept`]). Nothing secret
//! goes through argv, the environment or an inherited handle. When it ends
//! ([`LaunchedRelay::end`], or on drop) the job is killed and its end observed, then the
//! executable's grant is revoked and the profile deleted. The key is overwritten after
//! use, best effort.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    FreeSid, GetLengthSid, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

use super::handoff::{encode_handoff, GuestPipeHandoff, HandoffError, HandoffParts, Secret};
use super::relay_core::RouteTable;
use crate::foundation::ids::{digest, ExecutionId};
use crate::foundation::process::{
    Confinement, Escalation, HostProcess, NoProof, ProcessError, ProcessIdentity, ProcessRole,
    TerminationProof,
};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_link::guest_pipe::guest_pipe_name;
use crate::sandbox_contract::relay_link::{
    BrokerSide, LinkBinding, LinkKey, LinkPipe, LinkSessionId, PipeError, RelayPipeListener,
    RelayPipeName,
};

/// The length of a relay's link key: twice the shortest key the link accepts.
pub const RELAY_KEY_BYTES: usize = 32;

/// Domain of the digest a relay's AppContainer profile name is made from.
pub const PROFILE_NAME_DOMAIN: &str = "yougori/sandbox/relay-process/profile/v1";

/// The prefix of every relay AppContainer profile name.
pub const PROFILE_NAME_PREFIX: &str = "yougori.relay.";

/// The access the AppContainer gets on the relay executable: read and execute.
pub const EXECUTABLE_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

/// How the relay is ended when its launch is dropped or ended: killed at once, each kill
/// round waiting this long for the end to be observed.
pub const END_ESCALATION: Escalation = Escalation {
    grace: Duration::ZERO,
    kill_wait: Duration::from_secs(10),
};

/// The relay's `LOCALAPPDATA`. Windows refuses to start an AppContainer process without
/// the variable (`ERROR_ENVVAR_NOT_FOUND`) and derives the container's own folders from
/// it; the relay writes no file, so it gets a placeholder rather than a host path.
pub const LOCALAPPDATA_PLACEHOLDER: &str = "none";

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const HRESULT_ALREADY_EXISTS: u32 = 0x8007_00B7;

/// `ERROR_ALREADY_EXISTS`, which some versions return as is.
const ERROR_ALREADY_EXISTS: u32 = 183;

/// Grants on one executable are read, changed and written back; launches in this process
/// take turns so none loses another's grant.
static GRANTS: Mutex<()> = Mutex::new(());

/// What a relay is launched with.
#[derive(Clone, Debug)]
pub struct RelayLaunch {
    /// The sandbox the relay serves.
    pub sandbox: ExecutionId,
    /// The relay executable, an absolute path.
    pub executable: PathBuf,
    /// Its arguments, such as the mode that runs [`relay_main`](super::relay_main). They
    /// carry no secret: the key goes only through the handoff, on the admitted pipe.
    pub arguments: Vec<OsString>,
    pub routes: RouteTable,
    pub limits: ReaderLimits,
    /// The PID of the engine that serves the relay's guest pipe, when one does: the handoff
    /// then names the pipe (derived from the relay's identity) and that PID, and the relay
    /// opens it after the link. `None` for a relay whose guest port comes from elsewhere.
    pub guest_engine_pid: Option<u32>,
}

/// A step of the launch, for errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchStep {
    Executable,
    Key,
    CreateProfile,
    DeleteProfile,
    ReadGrant,
    WriteGrant,
    Identity,
}

impl fmt::Display for LaunchStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Executable => "check the relay executable",
            Self::Key => "make the link key",
            Self::CreateProfile => "create the AppContainer profile",
            Self::DeleteProfile => "delete the AppContainer profile",
            Self::ReadGrant => "read the executable's DACL",
            Self::WriteGrant => "change the executable's DACL",
            Self::Identity => "read this process's identity",
        })
    }
}

/// Why a relay could not be launched or cleaned up. No variant carries the key.
#[derive(Debug)]
pub enum LaunchError {
    /// A host call failed (an OS error or an HRESULT, as the call reports).
    Host {
        step: LaunchStep,
        code: u32,
    },
    Pipe(PipeError),
    Spawn(ProcessError),
    Handoff(HandoffError),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host { step, code } => write!(f, "could not {step} (code {code:#x})"),
            Self::Pipe(error) => write!(f, "the link pipe failed: {error}"),
            Self::Spawn(error) => write!(f, "the relay could not start: {error}"),
            Self::Handoff(error) => write!(f, "the handoff could not be written: {error}"),
        }
    }
}

impl std::error::Error for LaunchError {}

fn hresult(step: LaunchStep, result: i32) -> LaunchError {
    LaunchError::Host {
        step,
        code: u32::from_ne_bytes(result.to_ne_bytes()),
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// The AppContainer profile name of `sandbox`'s relay.
pub fn profile_name(sandbox: &ExecutionId) -> String {
    let hex = digest(PROFILE_NAME_DOMAIN, &[sandbox.as_str().as_bytes()]).to_hex();
    format!("{PROFILE_NAME_PREFIX}{}", &hex[..32.min(hex.len())])
}

/// One AppContainer profile with no capabilities, deleted when dropped.
struct AppContainerProfile {
    name: String,
    sid: Vec<u8>,
    deleted: bool,
}

impl AppContainerProfile {
    fn create(name: String) -> Result<Self, LaunchError> {
        let wide_name = wide(OsStr::new(&name));
        let display = wide(OsStr::new("Yougori guest relay"));
        let description = wide(OsStr::new(
            "The confined guest relay of one Yougori sandbox; no capabilities",
        ));
        let create = |sid: &mut PSID| {
            // SAFETY: every string is NUL-terminated and live; no capabilities are given;
            // `sid` is live.
            unsafe {
                CreateAppContainerProfile(
                    wide_name.as_ptr(),
                    display.as_ptr(),
                    description.as_ptr(),
                    null(),
                    0,
                    sid,
                )
            }
        };
        let mut sid: PSID = null_mut();
        let mut result = create(&mut sid);
        let code = u32::from_ne_bytes(result.to_ne_bytes());
        if code == HRESULT_ALREADY_EXISTS || code == ERROR_ALREADY_EXISTS {
            // Left by a relay of this sandbox that did not end cleanly: made again, so
            // nothing of it carries over.
            // SAFETY: the name is NUL-terminated and live.
            let deleted = unsafe { DeleteAppContainerProfile(wide_name.as_ptr()) };
            if deleted < 0 {
                return Err(hresult(LaunchStep::DeleteProfile, deleted));
            }
            result = create(&mut sid);
        }
        if result < 0 || sid.is_null() {
            return Err(hresult(LaunchStep::CreateProfile, result));
        }
        // SAFETY: `sid` is the valid SID the call returned, of the length it reports; it
        // is freed once, with FreeSid as the call requires.
        let bytes = unsafe {
            let length = usize::try_from(GetLengthSid(sid)).unwrap_or(0);
            let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec();
            FreeSid(sid);
            bytes
        };
        Ok(Self {
            name,
            sid: bytes,
            deleted: false,
        })
    }

    fn delete(&mut self) -> Result<(), LaunchError> {
        if self.deleted {
            return Ok(());
        }
        let name = wide(OsStr::new(&self.name));
        // SAFETY: the name is NUL-terminated and live.
        let result = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        if result < 0 {
            return Err(hresult(LaunchStep::DeleteProfile, result));
        }
        self.deleted = true;
        Ok(())
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        // Best effort on a path that did not end the launch explicitly.
        let _ = self.delete();
    }
}

/// The AppContainer's read and execute grant on the relay executable, revoked when
/// dropped.
struct ExecutableGrant {
    path: Vec<u16>,
    /// The AppContainer SID, aligned for a SID.
    sid: Vec<u32>,
    revoked: bool,
}

impl ExecutableGrant {
    fn grant(path: &Path, sid: &[u8]) -> Result<Self, LaunchError> {
        let mut aligned = vec![0_u32; sid.len().div_ceil(4)];
        // SAFETY: `aligned` holds at least `sid.len()` writable bytes and does not overlap
        // `sid`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.as_ptr(),
                aligned.as_mut_ptr().cast::<u8>(),
                sid.len(),
            );
        }
        let mut grant = Self {
            path: wide(path.as_os_str()),
            sid: aligned,
            revoked: true,
        };
        grant.apply(GRANT_ACCESS, EXECUTABLE_ACCESS)?;
        grant.revoked = false;
        Ok(grant)
    }

    fn revoke(&mut self) -> Result<(), LaunchError> {
        if self.revoked {
            return Ok(());
        }
        self.apply(REVOKE_ACCESS, 0)?;
        self.revoked = true;
        Ok(())
    }

    /// Merges one entry for the SID into the executable's DACL.
    fn apply(&mut self, mode: i32, access: u32) -> Result<(), LaunchError> {
        let _turn = GRANTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: the path is NUL-terminated and live; only the DACL is asked for, and
        // both out-pointers are live. The descriptor is freed below with LocalFree.
        let read = unsafe {
            GetNamedSecurityInfoW(
                self.path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if read != ERROR_SUCCESS {
            return Err(LaunchError::Host {
                step: LaunchStep::ReadGrant,
                code: read,
            });
        }
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: mode,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: self.sid.as_mut_ptr().cast(),
            },
        };
        let mut merged: *mut ACL = null_mut();
        // SAFETY: `entry` names a valid SID that outlives the call; `dacl` points into
        // `descriptor`, live until it is freed below; `merged` is freed with LocalFree.
        let result = unsafe {
            let merged_result = SetEntriesInAclW(1, &entry, dacl, &mut merged);
            let written = if merged_result == ERROR_SUCCESS {
                SetNamedSecurityInfoW(
                    self.path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    merged,
                    null(),
                )
            } else {
                merged_result
            };
            if !merged.is_null() {
                LocalFree(merged.cast());
            }
            LocalFree(descriptor);
            written
        };
        if result != ERROR_SUCCESS {
            return Err(LaunchError::Host {
                step: LaunchStep::WriteGrant,
                code: result,
            });
        }
        Ok(())
    }
}

impl Drop for ExecutableGrant {
    fn drop(&mut self) {
        // Best effort on a path that did not end the launch explicitly.
        let _ = self.revoke();
    }
}

/// The relay's command: the executable and its arguments; an environment of `SystemRoot`
/// and [`LOCALAPPDATA_PLACEHOLDER`], nothing of this process's; and the system directory as
/// its working directory.
fn relay_command(launch: &RelayLaunch) -> Command {
    let mut command = Command::new(&launch.executable);
    command.args(&launch.arguments);
    command.env_clear();
    command.env("LOCALAPPDATA", LOCALAPPDATA_PLACEHOLDER);
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.current_dir(Path::new(&root).join("System32"));
        command.env("SystemRoot", root);
    }
    command
}

/// Launches `launch`'s relay confined (see the module notes).
pub fn launch_relay(launch: RelayLaunch) -> Result<LaunchedRelay, LaunchError> {
    let executable_ok = launch.executable.is_absolute()
        && std::fs::metadata(&launch.executable).is_ok_and(|metadata| metadata.is_file());
    if !executable_ok {
        return Err(LaunchError::Host {
            step: LaunchStep::Executable,
            code: 2,
        });
    }
    let key_error = || LaunchError::Host {
        step: LaunchStep::Key,
        code: 0,
    };
    let mut key = Secret::new(vec![0_u8; RELAY_KEY_BYTES]);
    SystemRandom::new()
        .fill(key.as_mut())
        .map_err(|_| key_error())?;
    let broker_key = LinkKey::new(key.as_slice().to_vec()).map_err(|_| key_error())?;
    let broker = ProcessIdentity::holder_of(std::process::id())
        .ok()
        .flatten()
        .ok_or(LaunchError::Host {
            step: LaunchStep::Identity,
            code: 0,
        })?;
    let profile = AppContainerProfile::create(profile_name(&launch.sandbox))?;
    let grant = ExecutableGrant::grant(&launch.executable, &profile.sid)?;
    let confinement = Confinement::app_container(&profile.sid).map_err(LaunchError::Spawn)?;
    let process = HostProcess::spawn_confined(
        &relay_command(&launch),
        ProcessRole::GuestRelay {
            execution: launch.sandbox.clone(),
        },
        confinement,
    )
    .map_err(LaunchError::Spawn)?;
    let binding = LinkBinding {
        sandbox: launch.sandbox.clone(),
        relay: process.identity(),
        session: LinkSessionId::generate(),
    };
    let guest_pipe = match launch.guest_engine_pid {
        Some(_) => match guest_pipe_name(&binding.relay) {
            Ok(name) => Some(name),
            Err(error) => {
                let _ = process.terminate(END_ESCALATION);
                return Err(LaunchError::Pipe(error));
            }
        },
        None => None,
    };
    let guest = match (&guest_pipe, launch.guest_engine_pid) {
        (Some(name), Some(engine_pid)) => Some(GuestPipeHandoff {
            name: name.as_str().to_owned(),
            engine_pid,
        }),
        _ => None,
    };
    let prepared = RelayPipeListener::create_for_container(
        RelayPipeName::for_relay(&binding.relay),
        &profile.sid,
    )
    .map_err(LaunchError::Pipe)
    .and_then(|listener| {
        let handoff = encode_handoff(&HandoffParts {
            key: key.as_slice(),
            binding: &binding,
            broker: &broker,
            routes: &launch.routes,
            limits: launch.limits,
            guest: guest.as_ref(),
        })
        .map_err(LaunchError::Handoff)?;
        Ok((listener, handoff))
    });
    drop(key);
    let (listener, handoff) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            // The relay never gets its handoff; it is ended before its grant and profile
            // go.
            let _ = process.terminate(END_ESCALATION);
            return Err(error);
        }
    };
    Ok(LaunchedRelay {
        process,
        listener,
        binding,
        key: broker_key,
        handoff: Some(handoff),
        grant,
        profile_sid: profile.sid.clone(),
        profile_name: profile.name.clone(),
        profile: Some(profile),
        guest_pipe,
        ended: false,
    })
}

/// What ending a relay found: the host's proof that it ended, and whether its grant and
/// profile were removed.
#[derive(Debug)]
pub struct RelayEnd {
    pub proof: Result<TerminationProof, NoProof>,
    pub cleanup: Result<(), LaunchError>,
}

/// A relay launched confined, held until it ends (see the module notes).
pub struct LaunchedRelay {
    process: HostProcess,
    listener: RelayPipeListener,
    binding: LinkBinding,
    key: LinkKey,
    /// The handoff body, until the relay is admitted.
    handoff: Option<Secret>,
    grant: ExecutableGrant,
    profile_sid: Vec<u8>,
    profile_name: String,
    profile: Option<AppContainerProfile>,
    /// The guest pipe the relay opens after the link, when the launch asked for one.
    guest_pipe: Option<RelayPipeName>,
    ended: bool,
}

impl fmt::Debug for LaunchedRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchedRelay")
            .field("process", &self.process)
            .field("binding", &self.binding)
            .field("pipe", self.listener.name())
            .field("profile", &self.profile_name)
            .finish_non_exhaustive()
    }
}

impl LaunchedRelay {
    /// The relay's PX1 identity.
    pub fn identity(&self) -> ProcessIdentity {
        self.process.identity()
    }

    /// The relay's process, held through its handle and job.
    pub fn process(&self) -> &HostProcess {
        &self.process
    }

    /// What every frame of the link is bound to.
    pub fn binding(&self) -> &LinkBinding {
        &self.binding
    }

    pub fn pipe_name(&self) -> &RelayPipeName {
        self.listener.name()
    }

    /// The relay's AppContainer SID, binary.
    pub fn container_sid(&self) -> &[u8] {
        &self.profile_sid
    }

    /// The relay's AppContainer profile name.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// The guest pipe the relay opens after the link, named in its handoff, when the launch
    /// asked for one.
    pub fn guest_pipe(&self) -> Option<&RelayPipeName> {
        self.guest_pipe.as_ref()
    }

    /// Waits at most `within` for the relay on the pipe and admits it only if it is
    /// exactly the launched process (PX1 identity); another client is disconnected and
    /// the call may be made again. The admitted relay is then sent its handoff, ahead of
    /// the link, and the handoff is overwritten here.
    pub fn accept(&mut self, within: Duration) -> Result<LinkPipe<BrokerSide>, PipeError> {
        let handoff = self.handoff.as_ref().ok_or(PipeError::Spent)?;
        let link = self.listener.accept_with_handoff(
            self.binding.clone(),
            self.key.clone(),
            handoff.as_slice(),
            within,
        )?;
        self.handoff = None;
        Ok(link)
    }

    /// Ends the relay as `escalation` says, observes the end, then revokes the
    /// executable's grant and deletes the profile.
    pub fn end(mut self, escalation: Escalation) -> RelayEnd {
        self.finish(escalation)
    }

    fn finish(&mut self, escalation: Escalation) -> RelayEnd {
        self.ended = true;
        let proof = self.process.terminate(escalation);
        let revoked = self.grant.revoke();
        let deleted = self
            .profile
            .as_mut()
            .map_or(Ok(()), AppContainerProfile::delete);
        RelayEnd {
            proof,
            cleanup: revoked.and(deleted),
        }
    }
}

impl Drop for LaunchedRelay {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.finish(END_ESCALATION);
        }
    }
}
