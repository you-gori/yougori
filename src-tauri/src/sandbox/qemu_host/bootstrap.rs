//! The link bootstrap file, version 1, which QEMU hands the guest through fw_cfg (M02,
//! M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md: §3.2 line 2075: "Bootstrap
//! material is per instance, delivered through a backend-supported channel that does not
//! expose long-lived host secrets in arguments or logs"; VM-W19 row, line 2618; §7.3
//! lines 2378–2386). The QEMU profile names the file `link-secret` in the launch's private
//! directory and passes it as `-fw_cfg name=opt/yougori/link-secret,file=...`.
//!
//! The format, decided by Manager 2, is exactly [`BOOTSTRAP_FILE_BYTES`] (77) bytes:
//!
//! | offset | bytes | content |
//! |---|---|---|
//! | 0 | 4 | ASCII `YGLB` ([`BOOTSTRAP_MAGIC`]) |
//! | 4 | 1 | version `1` ([`BOOTSTRAP_VERSION`]) |
//! | 5 | 32 | the link bootstrap secret, fresh from the OS CSPRNG |
//! | 37 | 32 | the VM handle's digest ([`VmInstanceId::digest`]) |
//! | 69 | 8 | the boot generation, big-endian |
//!
//! [`encode_bootstrap`] takes the VM handle and boot generation from the CORE-04
//! [`ProcessRole::VmHost`] the QEMU process is started for, draws the secret from
//! `ring::rand::SystemRandom` (as `sandbox_contract/relay_process` does) and draws again
//! when the draw is one repeated byte, which [`BootstrapSecret::new`] refuses. It returns
//! the file's bytes and the [`BootstrapSecret`] the host's link binding derives its keys
//! from. [`write_bootstrap_file`] writes the bytes into a directory under the fixed name
//! with create-new semantics (an existing file or link of that name is never replaced) and
//! zeroes them afterwards. [`decode_bootstrap`] reads a file back strictly, for tests and
//! checks.
//!
//! Neither [`BootstrapFile`] nor [`DecodedBootstrap`] has serde or a `Debug` that shows
//! the secret, and both buffers are overwritten when dropped (best effort: copies the
//! allocator or the OS made are out of reach).

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{Digest, SandboxBootGeneration};
use crate::foundation::process::ProcessRole;
use crate::sandbox::link::{BootstrapSecret, SecretRefusal, BOOTSTRAP_SECRET_BYTES};
use crate::sandbox::qemu::LINK_SECRET_NAME;

/// The file's first four bytes.
pub const BOOTSTRAP_MAGIC: [u8; 4] = *b"YGLB";
/// The format version this module writes and reads.
pub const BOOTSTRAP_VERSION: u8 = 1;
/// The exact length of a version 1 file.
pub const BOOTSTRAP_FILE_BYTES: usize = 77;
/// How many times the secret is drawn before a degenerate draw is a failure.
pub const MAX_SECRET_DRAWS: usize = 4;

const SECRET_OFFSET: usize = BOOTSTRAP_MAGIC.len() + 1;
const VM_OFFSET: usize = SECRET_OFFSET + BOOTSTRAP_SECRET_BYTES;
const BOOT_OFFSET: usize = VM_OFFSET + 32;
const _: () = assert!(BOOT_OFFSET + 8 == BOOTSTRAP_FILE_BYTES);

/// The step of writing the file that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStep {
    /// Creating the file; it already exists when the error kind is `already_exists`.
    Create,
    Write,
    Sync,
}

/// Why the bootstrap file was not made, written or read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum BootstrapError {
    /// The process role is not the host process of a VM boot.
    NotVmHost,
    /// The OS CSPRNG failed.
    Random,
    /// Every draw was one repeated byte.
    Degenerate {
        draws: usize,
    },
    WrongLength {
        found_bytes: usize,
    },
    WrongMagic,
    UnsupportedVersion {
        version: u8,
    },
    /// The secret in a file is not usable bootstrap material.
    Secret {
        refusal: SecretRefusal,
    },
    /// Writing the file failed; no partial file is left.
    Write {
        step: WriteStep,
        kind: String,
        detail: String,
    },
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotVmHost => {
                f.write_str("a bootstrap file is made only for the host process of a VM boot")
            }
            Self::Random => f.write_str("the operating system's random generator failed"),
            Self::Degenerate { draws } => {
                write!(f, "{draws} random draws were each one repeated byte")
            }
            Self::WrongLength { found_bytes } => write!(
                f,
                "the bootstrap file is {found_bytes} bytes, not {BOOTSTRAP_FILE_BYTES}"
            ),
            Self::WrongMagic => f.write_str("the bootstrap file does not start with YGLB"),
            Self::UnsupportedVersion { version } => {
                write!(
                    f,
                    "bootstrap file version {version} is not {BOOTSTRAP_VERSION}"
                )
            }
            Self::Secret { refusal } => write!(f, "the bootstrap file's secret: {refusal}"),
            Self::Write { step, kind, detail } => {
                write!(
                    f,
                    "writing the bootstrap file failed at {step:?} ({kind}): {detail}"
                )
            }
        }
    }
}

impl std::error::Error for BootstrapError {}

/// A fixed buffer overwritten with zeros when dropped.
struct Zeroed<const N: usize>([u8; N]);

impl<const N: usize> Drop for Zeroed<N> {
    fn drop(&mut self) {
        self.0 = [0; N];
        std::hint::black_box(&self.0);
    }
}

/// The 77 bytes of one bootstrap file. No serde, no `Clone`, a `Debug` that shows none of
/// the bytes, and zeroed when dropped.
pub struct BootstrapFile {
    bytes: Zeroed<BOOTSTRAP_FILE_BYTES>,
}

impl BootstrapFile {
    /// The bytes to write: the secret is in them, so they go only to the file.
    pub fn as_bytes(&self) -> &[u8; BOOTSTRAP_FILE_BYTES] {
        &self.bytes.0
    }
}

impl fmt::Debug for BootstrapFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapFile(not shown)")
    }
}

/// The VM handle and boot generation of a VM host role.
fn instance_of(
    role: &ProcessRole,
) -> Result<(VmInstanceId, SandboxBootGeneration), BootstrapError> {
    match role {
        ProcessRole::VmHost { vm, boot, .. } => Ok((*vm, *boot)),
        _ => Err(BootstrapError::NotVmHost),
    }
}

/// The bootstrap file for the QEMU process started as `role`, and the secret in it (see
/// the module notes).
pub fn encode_bootstrap(
    role: &ProcessRole,
) -> Result<(BootstrapFile, BootstrapSecret), BootstrapError> {
    let random = SystemRandom::new();
    encode_with(role, |buffer| {
        random.fill(buffer).map_err(|_| BootstrapError::Random)
    })
}

/// [`encode_bootstrap`] over a given random source, so the redraw can be tested.
fn encode_with(
    role: &ProcessRole,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), BootstrapError>,
) -> Result<(BootstrapFile, BootstrapSecret), BootstrapError> {
    let (vm, boot) = instance_of(role)?;
    let mut material = Zeroed([0u8; BOOTSTRAP_SECRET_BYTES]);
    let mut secret = None;
    for _ in 0..MAX_SECRET_DRAWS {
        fill(&mut material.0)?;
        match BootstrapSecret::new(&material.0) {
            Ok(drawn) => {
                secret = Some(drawn);
                break;
            }
            Err(SecretRefusal::Degenerate) => {}
            Err(refusal) => return Err(BootstrapError::Secret { refusal }),
        }
    }
    let secret = secret.ok_or(BootstrapError::Degenerate {
        draws: MAX_SECRET_DRAWS,
    })?;
    let mut bytes = Zeroed([0u8; BOOTSTRAP_FILE_BYTES]);
    bytes.0[..SECRET_OFFSET - 1].copy_from_slice(&BOOTSTRAP_MAGIC);
    bytes.0[SECRET_OFFSET - 1] = BOOTSTRAP_VERSION;
    bytes.0[SECRET_OFFSET..VM_OFFSET].copy_from_slice(&material.0);
    bytes.0[VM_OFFSET..BOOT_OFFSET].copy_from_slice(vm.digest().as_bytes());
    bytes.0[BOOT_OFFSET..].copy_from_slice(&boot.get().to_be_bytes());
    Ok((BootstrapFile { bytes }, secret))
}

/// What a bootstrap file holds, read back. Its `Debug` shows the secret as not shown.
#[derive(Debug)]
pub struct DecodedBootstrap {
    pub vm: VmInstanceId,
    pub boot: SandboxBootGeneration,
    pub secret: BootstrapSecret,
}

/// Reads a version 1 bootstrap file strictly: exactly 77 bytes, the magic, version 1 and
/// a secret [`BootstrapSecret::new`] accepts.
pub fn decode_bootstrap(bytes: &[u8]) -> Result<DecodedBootstrap, BootstrapError> {
    if bytes.len() != BOOTSTRAP_FILE_BYTES {
        return Err(BootstrapError::WrongLength {
            found_bytes: bytes.len(),
        });
    }
    if bytes[..BOOTSTRAP_MAGIC.len()] != BOOTSTRAP_MAGIC {
        return Err(BootstrapError::WrongMagic);
    }
    let version = bytes[SECRET_OFFSET - 1];
    if version != BOOTSTRAP_VERSION {
        return Err(BootstrapError::UnsupportedVersion { version });
    }
    let secret = BootstrapSecret::new(&bytes[SECRET_OFFSET..VM_OFFSET])
        .map_err(|refusal| BootstrapError::Secret { refusal })?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[VM_OFFSET..BOOT_OFFSET]);
    let mut boot = [0u8; 8];
    boot.copy_from_slice(&bytes[BOOT_OFFSET..]);
    Ok(DecodedBootstrap {
        vm: VmInstanceId::new(Digest::from_bytes(digest)),
        boot: SandboxBootGeneration::new(u64::from_be_bytes(boot)),
        secret,
    })
}

fn write_error(step: WriteStep, error: &std::io::Error) -> BootstrapError {
    BootstrapError::Write {
        step,
        kind: format!("{:?}", error.kind()),
        detail: error.to_string(),
    }
}

/// Writes `file` as `directory`'s [`LINK_SECRET_NAME`], creating it new: an existing file
/// or link of that name is never opened or replaced. The bytes are synced to disk, then
/// zeroed with `file`; on a failure after the file was created, it is removed. Returns the
/// file's path.
pub fn write_bootstrap_file(
    directory: &Path,
    file: BootstrapFile,
) -> Result<PathBuf, BootstrapError> {
    let path = directory.join(LINK_SECRET_NAME);
    let mut handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| write_error(WriteStep::Create, &error))?;
    let written = handle
        .write_all(file.as_bytes())
        .map_err(|error| write_error(WriteStep::Write, &error))
        .and_then(|()| {
            handle
                .sync_all()
                .map_err(|error| write_error(WriteStep::Sync, &error))
        });
    drop(file);
    drop(handle);
    if let Err(error) = written {
        // Best effort: the file this call created holds part of a secret.
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ExecutionId};

    fn vm() -> VmInstanceId {
        VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm-a"]))
    }

    fn role(boot: u64) -> ProcessRole {
        ProcessRole::VmHost {
            execution: ExecutionId::new("exe-1").unwrap(),
            vm: vm(),
            boot: SandboxBootGeneration::new(boot),
        }
    }

    fn counting_bytes(buffer: &mut [u8]) -> Result<(), BootstrapError> {
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap() + 1;
        }
        Ok(())
    }

    #[test]
    fn the_file_is_77_bytes_in_the_decided_layout() {
        let (file, _secret) = encode_with(&role(0x0102_0304_0506_0708), counting_bytes).unwrap();
        let bytes = file.as_bytes();
        assert_eq!(bytes.len(), 77);
        assert_eq!(&bytes[..4], b"YGLB");
        assert_eq!(bytes[4], 1);
        let expected_secret: Vec<u8> = (1..=32).collect();
        assert_eq!(&bytes[5..37], expected_secret.as_slice());
        assert_eq!(&bytes[37..69], vm().digest().as_bytes());
        assert_eq!(&bytes[69..77], &[1, 2, 3, 4, 5, 6, 7, 8]);
        let decoded = decode_bootstrap(bytes).unwrap();
        assert_eq!(decoded.vm, vm());
        assert_eq!(
            decoded.boot,
            SandboxBootGeneration::new(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn the_secret_is_fresh_random_and_bound_to_the_file() {
        let (first, first_secret) = encode_bootstrap(&role(3)).unwrap();
        let (second, _) = encode_bootstrap(&role(3)).unwrap();
        assert_ne!(first.as_bytes()[5..37], second.as_bytes()[5..37]);
        assert_eq!(first.as_bytes()[..5], second.as_bytes()[..5]);
        assert_eq!(first.as_bytes()[37..], second.as_bytes()[37..]);
        // The returned secret derives the same link keys as the one in the file.
        let decoded = decode_bootstrap(first.as_bytes()).unwrap();
        let header = b"header";
        let sender = crate::sandbox::link::Sender::Guest;
        let from_file =
            crate::sandbox::link::LinkBinding::new(decoded.vm, decoded.boot, decoded.secret);
        let returned = crate::sandbox::link::LinkBinding::new(
            vm(),
            SandboxBootGeneration::new(3),
            first_secret,
        );
        assert_eq!(
            from_file.tag(sender, header, b"payload"),
            returned.tag(sender, header, b"payload")
        );
    }

    #[test]
    fn a_degenerate_draw_is_drawn_again_and_never_used() {
        let mut draws = 0;
        let (file, _) = encode_with(&role(1), |buffer| {
            draws += 1;
            if draws < 3 {
                buffer.fill(0x5a);
                Ok(())
            } else {
                counting_bytes(buffer)
            }
        })
        .unwrap();
        assert_eq!(draws, 3);
        assert_eq!(file.as_bytes()[5], 1);
        let always = encode_with(&role(1), |buffer| {
            buffer.fill(7);
            Ok(())
        });
        assert_eq!(
            always.err(),
            Some(BootstrapError::Degenerate {
                draws: MAX_SECRET_DRAWS
            })
        );
        let failing = encode_with(&role(1), |_| Err(BootstrapError::Random));
        assert_eq!(failing.err(), Some(BootstrapError::Random));
    }

    #[test]
    fn only_a_vm_host_role_gets_a_file() {
        let relay = ProcessRole::GuestRelay {
            execution: ExecutionId::new("exe-1").unwrap(),
        };
        assert_eq!(
            encode_bootstrap(&relay).err(),
            Some(BootstrapError::NotVmHost)
        );
    }

    #[test]
    fn the_decoder_is_strict() {
        let (file, _) = encode_with(&role(9), counting_bytes).unwrap();
        let good = *file.as_bytes();
        assert!(decode_bootstrap(&good).is_ok());
        assert_eq!(
            decode_bootstrap(&good[..76]).err(),
            Some(BootstrapError::WrongLength { found_bytes: 76 })
        );
        let mut longer = good.to_vec();
        longer.push(0);
        assert_eq!(
            decode_bootstrap(&longer).err(),
            Some(BootstrapError::WrongLength { found_bytes: 78 })
        );
        let mut magic = good;
        magic[0] = b'X';
        assert_eq!(
            decode_bootstrap(&magic).err(),
            Some(BootstrapError::WrongMagic)
        );
        let mut version = good;
        version[4] = 2;
        assert_eq!(
            decode_bootstrap(&version).err(),
            Some(BootstrapError::UnsupportedVersion { version: 2 })
        );
        let mut degenerate = good;
        degenerate[5..37].fill(0);
        assert_eq!(
            decode_bootstrap(&degenerate).err(),
            Some(BootstrapError::Secret {
                refusal: SecretRefusal::Degenerate
            })
        );
    }

    #[test]
    fn nothing_prints_the_secret() {
        let (file, secret) = encode_with(&role(2), counting_bytes).unwrap();
        let secret_hex = hex::encode(&file.as_bytes()[5..37]);
        let decoded = decode_bootstrap(file.as_bytes()).unwrap();
        for text in [
            format!("{file:?}"),
            format!("{secret:?}"),
            format!("{decoded:?}"),
            format!("{decoded:#?}"),
        ] {
            assert!(!text.contains(&secret_hex), "{text}");
            assert!(!text.contains(&secret_hex[..8]), "{text}");
        }
        assert_eq!(format!("{file:?}"), "BootstrapFile(not shown)");
    }

    #[test]
    fn the_file_is_written_new_and_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let (file, _) = encode_with(&role(4), counting_bytes).unwrap();
        let expected = *file.as_bytes();
        let path = write_bootstrap_file(directory.path(), file).unwrap();
        assert_eq!(path, directory.path().join("link-secret"));
        assert_eq!(std::fs::read(&path).unwrap(), expected.to_vec());
        let (again, _) = encode_with(&role(4), counting_bytes).unwrap();
        match write_bootstrap_file(directory.path(), again) {
            Err(BootstrapError::Write {
                step: WriteStep::Create,
                kind,
                ..
            }) => assert_eq!(kind, "AlreadyExists"),
            other => panic!("expected a create failure, got {other:?}"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), expected.to_vec());
        let missing = directory.path().join("absent");
        let (third, _) = encode_with(&role(4), counting_bytes).unwrap();
        assert!(matches!(
            write_bootstrap_file(&missing, third),
            Err(BootstrapError::Write {
                step: WriteStep::Create,
                ..
            })
        ));
        assert!(!missing.exists());
    }
}
