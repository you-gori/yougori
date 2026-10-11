//! Names from before the product was renamed to Yougori.
//!
//! Existing installs created data, credentials, VMs and runtimes under these names.
//! Most are kept only so that data can be found and moved to the Yougori names; no new
//! data is written under them. Delete those, and their call sites' legacy branches, once
//! supported upgrades no longer start from releases that used them.
//!
//! A few are storage keys that stay fixed because existing data is stored under them
//! and cannot be renamed in place: [`SNAPSHOT_DISK_HASH_DOMAIN`], [`IMAGE_NAME_PREFIX`]
//! and [`SNAPSHOT_TAG_PREFIX`]. Users never see them.

/// Product word in VM names created by earlier releases, such as "OpenDock microVM {id}".
pub const PRODUCT: &str = "OpenDock";

/// App data folder used by earlier releases, next to `com.yougori.desktop`.
pub const APP_DATA_FOLDER: &str = "com.opendock.desktop";

/// OS credential-store service for backup destination credentials.
pub const BACKUP_CREDENTIAL_SERVICE: &str = "com.opendock.desktop.backup";

/// OS credential-store service for Cloudflare tunnel credentials.
pub const CLOUDFLARE_CREDENTIAL_SERVICE: &str = "OpenDock.CloudflareTunnel.v1";

/// Hash input that identifies snapshot disks. It is part of the stored disk identity, so
/// it must not change: a different value would stop existing snapshots from matching.
pub const SNAPSHOT_DISK_HASH_DOMAIN: &[u8] = b"OpenDock snapshot disk\0";

/// Windows single-instance mutex held by earlier engines. New engines hold it too, so an
/// older engine that is still running can never own the same disks.
pub const WINDOWS_SINGLETON_MUTEX: &str = "Local\\OpenDock.Runtime.Singleton.v1";

/// Prefix of the per-user socket directory used by earlier engines on Unix.
pub const UNIX_SOCKET_DIRECTORY_PREFIX: &str = "/tmp/opendock-";

/// File extension of local backups made by earlier releases.
pub const BACKUP_FILE_EXTENSION: &str = "opendock";

/// Image name prefix the VM agent gives product images in containerd. containerd and
/// saved snapshot records store these names and cannot rename them, so the prefix stays
/// fixed. Must match `imageNamePrefix` in appliance/agent/legacy_names.go.
pub const IMAGE_NAME_PREFIX: &str = "opendock.local/";

/// Tag prefix of snapshot images, under [`IMAGE_NAME_PREFIX`].
pub const SNAPSHOT_TAG_PREFIX: &str = "opendock.local/snapshots:";

/// HTTP header names that apps built for earlier releases may still send.
pub const PORT_HEADER: &str = "opendock-port";
pub const FILES_HEADER: &str = "x-opendock-files";

/// Directory where earlier releases mounted shared folders, secrets and tools inside
/// containers. Containers they created still use it, so it stays reserved.
pub const CONTAINER_MOUNT_ROOT: &str = "/opendock";

/// Prefix of the WSL distribution that earlier releases registered for the CUDA runtime.
pub const CUDA_DISTRIBUTION_PREFIX: &str = "OpenDock-CUDA-";

/// Install marker that earlier releases wrote next to installed AI-tool skills.
pub const SKILL_INSTALL_MARKER: &str = ".opendock-install.json";

/// Exact closing text of the CLI-location line in skills written by earlier releases.
/// Used only to recognize those managed skills so they can be updated.
pub const SKILL_LOCATION_END: &str =
    "`. Invoke this absolute path if `opendock-cli` is not on PATH.\n";

/// Saved runtime-provider names from earlier releases, with their current names.
pub const RUNTIME_PROVIDER_NAMES: [(&str, &str); 2] =
    [("openDockOci", "yougoriOci"), ("openDockCuda", "yougoriCuda")];

/// Current name for a saved runtime-provider name, mapping earlier names forward.
pub fn runtime_provider_name(name: &str) -> &str {
    RUNTIME_PROVIDER_NAMES
        .iter()
        .find(|(legacy, _)| *legacy == name)
        .map_or(name, |(_, current)| current)
}

/// The earlier VM name for a current "Yougori ..." VM name.
pub fn vm_name(current: &str) -> Option<String> {
    current.strip_prefix("Yougori ").map(|suffix| format!("{PRODUCT} {suffix}"))
}

/// The earlier CUDA distribution name for a current one, keeping its digest suffix.
pub fn cuda_distribution(current: &str) -> Option<String> {
    current
        .strip_prefix("Yougori-CUDA-")
        .map(|digest| format!("{CUDA_DISTRIBUTION_PREFIX}{digest}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_saved_runtime_provider_names_forward_and_keeps_others() {
        assert_eq!(runtime_provider_name("openDockOci"), "yougoriOci");
        assert_eq!(runtime_provider_name("openDockCuda"), "yougoriCuda");
        assert_eq!(runtime_provider_name("qemu"), "qemu");
    }

    #[test]
    fn derives_earlier_vm_and_cuda_distribution_names() {
        assert_eq!(vm_name("Yougori microVM env-a").as_deref(), Some("OpenDock microVM env-a"));
        assert_eq!(vm_name("Other VM"), None);
        assert_eq!(
            cuda_distribution("Yougori-CUDA-0123456789ab").as_deref(),
            Some("OpenDock-CUDA-0123456789ab")
        );
        assert_eq!(cuda_distribution("Ubuntu"), None);
    }
}
