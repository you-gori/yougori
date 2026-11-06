//! The fixed layout inside every jail. Firecracker sees only these paths; none comes from
//! a launch request or a profile (§3.4 line 2101: minimize writable paths and management
//! APIs; VM-P03 line 2778: no undeclared agent socket or management endpoint).
//!
//! - `/images`: the pinned kernel and root image, staged read-only and root-owned.
//! - `/run`: a private directory the host creates for the API socket and the link's vsock
//!   socket; Firecracker binds both there.
//! - `/sinks`: host-owned named pipes for the logger and metrics; the jail may write them
//!   and may not create, replace or remove anything there.

use super::names::JailPath;

/// The directory of staged images.
pub const IMAGE_DIRECTORY: &str = "/images";
/// The pinned guest kernel, staged read-only.
pub const KERNEL_IMAGE: &str = "/images/vmlinux";
/// The pinned guest root image, staged read-only and attached read-only.
pub const ROOT_IMAGE: &str = "/images/rootfs.img";
/// The private directory of the API and link sockets.
pub const SOCKET_DIRECTORY: &str = "/run";
/// Firecracker's API socket (`--api-sock`).
pub const API_SOCKET: &str = "/run/firecracker.socket";
/// The vsock socket of the host–guest link.
pub const LINK_SOCKET: &str = "/run/link.sock";
/// The directory of host-owned sinks.
pub const SINK_DIRECTORY: &str = "/sinks";
/// The logger's named pipe.
pub const LOG_SINK: &str = "/sinks/log.fifo";
/// The metrics' named pipe.
pub const METRICS_SINK: &str = "/sinks/metrics.fifo";

/// Every fixed path, for the test that checks each against the path grammar.
#[cfg(test)]
pub const ALL: [&str; 9] = [
    IMAGE_DIRECTORY,
    KERNEL_IMAGE,
    ROOT_IMAGE,
    SOCKET_DIRECTORY,
    API_SOCKET,
    LINK_SOCKET,
    SINK_DIRECTORY,
    LOG_SINK,
    METRICS_SINK,
];

/// The jail path of a fixed layout entry.
pub fn path(fixed: &'static str) -> JailPath {
    JailPath::fixed(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixed_path_follows_the_grammar_and_lies_in_its_directory() {
        for fixed in ALL {
            assert_eq!(JailPath::new(fixed), Ok(path(fixed)), "{fixed}");
        }
        for (file, directory) in [
            (KERNEL_IMAGE, IMAGE_DIRECTORY),
            (ROOT_IMAGE, IMAGE_DIRECTORY),
            (API_SOCKET, SOCKET_DIRECTORY),
            (LINK_SOCKET, SOCKET_DIRECTORY),
            (LOG_SINK, SINK_DIRECTORY),
            (METRICS_SINK, SINK_DIRECTORY),
        ] {
            assert_eq!(path(file).parent(), Some(path(directory)), "{file}");
        }
    }
}
