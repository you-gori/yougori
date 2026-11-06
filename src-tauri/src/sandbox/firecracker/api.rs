//! The typed Firecracker API plan and its canonical JSON request sequence (§7.2 line 2368:
//! only required block, link, entropy and platform devices, no host-facing NIC unless
//! declared; VM-CP-02 line 3152: the Firecracker API calls are what the golden file pins).
//!
//! Each request names only what may vary; the rest is fixed in [`ApiRequest::body`]:
//! SMT and dirty-page tracking off, the root drive read-only, the boot arguments without
//! a console and with PCI off, the vsock link on guest CID 3, the logger at warning
//! level without origins. Nothing here can express a balloon, a metadata service, a
//! snapshot load, a shared filesystem or a rate-limit override.

use serde::Serialize;
use serde_json::{json, Value};

use super::canonical::canonical_json;
use super::names::{ApiId, InterfaceName, JailPath, MacAddress};
use crate::foundation::ids::{digest, Digest};

/// The HTTP method of every configuration call.
pub const METHOD: &str = "PUT";
/// The kernel command line: reboot by keyboard controller, panic reboots at once, no PCI
/// transport, no serial port, and no `console=` (VM-CP-02 line 3152: no console, no PCI
/// transport). Firecracker appends the root device itself.
pub const BOOT_ARGUMENTS: [&str; 4] = ["reboot=k", "panic=1", "pci=off", "8250.nr_uarts=0"];
/// The guest's vsock context id: the first id not reserved for the hypervisor or host.
pub const GUEST_CID: u32 = 3;
/// The Firecracker id of the root drive.
pub const ROOT_DRIVE_ID: &str = "rootfs";
/// The logger level.
pub const LOG_LEVEL: &str = "Warning";
/// Digest domain of [`ApiPlan::digest`].
pub const API_PLAN_DOMAIN: &str = "yougori/sandbox/firecracker/api-plan/v1";

/// One configuration request of the plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum ApiRequest {
    /// The logger, writing only to the host-owned log sink.
    Logger { log_path: JailPath },
    /// The metrics, written only to the host-owned metrics sink.
    Metrics { metrics_path: JailPath },
    /// vCPUs and memory; SMT and dirty-page tracking are always off.
    MachineConfig { vcpu_count: u8, mem_size_mib: u32 },
    /// The pinned kernel with [`BOOT_ARGUMENTS`].
    BootSource { kernel_image_path: JailPath },
    /// The pinned root image, read-only.
    RootDrive { path_on_host: JailPath },
    /// A network interface the profile declares; never present otherwise.
    NetworkInterface {
        iface_id: ApiId,
        host_dev_name: InterfaceName,
        guest_mac: MacAddress,
    },
    /// The vsock device of the link, bound to the host-created socket path.
    Vsock { uds_path: JailPath },
    /// The virtio entropy device, when the profile declares it.
    Entropy,
    /// Starts the configured VM.
    InstanceStart,
}

impl ApiRequest {
    /// The API path of the request.
    pub fn path(&self) -> String {
        match self {
            Self::Logger { .. } => "/logger".to_owned(),
            Self::Metrics { .. } => "/metrics".to_owned(),
            Self::MachineConfig { .. } => "/machine-config".to_owned(),
            Self::BootSource { .. } => "/boot-source".to_owned(),
            Self::RootDrive { .. } => format!("/drives/{ROOT_DRIVE_ID}"),
            Self::NetworkInterface { iface_id, .. } => format!("/network-interfaces/{iface_id}"),
            Self::Vsock { .. } => "/vsock".to_owned(),
            Self::Entropy => "/entropy".to_owned(),
            Self::InstanceStart => "/actions".to_owned(),
        }
    }

    /// The JSON body Firecracker receives.
    pub fn body(&self) -> Value {
        match self {
            Self::Logger { log_path } => json!({
                "log_path": log_path.as_str(),
                "level": LOG_LEVEL,
                "show_level": false,
                "show_log_origin": false,
            }),
            Self::Metrics { metrics_path } => json!({ "metrics_path": metrics_path.as_str() }),
            Self::MachineConfig {
                vcpu_count,
                mem_size_mib,
            } => json!({
                "vcpu_count": vcpu_count,
                "mem_size_mib": mem_size_mib,
                "smt": false,
                "track_dirty_pages": false,
            }),
            Self::BootSource { kernel_image_path } => json!({
                "kernel_image_path": kernel_image_path.as_str(),
                "boot_args": BOOT_ARGUMENTS.join(" "),
            }),
            Self::RootDrive { path_on_host } => json!({
                "drive_id": ROOT_DRIVE_ID,
                "path_on_host": path_on_host.as_str(),
                "is_root_device": true,
                "is_read_only": true,
            }),
            Self::NetworkInterface {
                iface_id,
                host_dev_name,
                guest_mac,
            } => json!({
                "iface_id": iface_id.as_str(),
                "host_dev_name": host_dev_name.as_str(),
                "guest_mac": guest_mac.to_string(),
            }),
            Self::Vsock { uds_path } => json!({
                "guest_cid": GUEST_CID,
                "uds_path": uds_path.as_str(),
            }),
            Self::Entropy => json!({}),
            Self::InstanceStart => json!({ "action_type": "InstanceStart" }),
        }
    }

    /// The call as sent: method, path and body.
    pub fn call(&self) -> ApiCall {
        ApiCall {
            method: METHOD,
            path: self.path(),
            body: self.body(),
        }
    }
}

/// One HTTP call to the Firecracker API socket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApiCall {
    pub method: &'static str,
    pub path: String,
    pub body: Value,
}

impl ApiCall {
    /// The call as a JSON value, for the canonical sequence.
    pub fn to_value(&self) -> Value {
        json!({ "method": self.method, "path": self.path, "body": self.body })
    }
}

/// The ordered configuration requests of one launch, ending with the instance start.
/// Only [`LaunchPlan::build`](super::LaunchPlan::build) makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ApiPlan {
    requests: Vec<ApiRequest>,
}

impl ApiPlan {
    pub(super) fn new(requests: Vec<ApiRequest>) -> Self {
        Self { requests }
    }

    pub fn requests(&self) -> &[ApiRequest] {
        &self.requests
    }

    /// The calls in the order they are sent.
    pub fn calls(&self) -> Vec<ApiCall> {
        self.requests.iter().map(ApiRequest::call).collect()
    }

    /// The canonical JSON request sequence: an array of `{body, method, path}` objects in
    /// sending order, keys sorted, no whitespace.
    pub fn canonical_json(&self) -> String {
        canonical_json(&Value::Array(
            self.calls().iter().map(ApiCall::to_value).collect(),
        ))
    }

    /// A digest of the canonical sequence.
    pub fn digest(&self) -> Digest {
        digest(API_PLAN_DOMAIN, &[self.canonical_json().as_bytes()])
    }
}

#[cfg(test)]
mod tests {
    use super::super::layout;
    use super::*;

    fn every_request() -> Vec<ApiRequest> {
        vec![
            ApiRequest::Logger {
                log_path: layout::path(layout::LOG_SINK),
            },
            ApiRequest::Metrics {
                metrics_path: layout::path(layout::METRICS_SINK),
            },
            ApiRequest::MachineConfig {
                vcpu_count: 2,
                mem_size_mib: 1024,
            },
            ApiRequest::BootSource {
                kernel_image_path: layout::path(layout::KERNEL_IMAGE),
            },
            ApiRequest::RootDrive {
                path_on_host: layout::path(layout::ROOT_IMAGE),
            },
            ApiRequest::NetworkInterface {
                iface_id: ApiId::new("eth0").unwrap(),
                host_dev_name: InterfaceName::new("tap0").unwrap(),
                guest_mac: MacAddress::parse("02:fc:00:00:00:01").unwrap(),
            },
            ApiRequest::Vsock {
                uds_path: layout::path(layout::LINK_SOCKET),
            },
            ApiRequest::Entropy,
            ApiRequest::InstanceStart,
        ]
    }

    #[test]
    fn each_request_has_its_firecracker_path_and_body() {
        let calls: Vec<(String, String)> = every_request()
            .iter()
            .map(|request| (request.path(), canonical_json(&request.body())))
            .collect();
        let expected = [
            (
                "/logger",
                r#"{"level":"Warning","log_path":"/sinks/log.fifo","show_level":false,"show_log_origin":false}"#,
            ),
            ("/metrics", r#"{"metrics_path":"/sinks/metrics.fifo"}"#),
            (
                "/machine-config",
                r#"{"mem_size_mib":1024,"smt":false,"track_dirty_pages":false,"vcpu_count":2}"#,
            ),
            (
                "/boot-source",
                r#"{"boot_args":"reboot=k panic=1 pci=off 8250.nr_uarts=0","kernel_image_path":"/images/vmlinux"}"#,
            ),
            (
                "/drives/rootfs",
                r#"{"drive_id":"rootfs","is_read_only":true,"is_root_device":true,"path_on_host":"/images/rootfs.img"}"#,
            ),
            (
                "/network-interfaces/eth0",
                r#"{"guest_mac":"02:fc:00:00:00:01","host_dev_name":"tap0","iface_id":"eth0"}"#,
            ),
            ("/vsock", r#"{"guest_cid":3,"uds_path":"/run/link.sock"}"#),
            ("/entropy", "{}"),
            ("/actions", r#"{"action_type":"InstanceStart"}"#),
        ];
        assert_eq!(calls.len(), expected.len());
        for ((path, body), (want_path, want_body)) in calls.iter().zip(expected) {
            assert_eq!(path, want_path);
            assert_eq!(body, want_body, "{path}");
        }
        assert!(every_request()
            .iter()
            .all(|request| request.call().method == "PUT"));
    }

    #[test]
    fn the_boot_arguments_have_no_console_and_turn_pci_off() {
        assert!(BOOT_ARGUMENTS
            .iter()
            .all(|argument| !argument.starts_with("console=")));
        assert!(BOOT_ARGUMENTS.contains(&"pci=off"));
    }

    #[test]
    fn the_canonical_sequence_is_deterministic_and_its_digest_tracks_every_request() {
        let plan = ApiPlan::new(every_request());
        assert_eq!(
            plan.canonical_json(),
            ApiPlan::new(every_request()).canonical_json()
        );
        assert!(plan
            .canonical_json()
            .starts_with(r#"[{"body":{"level":"Warning","#));
        assert!(plan.canonical_json().ends_with(
            r#"{"body":{"action_type":"InstanceStart"},"method":"PUT","path":"/actions"}]"#
        ));
        let digest = plan.digest();
        for index in 0..every_request().len() {
            let mut requests = every_request();
            requests.remove(index);
            assert_ne!(ApiPlan::new(requests).digest(), digest, "{index}");
        }
        let mut reordered = every_request();
        reordered.swap(0, 1);
        assert_ne!(ApiPlan::new(reordered).digest(), digest);
        let mut resized = every_request();
        resized[2] = ApiRequest::MachineConfig {
            vcpu_count: 2,
            mem_size_mib: 2048,
        };
        assert_ne!(ApiPlan::new(resized).digest(), digest);
        assert_eq!(
            serde_json::to_value(&plan).unwrap()[7]["request"],
            "entropy"
        );
    }
}
