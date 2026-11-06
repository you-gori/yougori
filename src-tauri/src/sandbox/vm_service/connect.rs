//! Sandbox-to-sandbox connections (M14; VM part §4.7 "connections between sandboxes require
//! explicit grants at both ends; transitive access is not inferred"; VM-W13, VM-CP-29): the
//! service's half of the connection gate's broker.
//!
//! A sandbox declares at launch the connection endpoints its programs may use
//! ([`ConnectionEndpoint`]: a host name label and the port they connect to). The guest maps
//! each name to a loopback address of its own and opens one egress stream for every
//! connection a program makes there; the stream is accepted and credited back only as the
//! connection's other end takes its bytes (`sandbox::host`). An endpoint reaches nothing
//! until it is granted a declared service of another sandbox
//! ([`VmService::connect`](super::VmService::connect)): the gate then holds both copies of
//! V02's grant, the caller's and the callee's, each under that sandbox's network mode, and
//! both expire. Every connection a program opens is checked by the gate against both grants
//! and the callee's published-service grant, and joined to a stream the callee's guest
//! opens to the service's port only once admitted, so a refused one never reaches the
//! callee. Bytes each way count against the connection's budget, the callee's answers also
//! against its release account (they leave it); either end's end of writing reaches the
//! other (a half close). Withdrawing the grant, its expiry, or either sandbox's revocation or
//! stop closes the connection.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sandbox::backend::GuestEgressEndpoint;

/// The most connection endpoints one launch declares.
pub const MAX_CONNECTION_ENDPOINTS: usize = 8;

/// The longest one connection grant lasts.
pub const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// What one connection may carry each way unless granted otherwise.
pub const DEFAULT_CONNECTION_BUDGET_BYTES: u64 = 8 << 20;

/// The most one connection may be granted to carry each way.
pub const MAX_CONNECTION_BUDGET_BYTES: u64 = 1 << 30;

/// A connection endpoint a sandbox declares at launch: the name its programs reach (one host
/// name label) and the port they connect to there.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionEndpoint {
    pub name: String,
    pub port: u16,
}

impl ConnectionEndpoint {
    /// The endpoint as the guest learns it at boot.
    pub fn guest_endpoint(&self) -> Result<GuestEgressEndpoint, String> {
        GuestEgressEndpoint::connection(&self.name, self.port)
            .map_err(|error| format!("the connection endpoint {}: {error}", self.name))
    }
}

/// Checks a launch's connection endpoints: at most [`MAX_CONNECTION_ENDPOINTS`], each one host
/// name label with a port from 1, no name repeated, and no port one of `service_ports`, the
/// sandbox's own published services: its guest's agent listens on each endpoint's loopback address
/// and port, so a service listening on every address with the same port could not start.
pub fn check_connect(endpoints: &[ConnectionEndpoint], service_ports: &[u16]) -> Result<(), String> {
    if endpoints.len() > MAX_CONNECTION_ENDPOINTS {
        return Err(format!(
            "at most {MAX_CONNECTION_ENDPOINTS} connection endpoints may be declared, not {}",
            endpoints.len()
        ));
    }
    let mut names = BTreeSet::new();
    for endpoint in endpoints {
        let guest = endpoint.guest_endpoint()?;
        if !names.insert(guest.name().to_owned()) {
            return Err(format!(
                "the connection endpoint {} is declared twice",
                endpoint.name
            ));
        }
        if service_ports.contains(&endpoint.port) {
            return Err(format!(
                "the connection endpoint {} uses port {}, which a service of the same sandbox listens on; give the endpoint another port",
                endpoint.name, endpoint.port
            ));
        }
    }
    Ok(())
}

/// What one endpoint is granted, as status shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantView {
    /// The sandbox whose service it reaches.
    pub sandbox: String,
    pub service: String,
    /// `active`, or `expired` once it passed: a new grant replaces an expired one.
    pub state: &'static str,
    pub expires_in_seconds: u64,
    /// Each connection's budget, each way.
    pub budget_bytes: u64,
    /// Connections the gate opened under the grant.
    pub connections_opened: u64,
}

/// One connection endpoint of a sandbox, as status shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EndpointView {
    pub name: String,
    pub port: u16,
    /// What it is granted, if anything.
    pub granted: Option<GrantView>,
}

/// Another sandbox's endpoint granted one of this sandbox's services.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CallerView {
    pub sandbox: String,
    pub endpoint: String,
    pub service: String,
    pub expires_in_seconds: u64,
}

/// A sandbox's connections, for status.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConnectionsView {
    /// Its connection endpoints, each with what it is granted.
    pub endpoints: Vec<EndpointView>,
    /// Other sandboxes' endpoints granted its services.
    pub callers: Vec<CallerView>,
    /// Connections open now with it at either end.
    pub open_connections: usize,
    /// Connections its programs opened that the gate refused (no grant, an expired one, or
    /// the other sandbox gone).
    pub refused_connections: u64,
    /// Connections its programs opened that the gate admitted.
    pub admitted_connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_launch_declares_distinct_host_name_labels_with_ports() {
        let endpoint = |name: &str, port| ConnectionEndpoint {
            name: name.to_owned(),
            port,
        };
        assert!(check_connect(&[endpoint("api", 8080), endpoint("db", 5432)], &[]).is_ok());
        assert!(check_connect(&[endpoint("api", 8080), endpoint("API", 9000)], &[])
            .unwrap_err()
            .contains("declared twice"));
        assert!(check_connect(&[endpoint("api.internal", 8080)], &[]).is_err());
        assert!(check_connect(&[endpoint("api", 0)], &[]).is_err());
        let many: Vec<ConnectionEndpoint> = (0..9).map(|n| endpoint(&format!("e{n}"), 80)).collect();
        assert!(check_connect(&many, &[]).unwrap_err().contains("at most 8"));
        assert!(check_connect(&[endpoint("api", 8080)], &[8080])
            .unwrap_err()
            .contains("a service of the same sandbox listens on"));
    }
}
