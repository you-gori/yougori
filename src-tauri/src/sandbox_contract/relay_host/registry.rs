//! At most one running relay per sandbox (module docs in `mod.rs`).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::foundation::ids::{Clock, ExecutionId};
use crate::sandbox_contract::relay::ReaderLimits;
use crate::sandbox_contract::relay_broker::RelayBroker;
use crate::sandbox_contract::relay_process::RouteTable;

use super::backend::RelayBackend;
use super::host::{
    RelayFacts, RelayHost, RelayHostSettings, RelayLife, RelayStatus, StartError, StopReason,
};

/// The relays of every sandbox this host serves.
pub struct RelayHosts {
    backend: Box<dyn RelayBackend>,
    settings: RelayHostSettings,
    hosts: BTreeMap<ExecutionId, RelayHost>,
}

impl fmt::Debug for RelayHosts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHosts")
            .field("hosts", &self.hosts.len())
            .field("running", &self.running())
            .finish_non_exhaustive()
    }
}

impl RelayHosts {
    pub fn new(backend: Box<dyn RelayBackend>, settings: RelayHostSettings) -> Self {
        Self {
            backend,
            settings,
            hosts: BTreeMap::new(),
        }
    }

    /// Starts `sandbox`'s relay. A sandbox whose relay runs is refused
    /// ([`StartError::AlreadyRunning`]); an ended relay is replaced by the new one.
    pub fn start<C: Clock + Send + Sync + 'static>(
        &mut self,
        sandbox: ExecutionId,
        routes: &RouteTable,
        limits: ReaderLimits,
        broker: Arc<RelayBroker<C>>,
    ) -> Result<(), StartError> {
        if let Some(host) = self.hosts.get_mut(&sandbox) {
            host.poll();
            if host.is_running() {
                return Err(StartError::AlreadyRunning);
            }
        }
        let host = RelayHost::start(
            self.backend.as_mut(),
            sandbox.clone(),
            routes,
            limits,
            broker,
            self.settings,
        )?;
        self.hosts.insert(sandbox, host);
        Ok(())
    }

    /// Stops `sandbox`'s relay for `reason`; the life, or `None` for a sandbox without a
    /// relay. Idempotent.
    pub fn stop(&mut self, sandbox: &ExecutionId, reason: StopReason) -> Option<RelayLife> {
        let host = self.hosts.get_mut(sandbox)?;
        let life = host.stop(reason).clone();
        host.reported = true;
        Some(life)
    }

    /// Stops every relay (the service shuts down).
    pub fn stop_all(&mut self, reason: StopReason) -> Vec<RelayLife> {
        let sandboxes: Vec<ExecutionId> = self.hosts.keys().cloned().collect();
        sandboxes
            .iter()
            .filter_map(|sandbox| self.stop(sandbox, reason))
            .collect()
    }

    /// Notices relays that ended on their own since the last call; each life once.
    pub fn poll(&mut self) -> Vec<RelayLife> {
        let mut ended = Vec::new();
        for host in self.hosts.values_mut() {
            let life = host.poll().cloned();
            if let Some(life) = life {
                if !host.reported {
                    host.reported = true;
                    ended.push(life);
                }
            }
        }
        ended
    }

    pub fn status(&self, sandbox: &ExecutionId) -> Option<RelayStatus> {
        self.hosts.get(sandbox).map(RelayHost::status)
    }

    /// The running relay's facts for its guest pipe; `None` without a running relay.
    pub fn facts(&self, sandbox: &ExecutionId) -> Option<RelayFacts> {
        self.hosts.get(sandbox).and_then(RelayHost::facts)
    }

    pub fn running(&self) -> usize {
        self.hosts.values().filter(|host| host.is_running()).count()
    }

    /// Forgets the ended relays whose lives were reported.
    pub fn forget_ended(&mut self) -> usize {
        let before = self.hosts.len();
        self.hosts
            .retain(|_, host| host.is_running() || !host.reported);
        before - self.hosts.len()
    }
}
