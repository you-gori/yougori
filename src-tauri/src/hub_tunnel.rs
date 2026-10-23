//! A hub's Cloudflare tunnel, shared by the Closed Neo Grid and the Sandbox Grid: how it is set
//! up (saved beside the hub so it reconnects after a restart), and a supervisor that keeps
//! `cloudflared` running for the hub's tunnel entry and publishes the address it got.
use crate::store::PlatformStore;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::Manager;
use crate::AppHandle;
use tokio_util::sync::CancellationToken;
use yougori_grid::net::HubAddress;

/// How the hub's tunnel is set up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub(crate) enum TunnelSetup {
    /// A temporary trycloudflare.com address, new each time `cloudflared` starts.
    Quick,
    /// A saved Cloudflare domain whose tunnel routes to the hub's tunnel port.
    Domain { domain: String },
}

impl TunnelSetup {
    /// `quick`, a saved domain, or nothing.
    pub(crate) fn parse(choice: Option<&str>) -> Option<TunnelSetup> {
        match choice.map(str::trim).filter(|choice| !choice.is_empty()) {
            None => None,
            Some(choice) if choice.eq_ignore_ascii_case("quick") => Some(TunnelSetup::Quick),
            Some(domain) => Some(TunnelSetup::Domain { domain: domain.to_owned() }),
        }
    }

    /// The loopback port the tunnel forwards to: any free one for a Quick Tunnel (not the hub's
    /// own), a domain's saved route otherwise.
    pub(crate) fn port(&self, app: &AppHandle, hub_port: u16, default: u16) -> Result<u16, String> {
        match self {
            TunnelSetup::Quick => Ok(if hub_port == default { default + 1 } else { default }),
            TunnelSetup::Domain { domain } => Ok(crate::workspace::cloudflare::domain_route(&app.state::<PlatformStore>(), domain)?.1),
        }
    }
}

/// What the supervisor published: the tunnel's address, or why it is not connected.
#[derive(Default)]
pub(crate) struct Published {
    pub url: Option<String>,
    pub error: Option<String>,
}

/// The hub's tunnel while the engine runs. The supervisor task owns `cloudflared`; only what it
/// published is kept here. Replacing or stopping it gives it a fresh `published`, so a stale
/// supervisor can never write into the new one.
#[derive(Default)]
pub(crate) struct TunnelState {
    pub setup: Option<TunnelSetup>,
    pub published: Arc<Mutex<Published>>,
    stop: Option<CancellationToken>,
}

impl TunnelState {
    pub(crate) fn url(&self) -> Option<String> {
        self.published.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).url.clone()
    }

    pub(crate) fn error(&self) -> Option<String> {
        self.published.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).error.clone()
    }

    /// The address company computers reach the hub at, once the tunnel has one.
    pub(crate) fn reach(&self) -> Option<HubAddress> {
        self.url().and_then(|url| HubAddress::parse(&url).ok())
    }

    /// Status for the dashboard: kind, domain, address, whether connected, and the last error.
    pub(crate) fn status(&self) -> Option<serde_json::Value> {
        let setup = self.setup.as_ref()?;
        let (kind, domain) = match setup {
            TunnelSetup::Quick => ("quick", None),
            TunnelSetup::Domain { domain } => ("domain", Some(domain.as_str())),
        };
        let url = self.url();
        Some(serde_json::json!({"kind": kind, "domain": domain, "url": url, "connected": url.is_some(), "error": self.error()}))
    }

    pub(crate) fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.cancel();
        }
        *self = TunnelState::default();
    }
}

pub(crate) fn load(path: &Path) -> Option<TunnelSetup> {
    std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

pub(crate) fn save(path: &PathBuf, setup: &TunnelSetup) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid grid folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(setup).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

async fn start(app: &AppHandle, setup: &TunnelSetup, port: u16) -> Result<crate::workspace::cloudflare::Started, String> {
    let manager = app.state::<crate::workspace::WorkspaceManager>();
    let store = app.state::<PlatformStore>();
    let domain = match setup {
        TunnelSetup::Quick => None,
        TunnelSetup::Domain { domain } => Some(domain.as_str()),
    };
    manager.grid_tunnel(domain, port, &store).await
}

/// Keeps a hub's tunnel connected while the engine runs: starts `cloudflared` for the hub's
/// tunnel entry on `port` and starts it again whenever it exits, with a growing pause after
/// failures. A Quick Tunnel gets a new address each time. A supervisor already in `state` is
/// replaced.
pub(crate) fn keep(app: &AppHandle, state: &mut TunnelState, setup: TunnelSetup, port: u16) {
    state.stop();
    let stop = crate::automation::shutdown_signal(app).child_token();
    let published = Arc::new(Mutex::new(Published::default()));
    *state = TunnelState { setup: Some(setup.clone()), published: published.clone(), stop: Some(stop.clone()) };
    let app = app.clone();
    let publish = move |url: Option<String>, error: Option<String>| {
        let mut current = published.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        current.url = url;
        current.error = error;
    };
    tauri::async_runtime::spawn(async move {
        let mut pause = Duration::from_secs(5);
        loop {
            let started = tokio::select! {
                _ = stop.cancelled() => return,
                started = start(&app, &setup, port) => started,
            };
            match started {
                Ok(mut started) => {
                    pause = Duration::from_secs(5);
                    let url = HubAddress::parse(&started.url).map(|address| address.to_string()).unwrap_or_else(|_| started.url.clone());
                    publish(Some(url), None);
                    let exited = tokio::select! {
                        _ = stop.cancelled() => false,
                        _ = started.child.wait() => true,
                    };
                    let _ = started.child.kill().await;
                    if !exited {
                        return;
                    }
                    publish(None, Some("The tunnel disconnected; reconnecting".into()));
                }
                Err(error) => {
                    publish(None, Some(error));
                    pause = (pause * 2).min(Duration::from_secs(5 * 60));
                }
            }
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(pause) => {}
            }
        }
    });
}
