//! A realm: one trust boundary, with its own keys, its own people and computers, its own audit,
//! and the capabilities its owner turned on.
//!
//! A company's primary realm may serve models, host workspaces and broker credentials. Authorised
//! research runs in a realm of its own, built from this same code, so that unreviewed source and
//! company credentials never share a boundary. Nothing about that separation changes how any
//! model behaves; it separates data, keys and permissions.
use serde::{Deserialize, Serialize};

/// What a realm is for. The two kinds run the same code with different defaults, and no token of
/// one is ever accepted by the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RealmKind {
    /// The company's own grid: models, workspaces and credentials, as its owner allows.
    Primary,
    /// Authorised research, offline unless its policy says otherwise, with nothing inherited.
    Research,
}

/// What a realm can do. A capability is a namespace for policy, not a grant: switching one on
/// gives it nothing from the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Capability {
    /// Serving models from the company's own computers.
    Models,
    /// Workspaces built on the company's computers for named people.
    Workspaces,
    /// Credentials used through a broker, never handed out.
    Credentials,
    /// Authorised research on approved source, in a realm of its own.
    Research,
}

impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Capability::Models => "models",
            Capability::Workspaces => "workspaces",
            Capability::Credentials => "credentials",
            Capability::Research => "research",
        }
    }

    /// The same capability as something a grid does, for the sentences that need a verb. `name` is
    /// a noun for a list, and "this grid does not credentials" is not a sentence anybody should be
    /// shown.
    pub fn doing(self) -> &'static str {
        match self {
            Capability::Models => "serve models",
            Capability::Workspaces => "host workspaces",
            Capability::Credentials => "broker credentials",
            Capability::Research => "run authorised research",
        }
    }

    /// Which capabilities a kind of realm may turn on. Research is alone in its realm, and the
    /// company's three never share a realm with it.
    pub fn allowed_in(kind: RealmKind) -> &'static [Capability] {
        match kind {
            RealmKind::Primary => &[Capability::Models, Capability::Workspaces, Capability::Credentials],
            RealmKind::Research => &[Capability::Research],
        }
    }
}

/// Where a realm is in its life. A paused realm answers but serves nothing; a closing realm is
/// being deleted and tells every computer so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Lifecycle {
    #[default]
    Open,
    Paused,
    Closing,
    Gone,
}

/// Whether work may run at all in this state.
impl Lifecycle {
    pub fn serves(self) -> bool {
        matches!(self, Lifecycle::Open)
    }

    /// What to call this in a sentence somebody reads.
    pub fn word(self) -> &'static str {
        match self {
            Lifecycle::Open => "open",
            Lifecycle::Paused => "paused",
            Lifecycle::Closing => "closing",
            Lifecycle::Gone => "gone",
        }
    }
}

/// What the network may do with a realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// Workloads may reach the internet.
    pub outbound: bool,
    /// Destinations a workload may reach when `outbound` is on; empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
    /// The hub may be reached from outside the company network, through a tunnel.
    pub published: bool,
}

impl NetworkPolicy {
    /// The company's default: the hub is reachable only where the admin publishes it, and
    /// workloads may reach the internet unless a profile narrows it.
    pub fn company() -> NetworkPolicy {
        NetworkPolicy { outbound: true, destinations: Vec::new(), published: false }
    }

    /// Research's default: nothing leaves.
    pub fn offline() -> NetworkPolicy {
        NetworkPolicy { outbound: false, destinations: Vec::new(), published: false }
    }

    /// Whether a workload in this realm may reach `destination`.
    pub fn allows(&self, destination: &str) -> bool {
        self.outbound && (self.destinations.is_empty() || self.destinations.iter().any(|allowed| allowed == destination))
    }
}

/// One trust boundary and everything scoped to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Realm {
    pub id: String,
    pub name: String,
    pub kind: RealmKind,
    /// What its owner turned on, always a subset of what its kind allows.
    pub capabilities: Vec<Capability>,
    pub network: NetworkPolicy,
    pub lifecycle: Lifecycle,
    /// The realm's own signing key, kept as a hash here; the value lives in the OS vault.
    pub key_fingerprint: String,
    pub created_at: i64,
}

impl Realm {
    /// A new realm. `key` is its signing secret, which the caller stores in the vault; only its
    /// fingerprint is written here.
    pub fn new(name: &str, kind: RealmKind, capabilities: &[Capability], key: &str, now: i64) -> Result<Realm, String> {
        let name = crate::label(name, "realm name")?;
        let mut chosen: Vec<Capability> = Vec::new();
        for capability in capabilities {
            if !Capability::allowed_in(kind).contains(capability) {
                return Err(format!("A {} realm cannot {}", if kind == RealmKind::Primary { "company" } else { "research" }, capability.doing()));
            }
            if !chosen.contains(capability) {
                chosen.push(*capability);
            }
        }
        if chosen.is_empty() {
            return Err("Choose at least one thing for this grid to do".into());
        }
        chosen.sort();
        Ok(Realm {
            id: format!("realm-{}", &crate::token()[..16]),
            name,
            kind,
            capabilities: chosen,
            network: if kind == RealmKind::Research { NetworkPolicy::offline() } else { NetworkPolicy::company() },
            lifecycle: Lifecycle::Open,
            key_fingerprint: crate::digest("realm-key", key),
            created_at: now,
        })
    }

    pub fn can(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Whether `key` is this realm's signing secret.
    pub fn keyed_by(&self, key: &str) -> bool {
        crate::desks::same_hash(&self.key_fingerprint, &crate::digest("realm-key", key))
    }
}
