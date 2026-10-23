//! What happened, in order, in a way that shows when it has been altered.
//!
//! Every change of state in a realm writes one event, sealed with the realm's own key over its
//! own fields and the seal of the event before it. Because the key is in the operating system's
//! vault and not in the record, someone who can edit the file cannot re-seal what they changed:
//! a plain hash chain would let them recompute the whole chain and leave no trace.
//!
//! A local chain is still not an archive the hub cannot reach. An export to the customer's own
//! storage is what makes the record durable against whoever holds this computer, and the product
//! says so rather than implying more.
use serde::{Deserialize, Serialize};

/// Whether the thing was allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Decision {
    Allowed,
    Refused,
}

/// One recorded change or decision. No secret value is ever a field of this.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: String,
    pub sequence: u64,
    pub at: i64,
    pub realm_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<super::realm::Capability>,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    pub policy_version: u64,
    pub decision: Decision,
    /// Why, in words, for a person reading the log. Never a secret.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// The typed command this came from, by its readable name, when it came from one. A
    /// supervisor's own tick has none, and neither has anything an earlier build sealed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The seal of the event before this one, or `root` for the first.
    pub previous_seal: String,
    /// This event sealed with the realm's key.
    pub seal: String,
}

impl Event {
    /// What the hash is taken over: every field except the hash itself, in a fixed order.
    ///
    /// `command` joins the body only when there is one. An event sealed before commands were
    /// correlated therefore seals exactly the bytes it sealed then, and a chain written by an
    /// earlier build still verifies under this one.
    fn body(&self) -> String {
        let mut fields = serde_json::json!({
            "id": self.id, "sequence": self.sequence, "at": self.at, "realmId": self.realm_id,
            "capability": self.capability, "principalId": self.principal_id, "deviceId": self.device_id,
            "workloadId": self.workload_id, "action": self.action, "resourceId": self.resource_id,
            "policyVersion": self.policy_version, "decision": self.decision, "reason": self.reason,
            "previousSeal": self.previous_seal,
        });
        if let Some(command) = &self.command {
            fields["command"] = serde_json::Value::String(command.clone());
        }
        fields.to_string()
    }

    /// One event, sealed with the realm's key over its own fields and the seal of the event
    /// before it. The store uses this to add an event without holding the whole chain in memory.
    pub fn sealed(entry: Entry, sequence: u64, at: i64, previous_seal: String, key: &str) -> Event {
        let mut event = Event {
            id: format!("event-{}", &crate::token()[..16]),
            sequence,
            at,
            realm_id: entry.realm_id,
            capability: entry.capability,
            principal_id: entry.principal_id,
            device_id: entry.device_id,
            workload_id: entry.workload_id,
            action: entry.action,
            resource_id: entry.resource_id,
            policy_version: entry.policy_version,
            decision: entry.decision,
            reason: entry.reason,
            command: entry.command,
            previous_seal,
            seal: String::new(),
        };
        event.seal = event.compute(key);
        event
    }

    /// The seal over this event, under the realm's key.
    fn compute(&self, key: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("HMAC takes any key length");
        mac.update(self.body().as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

/// What to record, before it becomes an event in a chain.
#[derive(Clone, Debug)]
pub struct Entry {
    pub realm_id: String,
    pub capability: Option<super::realm::Capability>,
    pub principal_id: String,
    pub device_id: Option<String>,
    pub workload_id: Option<String>,
    pub action: String,
    pub resource_id: Option<String>,
    pub policy_version: u64,
    pub decision: Decision,
    pub reason: String,
    /// The typed command this is part of, by its readable name.
    pub command: Option<String>,
}

impl Entry {
    pub fn new(realm_id: &str, principal_id: &str, action: &str, decision: Decision) -> Entry {
        Entry {
            realm_id: realm_id.to_owned(),
            capability: None,
            principal_id: principal_id.to_owned(),
            device_id: None,
            workload_id: None,
            action: action.to_owned(),
            resource_id: None,
            policy_version: 0,
            decision,
            reason: String::new(),
            command: None,
        }
    }

    /// Ties this to the one typed command that caused it.
    pub fn under_command(mut self, command: &str) -> Entry {
        self.command = Some(command.to_owned());
        self
    }
    pub fn about(mut self, capability: super::realm::Capability, resource_id: &str) -> Entry {
        self.capability = Some(capability);
        self.resource_id = Some(resource_id.to_owned());
        self
    }
    pub fn from(mut self, device_id: &str) -> Entry {
        self.device_id = Some(device_id.to_owned());
        self
    }
    pub fn for_work(mut self, workload_id: &str) -> Entry {
        self.workload_id = Some(workload_id.to_owned());
        self
    }
    pub fn because(mut self, reason: &str) -> Entry {
        self.reason = reason.chars().filter(|c| !c.is_control()).take(500).collect();
        self
    }
    pub fn under(mut self, policy_version: u64) -> Entry {
        self.policy_version = policy_version;
        self
    }

    /// The entry with anything that looks like a value taken out of its reason.
    ///
    /// `Core::note` calls this on every event a realm writes, so no reason anywhere can carry a
    /// secret: not the broker's, not a connector's note, not a free-text reason somebody passes
    /// in later. What is left says that something was withheld, rather than quietly dropping it.
    pub fn safe(mut self) -> Entry {
        if super::credential::looks_like_a_secret(&self.reason) {
            self.reason = "withheld: this reason looked like a value".into();
        }
        self
    }
}

/// A realm's events, in order, each tied to the one before it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chain {
    #[serde(default)]
    pub events: Vec<Event>,
}

/// How many events a chain keeps before the oldest are exported and dropped. Dropping from the
/// front is recorded, so verification still knows the chain was trimmed rather than edited.
pub const KEEP: usize = 20_000;

impl Chain {
    /// Adds `entry`, sealed with the realm's key, and returns the event as recorded.
    pub fn record(&mut self, entry: Entry, at: i64, key: &str) -> Event {
        let previous_seal = self.events.last().map(|event| event.seal.clone()).unwrap_or_else(|| "root".into());
        let sequence = self.events.last().map(|event| event.sequence + 1).unwrap_or(1);
        let event = Event::sealed(entry, sequence, at, previous_seal, key);
        self.events.push(event.clone());
        if self.events.len() > KEEP {
            let drop = self.events.len() - KEEP;
            self.events.drain(..drop);
        }
        event
    }

    /// Checks the chain with the realm's key. Says which event first failed, and why, or nothing
    /// when it is whole. Without the key nothing verifies, which is the point of sealing it.
    pub fn verify(&self, key: &str) -> Result<(), String> {
        let mut previous: Option<&Event> = None;
        for event in &self.events {
            if event.seal != event.compute(key) {
                return Err(format!("Event {} was altered", event.sequence));
            }
            match previous {
                None => {}
                Some(earlier) => {
                    if event.previous_seal != earlier.seal {
                        return Err(format!("The chain breaks between events {} and {}", earlier.sequence, event.sequence));
                    }
                    if event.sequence != earlier.sequence + 1 {
                        return Err(format!("Event {} is missing", earlier.sequence + 1));
                    }
                }
            }
            previous = Some(event);
        }
        Ok(())
    }

    /// The events from `after` onward, for exporting to the customer's own storage.
    pub fn since(&self, after: u64) -> Vec<&Event> {
        self.events.iter().filter(|event| event.sequence > after).collect()
    }

    /// Everything one typed command caused, in the order it caused it.
    pub fn under(&self, command: &str) -> Vec<&Event> {
        self.events.iter().filter(|event| event.command.as_deref() == Some(command)).collect()
    }
}
