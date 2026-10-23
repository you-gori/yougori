//! Making a request with a credential the workload never sees.
//!
//! The workload holds a permission naming a credential, a place, a method, a path and a size. It
//! never holds the value, and nothing it sends can put one anywhere: the header or parameter the
//! credential travels in is stripped from whatever it asked for, and so is every header the
//! forwarder owns.
//!
//! The order is the whole point. Everything that can be decided without a value is decided before
//! one is read. The narrow checks are then made again against the request as it will actually go
//! out, immediately before it goes, because reading from a vault takes unbounded wall time: a
//! locked keychain, a slow vault or a prompt in front of the person at the computer can hold it
//! open for minutes while an administrator revokes a computer, retires the credential or rotates
//! it. Revocation is promised to bite at the moment of use, and the moment of use is the send.
//!
//! Time is part of that. The last look is taken at the instant the request was asked at plus the
//! time actually spent waiting, measured monotonically, so an agreement that simply ran out while
//! the vault was open is refused in the same breath as one somebody took back by hand. Reading the
//! wall clock instead would let a clock correction move the last look backwards.
//!
//! Two deliberate choices are worth reading before the code.
//!
//! The first is that the wire is the Access Grid's forwarder, not a second one of Core's own.
//! `crate::access::forward` is where TLS, redirects, path canonicalisation, header hygiene and
//! hiding a value in an answer are decided, and a second copy of those rules is how one of them
//! quietly stops matching the other. This is a dependency pointing the wrong way through the
//! layers, from Core up into a profile, and it is accepted on purpose: when Grid Core becomes a
//! crate of its own the forwarder moves with it into a module both layers call, and nothing else
//! about this file changes.
//!
//! The second is that the broker never holds the realm while a request is in flight. It takes a
//! lock three times, each time for one short synchronous step, and the request goes out with no
//! lock held at all, so a hub brokering two requests does not serialise them on the network.
use super::{
    audit::{Decision, Entry},
    capability::{Attempt, Authority},
    credential::Credential,
    mint,
    realm::Capability,
    vault::{self, Held, Vault},
    Core,
};
use crate::access::{
    forward::{self, Outgoing, Prepared, Target, RESERVED_HEADERS},
    policy::METHODS,
};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

#[cfg(test)]
mod tests;

/// How long a record of a request may sit open before something else closes it. The forwarder's
/// own timeout plus a minute: past that, nobody is still waiting for that answer.
pub const OPEN_FOR: i64 = forward::TIMEOUT.as_secs() as i64 + 60;

/// What a workload is asking the broker to send. Nothing here is a value.
#[derive(Clone, Debug)]
pub struct Ask<'a> {
    /// The permission `Core::use_credential` handed it.
    pub token: &'a str,
    pub realm_id: &'a str,
    pub device_id: &'a str,
    pub workload_id: &'a str,
    pub credential_id: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub headers: serde_json::Map<String, serde_json::Value>,
    pub body: Vec<u8>,
}

/// One brokered request, as the realm records it. There is no value in it and no query, because a
/// query credential's value travels in one.
#[derive(Clone, Debug)]
pub struct Use {
    pub id: String,
    pub realm_id: String,
    pub credential_id: String,
    pub capability_id: String,
    pub approval_id: Option<String>,
    pub principal_id: String,
    pub device_id: String,
    pub workload_id: String,
    /// Scheme, host and port, and the path prefix it was confined to.
    pub destination: String,
    pub method: String,
    pub path: String,
    pub request_bytes: u64,
    pub answer_bytes: Option<u64>,
    pub status: Option<u16>,
    pub vault_id: String,
    pub vault_version: u32,
    pub outcome: String,
    /// One word from a fixed list. What a person reads is the audit event.
    pub reason: String,
    pub policy_version: u64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

/// One place a credential names in its own row that is not among the places it may be sent.
///
/// There is no value in it and no secret: a credential's name, its identifier and an address.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeftOut {
    pub credential_id: String,
    pub credential_name: String,
    /// The address as the credential's own row still carries it.
    pub destination: String,
    /// A sentence for the administrator reading this.
    pub why: String,
}

/// A request that has passed every check, and where to read the value from. It holds no value,
/// and its `Debug` can be printed anywhere.
#[derive(Clone, Debug)]
pub struct Cleared {
    pub use_id: String,
    pub realm_id: String,
    pub capability_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub workload_id: String,
    pub approval_id: Option<String>,
    pub credential_id: String,
    pub presentation: super::credential::Kind,
    pub field: String,
    /// What a minting credential needs besides its value. Names and addresses, never a value.
    pub settings: BTreeMap<String, String>,
    /// Everything about how this credential travels, as one digest, so the last look can tell
    /// that a token endpoint, a region or the permission to travel in the URL moved while the
    /// vault was open.
    pub shape: String,
    pub entry: vault::Entry,
    /// What the realm says the value in that entry fingerprints to.
    pub fingerprint: String,
    pub generation: u32,
    pub realm_generation: u64,
    pub policy_version: u64,
    pub maximum_bytes: u64,
    /// The one place out of the credential's list that this request is confined to.
    pub place: String,
    /// The request as it will go out, with no value on it yet.
    pub outgoing: Outgoing,
}

impl Cleared {
    /// What minting needs to know about this request. There is no value in it.
    fn recipe(&self) -> mint::Recipe<'_> {
        mint::Recipe {
            credential_id: &self.credential_id,
            realm_id: &self.realm_id,
            generation: self.generation,
            vault_version: self.entry.version,
            presentation: self.presentation,
            field: &self.field,
            settings: &self.settings,
            person: &self.principal_id,
        }
    }
}

/// How a brokered request ended.
///
/// The word in the ledger comes from a fixed list, because the sentence a TLS library or a service
/// chose is free text and a ledger column is not the place for it. The sentence goes to the person
/// who asked and into the audit event, which passes the realm's redaction gate on the way.
#[derive(Clone, Debug)]
pub enum Ended {
    Sent { status: u16, bytes: u64 },
    /// This grid refused to send it.
    Refused(&'static str, String),
    /// It was sent, and something went wrong on the way.
    Failed(&'static str, String),
}

impl Ended {
    fn outcome(&self) -> &'static str {
        match self {
            Ended::Sent { .. } => "sent",
            Ended::Refused(..) => "refused",
            Ended::Failed(..) => "failed",
        }
    }

    /// The one word the ledger keeps.
    fn word(&self) -> &'static str {
        match self {
            Ended::Sent { .. } => "",
            Ended::Refused(word, _) | Ended::Failed(word, _) => word,
        }
    }

    /// The sentence for the person who asked.
    pub fn say(&self) -> String {
        match self {
            Ended::Sent { status, bytes } => format!("answered {status} in {bytes} bytes"),
            Ended::Refused(_, said) | Ended::Failed(_, said) => said.clone(),
        }
    }

    /// Which way a service's trouble is recorded, from the sentence the forwarder gave. The three
    /// words are the three things a caller can do something about.
    fn from_wire(said: &str) -> Ended {
        let word = if said.contains("did not answer within") {
            "timeout"
        } else if said.starts_with("Cannot reach") {
            "unreachable"
        } else {
            "interrupted"
        };
        Ended::Failed(word, said.to_owned())
    }
}

/// The prepared request with the value on it, overwritten when it is dropped.
///
/// `forward::Prepared` keeps the value in ordinary strings, which are freed without being cleared.
/// This owns it, so when the request ends those strings are overwritten in place, by the same
/// function the minting cache uses, so the two cannot drift apart about which of them holds a
/// secret. What cannot be reached from here is written down rather than glossed over:
/// `Prepared::plain` builds one temporary string for a basic credential, the forwarder
/// percent-encodes a query credential into a URI, hyper copies the header into its own buffer,
/// rustls copies it into a TLS record and the kernel copies it into a socket buffer. None of those
/// is owned by this code and none of them is wiped.
pub struct Sealed(Prepared);

impl Sealed {
    /// Puts the credential on the request, in the one way this credential travels.
    ///
    /// For the four kinds that go as they are this is `Prepared::plain`, which is the one function
    /// that decides what goes on the wire and what the answer filter will hide, so it is called
    /// rather than copied. For the three that mint, this is where a token endpoint is reached, and
    /// that is a network call of unbounded length: it happens here, before the last look, so the
    /// last look is still the statement immediately before the send.
    /// The word that comes back with a refusal is the one the ledger keeps, and it says which of
    /// the two halves failed: what the vault held, or what this grid could make from it.
    async fn put(cache: &mint::Cache, cleared: &Cleared, held: &Held, keeper: &str, now: i64) -> Result<Sealed, (&'static str, String)> {
        let value = mint::value_in(cleared.presentation, held).map_err(|trouble| ("vault", trouble.describe(&cleared.entry, keeper)))?;
        let prepared = mint::prepare(cache, &cleared.recipe(), value, now).await.map_err(|said| ("minting", said))?;
        Ok(Sealed(prepared))
    }
}

impl Drop for Sealed {
    fn drop(&mut self) {
        mint::wipe_prepared(&mut self.0);
    }
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Sealed(hidden)")
    }
}

/// Sends one request with a credential the workload never sees.
///
/// The realm is taken three times, each time for one short step with no await inside it: to clear
/// the request and open its record, to take the last look before it goes, and to close the record
/// with how it ended. The request itself goes out with the realm free, so brokering two requests
/// does not make one wait for the other's network call.
///
/// Every way out of this function after the record is opened closes it exactly once.
///
/// The one clock this has is `now`, and the wait in the middle is unbounded, so the last look and
/// the closing record are taken at `now` plus however long was actually spent waiting. That time
/// is measured with `Instant`, which only goes forwards: a test's made-up epoch still works, and a
/// wall clock corrected while a prompt was open cannot move the last look backwards.
pub async fn send(core: &Mutex<Core>, vault: &Arc<dyn Vault>, cache: &mint::Cache, ask: &Ask<'_>, now: i64) -> Result<serde_json::Value, String> {
    let since = std::time::Instant::now();
    let cleared = {
        let mut realm = core.lock().await;
        realm.clear_to_send(ask, now)?
    };
    let (ended, answer) = attempt(core, vault, cache, &cleared, now, since).await;
    {
        let mut realm = core.lock().await;
        realm.closing_use(&cleared, &ended, now + waited(since))?;
    }
    answer
}

/// Whole seconds spent since the request was asked at. Rounded down, so the clock the last look
/// uses is never later than the truth, and an agreement is never refused for time that has not
/// actually passed.
fn waited(since: std::time::Instant) -> i64 {
    since.elapsed().as_secs().min(i64::MAX as u64) as i64
}

/// Everything between opening the record and closing it. It returns how the request ended rather
/// than using `?`, so there is no path out of here that leaves a record open.
async fn attempt(core: &Mutex<Core>, vault: &Arc<dyn Vault>, cache: &mint::Cache, cleared: &Cleared, now: i64, since: std::time::Instant) -> (Ended, Result<serde_json::Value, String>) {
    let refused = |word: &'static str, said: String| (Ended::Refused(word, said.clone()), Err(said));

    // The value, for the first time, and only now. Reading it is a synchronous call into the
    // operating system that can block for as long as the person at the computer takes to answer a
    // prompt, so it happens on a thread kept for blocking work rather than on one running tasks.
    let entry = cleared.entry.clone();
    let keeper = Arc::clone(vault);
    let read = tokio::task::spawn_blocking(move || keeper.read(&entry)).await;
    let held = match read {
        Ok(Ok(held)) => held,
        Ok(Err(trouble)) => return refused("vault", trouble.describe(&cleared.entry, &vault.name())),
        Err(_) => return refused("vault", format!("Reading {} was interrupted", cleared.entry.account())),
    };

    // It is the value this grid recorded, at the version this credential is on.
    match held.fingerprint() {
        Ok(print) if print == cleared.fingerprint => {}
        Ok(_) => return refused("fingerprint", "The value in the vault is not the one this grid recorded for this credential".to_owned()),
        Err(trouble) => return refused("vault", trouble.describe(&cleared.entry, &vault.name())),
    }

    // What actually goes on the request. For a credential this grid mints from, that means
    // reaching a token endpoint, which is why it happens here and not at the last look: the last
    // look has to be the statement before the send, and this is not it. The clock the mint is
    // given is `now` plus the time already spent, so a GitHub assertion is not signed with a
    // timestamp from before a locked keychain was opened.
    let prepared = match Sealed::put(cache, cleared, &held, &vault.name(), now + waited(since)).await {
        Ok(prepared) => prepared,
        Err((word, said)) => return refused(word, said),
    };

    // The last look, against the realm as it is at this instant and against the request that is
    // about to go. The realm is given back and the next statement is the send.
    //
    // At `now` plus the time actually spent above, not at `now`. The read of the value can sit in
    // front of a person for minutes, and every time-based rule in `still_clear` would otherwise be
    // asked about the instant the request was cleared at, so an agreement that simply lapsed while
    // the vault was open would be answered as if it still stood.
    let last = {
        let realm = core.lock().await;
        realm.still_clear(cleared, now + waited(since))
    };
    if let Err(said) = last {
        return refused("rechecked", said);
    }
    let answer = forward::send(&cleared.outgoing, &prepared.0).await;

    // The value is gone from everything this code owns before anything is recorded.
    drop(prepared);
    drop(held);

    match answer {
        Ok(answer) => {
            let ended = Ended::Sent { status: answer["status"].as_u64().unwrap_or_default() as u16, bytes: answer["bytes"].as_u64().unwrap_or_default() };
            (ended, Ok(answer))
        }
        Err(said) => (Ended::from_wire(&said), Err(said)),
    }
}

impl Core {
    /// Everything that can be decided without a value, in the order it has to be decided in.
    ///
    /// Every way this can fail happens before the record of the request is opened, so no `?` here
    /// can leave one open. The record is the last thing this does, and from then on the only
    /// caller is `send`, which closes it on every path.
    pub fn clear_to_send(&mut self, ask: &Ask<'_>, now: i64) -> Result<Cleared, String> {
        if !self.realm.can(Capability::Credentials) {
            return Err("This grid does not broker credentials".into());
        }
        if ask.realm_id != self.realm.id {
            return Err("This permission was not issued by this grid".into());
        }
        let realm = self.store.realm()?;
        if !realm.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }

        // The shape of what is being asked, before anything is looked up. The forwarder's own
        // parsing is what refuses `..`, `%2e%2e`, `%2F` and `..;` rather than a rule of our own.
        let method = ask.method.trim().to_ascii_uppercase();
        if !METHODS.contains(&method.as_str()) {
            return Err(format!("{method} is not a method this grid sends"));
        }
        if ask.body.len() > forward::MAX_BODY {
            return Err(format!("A request body is at most {} bytes", forward::MAX_BODY));
        }
        let target = forward::target(ask.url)?;

        // The credential as it is now, and which of its places holds the target.
        let credential = self.store.credential(ask.credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        credential.ready_to_send()?;
        let place = Core::place_for(&credential, &target, ask.token)?;
        Core::egress_allows(&realm, &target)?;
        // Where this grid itself would connect to make a short-lived credential from this one is
        // bound by the realm's own outbound rules too, and it is asked about here, before any
        // value is read. A token endpoint is not one of the credential's destinations: it is a
        // place the grid reaches on its own behalf, and the one list that stops every credential
        // at once is the one that has to allow it.
        for endpoint in mint::endpoints(credential.presentation, &credential.settings)? {
            if let Err(said) = Core::egress_allows(&realm, &endpoint) {
                return Err(format!("{said}, and that is where this credential's short-lived token is made"));
            }
        }

        // The permission. Accepting it spends it, and re-checks the realm, the account, the
        // computer, the policy, the credential's generation and whether it was used before.
        let attempt = Attempt {
            realm_id: ask.realm_id,
            device_id: ask.device_id,
            workload_id: ask.workload_id,
            resource_id: ask.credential_id,
            destination: Some(&place),
            method: Some(&method),
            path: Some(&target.path),
            bytes: Some(ask.body.len() as u64),
        };
        let claims = self.accept(ask.token, &attempt, now)?;

        // What the credential, the grant and the agreement allow, as they are now.
        if !credential.allows(&method, &target.path) {
            return Err(format!("This credential is not for {method} {}", target.path));
        }
        let grant = self.store.grant_for(&credential.id, &claims.principal_id)?.ok_or("Nobody has given them this credential")?;
        if !grant.covers(&method, &target.path, now) {
            return Err(format!("They may not use this credential for {method} {}", target.path));
        }
        self.agreement_stands(claims.approval_id.as_deref(), now)?;
        let maximum_bytes = credential.maximum_bytes.unwrap_or(forward::MAX_BODY as u64);
        if ask.body.len() as u64 > maximum_bytes {
            return Err(format!("This credential carries at most {maximum_bytes} bytes"));
        }

        // Nothing the workload asked to send can carry a credential: the headers the forwarder
        // owns and the one this credential travels in are dropped from what it gave.
        let headers = forward::agent_headers(&ask.headers, &forward::owned_headers(credential.presentation, &credential.field))?;
        let cleared = Cleared {
            use_id: format!("use-{}", &crate::token()[..16]),
            realm_id: self.realm.id.clone(),
            capability_id: claims.id.clone(),
            principal_id: claims.principal_id.clone(),
            device_id: claims.device_id.clone(),
            workload_id: claims.workload_id.clone(),
            approval_id: claims.approval_id.clone(),
            credential_id: credential.id.clone(),
            presentation: credential.presentation,
            field: credential.field.clone(),
            settings: credential.settings.clone(),
            shape: credential.shape(),
            entry: vault::Entry::of(&credential),
            fingerprint: credential.fingerprint.clone(),
            generation: credential.generation,
            realm_generation: self.store.realm_generation()?,
            policy_version: self.store.policy_version()?,
            maximum_bytes,
            place,
            outgoing: Outgoing { method, target, headers, body: ask.body.clone() },
        };
        self.opening_use(&cleared, now)?;
        Ok(cleared)
    }

    /// The last look, against the realm as it is at this instant and against the request as it
    /// will actually go out.
    ///
    /// It refuses if the credential has been retired or rotated, the place has left its list, the
    /// target has stopped lying inside that place, the realm's egress or lifecycle has changed,
    /// the method or path is no longer allowed, the grant has been taken back, the agreement has
    /// run out, the account or the computer has been withdrawn, the policy has moved, or the
    /// request carries a header the credential owns or the forwarder reserves.
    ///
    /// The agreement is looked for as an allowance first and as a request second, because
    /// `claims.approval_id` names a request on both paths: `agreement_for` returns the allowance's
    /// `approval_id`, which is the request it came from. A request's own life is short while the
    /// allowance it created runs for hours, so checking the request alone would refuse every
    /// standing-allowance use the moment the original request lapsed.
    pub fn still_clear(&self, cleared: &Cleared, now: i64) -> Result<(), String> {
        let gone = |what: &str| Err(format!("{what} changed between the agreement and the moment this request would have been sent"));
        let realm = self.store.realm()?;
        if realm.id != cleared.realm_id || !realm.can(Capability::Credentials) || !realm.lifecycle.serves() {
            return gone("This grid");
        }
        if self.store.realm_generation()? != cleared.realm_generation {
            return gone("This grid's trust");
        }
        if self.store.policy_version()? != cleared.policy_version {
            return gone("This grid's policy");
        }
        if !self.store.principal(&cleared.principal_id)?.is_some_and(|person| person.active()) {
            return gone("This account");
        }
        if !self.store.device(&cleared.device_id)?.is_some_and(|device| device.active()) {
            return gone("This computer");
        }
        let credential = self.store.credential(&cleared.credential_id)?.ok_or_else(|| "This credential is no longer in this grid".to_owned())?;
        if !credential.live(now) || credential.generation != cleared.generation {
            return gone("This credential");
        }
        if credential.vault.id != cleared.entry.vault_id || credential.vault.version != cleared.entry.version {
            return gone("The entry this credential's value is in");
        }
        // Asked again, so that taking back the permission to travel in the URL, or changing a
        // token endpoint, stops the next request the way every other withdrawal does. The digest
        // catches the changes `ready_to_send` would still accept, such as a region moved from one
        // valid one to another.
        credential.ready_to_send()?;
        if credential.shape() != cleared.shape {
            return gone("How this credential travels");
        }
        let target = &cleared.outgoing.target;
        if !credential.places().iter().any(|place| place == &cleared.place) || !forward::within(target, &cleared.place) {
            return gone("Where this credential may be sent");
        }
        Core::egress_allows(&realm, target)?;
        for endpoint in mint::endpoints(credential.presentation, &credential.settings)? {
            if Core::egress_allows(&realm, &endpoint).is_err() {
                return gone("Whether this grid may reach where this credential's token is made");
            }
        }
        if !credential.allows(&cleared.outgoing.method, &target.path) {
            return gone("What this credential may be used for");
        }
        let grant = self.store.grant_for(&credential.id, &cleared.principal_id)?.ok_or_else(|| "This credential has been taken back".to_owned())?;
        if !grant.covers(&cleared.outgoing.method, &target.path, now) {
            return gone("What they may use this credential for");
        }
        self.agreement_stands(cleared.approval_id.as_deref(), now)?;
        if cleared.outgoing.body.len() as u64 > credential.maximum_bytes.unwrap_or(forward::MAX_BODY as u64) {
            return gone("How much this credential may carry");
        }
        let owned = forward::owned_headers(credential.presentation, &credential.field);
        for (name, _) in &cleared.outgoing.headers {
            let lower = name.to_ascii_lowercase();
            if RESERVED_HEADERS.contains(&lower.as_str()) || owned.contains(&lower) {
                return Err(format!("This request carries {lower}, which the grid itself sets"));
            }
        }
        Ok(())
    }

    /// Which of a credential's places this request is confined to.
    ///
    /// Only a place the credential itself holds, and that the target lies inside, can be chosen.
    /// Which of several the permission named is read out of the permission without trusting it:
    /// the signature over it is checked by `accept` a moment later, and a permission naming a
    /// place this credential no longer holds falls back to the first that does, where `accept`
    /// then refuses it for naming a different destination.
    fn place_for(credential: &Credential, target: &Target, token: &str) -> Result<String, String> {
        let inside: Vec<String> = credential.places().into_iter().filter(|place| forward::within(target, place)).collect();
        let Some(first) = inside.first().cloned() else {
            return Err(format!("{} is not a place this credential may be sent to", target.shown()));
        };
        let named = Authority::peek(token).and_then(|claims| claims.destination);
        Ok(named.filter(|named| inside.contains(named)).unwrap_or(first))
    }

    /// Whether the realm's own outbound rules allow this target, by the same matcher a
    /// credential's places go through, so there is one way an address is compared and not two.
    fn egress_allows(realm: &super::realm::Realm, target: &Target) -> Result<(), String> {
        if !realm.network.outbound {
            return Err("This grid is not reaching anything outside it at the moment".into());
        }
        if realm.network.destinations.is_empty() || realm.network.destinations.iter().any(|allowed| forward::within(target, allowed)) {
            return Ok(());
        }
        Err(format!("This grid does not reach {}", target.origin()))
    }

    /// Whether the agreement a permission came from still stands. See `still_clear` for why an
    /// allowance is looked for first.
    ///
    /// What the request was asked for is read again here, at the moment the value would go out,
    /// and not taken on the word of the permission that names it. Approving a credential and
    /// approving research are separate permissions, and this is the last place that distinction
    /// can still hold.
    fn agreement_stands(&self, approval_id: Option<&str>, now: i64) -> Result<String, String> {
        let Some(id) = approval_id else {
            return Err("This permission does not name an agreement, so nothing allows this use".into());
        };
        if !self.asked_to_use_a_credential(id)? {
            return Err("The agreement this use came from was given for something other than using a credential".into());
        }
        if self.store.allowance_from(id, now)? {
            return Ok(id.to_owned());
        }
        match self.store.request(id)? {
            Some(request) if request.stands(now) => Ok(id.to_owned()),
            _ => Err("The agreement this use came from has run out; ask again".into()),
        }
    }

    /// Opens the record of one request, before any value is read.
    fn opening_use(&mut self, cleared: &Cleared, now: i64) -> Result<(), String> {
        self.store.open_use(&Use {
            id: cleared.use_id.clone(),
            realm_id: cleared.realm_id.clone(),
            credential_id: cleared.credential_id.clone(),
            capability_id: cleared.capability_id.clone(),
            approval_id: cleared.approval_id.clone(),
            principal_id: cleared.principal_id.clone(),
            device_id: cleared.device_id.clone(),
            workload_id: cleared.workload_id.clone(),
            destination: cleared.place.clone(),
            method: cleared.outgoing.method.clone(),
            path: cleared.outgoing.target.path.clone(),
            request_bytes: cleared.outgoing.body.len() as u64,
            answer_bytes: None,
            status: None,
            vault_id: cleared.entry.vault_id.clone(),
            vault_version: cleared.entry.version,
            outcome: "opening".into(),
            reason: String::new(),
            policy_version: cleared.policy_version,
            started_at: now,
            finished_at: None,
        })
    }

    /// Closes it, once, and writes the one event for it. The query is never in either, because a
    /// query credential's value travels in it.
    pub fn closing_use(&mut self, cleared: &Cleared, ended: &Ended, now: i64) -> Result<(), String> {
        let (status, bytes) = match ended {
            Ended::Sent { status, bytes } => (Some(*status), Some(*bytes)),
            _ => (None, None),
        };
        self.store.close_use(&cleared.use_id, ended.outcome(), ended.word(), status, bytes, now)?;
        let action = match ended {
            Ended::Sent { .. } => "credential.sent",
            Ended::Refused(..) => "credential.refused",
            Ended::Failed(..) => "credential.failed",
        };
        let decision = if matches!(ended, Ended::Sent { .. }) { Decision::Allowed } else { Decision::Refused };
        let entry = Entry::new(&self.realm.id, &cleared.principal_id, action, decision)
            .about(Capability::Credentials, &cleared.credential_id)
            .from(&cleared.device_id)
            .for_work(&cleared.workload_id)
            .because(&format!("{} {} at {}: {}", cleared.outgoing.method, cleared.outgoing.target.path, cleared.place, ended.say()));
        self.note(entry, now)
    }

    /// Closes records left open by a hub that stopped between opening one and closing it.
    ///
    /// `opening` is not proof that the request never reached the service: the hub may have gone
    /// away with the request already on the wire. These are closed as unknown, which is what is
    /// actually known about them.
    pub fn reap_open_uses(&mut self, now: i64) -> Result<usize, String> {
        let open = self.store.open_uses(now - OPEN_FOR)?;
        let mut closed = 0;
        for row in &open {
            if self.store.close_use(&row.id, "unknown", "abandoned", None, None, now).is_ok() {
                closed += 1;
            }
        }
        if closed > 0 {
            self.note(
                Entry::new(&self.realm.id, "owner", "credential.unknown", Decision::Refused)
                    .about(Capability::Credentials, "")
                    .because(&format!("{closed} requests were left open by a hub that stopped; whether each one reached its service is not known")),
                now,
            )?;
        }
        Ok(closed)
    }

    // ---- What an administrator does with all this ----

    /// Hands a piece of work a permission to use a credential once, in one way, to one of the
    /// places it may be sent. `destination` picks which one; nothing picks more than one.
    pub fn use_credential_to(
        &mut self,
        principal_id: &str,
        device_id: &str,
        workload_id: &str,
        credential_id: &str,
        destination: Option<&str>,
        method: &str,
        path: &str,
        seconds: i64,
        now: i64,
    ) -> Result<String, String> {
        if !self.realm.can(Capability::Credentials) {
            return Err("This grid does not broker credentials".into());
        }
        if !self.realm.lifecycle.serves() {
            return Err("This grid is not serving work at the moment".into());
        }
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        // Refused here as well as at the send, so nobody is handed a permission for a credential
        // this grid would not put on a request anyway.
        credential.ready_to_send()?;
        let places = credential.places();
        let place = match destination {
            Some(wanted) => {
                let wanted = super::credential::destination_of(wanted)?;
                places.iter().find(|place| *place == &wanted).cloned().ok_or_else(|| format!("This credential may not be sent to {wanted}"))?
            }
            None => places.first().cloned().ok_or("This credential has nowhere it may be sent; give it a destination first")?,
        };
        let person = self.person(principal_id)?;
        if !person.active() {
            return Err("This account is suspended".into());
        }
        let device = self.store.device(device_id)?.filter(|device| device.active()).ok_or("This computer is not in this grid")?;
        if device.principal_id != principal_id {
            return Err("That computer belongs to someone else".into());
        }
        if !credential.allows(method, path) {
            return Err(format!("This credential is not for {} {path}", method.to_ascii_uppercase()));
        }
        let grant = self.store.grant_for(credential_id, principal_id)?.ok_or("Nobody has given them this credential")?;
        if !grant.covers(method, path, now) {
            return Err(format!("They may not use this credential for {} {path}", method.to_ascii_uppercase()));
        }
        let approval_id = self.agreement_for(&credential, principal_id, method, path, now)?;
        let mut claims = super::capability::Claims::new(&self.realm.id, Capability::Credentials, principal_id, device_id, workload_id, credential_id, now, seconds)
            .bound_to(&place, method, path, credential.maximum_bytes.unwrap_or(1 << 20));
        claims.approval_id = Some(approval_id);
        let token = self.mint(&claims)?;
        self.note(
            Entry::new(&self.realm.id, principal_id, "credential.lent", Decision::Allowed)
                .about(Capability::Credentials, credential_id)
                .from(device_id)
                .for_work(workload_id)
                .because(&format!("{} {path} at {place}", method.to_ascii_uppercase())),
            now,
        )?;
        Ok(token)
    }

    /// Adds a place a credential may be sent.
    pub fn allow_destination(&mut self, by: &str, credential_id: &str, destination: &str, now: i64) -> Result<String, String> {
        self.allowed(by, super::identity::Action::ManageCredentials)?;
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        let destination = super::credential::destination_of(destination)?;
        if super::credential::looks_like_a_secret(&destination) {
            return Err("A destination is an address, not a secret".into());
        }
        self.store.put_destination(credential_id, &destination, by, now)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.destination allowed", Decision::Allowed).about(Capability::Credentials, credential_id).because(&destination),
            now,
        )?;
        Ok(destination)
    }

    /// Takes one away. The last one cannot go: a credential with nowhere to be sent is not a
    /// credential this grid will send, and retiring it is how it is taken out of use.
    pub fn deny_destination(&mut self, by: &str, credential_id: &str, destination: &str, now: i64) -> Result<(), String> {
        self.allowed(by, super::identity::Action::ManageCredentials)?;
        let destination = super::credential::destination_of(destination)?;
        let places = self.store.destinations(credential_id)?;
        if places.len() <= 1 && places.contains(&destination) {
            return Err("A credential needs somewhere it may be sent; retire it instead".into());
        }
        if self.store.drop_destination(credential_id, &destination)? == 0 {
            return Err("This credential was not being sent there".into());
        }
        self.note(
            Entry::new(&self.realm.id, by, "credential.destination denied", Decision::Allowed).about(Capability::Credentials, credential_id).because(&destination),
            now,
        )
    }

    /// Every place one credential may be sent.
    pub fn destinations(&self, credential_id: &str) -> Result<Vec<String>, String> {
        self.store.destinations(credential_id)
    }

    /// Lets one credential's value travel in the URL, on an administrator's say-so.
    ///
    /// This is the only way a query credential becomes sendable. The reason it is a decision
    /// somebody makes by name is that it is the one way of travelling whose consequences this grid
    /// cannot reach: the service's own access log keeps the whole URL, and so does every proxy in
    /// between. Nothing this grid writes carries the query, and the broker keeps it out of the
    /// record and out of the audit reason, but those copies are not ours to delete.
    pub fn allow_query_credential(&mut self, by: &str, credential_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, super::identity::Action::ManageCredentials)?;
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if credential.presentation != super::credential::Kind::Query {
            return Err("This credential does not travel in the URL, so there is nothing to allow".into());
        }
        self.store.set_query_allowed(credential_id, Some((by, now)))?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.in the url allowed", Decision::Allowed)
                .about(Capability::Credentials, credential_id)
                .because("its value will travel in the URL, where the service's own access log and every proxy in between keeps a copy"),
            now,
        )
    }

    /// Takes that back. The next request made with the credential is refused, because the broker
    /// asks again in the last look before it sends.
    pub fn deny_query_credential(&mut self, by: &str, credential_id: &str, now: i64) -> Result<(), String> {
        self.allowed(by, super::identity::Action::ManageCredentials)?;
        self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        self.store.set_query_allowed(credential_id, None)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.in the url denied", Decision::Allowed)
                .about(Capability::Credentials, credential_id)
                .because("its value may no longer travel in the URL"),
            now,
        )
    }

    /// Changes what a minting credential needs besides its value: a token endpoint, a region, a
    /// role. None of it is a value, and the same rules the builder applies are applied here.
    ///
    /// The whole map is replaced rather than one key changed, because the rules are about the map
    /// as a whole: a kind that needs a token endpoint and a client identifier is checked for both,
    /// and a key-at-a-time door would let a credential sit in a half-written state between two
    /// calls. Anything already minted from this credential is dropped from the cache by the
    /// caller; a request already cleared is refused at the last look, because the digest the
    /// broker took will no longer match.
    pub fn set_credential_settings(&mut self, by: &str, credential_id: &str, settings: &[(&str, &str)], now: i64) -> Result<(), String> {
        self.allowed(by, super::identity::Action::ManageCredentials)?;
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        if !credential.live(now) {
            return Err("This credential has been retired".into());
        }
        let changed = credential.clone().minting_as(credential.presentation, settings)?;
        self.store.set_credential_settings(credential_id, &changed.settings)?;
        self.note(
            Entry::new(&self.realm.id, by, "credential.settings", Decision::Allowed)
                .about(Capability::Credentials, credential_id)
                .because(&format!("{} settings for a credential this grid makes a short-lived one from", changed.settings.len())),
            now,
        )
    }

    /// Every place a credential still names in its own row that is not among the places it may be
    /// sent, and why.
    ///
    /// This is the report the upgrade to version 5 owed and did not leave. That step copied each
    /// credential's one destination into the new list with `INSERT OR IGNORE`, so a destination
    /// written by a build whose only rule was that it began `https://` was dropped rather than
    /// aborting the step and stranding the realm at version 4. Nothing said which.
    ///
    /// It is computed from what the realm holds now rather than from a record the step did not
    /// keep, and that is the honest limit of it: a destination an administrator took away by hand
    /// afterwards shows up here as well. The two are told apart by the reason, because one of them
    /// is an address this grid would refuse today and the other is not.
    pub fn destinations_left_out(&self) -> Result<Vec<LeftOut>, String> {
        let mut left_out = Vec::new();
        for credential in self.store.credentials()? {
            let places = credential.places();
            if places.iter().any(|place| place == &credential.destination) {
                continue;
            }
            let why = match super::credential::destination_of(&credential.destination) {
                Err(trouble) => format!("the upgrade to version 5 could not carry it: {trouble}"),
                Ok(written) if written != credential.destination => {
                    format!("the upgrade to version 5 could not carry it as written; this grid would write that address {written}")
                }
                Ok(_) => "this grid would accept that address, so it was taken away after the upgrade rather than left out by it".to_owned(),
            };
            left_out.push(LeftOut { credential_id: credential.id.clone(), credential_name: credential.name.clone(), destination: credential.destination.clone(), why });
        }
        Ok(left_out)
    }

    /// The realm's own outbound rules, which bound every brokered request whatever a credential
    /// allows. There is one outbound list and this is it; turning `outbound` off stops every
    /// credential at once.
    ///
    /// What a realm may reach is decided in one place, `checked_network`, and this door asks it
    /// the same question `Core::set_network` does. A company realm's policy comes back from it
    /// unchanged; a research realm is held to offline, to addressable https destinations, and to
    /// what has actually been admitted to an open scope, here as everywhere else.
    pub fn set_egress(&mut self, by: &str, outbound: bool, destinations: &[&str], now: i64) -> Result<(), String> {
        self.allowed(by, super::identity::Action::ManageSecurity)?;
        let mut written = Vec::new();
        for destination in destinations {
            let destination = super::credential::destination_of(destination)?;
            if !written.contains(&destination) {
                written.push(destination);
            }
        }
        let network = self.checked_network(super::realm::NetworkPolicy { outbound, destinations: written, published: self.realm.network.published }, now)?;
        self.store.set_network(&network)?;
        // The realm is held in memory while it is open, so the copy here is brought up to date
        // rather than left saying what the rules were a moment ago.
        self.realm = self.store.realm()?;
        self.note(
            Entry::new(&self.realm.id, by, "realm.egress", Decision::Allowed).because(&if outbound {
                match self.realm.network.destinations.len() {
                    0 => "anywhere".to_owned(),
                    count => format!("{count} places"),
                }
            } else {
                "nothing leaves".to_owned()
            }),
            now,
        )
    }

    /// The ledger of brokered requests, for an admin view. No value and no query is in it.
    pub fn uses(&self, credential_id: Option<&str>, since: i64) -> Result<Vec<Use>, String> {
        self.store.uses(credential_id, since)
    }

    /// The exact vault entry a rotation has to write, so nobody has to guess the naming.
    ///
    /// Rotation stays two steps and no value ever becomes an argument to Core: the administrator's
    /// tool writes the new value to this entry through `Vault::write`, fingerprints it with
    /// `credential::fingerprint_of`, and then calls `rotate_credential`, which moves the version,
    /// the fingerprint and the generation in one statement.
    pub fn rotation_target(&self, credential_id: &str) -> Result<vault::Entry, String> {
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        Ok(vault::Entry::next(&credential))
    }

    /// Which older versions of a credential's entry can now be taken out of the vault, for an
    /// administrator tidying up after a rotation has settled.
    pub fn retired_entries(&self, credential_id: &str) -> Result<Vec<vault::Entry>, String> {
        let credential = self.store.credential(credential_id)?.ok_or("No such credential is in this grid")?;
        // A retired credential's current version is on nothing, so that one can go as well.
        let last = if credential.retired_at.is_none() { credential.vault.version.saturating_sub(1) } else { credential.vault.version };
        Ok((1..=last)
            .map(|version| vault::Entry { realm_id: credential.realm_id.clone(), vault_id: credential.vault.id.clone(), version })
            .collect())
    }
}
