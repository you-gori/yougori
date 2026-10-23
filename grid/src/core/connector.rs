//! The seam every connector goes through, and the reason a connector can never be handed a secret.
//!
//! A connector is the one piece of a grid that talks to somebody else's system. Workspaces need
//! it to seat a person at a desktop service the company already runs; later phases will need it
//! for storage, for directories and for exporting what happened. There is one trait here and
//! nine operations on it, and every profile that wants an outside system goes through them rather
//! than writing its own door.
//!
//! The five that read come first: `discover`, `plan`, `validate`, `dry_run` and `observe`. A
//! connector that can only do those is still useful and can be shipped, because none of them
//! changes anybody's tenant. The four that follow are `apply`, `reconcile`, `revoke` and
//! `export_audit`, and the first three of them cannot be called at all until `validate` has
//! passed for the exact plan being carried out.
//!
//! Three things in here are the whole point.
//!
//! The first is that no argument of any operation can carry a secret value, and that is a fact
//! about the types rather than a request in a comment. Every argument is one of the types defined
//! in this file, every one of them is built through a constructor that checks it, and all of them
//! check the same thing in `carries_a_value`, so there is one rule to read rather than a check
//! in each place. `Settings` also refuses a key whose name promises a secret whatever is in it,
//! so there is no free-form map a caller could smuggle a password through. `Ticket` is read from
//! a permission the realm minted and keeps the claims rather than the bearer string, so a
//! connector learns which credential it may use and never holds anything it could replay or copy
//! into a log. Where a value does have to be read, it is read through the connector's own
//! construction, which is `desktop::Keyring` and is reachable from no operation's arguments.
//!
//! The second is that nothing changes a provider until a plan has been checked. `validate` is the
//! only thing that returns a `Checked`, `apply`, `reconcile` and `revoke` all require one, and a
//! `Checked` is bound to one plan's fingerprint and lapses after `CHECKED_FOR`. Calling apply
//! before validate is not a mistake that gets caught at run time; it is a call that does not
//! compile, because the caller has nothing to pass.
//!
//! The third is that a connector cannot touch the realm. Nothing here is given a `Core` or a
//! `Store`. An operation returns what happened and a list of notes, and whoever called it decides
//! what to write. A connector that fails, or that half finishes and then fails, therefore cannot
//! leave the realm's database in a state nobody chose. What that leaves open is a provider that
//! moved while the realm recorded nothing, and `intent` is the answer to it: the realm writes down
//! what it is about to ask for before it asks, and `sweep` reads those rows back.
//!
//! A fourth thing arrived with the compute and storage adapters. `Request` carries a `Subject`
//! that has to be an email, so this trait models exactly one thing: giving or taking back one
//! named person's access at one provider. Listing the machines a credential reaches is not that
//! shape, and neither is reading a bucket. Those connectors answer `alters_anything` with no, and
//! then every plan they make has reading steps and nothing else, which `cleared` refuses to carry
//! out. Two things that are not this shape at all got their own seams rather than being bent into
//! this one: `super::hardware` for a computer reporting on itself, which has no credential and no
//! person, and `super::export` for a stream of events, which has no person either and for which
//! `revoke` would mean nothing.
use super::audit::{Decision, Entry};
use super::capability::{Authority, Claims};
use super::realm::Capability;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

/// The read-only adapters for cloud compute and object storage, over the one wire seam.
pub mod cloud;
pub mod desktop;
/// What the realm asked a connector to do, written before it is asked.
pub mod intent;
/// How often a connector may reach a provider, when it may try again, and when it stops asking.
pub mod limits;
pub mod registry;
/// People and group membership over SCIM 2.0, which is the one standard that fits this shape.
pub mod scim;
/// Bringing a provider back into step with what the realm decided.
pub mod sweep;
/// One request, with a credential the connector never sees.
pub mod wire;

#[cfg(test)]
mod tests;

/// How long a passed validation stands before the plan has to be checked again. The same quarter
/// hour an approval request waits in `approval`, because both answer the question "is this still
/// true?" and neither should be answered by something somebody checked this morning.
pub const CHECKED_FOR: i64 = 15 * 60;

/// What an operation answers with while it waits for a provider.
///
/// A boxed future rather than an `async fn` on the trait, because a seam later phases plug into
/// has to be usable as `dyn Connector` and an `async fn` in a trait is not. Nothing is added to
/// the build for it: this is the standard library's own future, in a box.
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, Trouble>> + Send + 'a>>;

/// Why an operation did not do what was asked, in words for the person who asked.
///
/// The four are told apart by what a caller can do next, not by where in the code they came from.
/// Only one of them says that something out at the provider may already have moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trouble {
    /// The connector was not given enough to act. Nothing was sent anywhere.
    Missing(String),
    /// The permission does not cover this, or the plan was never checked. Nothing was sent.
    NotAllowed(String),
    /// The provider was asked and said no, or could not be reached. Nothing was changed.
    Refused(String),
    /// Something at the provider was changed and then a later step failed. This is the only
    /// trouble that leaves work behind, and it is why `reconcile` exists.
    PartlyDone(String),
}

impl Trouble {
    pub fn say(&self) -> &str {
        match self {
            Trouble::Missing(words) | Trouble::NotAllowed(words) | Trouble::Refused(words) | Trouble::PartlyDone(words) => words,
        }
    }

    /// Whether anything at the provider may already have moved. A caller that sees this reconciles
    /// rather than assuming the attempt did nothing.
    pub fn changed_something(&self) -> bool {
        matches!(self, Trouble::PartlyDone(_))
    }
}

/// Whether a piece of free text carries a value rather than describing one.
///
/// Every string that enters this seam goes through here, so there is one rule to read rather than
/// a check in each place. `credential::looks_like_a_secret` also calls a long unbroken
/// random-looking run a value, which is right where it is used and wrong here: a tenant, a
/// subscription, a resource group and a directory group are all named by GUIDs, and that rule
/// would refuse every correct setting a Microsoft connector needs. What is refused here are the
/// markers that only a secret carries.
pub fn carries_a_value(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    text.contains("-----BEGIN") || lowered.contains("private key") || ["password=", "secret=", "api_key=", "apikey=", "token=", "bearer "].iter().any(|marker| lowered.contains(marker))
}

/// Whether a setting names something or holds it. A key whose name promises a secret is refused
/// whatever is in it, and so is a value that carries one.
fn names_rather_than_holds(key: &str, value: &str) -> Result<(), String> {
    let name = key.trim();
    if name.is_empty() || name.len() > 64 || !name.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')) {
        return Err("A setting is named in up to 64 letters, digits, dashes and underscores".into());
    }
    let lowered = name.to_ascii_lowercase();
    for promise in ["secret", "password", "passphrase", "token", "apikey", "api_key", "privatekey", "private_key", "credential", "certificate", "pem", "key"] {
        if lowered.contains(promise) {
            return Err(format!("A connector's settings name things. Put {name} in this computer's vault and give the connector a permission naming it."));
        }
    }
    let text = value.trim();
    if text.len() > 1024 || text.chars().any(char::is_control) {
        return Err(format!("The setting {name} is up to 1024 printable characters on one line"));
    }
    if carries_a_value(text) {
        return Err(format!("The setting {name} carries a secret. A connector is given a permission naming a credential, never the credential."));
    }
    Ok(())
}

/// What a connector needs to know about where it is pointed: a tenant, a group, a pool, a site.
/// Identifiers only. There is no way to put a value in one, which is what makes "a connector
/// never receives a secret" a fact about this type rather than a rule somebody has to remember.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    entries: BTreeMap<String, String>,
}

impl Settings {
    pub fn new() -> Settings {
        Settings::default()
    }

    /// Adds one setting, or says why it is not a setting.
    pub fn with(mut self, key: &str, value: &str) -> Result<Settings, String> {
        names_rather_than_holds(key, value)?;
        self.entries.insert(key.trim().to_owned(), value.trim().to_owned());
        Ok(self)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str).filter(|value| !value.is_empty())
    }

    /// One setting that has to be there, with the words to tell somebody which one is missing.
    pub fn needed(&self, key: &str, what: &str) -> Result<&str, Trouble> {
        self.get(key).ok_or_else(|| Trouble::Missing(format!("This connection has no {what}. Enter it on the connection and try again.")))
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// The settings as a plain table, for a connector that has to hand them to something older.
    pub fn table(&self) -> BTreeMap<String, String> {
        self.entries.clone()
    }
}

/// A permission naming a credential, which is the only thing a connector is ever given about one.
///
/// The realm mints the permission and accepts it; this reads what it says. The bearer string is
/// deliberately not kept: a connector needs to know which credential it may use, where it may be
/// used and until when, and it needs none of that to be something it could hand on to anybody
/// else. `Debug` prints identifiers and a time, never anything that could be presented.
#[derive(Clone)]
pub struct Ticket {
    claims: Claims,
}

impl Ticket {
    /// Reads a permission the realm minted. The signature is not checked here and is not meant to
    /// be: the realm accepts the permission through `Core::accept` before a connector is called,
    /// and this is how the connector learns what it may touch, not how it is authorised.
    pub fn read(token: &str, now: i64) -> Result<Ticket, String> {
        Ticket::of(Authority::peek(token).ok_or("This permission is not readable")?, now)
    }

    /// The permission the realm has just accepted, without reading it twice.
    pub fn accepted(claims: Claims, now: i64) -> Result<Ticket, String> {
        Ticket::of(claims, now)
    }

    fn of(claims: Claims, now: i64) -> Result<Ticket, String> {
        if claims.capability != Capability::Credentials {
            return Err("A connector is given a permission to use a credential, and this one is for something else".into());
        }
        if claims.destination.as_deref().unwrap_or_default().trim().is_empty() {
            return Err("A connector's permission has to name the one place it may be used".into());
        }
        if now >= claims.expires_at {
            return Err("This permission has expired".into());
        }
        Ok(Ticket { claims })
    }

    pub fn realm_id(&self) -> &str {
        &self.claims.realm_id
    }

    /// Which credential this names. Never its value, which this type has no field for.
    pub fn credential_id(&self) -> &str {
        &self.claims.resource_id
    }

    /// The one place it may be used.
    pub fn destination(&self) -> &str {
        self.claims.destination.as_deref().unwrap_or_default()
    }

    pub fn principal_id(&self) -> &str {
        &self.claims.principal_id
    }

    pub fn device_id(&self) -> &str {
        &self.claims.device_id
    }

    pub fn workload_id(&self) -> &str {
        &self.claims.workload_id
    }

    pub fn expires_at(&self) -> i64 {
        self.claims.expires_at
    }

    pub fn live(&self, now: i64) -> bool {
        now < self.claims.expires_at
    }
}

impl std::fmt::Debug for Ticket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ticket")
            .field("credential", &self.claims.resource_id)
            .field("destination", &self.claims.destination)
            .field("expires_at", &self.claims.expires_at)
            .finish()
    }
}

/// What every operation checks about its permission before it does anything at all: that it has
/// not run out, and that it is for this provider and not another one.
pub fn admits(ticket: &Ticket, destination: &str, now: i64) -> Result<(), Trouble> {
    if !ticket.live(now) {
        return Err(Trouble::NotAllowed("This permission has expired. Ask for it again.".into()));
    }
    if ticket.destination() != destination {
        return Err(Trouble::NotAllowed(format!("This permission is for {}, and this connector reaches {destination}", ticket.destination())));
    }
    Ok(())
}

/// Which way a plan moves: somebody gets what the provider offers, or it is taken back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Change {
    Give,
    TakeBack,
}

impl Change {
    pub fn word(self) -> &'static str {
        match self {
            Change::Give => "give",
            Change::TakeBack => "take back",
        }
    }
}

/// The person a plan is about. Providers know people by their email, so that is what is carried
/// and it is checked rather than taken on trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    email: String,
    name: String,
}

impl Subject {
    pub fn new(email: &str, name: &str) -> Result<Subject, String> {
        let email = email.trim();
        if email.len() < 3 || email.len() > 254 || !email.contains('@') || email.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
            return Err("A provider knows a person by their email, so give one".into());
        }
        let name = crate::label(if name.trim().is_empty() { email } else { name }, "name")?;
        if carries_a_value(email) || carries_a_value(&name) {
            return Err("A person is named by their email and their name, and neither of those is a secret".into());
        }
        Ok(Subject { email: email.to_owned(), name })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// What the realm wants done, for whom.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub change: Change,
    pub about: Subject,
}

impl Request {
    pub fn new(change: Change, about: Subject) -> Request {
        Request { change, about }
    }
}

/// One thing a plan would do, in words a person can read, and whether doing it changes anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub what: String,
    /// False for a step that only reads. A plan whose steps all read changes nothing, and a dry
    /// run of it is the whole of it.
    pub alters: bool,
}

impl Step {
    pub fn reading(what: &str) -> Step {
        Step { what: what.to_owned(), alters: false }
    }

    pub fn altering(what: &str) -> Step {
        Step { what: what.to_owned(), alters: true }
    }
}

/// What a connector would do, worked out without reaching anybody.
///
/// A plan is also the thing a validation is bound to. Its fingerprint covers everything in it, so
/// a plan that has been edited since it was checked is a plan that has not been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    connector: &'static str,
    credential_id: String,
    change: Change,
    about: Subject,
    target: String,
    steps: Vec<Step>,
}

impl Plan {
    /// A plan for one person at one target. The target and the steps are checked here for the
    /// same reason a setting is: a plan is shown to an administrator, carried in a fingerprint and
    /// described in the audit, and none of that is a place for a value.
    pub fn new(connector: &'static str, ticket: &Ticket, change: Change, about: Subject, target: &str, steps: Vec<Step>) -> Result<Plan, Trouble> {
        if carries_a_value(target) || steps.iter().any(|step| carries_a_value(&step.what)) {
            return Err(Trouble::NotAllowed("A plan says what would be done, in words. It is not somewhere a secret goes.".into()));
        }
        Ok(Plan { connector, credential_id: ticket.credential_id().to_owned(), change, about, target: target.to_owned(), steps })
    }

    pub fn connector(&self) -> &'static str {
        self.connector
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn change(&self) -> Change {
        self.change
    }

    pub fn about(&self) -> &Subject {
        &self.about
    }

    /// What at the provider this acts on, in words.
    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    /// Whether carrying this out would change anything at the provider.
    pub fn alters(&self) -> bool {
        self.steps.iter().any(|step| step.alters)
    }

    pub fn describe(&self) -> String {
        format!("{} {} {}: {}", self.change.word(), self.about.email, self.target, self.steps.iter().map(|step| step.what.as_str()).collect::<Vec<_>>().join("; "))
    }

    /// What a validation is bound to. Everything a person could have edited is in it, so changing
    /// the plan after it was checked makes the check stop covering it.
    ///
    /// Public because an intent row written now has to recognise the same plan hours later, when
    /// the sweeper re-plans it. It is a digest and carries nothing anybody typed.
    pub fn fingerprint(&self) -> String {
        let steps: Vec<String> = self.steps.iter().map(|step| format!("{}:{}", if step.alters { "alters" } else { "reads" }, step.what)).collect();
        crate::digest(
            "connector-plan",
            &format!("{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}", self.connector, self.credential_id, self.change.word(), self.about.email, self.target, steps.join("\u{1e}")),
        )
    }
}

/// Proof that one plan passed its connector's own checks, a moment ago.
///
/// Only `Connector::validate` returns one, and `apply`, `reconcile` and `revoke` all require one,
/// so a caller that has not validated has nothing to pass and the call does not compile. The
/// run-time part of the gate is in `cleared`: the proof covers one plan and lapses, so a plan
/// edited after it was checked, or checked an hour ago, is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    connector: &'static str,
    fingerprint: String,
    at: i64,
    until: i64,
}

impl Checked {
    /// Recorded by a connector when its own checks have passed for this exact plan.
    pub fn passed(plan: &Plan, now: i64) -> Checked {
        Checked { connector: plan.connector, fingerprint: plan.fingerprint(), at: now, until: now + CHECKED_FOR }
    }

    pub fn at(&self) -> i64 {
        self.at
    }

    pub fn until(&self) -> i64 {
        self.until
    }
}

/// The words a connector that only reads refuses with, in one place, so every read-only connector
/// says the same thing to an administrator rather than each inventing its own sentence.
///
/// `row` is the registry row the connector names, which is what an administrator sees in the
/// documentation, so the refusal and the matrix use the same words for the same thing.
pub fn reads_only(row: &str) -> Trouble {
    Trouble::NotAllowed(format!(
        "{row} only reads. It can say what this credential reaches and what is true at the provider now, and it changes nothing there."
    ))
}

/// The gate in front of everything that changes a provider. Every connector calls this first.
///
/// A plan with no altering step is refused here, which is what makes a read-only connector
/// structurally unable to change a tenant rather than merely written not to. `apply`, `reconcile`
/// and `revoke` all need a `Checked`, a `Checked` is only ever handed to this function, and this
/// function refuses the only kind of plan a read-only connector can make. There is no path from a
/// connector whose `alters_anything` is false to a request that moves anything.
pub fn cleared(plan: &Plan, checked: &Checked, now: i64) -> Result<(), Trouble> {
    if !plan.alters() {
        return Err(reads_only(plan.connector));
    }
    if checked.connector != plan.connector {
        return Err(Trouble::NotAllowed(format!("This plan was checked for {}, not for {}. Check it again before carrying it out.", checked.connector, plan.connector)));
    }
    if checked.fingerprint != plan.fingerprint() {
        return Err(Trouble::NotAllowed("This is not the plan that was checked. Check it again before carrying it out.".into()));
    }
    if now >= checked.until {
        return Err(Trouble::NotAllowed("This plan was checked too long ago. Check it again before carrying it out.".into()));
    }
    Ok(())
}

/// One thing a credential turned out to reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// What sort of thing it is at the provider: an application group, a delivery group, a pool.
    pub kind: String,
    pub id: String,
    /// What the provider said about it, in its own words.
    pub description: String,
}

/// What a credential reaches, which is the first question anybody asks of a new connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Discovery {
    pub reached: Vec<Found>,
    pub note: String,
}

/// A plan, and the evidence that running the dry run changed nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rehearsal {
    pub plan: Plan,
    /// Whether the provider was actually reached. A rehearsal that reached nobody says so rather
    /// than letting an admin believe it proved the credential works.
    pub reached: bool,
    pub note: String,
}

impl Rehearsal {
    /// The steps that would change something, which is what an admin is really being shown.
    pub fn would_change(&self) -> Vec<&Step> {
        self.plan.steps.iter().filter(|step| step.alters).collect()
    }
}

/// What the provider says is true now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// Whether the person already has what the plan would give them, when the provider API this
    /// connector uses can say. Nothing is the honest answer when it cannot, and the note says why.
    pub holds: Option<bool>,
    pub note: String,
}

/// What carrying a plan out actually did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Whether anything at the provider moved.
    pub changed: bool,
    /// Whether the provider said it was already this way. This is what makes applying a plan twice
    /// safe, and a connector reports it rather than inferring it from its own memory.
    pub already: bool,
    pub note: String,
}

impl Outcome {
    pub fn done(note: &str) -> Outcome {
        Outcome { changed: true, already: false, note: note.to_owned() }
    }

    pub fn already(note: &str) -> Outcome {
        Outcome { changed: false, already: true, note: note.to_owned() }
    }
}

/// One thing a connector did, in the shape the realm seals.
///
/// A connector writes nothing to a realm. It keeps these and hands them over through
/// `export_audit`, and whoever called the connector turns each into an `Entry` and notes it. That
/// way a connector that fails, or that is never trusted with a realm at all, still leaves a
/// record, and the record is written by the thing that holds the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub at: i64,
    pub connector: &'static str,
    /// What was attempted: `discover`, `apply`, `revoke` and so on.
    pub action: String,
    pub decision: Decision,
    /// Why, in words for a person. Never a secret: these are the provider's own sentences and the
    /// connectors that produce them are written to keep values out of them.
    pub reason: String,
}

impl Note {
    pub fn new(connector: &'static str, at: i64, action: &str, decision: Decision, reason: &str) -> Note {
        Note { at, connector, action: action.to_owned(), decision, reason: reason.chars().filter(|letter| !letter.is_control()).take(500).collect() }
    }

    /// The same thing as one of the realm's own entries, ready to be sealed by whoever holds the
    /// realm's key.
    pub fn entry(&self, realm_id: &str, principal_id: &str, credential_id: &str) -> Entry {
        Entry::new(realm_id, principal_id, &format!("connector.{}", self.action), self.decision)
            .about(Capability::Credentials, credential_id)
            .because(&format!("{}: {}", self.connector, self.reason))
    }
}

/// The notes one connector is holding until somebody takes them.
///
/// Every connector used to keep its own `Vec<Note>` and hand back a copy, and both halves of that
/// were wrong in the same way: nothing ever emptied it, so a connector that is never asked for its
/// notes grows for as long as the process runs, and a connector that is asked twice hands the same
/// note over twice, so a sweeper working through a hundred tasks sealed the first task's notes a
/// hundred times into the realm's history.
///
/// So this is the one note book, it is bounded, and taking the notes empties it. What a cap costs
/// has to be said rather than hidden: once `MOST` are waiting, the oldest go, and `take` says in
/// its first note how many went and what to do about it. The newest are kept because they are the
/// ones that describe what the connector is doing now; the record of what actually changed a
/// provider is the realm's own connector task row and does not depend on a note surviving.
#[derive(Debug, Default)]
pub struct Notes {
    held: std::sync::Mutex<Kept>,
}

#[derive(Debug, Default)]
struct Kept {
    notes: std::collections::VecDeque<Note>,
    /// How many were dropped since the last time anybody took them.
    dropped: usize,
}

impl Notes {
    /// How many notes one connector holds before the oldest start going.
    ///
    /// Five hundred and twelve. One connector task is nine operations and each writes at most one
    /// note, so this is more than fifty tasks' worth for a caller that never drains, and it is
    /// small enough that a connector nobody drains holds a few hundred kilobytes rather than
    /// whatever a process that ran for a month would reach.
    pub const MOST: usize = 512;

    pub fn new() -> Notes {
        Notes::default()
    }

    /// Keeps one note. A poisoned lock loses the note rather than failing the operation the note
    /// is about, which is the same choice the connectors made before this type existed.
    pub fn keep(&self, note: Note) {
        let Ok(mut kept) = self.held.lock() else { return };
        if kept.notes.len() >= Notes::MOST {
            kept.notes.pop_front();
            kept.dropped += 1;
        }
        kept.notes.push_back(note);
    }

    /// Takes every note and leaves the connector holding none.
    ///
    /// When notes were dropped, the first note handed back says so, because a history that is
    /// missing part of a run and does not say it is missing is worse than one that is short. That
    /// note is stamped with the time of the oldest note still held, because the dropped ones all
    /// happened before it; nothing here reads a clock.
    pub fn take(&self, connector: &'static str) -> Vec<Note> {
        let Ok(mut kept) = self.held.lock() else { return Vec::new() };
        let dropped = std::mem::take(&mut kept.dropped);
        let at = kept.notes.front().map(|note| note.at).unwrap_or_default();
        let mut taken: Vec<Note> = kept.notes.drain(..).collect();
        if dropped > 0 {
            taken.insert(
                0,
                Note::new(
                    connector,
                    at,
                    "notes dropped",
                    Decision::Refused,
                    &format!(
                        "This connector was holding {} notes, which is all it keeps, so the {dropped} oldest were dropped before this. Take a connector's notes after each task, through settle_connector_task, so that none is lost.",
                        Notes::MOST
                    ),
                ),
            );
        }
        taken
    }

    /// How many are waiting, for a test and for a reading. Never a reason to leave them waiting.
    pub fn waiting(&self) -> usize {
        self.held.lock().map(|kept| kept.notes.len()).unwrap_or(0)
    }
}

/// The one way a grid reaches a system somebody else runs.
///
/// Every operation takes the moment it is called, because the core has no clock of its own and a
/// connector should not grow one. `plan` is the only one that is not something you wait for, and
/// that is the point of it: working out what would be done never reaches anybody.
pub trait Connector: Send + Sync {
    /// Which row of `registry::INTEGRATIONS` this is. The registry says what is actually true
    /// about that integration, so a connector naming a row is a connector that cannot claim more
    /// than the documentation does.
    fn integration(&self) -> &'static str;

    /// The one place this connector's credential is used. A permission has to name the same place,
    /// which is what stops a permission minted for one provider being spent at another.
    fn destination(&self) -> &str;

    /// Whether this connector can change anything at a provider at all.
    ///
    /// The default is yes, so the connectors that already exist are untouched by this answer
    /// existing. A connector that only reads answers no, and then every plan it makes has reading
    /// steps and nothing else, which `cleared` refuses to carry out. The answer is therefore
    /// something a caller can ask before it starts, and the refusal is something the seam enforces
    /// whether a caller asked or not: one is for showing an administrator what a connection can
    /// do, the other is for making sure it cannot do more.
    ///
    /// Compute and storage adapters answer no for a reason worth writing down. The trait models
    /// giving or taking back one named person's access, because `Request` carries a `Subject` that
    /// has to be an email. Creating a machine or a bucket is about nobody, so there is no honest
    /// `Request` for it, and widening the trait to make one up would weaken the thing that stops a
    /// connector being handed a person it was never told about.
    fn alters_anything(&self) -> bool {
        true
    }

    /// What this credential reaches. Read-only, and the first thing an admin runs on a new
    /// connection.
    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> Answer<'a, Discovery>;

    /// What would be done for this request. Reaches nobody, so it is not something you wait for.
    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble>;

    /// Whether this plan can be carried out: the settings are complete, the permission fits, and
    /// the provider answers. The only thing that returns a `Checked`.
    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Checked>;

    /// The plan, with the evidence that running this changed nothing.
    fn dry_run<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Rehearsal>;

    /// What the provider says is true now. Read-only.
    fn observe<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Seen>;

    /// Carries out the plan. Needs a `Checked` for this exact plan, taken a moment ago.
    fn apply<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome>;

    /// Carries out the plan again, to make what the provider holds match what the realm decided.
    /// Doing this twice must leave the provider exactly as doing it once did.
    fn reconcile<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome>;

    /// Undoes the plan, whichever way the plan went. Every connector that may change something has
    /// to have this, because a change nobody can undo is a change nobody should have made.
    fn revoke<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome>;

    /// Everything this connector has done since the last time anybody asked, for the realm to seal
    /// into its own chain. Asking empties it: a connector holds its notes only until somebody with
    /// a realm's key takes them, and a note handed over twice is a note sealed into the history
    /// twice.
    fn export_audit(&self) -> Vec<Note>;
}
