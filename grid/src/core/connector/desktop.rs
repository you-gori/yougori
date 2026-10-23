//! The four connectors that already exist, behind the seam.
//!
//! Azure Virtual Desktop, Windows 365, Citrix DaaS and Omnissa Horizon are all in
//! `grid/src/provisioning.rs`, and this wraps them rather than rewriting them. That is a
//! deliberate choice and worth saying plainly: those four are the only connectors in this
//! repository that have been exercised against anything, each against a loopback server that
//! imitates the provider, and rewriting them to fit a new shape would have thrown that away and
//! replaced it with a shape nobody has run. So the requests they make, the order they make them
//! in, the headers they set and the sentences they return are all untouched, and their own tests
//! still exercise them directly.
//!
//! Wrapping also puts the one awkward thing in exactly one place. A `provisioning::Task` carries
//! the secret part of the credential, because it is the thing that makes the request; the seam
//! must never carry one. So the value is read here, from this computer's vault, by the name the
//! permission gave, between the permission being checked and the task being built. Nothing above
//! this file can pass a value in and nothing below it can hand one back: `Keyring` is reachable
//! only through this connector's own construction, which is not an argument of any operation.
//!
//! What is honestly lost by wrapping is detail in the failures. A connector underneath returns one
//! sentence, so this cannot tell a refusal that changed nothing from a half-finished change, and
//! it says `Refused` rather than guessing. That is the reason `reconcile` is worth running after
//! a failure even when the failure looked clean.
//!
//! What wrapping does not excuse is leaving these four with none of the restraint every connector
//! written since has. `wire::Keyed` carries a budget, a breaker and a gate, and these four reached
//! their providers with nothing at all in front of them, which is the wrong way round: they are
//! the only connectors here that have ever been pointed at something. So the same three are in
//! front of `provisioning::run` now, along with a deadline over the whole operation. The deadline
//! is the one thing the connectors underneath could not already do for themselves: each HTTP call
//! they make has its own minute, and one operation is a sign-in and then two or three more calls,
//! so a provider that is slow but never times out could hold a caller for four minutes. None of
//! the requests they make, the order they make them in or the headers they set has changed.
use super::registry;
use super::limits::{Breaker, Budget, Gate};
use super::{admits, cleared, Answer, Change, Checked, Connector, Discovery, Found, Note, Notes, Outcome, Plan, Rehearsal, Request, Seen, Settings, Step, Subject, Ticket, Trouble};
use crate::core::audit::Decision;
use crate::enterprise::{Connection, Provider};
use crate::provisioning::{self, Task, Want};
use serde_json::Value;
use std::sync::Mutex;
use std::time::Duration;

/// Where a connector's secret comes from.
///
/// This is the only thing in the whole seam that hands back a value, and it is deliberately not
/// part of the `Connector` trait: a connector is built with one, and no operation takes one, so
/// there is no call anywhere that could carry a secret into a connector or out of it. What an
/// implementation is given is the name of a credential, which is what the permission said; what
/// it hands back is read at that moment and kept by nobody.
pub trait Keyring: Send + Sync {
    /// The secret fields of one credential, by the name the realm knows it under. For these four
    /// providers that is `{"clientSecret": …}` or `{"password": …}`, which is what
    /// `enterprise::Connection::secret_fields` already says each one needs.
    fn open(&self, credential_id: &str) -> Result<Value, String>;
}

/// One of the four desktop services, behind the seam.
pub struct DesktopService {
    provider: Provider,
    /// The registry row this is, so what it claims and what the documentation says are one thing.
    row: &'static str,
    /// The one place its credential may be used, which a permission has to name.
    destination: String,
    /// The connection's own address. Horizon's API lives under it; for the other three it is the
    /// portal a person would open, and the provider's own API addresses are the standard ones.
    url: String,
    settings: Settings,
    keyring: Box<dyn Keyring>,
    budget: Mutex<Budget>,
    breaker: Mutex<Breaker>,
    gate: Gate,
    notes: Notes,
}

/// How long one whole operation against one of these four providers may take.
///
/// Two minutes. One operation is a sign-in followed by two or three more calls, each of which
/// `provisioning.rs` already gives a minute of its own, so without this one operation can hold a
/// caller for four minutes and a sweeper working through a backlog for much longer. Two minutes is
/// comfortably more than any of these providers takes to answer four requests and far less than
/// the sum of the four individual waits, which is the gap this closes.
pub const WHOLE_OPERATION: Duration = Duration::from_secs(120);

impl std::fmt::Debug for DesktopService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DesktopService").field("provider", &self.provider).field("destination", &self.destination).field("settings", &self.settings.names()).finish()
    }
}

/// The registry row each provider is, which is also the name a plan carries.
fn row_for(provider: Provider) -> &'static str {
    match provider {
        Provider::AzureVirtualDesktop => "Azure Virtual Desktop",
        Provider::Windows365 => "Windows 365",
        Provider::Citrix => "Citrix DaaS",
        Provider::Horizon => "Omnissa Horizon",
    }
}

/// What each provider's credential is pointed at: the setting that names it, and the words for it.
fn target_setting(provider: Provider) -> (&'static str, &'static str) {
    match provider {
        Provider::AzureVirtualDesktop => ("applicationGroup", "application group"),
        Provider::Windows365 => ("groupId", "group"),
        Provider::Citrix => ("deliveryGroup", "delivery group"),
        Provider::Horizon => ("pool", "desktop pool"),
    }
}

impl DesktopService {
    /// Builds a connector for one connection.
    ///
    /// `destination` is where the credential may be used and is what a permission has to name.
    /// `url` is the connection's own address. The two are separate because for three of these the
    /// credential is spent at the provider's own API while the address a person opens is a portal,
    /// and because Horizon's API lives under the appliance's address rather than a public one.
    ///
    /// `now` is when the connection was made, and it is here for the same reason `Keyed::new`
    /// takes one: the rate this connection holds itself to starts filling from that moment, and
    /// the core has no clock of its own to ask.
    pub fn new(provider: Provider, destination: &str, url: &str, settings: Settings, keyring: Box<dyn Keyring>, now: i64) -> Result<DesktopService, String> {
        let destination = destination.trim().trim_end_matches('/');
        if !destination.starts_with("https://") || destination.len() > 512 || destination.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
            return Err("A connector's destination is one https:// address".into());
        }
        let url = url.trim().trim_end_matches('/');
        let (secure, host, _, _) = crate::https::parse(url)?;
        if !secure && !matches!(host.as_str(), "127.0.0.1" | "localhost") {
            return Err("A connection's address is an https:// address, unless it is a server on this computer".into());
        }
        if super::carries_a_value(destination) || super::carries_a_value(url) {
            return Err("An address is where something is, not a way into it. Put the secret in this computer's vault.".into());
        }
        Ok(DesktopService {
            provider,
            row: row_for(provider),
            destination: destination.to_owned(),
            url: url.to_owned(),
            settings,
            keyring,
            budget: Mutex::new(Budget::standard(now)),
            breaker: Mutex::new(Breaker::new()),
            gate: Gate::standard(),
            notes: Notes::new(),
        })
    }

    /// Whether this connection has been told everything the provider needs, named in the words an
    /// administrator saw when they entered it.
    fn complete(&self) -> Result<(), Trouble> {
        for (field, what) in Connection::required_target(self.provider) {
            self.settings.needed(field, what)?;
        }
        Ok(())
    }

    /// What this credential is pointed at: the sort of thing and its name at the provider.
    fn target(&self) -> Result<(&'static str, &str), Trouble> {
        let (field, kind) = target_setting(self.provider);
        Ok((kind, self.settings.needed(field, kind)?))
    }

    /// Everything checked before an operation that names a plan: the permission fits this
    /// connector, the connection is complete, and the plan is this connector's and this
    /// credential's. A plan built for another credential is refused here rather than being sent
    /// with whatever secret this connection happens to hold.
    fn fits(&self, ticket: &Ticket, plan: &Plan, now: i64) -> Result<(), Trouble> {
        admits(ticket, &self.destination, now)?;
        self.complete()?;
        if plan.connector() != self.row {
            return Err(Trouble::NotAllowed(format!("This plan is for {}, and this connector is {}", plan.connector(), self.row)));
        }
        if plan.credential_id() != ticket.credential_id() {
            return Err(Trouble::NotAllowed("This plan was made for another credential. Make it again with the permission you hold.".into()));
        }
        Ok(())
    }

    fn record(&self, at: i64, action: &str, decision: Decision, reason: &str) {
        self.notes.keep(Note::new(self.row, at, action, decision, reason));
    }

    /// Whether anything may go out right now: the breaker is shut and the budget has a token.
    /// The same two questions `wire::Keyed::may_send` asks, in the same order and for the same
    /// reasons, because a connector that is wrapped rather than rewritten should still be held to
    /// what every other connector is held to.
    fn may_send(&self, now: i64) -> Result<(), Trouble> {
        let unusable = || Trouble::Refused("This connection is in an unusable state and was not used".to_owned());
        self.breaker.lock().map_err(|_| unusable())?.allow(now)?;
        let wait = self.budget.lock().map_err(|_| unusable())?.take(now).err();
        match wait {
            None => Ok(()),
            Some(seconds) => Err(Trouble::Refused(format!(
                "This connection has made as many requests as it allows itself for the moment. Try again in {seconds} seconds. Nothing was sent."
            ))),
        }
    }

    /// What the breaker makes of how an operation ended.
    ///
    /// The connectors underneath hand back one sentence and no status, so this reads the sentence.
    /// That is worth saying plainly rather than hiding: a provider whose refusal is worded in a way
    /// this does not recognise is counted as an ordinary failure, which opens the breaker after
    /// five rather than stopping at the first, and a provider that is simply refusing this grid's
    /// permission opens it after five too. Neither is wrong, and both are better than nothing in
    /// front of a provider that has stopped answering.
    fn finished(&self, outcome: Result<&str, &str>, now: i64) {
        let Ok(mut breaker) = self.breaker.lock() else { return };
        match outcome {
            Ok(_) => breaker.succeeded(),
            Err(said) => {
                let lowered = said.to_ascii_lowercase();
                if lowered.contains("429") || lowered.contains("too many requests") || lowered.contains("throttl") {
                    breaker.throttled(None, now);
                } else {
                    breaker.failed(now);
                }
            }
        }
    }

    /// Asks the connector underneath to do one thing, unchanged.
    ///
    /// The secret exists on this line and nowhere else in the seam: it is read from the vault by
    /// the name the permission gave, handed to the task that was already written to use it, and
    /// dropped with the task. What goes into a note is the sentence the provider's own connector
    /// returned, which those connectors are written to keep values out of.
    async fn ask(&self, want: Want, ticket: &Ticket, about: Option<&Subject>, action: &str, now: i64) -> Result<String, Trouble> {
        // Before the vault, because a request the budget or the breaker will not let out has no
        // business reading somebody's credential. This is the same order `broker` keeps for the
        // same reason: what can be decided without a value is decided first.
        if let Err(trouble) = self.may_send(now) {
            self.record(now, action, Decision::Refused, trouble.say());
            return Err(trouble);
        }
        // Held for the length of the call, and given back whatever happens to it.
        let place = match self.gate.enter() {
            Ok(place) => place,
            Err(trouble) => {
                self.record(now, action, Decision::Refused, trouble.say());
                return Err(trouble);
            }
        };
        let secret = match self.keyring.open(ticket.credential_id()) {
            Ok(secret) => secret,
            Err(error) => {
                self.record(now, action, Decision::Refused, &error);
                return Err(Trouble::NotAllowed(error));
            }
        };
        let task = Task {
            provider: self.provider,
            url: self.url.clone(),
            target: self.settings.table(),
            secret,
            want,
            email: about.map(|who| who.email().to_owned()).unwrap_or_default(),
            name: about.map(|who| who.name().to_owned()).unwrap_or_default(),
        };
        let answer = tokio::time::timeout(WHOLE_OPERATION, provisioning::run(&task)).await;
        drop(place);
        match answer {
            Ok(Ok(said)) => {
                self.finished(Ok(&said), now);
                self.record(now, action, Decision::Allowed, &said);
                Ok(said)
            }
            Ok(Err(error)) => {
                self.finished(Err(&error), now);
                self.record(now, action, Decision::Refused, &error);
                Err(Trouble::Refused(error))
            }
            // A deadline on something that was going to change the provider is not a refusal
            // that changed nothing: the request may have arrived and the answer may have been
            // lost. That is what `PartlyDone` is for, and `limits::may_retry` refuses to repeat
            // one, so a lost answer cannot become a second change. A deadline on a read changed
            // nothing by construction, so it stays an ordinary refusal and may be repeated.
            Err(_) => {
                let said = format!(
                    "{} did not answer within {} seconds, so this grid stopped waiting.",
                    self.row,
                    WHOLE_OPERATION.as_secs()
                );
                self.finished(Err(&said), now);
                let said = if want == Want::Test {
                    format!("{said} Nothing there was being changed, so nothing was.")
                } else {
                    format!("{said} Whether anything there was changed is not known from here; reconcile this task rather than asking again.")
                };
                self.record(now, action, Decision::Refused, &said);
                Err(if want == Want::Test { Trouble::Refused(said) } else { Trouble::PartlyDone(said) })
            }
        }
    }

    /// How this connector finds the person, in words, which differs by provider and is worth
    /// showing an administrator before anything is sent.
    fn finding(&self, email: &str) -> Step {
        match self.provider {
            Provider::AzureVirtualDesktop | Provider::Windows365 => Step::reading(&format!("find {email} in the Entra ID tenant")),
            Provider::Citrix => Step::reading(&format!("name {email} to Citrix DaaS, which resolves them itself")),
            Provider::Horizon => Step::reading(&format!("find {email} in the directory Horizon uses")),
        }
    }

    /// The one step that changes anything, in the provider's own terms.
    fn moving(&self, change: Change, target: &str) -> Step {
        match (self.provider, change) {
            (Provider::AzureVirtualDesktop, Change::Give) => Step::altering(&format!("assign them the Desktop Virtualization User role on {target}")),
            (Provider::AzureVirtualDesktop, Change::TakeBack) => Step::altering(&format!("remove the Desktop Virtualization User role assignments this grid made for them on {target}")),
            (Provider::Windows365, Change::Give) => Step::altering(&format!("add them to {target}, from which Windows 365 provisions a Cloud PC by its own policy")),
            (Provider::Windows365, Change::TakeBack) => Step::altering(&format!("remove them from {target}, after which Windows 365 retires their Cloud PC by its own policy")),
            (Provider::Citrix, Change::Give) => Step::altering(&format!("add them to the users of {target}")),
            (Provider::Citrix, Change::TakeBack) => Step::altering(&format!("remove them from the users of {target}")),
            (Provider::Horizon, Change::Give) => Step::altering(&format!("entitle them to {target}")),
            (Provider::Horizon, Change::TakeBack) => Step::altering(&format!("remove their entitlement to {target}")),
        }
    }

    /// Which way a compensating action goes. Undoing a plan that gave somebody a desktop takes it
    /// back; undoing one that took it back gives it again.
    fn undoing(change: Change) -> Want {
        match change {
            Change::Give => Want::Revoke,
            Change::TakeBack => Want::Assign,
        }
    }

    fn carrying_out(change: Change) -> Want {
        match change {
            Change::Give => Want::Assign,
            Change::TakeBack => Want::Revoke,
        }
    }
}

/// What the provider's own sentence says about whether anything had to move.
///
/// The connectors underneath already answer a conflict with "already had the application group",
/// "was already in the group" and, when there is nothing to take back, "had no assignment of ours
/// to take back". Reading what they say is the honest option: making them return more would be
/// changing four connectors whose current behaviour is the only behaviour anything here has ever
/// exercised.
fn outcome_of(said: &str) -> Outcome {
    let lowered = said.to_ascii_lowercase();
    if lowered.contains("already") || lowered.contains("no assignment of ours") {
        Outcome::already(said)
    } else {
        Outcome::done(said)
    }
}

impl Connector for DesktopService {
    fn integration(&self) -> &'static str {
        self.row
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> Answer<'a, Discovery> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            self.complete()?;
            let (kind, id) = self.target()?;
            let id = id.to_owned();
            let said = self.ask(Want::Test, ticket, None, "discover", now).await?;
            Ok(Discovery { reached: vec![Found { kind: kind.to_owned(), id, description: said.clone() }], note: said })
        })
    }

    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble> {
        admits(ticket, &self.destination, now)?;
        self.complete()?;
        let (kind, id) = self.target()?;
        let target = format!("{kind} {id}");
        let steps = vec![
            Step::reading(&format!("sign in to {} with the credential this connection holds", self.row)),
            self.finding(request.about.email()),
            self.moving(request.change, &target),
        ];
        Plan::new(self.row, ticket, request.change, request.about.clone(), &target, steps)
    }

    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Checked> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            self.ask(Want::Test, ticket, None, "validate", now).await?;
            Ok(Checked::passed(plan, now))
        })
    }

    fn dry_run<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Rehearsal> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let said = self.ask(Want::Test, ticket, None, "dry run", now).await?;
            Ok(Rehearsal { plan: plan.clone(), reached: true, note: format!("{said}. Nothing was changed: a dry run reads the target and goes no further.") })
        })
    }

    fn observe<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Seen> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let said = self.ask(Want::Test, ticket, None, "observe", now).await?;
            Ok(Seen {
                holds: None,
                note: format!(
                    "{said}. Whether {} already holds it is not something this says: the provider API this connector uses reads the target, not one person's entitlement.",
                    plan.about().email()
                ),
            })
        })
    }

    fn apply<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            let said = self.ask(DesktopService::carrying_out(plan.change()), ticket, Some(plan.about()), "apply", now).await?;
            Ok(outcome_of(&said))
        })
    }

    fn reconcile<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            // The same request as apply. These providers answer a request for something that is
            // already true with a conflict rather than a second membership, so running this twice
            // leaves the tenant exactly as running it once did.
            let said = self.ask(DesktopService::carrying_out(plan.change()), ticket, Some(plan.about()), "reconcile", now).await?;
            Ok(outcome_of(&said))
        })
    }

    fn revoke<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            let said = self.ask(DesktopService::undoing(plan.change()), ticket, Some(plan.about()), "revoke", now).await?;
            Ok(outcome_of(&said))
        })
    }

    fn export_audit(&self) -> Vec<Note> {
        self.notes.take(self.row)
    }
}

/// Whether every provider this module wraps has a registry row, and whether that row still says
/// what this module is. A connector that outgrew its row, or a row that was quietly improved,
/// fails here rather than in a customer's reading of the documentation.
pub fn rows_are_honest() -> Result<(), String> {
    for provider in [Provider::AzureVirtualDesktop, Provider::Windows365, Provider::Citrix, Provider::Horizon] {
        let row = row_for(provider);
        let state = registry::state_of(row).ok_or_else(|| format!("{row} has no row in the registry"))?;
        if state != registry::State::MockTested {
            return Err(format!("{row} is a connector exercised against a loopback server, and its row says {}", state.name()));
        }
    }
    Ok(())
}
