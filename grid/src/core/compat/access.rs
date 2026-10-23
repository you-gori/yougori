//! The bridge from the shipped Access Grid hub onto Grid Core's credentials profile.
//!
//! The hub keeps one record: the people who sign in, the computers they stay signed in on, the
//! company credentials it holds, and the rules that say who may use what for what. The core keeps
//! a realm: accounts with roles, the computers they act from, credentials that are references to
//! a vault rather than values, and permissions to use them. This turns one into the other, and
//! can turn it back.
//!
//! Nothing here changes the hub's record. Every function takes it by reference, so an Access Grid
//! can be rehearsed and brought across while it is still serving, and the hub goes on owning the
//! credentials until somebody decides otherwise. Nothing here unseals a value, and nothing here
//! could: the sealing key is in that computer's own vault and this crate is never handed it.
//!
//! Four things are said out loud rather than quietly papered over, because a migration that hides
//! what it changed is worth nothing:
//!
//! - **No value comes across.** The record holds each credential's value sealed with the hub's
//!   key; a realm refuses to hold a value at all. What crosses is the name of a vault entry that
//!   nobody has written yet, so every credential arrives recorded and unusable, and the broker
//!   refuses it in words until an administrator puts the value in that entry and records what it
//!   fingerprints to. That is a refusal, never a wrong send.
//! - **A rule that says ask becomes a credential that asks every time.** The hub decides per rule
//!   and the realm decides per credential, so one asking rule makes the whole credential ask. That
//!   is less than the hub allowed, which is the direction a migration is allowed to err in.
//! - **An Access Grid administrator does not become a realm administrator.** They become a
//!   credential administrator, a credential approver and an auditor, which is everything they
//!   could do with credentials, rules and the record. Adding and removing accounts is a realm
//!   administrator's permission, wider than the Access Grid ever granted, and a migration does not
//!   hand it out.
//! - **Decisions cannot be taken back out.** A decided request is written once and never
//!   withdrawn, which the realm's own database enforces, so an import that carried one refuses to
//!   roll back and says why.
use super::{
    observe::{Heading, Observation, Profile, Verdict},
    AccessComparison, AccessImported, AccessRehearsal, Decided, Renamed,
};
use crate::access::{activity, hub, policy};
use crate::core::{
    approval::{Approval, State},
    audit::{Decision, Entry},
    credential::{Credential, Grant, Secret, Vault},
    identity::{Action, Attestation, Device, Principal, PrincipalKind, Role},
    realm::Capability,
    Core,
};

/// The most lines of the hub's own log one import will carry. The hub itself keeps this many in
/// memory for its page, so it is the number an administrator can actually look at, and a bridge
/// that carried an unbounded file would put a copy of the grid's whole history in one transaction.
pub const MOST_ACTIVITY: usize = activity::KEPT;

/// The hub's Access Grid as the core's own shapes, built in memory and written by nobody.
struct Translation {
    /// The account that stands for the grid itself: what the import records things under, as the
    /// other bridges name theirs too.
    grid_account: Principal,
    people: Vec<(String, Principal)>,
    devices: Vec<Device>,
    /// The hub's remembered-computer identifiers against the core's, in the record's own order.
    device_ids: Vec<(String, String)>,
    credentials: Vec<Credential>,
    /// The hub's credential identifiers against the core's, in the record's own order.
    credential_ids: Vec<(String, String)>,
    grants: Vec<Grant>,
    /// Remembered computers that had already stopped being accepted, which arrive withdrawn.
    lapsed: usize,
    /// Rules that forbid outright, which cross as the absence of a permission.
    forbidding: usize,
    notes: Vec<String>,
}

/// The part of a hub identifier that is its own, under the core's name for the same thing, so a
/// person looking at either can see they are the same thing and a migration can be traced without
/// keeping a table of what became what. The other bridges do exactly this.
fn same_tail(prefix: &str, legacy: &str) -> String {
    format!("{prefix}-{}", legacy.rsplit('-').next().unwrap_or(legacy))
}

fn name_of(raw: &str) -> String {
    crate::label(raw, "name").unwrap_or_else(|_| "Computer".to_owned())
}

/// A piece of text as eight hexadecimal characters, so two sides can be compared without the text
/// itself travelling. An observation never carries a name, an address or a path, and a rule's path
/// is a path, so what travels is a digest that says whether two answers are the same and nothing
/// else about what they are.
fn short(text: &str) -> String {
    crate::digest("access-observation", text)[..8].to_owned()
}

/// What a person could do on the hub, said in the realm's words.
///
/// This is the hub's side of the permissions comparison, and the one place where the two differ on
/// purpose: an Access Grid administrator could add and remove people, which in a realm is a realm
/// administrator's permission. The bridge does not grant it, so this reads as the core allowing
/// less, which is what `observe::judge` calls a note rather than a stop.
fn on_the_hub(permission: policy::Permission) -> String {
    let mut roles: Vec<&str> = match permission {
        policy::Permission::Member => vec![Role::User.name()],
        policy::Permission::Approver => vec![Role::User.name(), Role::CredentialApprover.name(), Role::Auditor.name()],
        policy::Permission::Auditor => vec![Role::User.name(), Role::Auditor.name()],
        policy::Permission::Admin => {
            vec![Role::User.name(), Role::CredentialAdmin.name(), Role::CredentialApprover.name(), Role::Auditor.name(), Role::RealmAdmin.name()]
        }
    };
    roles.sort_unstable();
    roles.join(", ")
}

/// What a person becomes in the realm.
///
/// An approver and an administrator both read the whole grid and its activity on the hub, so both
/// carry the auditor permission here; the realm keeps reading policy and reading the history in
/// one role. Nothing implies anything else: `Role::implies` only gives a realm administrator the
/// two approving permissions as separate derived rows, and no account here is made a realm
/// administrator, so every permission an account holds is one this bridge wrote on purpose.
fn roles_of(permission: policy::Permission) -> Vec<Role> {
    let mut roles = match permission {
        policy::Permission::Member => vec![Role::User],
        policy::Permission::Approver => vec![Role::User, Role::CredentialApprover, Role::Auditor],
        policy::Permission::Auditor => vec![Role::User, Role::Auditor],
        policy::Permission::Admin => vec![Role::User, Role::CredentialAdmin, Role::CredentialApprover, Role::Auditor],
    };
    roles.sort();
    roles.dedup();
    roles
}

/// What kind of secret a credential is, from the way it travels. The realm shows this beside a
/// credential and never decides where it goes by it.
fn secret_of(kind: policy::Kind) -> Secret {
    match kind {
        policy::Kind::Bearer => Secret::Token,
        policy::Kind::Header | policy::Kind::Query => Secret::ApiKey,
        policy::Kind::Basic => Secret::Password,
        policy::Kind::Oauth | policy::Kind::GithubApp | policy::Kind::Aws => Secret::ServiceAccount,
    }
}

/// What a minting credential needs besides its value, as the realm writes it.
///
/// The hub keeps these in a loose map, where a number is a number and a key nothing reads is
/// simply carried along; the realm keeps a checked map of text. Numbers become the text of
/// themselves, because `sessionSeconds` is the one that is written as a number and the realm reads
/// it back by parsing. A key the realm has no use for is left behind rather than written down,
/// because a setting nothing reads is a setting somebody believes in.
fn settings_of(kind: policy::Kind, config: &serde_json::Map<String, serde_json::Value>) -> std::collections::BTreeMap<String, String> {
    let (needed, allowed) = crate::core::credential::settings_for(kind);
    let mut settings = std::collections::BTreeMap::new();
    for key in [needed, allowed].concat() {
        let written = match config.get(key) {
            Some(serde_json::Value::String(text)) => text.trim().to_owned(),
            Some(serde_json::Value::Number(number)) => number.to_string(),
            _ => continue,
        };
        if !written.is_empty() {
            settings.insert(key.to_owned(), written);
        }
    }
    settings
}

/// What a credential's value would fingerprint to, which nothing here can know.
///
/// `credential::fingerprint_of` is a digest over the value itself, and the value is sealed with a
/// key this crate is never handed. So what is written is a digest over this bridge's own purpose
/// and the credential's identifier: it is the right shape, it is stable, and it matches no value
/// that exists. The broker compares it against what it reads from the vault and refuses when they
/// differ, so a credential brought across is refused in words until an administrator writes the
/// value into the realm's vault entry and records what that value fingerprints to.
fn placeholder_fingerprint(credential_id: &str) -> String {
    crate::digest("access-credential-not-yet-in-this-realm", credential_id)
}

/// Everything one rule allows one person, gathered across every rule that covers them.
#[derive(Default)]
struct Allowed {
    methods: Vec<String>,
    paths: Vec<String>,
    /// A rule with no method, or no path, allows any of them, and the realm says that with an
    /// empty list. One such rule therefore widens the permission to every method or every path,
    /// exactly as the hub's own matching does.
    any_method: bool,
    any_path: bool,
    expires_at: Option<i64>,
    never_expires: bool,
    /// When the first rule that covered this pair was written. `None` only before any has been
    /// taken, because a rule written at the very start of the epoch is still a rule.
    from: Option<i64>,
}

impl Allowed {
    fn take(&mut self, rule: &policy::Rule) {
        if rule.methods.is_empty() {
            self.any_method = true;
        }
        for method in &rule.methods {
            if !self.methods.contains(method) {
                self.methods.push(method.clone());
            }
        }
        if rule.path.is_empty() {
            self.any_path = true;
        } else if !self.paths.contains(&rule.path) {
            self.paths.push(rule.path.clone());
        }
        match rule.expires_at {
            None => self.never_expires = true,
            Some(at) => self.expires_at = Some(self.expires_at.map_or(at, |held| held.max(at))),
        }
        self.from = Some(self.from.map_or(rule.created_at, |held| held.min(rule.created_at)));
    }
}

/// The hub's Access Grid in the core's shapes. `realm_id` is the realm it would belong to; a
/// rehearsal belongs to no realm, so it passes the grid's own identifier.
fn translate(realm_id: &str, record: &hub::Record, now: i64) -> Result<Translation, String> {
    let mut notes = Vec::new();
    let grid_account = Principal {
        id: same_tail("principal", &record.id),
        realm_id: realm_id.to_owned(),
        kind: PrincipalKind::Service,
        name: name_of(&format!("{} credentials", record.company)),
        email: None,
        roles: Vec::new(),
        created_at: record.created_at,
        suspended_at: None,
    };

    let mut people = Vec::new();
    let mut administrators = 0;
    for person in &record.people {
        if person.permission == policy::Permission::Admin {
            administrators += 1;
        }
        people.push((
            person.id.clone(),
            Principal {
                id: same_tail("principal", &person.id),
                realm_id: realm_id.to_owned(),
                kind: PrincipalKind::Person,
                name: name_of(&person.name),
                email: person.email.clone(),
                roles: roles_of(person.permission),
                created_at: person.created_at,
                suspended_at: None,
            },
        ));
    }
    if administrators > 0 {
        notes.push(format!(
            "{administrators} administrators become credential administrators, credential approvers and auditors, which is everything they could do with credentials, rules and the record; adding and removing accounts is a realm administrator's permission and is not granted here"
        ));
    }
    notes.push("nobody's password, two-step secret or sign-in token comes across: an account in a realm holds no sign-in secret at all".to_owned());
    notes.push(
        "every account arrives holding the realm's one user permission, which also covers using a workspace and calling a model; while this realm brokers credentials alone there is nothing for it to reach, and turning another capability on would widen what these accounts may do"
            .to_owned(),
    );

    let mut devices = Vec::new();
    let mut device_ids = Vec::new();
    let mut lapsed = 0;
    for person in &record.people {
        let Some((_, principal)) = people.iter().find(|(hub_id, _)| hub_id == &person.id) else { continue };
        for device in &person.devices {
            let live = device.live(person, now);
            if !live {
                lapsed += 1;
            }
            device_ids.push((device.id.clone(), same_tail("device", &device.id)));
            devices.push(Device {
                id: same_tail("device", &device.id),
                realm_id: realm_id.to_owned(),
                principal_id: principal.id.clone(),
                name: name_of(&device.computer),
                // The hub never asked a remembered computer what it is, only that it signed in.
                platform: String::new(),
                // The token this computer holds is the hub's, for the hub's own door. It is not
                // carried across, so nothing brought over can act in the realm until it enrols.
                token_hash: String::new(),
                enrolled_at: device.created_at,
                last_seen_at: Some(device.last_used_at),
                // A computer whose sign-in the hub would no longer accept, because the person's
                // generation moved on or because it lapsed, arrives withdrawn rather than live.
                revoked_at: (!live).then_some(device.last_used_at),
                attestation: Attestation::default(),
            });
        }
    }
    if lapsed > 0 {
        notes.push(format!("{lapsed} remembered computers had already stopped being accepted by the hub, and they arrive withdrawn rather than live"));
    }
    notes.push("no computer brought across can act in the realm until it enrols: the token each one holds is the hub's, and it is not carried over".to_owned());

    // What each rule allows whom, gathered per credential and per person, because the realm holds
    // one permission per pair and the hub may cover one pair with several rules. A rule that
    // forbids wins over every other, exactly as `policy::evaluate` decides it.
    let mut allowances: Vec<(String, String, Allowed)> = Vec::new();
    let mut forbidden: Vec<(String, String)> = Vec::new();
    let mut forbidding = 0;
    let mut asking: Vec<String> = Vec::new();
    let mut expired_rules = 0;
    let mut team_rules = 0;
    let mut limited = 0;
    let mut revealing = 0;
    for rule in &record.rules {
        if !record.credentials.iter().any(|credential| credential.id == rule.credential) {
            continue;
        }
        if !rule.live(now) {
            expired_rules += 1;
            continue;
        }
        if matches!(rule.who, policy::Who::Team(_)) {
            team_rules += 1;
        }
        if rule.limit.is_some() && rule.decision == policy::Decision::Allow {
            limited += 1;
        }
        if rule.reveal {
            revealing += 1;
        }
        if rule.decision == policy::Decision::Never {
            forbidding += 1;
        }
        if rule.decision == policy::Decision::Ask && !asking.contains(&rule.credential) {
            asking.push(rule.credential.clone());
        }
        for person in record.people.iter().filter(|person| rule.who.covers(person)) {
            let pair = (rule.credential.clone(), person.id.clone());
            match rule.decision {
                policy::Decision::Never => {
                    if !forbidden.contains(&pair) {
                        forbidden.push(pair);
                    }
                }
                policy::Decision::Allow | policy::Decision::Ask => {
                    match allowances.iter_mut().find(|(credential, who, _)| credential == &pair.0 && who == &pair.1) {
                        Some((_, _, allowed)) => allowed.take(rule),
                        None => {
                            let mut allowed = Allowed::default();
                            allowed.take(rule);
                            allowances.push((pair.0, pair.1, allowed));
                        }
                    }
                }
            }
        }
    }
    if expired_rules > 0 {
        notes.push(format!("{expired_rules} rules had already run out, and they grant nobody anything here, as the hub's own matching leaves them"));
    }
    if forbidding > 0 {
        notes.push(format!(
            "{forbidding} rules forbid outright; a realm says that by granting nobody, so those people arrive with no permission to use that credential rather than with a rule of their own"
        ));
    }
    if team_rules > 0 {
        notes.push(format!("{team_rules} rules are written for a team; a realm has no teams, so each becomes one permission per person who is in that team today"));
    }
    if limited > 0 {
        notes.push(format!("{limited} rules allow only so many uses an hour before an approver decides; a realm has no hourly limit, so those uses arrive allowed without one"));
    }
    if revealing > 0 {
        notes.push(format!(
            "{revealing} rules let somebody ask to see a value; a realm never hands a value out at all, so nothing carries that and those people use the credential through the broker instead"
        ));
    }

    let mut credentials = Vec::new();
    let mut credential_ids = Vec::new();
    let mut unmintable: Vec<String> = Vec::new();
    for credential in &record.credentials {
        let id = same_tail("credential", &credential.id);
        let name = crate::label(&credential.name, "credential name").map_err(|why| format!("The credential {} cannot be brought across: {why}", credential.id))?;
        if crate::core::credential::looks_like_a_secret(&name) {
            return Err(format!("The credential {} is named in a way a realm will not hold: a credential's name is a name, not the secret itself", credential.id));
        }
        let mut places = Vec::new();
        for destination in &credential.destinations {
            let place = crate::core::credential::destination_of(destination)
                .map_err(|why| format!("The credential {} names a destination a realm will not hold: {why}", credential.id))?;
            if !places.contains(&place) {
                places.push(place);
            }
        }
        let destination = places.first().cloned().ok_or_else(|| format!("The credential {} names nowhere it may be sent", credential.id))?;
        // What the rules let anybody do with this credential at all, which is the ceiling the
        // realm puts on it; each person's own permission narrows it again. A rule with no method
        // or no path means any of them, and the realm says that with an empty list.
        let covering = || allowances.iter().filter(|(known, _, _)| known == &credential.id).map(|(_, _, allowed)| allowed);
        let any_method = covering().any(|allowed| allowed.any_method);
        let any_path = covering().any(|allowed| allowed.any_path);
        let mut methods: Vec<String> = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        if !any_method {
            for method in covering().flat_map(|allowed| allowed.methods.iter()) {
                if !methods.contains(method) {
                    methods.push(method.clone());
                }
            }
        }
        if !any_path {
            for path in covering().flat_map(|allowed| allowed.paths.iter()) {
                if !paths.contains(path) {
                    paths.push(path.clone());
                }
            }
        }
        // A credential the hub mints a short-lived one from crosses as what it is, settings and
        // all, because the realm's broker mints the same three kinds now. What does not cross is
        // one whose settings a realm will not hold: the realm checks a token endpoint, a region
        // and a role on the way in, and recording one that failed those checks would be writing
        // down something that reads as working and refuses on first use. Those are counted and
        // named in a note instead of stopping the whole import.
        let settings = settings_of(credential.kind, &credential.config);
        if let Err(why) = crate::core::credential::checked_settings(credential.kind, &settings) {
            unmintable.push(format!("{}: {why}", credential.name));
            continue;
        }
        credentials.push(Credential {
            id: id.clone(),
            realm_id: realm_id.to_owned(),
            name,
            kind: secret_of(credential.kind),
            // The entry the value would live in, which nobody has written. Named after this
            // credential so an administrator filling them in can see which is which.
            vault: Vault { id: crate::core::credential::vault_entry(&same_tail("access", &credential.id))?, version: 1 },
            fingerprint: placeholder_fingerprint(&credential.id),
            destinations: places,
            destination,
            presentation: credential.kind,
            field: if credential.kind.mints() { String::new() } else { credential.field.clone() },
            settings,
            // The hub has no such decision to carry: it sends a query credential's value in the
            // URL on nobody's say-so. So one arrives recorded and unsendable, and an administrator
            // of the realm has to allow it by name before the broker will put it on a request.
            // That is less than the hub allowed, which is the direction a migration may err in.
            query_allowed_by: None,
            query_allowed_at: None,
            generation: 1,
            methods,
            paths,
            maximum_bytes: None,
            owner_id: record
                .people
                .iter()
                .find(|person| person.username == credential.created_by)
                .and_then(|person| people.iter().find(|(hub_id, _)| hub_id == &person.id))
                .map_or_else(|| grid_account.id.clone(), |(_, principal)| principal.id.clone()),
            // One rule that asks makes the whole credential ask, because the hub decides per rule
            // and the realm decides per credential. That is less than the hub allowed, which is
            // the direction a migration is allowed to err in.
            every_time: asking.contains(&credential.id),
            created_at: credential.created_at,
            rotated_at: None,
            rotate_by: None,
            retired_at: None,
        });
        credential_ids.push((credential.id.clone(), id));
    }
    let unused = credentials
        .iter()
        .filter(|credential| !grants_would_cover(&allowances, &forbidden, &credential_ids, &credential.id))
        .count();
    if unused > 0 {
        notes.push(format!("{unused} credentials have no live rule that lets anybody use them, so they arrive with nobody permitted to use them at all, as the hub's own matching leaves them"));
    }
    let every_time = credentials.iter().filter(|credential| credential.every_time).count();
    if every_time > 0 {
        notes.push(format!(
            "{every_time} credentials arrive needing an approver every single time, because at least one rule on each of them asks and a realm decides that per credential rather than per rule"
        ));
    }
    if !unmintable.is_empty() {
        notes.push(format!(
            "{} credentials the hub mints a short-lived credential from do not cross, because a realm checks what each one needs before it holds it and these did not pass: {}",
            unmintable.len(),
            unmintable.join("; ")
        ));
    }
    let in_the_url = credentials.iter().filter(|credential| credential.presentation == policy::Kind::Query).count();
    if in_the_url > 0 {
        notes.push(format!(
            "{in_the_url} credentials travel in the URL, where the service's own access log and every proxy in between keeps a copy; the hub does that on nobody's say-so and a realm does not, so each of them arrives recorded and unsendable until an administrator of the realm allows it by name"
        ));
    }
    notes.push(
        "no value comes across: each credential arrives naming a vault entry nobody has written, so the broker refuses it in words until an administrator puts the value there and records what it fingerprints to"
            .to_owned(),
    );

    let mut grants = Vec::new();
    for (credential_id, person_id, allowed) in &allowances {
        if forbidden.iter().any(|(credential, who)| credential == credential_id && who == person_id) {
            continue;
        }
        let Some((_, core_credential)) = credential_ids.iter().find(|(hub_id, _)| hub_id == credential_id) else { continue };
        let Some((_, principal)) = people.iter().find(|(hub_id, _)| hub_id == person_id) else { continue };
        grants.push(Grant {
            // Named from the pair it is about rather than from a fresh token, so the same import
            // run twice names the same permission and a rollback takes out exactly what it wrote.
            id: format!("grant-{}", &crate::digest("access-grant", &format!("{core_credential}:{}", principal.id))[..16]),
            realm_id: realm_id.to_owned(),
            credential_id: core_credential.clone(),
            principal_id: principal.id.clone(),
            methods: if allowed.any_method { Vec::new() } else { allowed.methods.clone() },
            paths: if allowed.any_path { Vec::new() } else { allowed.paths.clone() },
            granted_by: grid_account.id.clone(),
            granted_at: allowed.from.unwrap_or(record.created_at),
            expires_at: if allowed.never_expires { None } else { allowed.expires_at },
        });
    }

    if record.sso.is_some() {
        notes.push("this grid signs people in through a company identity provider; a realm has no provider settings, so people sign in to whatever the realm is given later and the provider is never reached from here".to_owned());
    }
    if record.settings.require_two_step {
        notes.push("this grid requires a second factor before anybody uses anything; a realm has no such setting, so that rule stays with the hub".to_owned());
    }
    if record.closing.is_some() {
        notes.push("this grid has been scheduled for deletion; bringing it across copies what it still holds and does not take that back".to_owned());
    }
    Ok(Translation { grid_account, people, devices, device_ids, credentials, credential_ids, grants, lapsed, forbidding, notes })
}

/// What bringing this Access Grid across would create, written down without writing any of it.
///
/// `activity` is whatever the caller read out of the grid's own log with the product's own
/// exporter, and may be empty. A rehearsal runs against a copy of the record alone, so it usually
/// is, and the counts say so rather than implying the log was looked at.
pub fn rehearse(record: &hub::Record, activity: &[activity::Entry], now: i64) -> Result<AccessRehearsal, String> {
    let translation = translate(&record.id, record, now)?;
    let permission = |wanted: policy::Permission| record.people.iter().filter(|person| person.permission == wanted).count();
    let decided = decisions_in(record, activity);
    let decisions = decided.len();
    let unreadable = activity.iter().filter(|entry| entry.action == "approve" || entry.action == "deny").count() - decisions;
    let mut notes = translation.notes;
    if unreadable > 0 {
        notes.push(format!(
            "{unreadable} lines of this grid's log record a decision that cannot be read as one here: the approver is named in the outcome sentence rather than in a field, and a line naming somebody or something this grid no longer has does not cross"
        ));
    }
    Ok(AccessRehearsal {
        grid_id: record.id.clone(),
        people: record.people.len(),
        administrators: permission(policy::Permission::Admin),
        approvers: permission(policy::Permission::Approver),
        auditors: permission(policy::Permission::Auditor),
        credentials: record.credentials.len(),
        credentials_carried: translation.credentials.len(),
        rules: record.rules.len(),
        rules_that_ask: record.rules.iter().filter(|rule| rule.decision == policy::Decision::Ask).count(),
        rules_that_forbid: translation.forbidding,
        remembered_computers: translation.devices.len(),
        lapsed_computers: translation.lapsed,
        with_two_step: record.people.iter().filter(|person| person.two_step.is_some()).count(),
        has_identity_provider: record.sso.is_some(),
        principals: translation.people.len() + 1,
        grants: translation.grants.len(),
        every_time: translation.credentials.iter().filter(|credential| credential.every_time).count(),
        decisions,
        events: activity.iter().filter(|entry| entry.action != "approve" && entry.action != "deny").count(),
        notes,
    })
}

/// What is still missing once the bridge exists, said once, here, and repeated in
/// `docs/grid-core/rollout.md`. Each of these is a note on a rehearsal, never a silence.
pub fn missing() -> &'static [&'static str] {
    &[
        "no credential value crosses: the record holds each one sealed with the hub's own key, a realm refuses to hold a value at all, and an administrator has to put each value into the realm's vault entry before the broker can send it",
        "two-step secrets, remembered sign-in tokens and the identity provider's settings have no counterpart in a realm, so people sign in to whatever the realm is given later",
        "the hub's own tamper-evident log and the realm's sealed history cannot verify one another; the lines this bridge carries are sealed by the realm as lines it was told, never as events it witnessed",
        "an hourly limit and a rule that lets somebody see a value have no counterpart in a realm, so neither crosses",
        "an import that carried a decision cannot be taken back out, because a realm writes a decision once and never withdraws one",
        "a credential that travels in the URL arrives unsendable: the hub does that on nobody's say-so and a realm needs an administrator to allow it by name, so somebody has to allow each one after the import",
    ]
}

// -------------------------------------------------------------------------------------------
// The decisions in the hub's own log
// -------------------------------------------------------------------------------------------

/// One decision the Access Grid's log recorded, as much of it as the log holds.
///
/// The hub keeps its waiting requests in memory and writes none of them to its record, so the log
/// is the only durable trace a decision leaves. The approver's name is in the outcome sentence
/// rather than in a field of its own, so it is read out of that sentence; a line whose outcome
/// does not read that way is left out and counted instead of being guessed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecidedUse {
    pub at: i64,
    /// The username of the person who asked, and of the person who decided.
    pub requester: String,
    pub approver: String,
    /// The hub's own credential identifier.
    pub credential_id: String,
    pub granted: bool,
    pub method: Option<String>,
    pub path: Option<String>,
}

/// The username in `approved by ada once` or `denied by ada: no`. A username is letters, digits,
/// dots, dashes and underscores, so the name ends at the first space or colon.
fn decided_by(outcome: &str) -> Option<(&str, bool)> {
    let (rest, granted) = match (outcome.strip_prefix("approved by "), outcome.strip_prefix("denied by ")) {
        (Some(rest), _) => (rest, true),
        (_, Some(rest)) => (rest, false),
        _ => return None,
    };
    let name = rest.split([' ', ':']).next().unwrap_or_default();
    policy::username(name).ok().map(|_| (&rest[..name.len()], granted))
}

/// Every decision in these lines that names a person this grid still has and a credential it still
/// holds. Lines that do not are left out rather than carried as something they are not.
pub fn decisions_in(record: &hub::Record, activity: &[activity::Entry]) -> Vec<DecidedUse> {
    let mut decided = Vec::new();
    for entry in activity.iter().filter(|entry| entry.action == "approve" || entry.action == "deny") {
        let Some((approver, granted)) = decided_by(&entry.outcome) else { continue };
        if !record.people.iter().any(|person| person.username == entry.person) || !record.people.iter().any(|person| person.username == approver) {
            continue;
        }
        let Some(credential) = record.credentials.iter().find(|credential| credential.name.eq_ignore_ascii_case(&entry.credential)) else { continue };
        let (method, path) = match entry.target.split_once(' ') {
            Some((method, address)) => (Some(method.to_ascii_uppercase()), Some(path_of(address))),
            None => (None, None),
        };
        decided.push(DecidedUse {
            at: entry.at,
            requester: entry.person.clone(),
            approver: approver.to_owned(),
            credential_id: credential.id.clone(),
            granted,
            method,
            path,
        });
    }
    decided
}

/// The path part of `https://host/a/b`, which is what a request was narrowed to. The hub never
/// writes the query into its log, so there is none here to drop.
fn path_of(address: &str) -> String {
    let after_scheme = address.split_once("://").map_or(address, |(_, rest)| rest);
    match after_scheme.find('/') {
        Some(at) => after_scheme[at..].to_owned(),
        None => "/".to_owned(),
    }
}

// -------------------------------------------------------------------------------------------
// Bringing it across, and taking it back out
// -------------------------------------------------------------------------------------------

/// Brings an Access Grid's people, computers, credentials and rules into a realm.
///
/// Nothing is decided again: every person keeps the permissions their rules already gave them, and
/// every credential arrives narrowed to what some rule allowed. The hub's record is not touched
/// and goes on being the grid that is actually serving until somebody decides otherwise.
///
/// `activity` is whatever the caller read out of the grid's own log. Its decisions become requests
/// and decisions in the realm and the rest become events in the realm's history. Both are honest
/// only if they are read as what they are: lines the realm was told, sealed with the realm's key
/// as a record of this import, never as events the realm witnessed. Handing in no lines at all is
/// the ordinary case, and it is the only one that can be taken back out again.
pub fn import(core: &mut Core, by: &str, record: &hub::Record, activity: &[activity::Entry], now: i64) -> Result<AccessImported, String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageCredentials)?;
    if !core.realm().can(Capability::Credentials) {
        return Err("This grid does not broker credentials".into());
    }
    if core.store.holds_any_credential_or_grant()? {
        return Err("This grid already has credentials of its own; an Access Grid is brought across into a grid of its own".into());
    }
    if activity.len() > MOST_ACTIVITY {
        return Err(format!("An import carries at most {MOST_ACTIVITY} lines of the grid's own log; export fewer and bring the rest across as a file"));
    }
    if record.credentials.len() > crate::core::limits::MAX_CREDENTIALS {
        return Err(format!("A grid holds at most {} credentials", crate::core::limits::MAX_CREDENTIALS));
    }
    let translation = translate(&core.realm().id, record, now)?;
    // Everything that could already be here is looked at before anything is written, so an import
    // either happens or does not; there is no half-brought-across grid to clear up by hand.
    for (_, principal) in &translation.people {
        if core.store.principal(&principal.id)?.is_some() {
            return Err(format!("An account called {} is already in this grid", principal.id));
        }
    }
    for device in &translation.devices {
        if core.store.device(&device.id)?.is_some() {
            return Err(format!("A computer called {} is already in this grid", device.id));
        }
    }
    for credential in &translation.credentials {
        credential.is_a_reference()?;
    }
    // And the realm has to have room for all of it. The grid's own account counts only when this
    // import would be the one to create it.
    let accounts = translation.people.len() + usize::from(core.store.principal(&translation.grid_account.id)?.is_none());
    super::room_for("accounts", core.store.people_count()?, accounts, crate::core::limits::MAX_PEOPLE)?;
    super::room_for("computers", core.store.device_count()?, translation.devices.len(), crate::core::limits::MAX_DEVICES)?;
    super::room_for("permissions", core.store.grant_count()?, translation.grants.len(), crate::core::limits::MAX_GRANTS)?;

    let mut imported = AccessImported { realm_id: core.realm().id.clone(), grid_id: record.id.clone(), at: now, ..AccessImported::default() };
    if core.store.principal(&translation.grid_account.id)?.is_none() {
        core.store.add_principal(&translation.grid_account, by, now)?;
        imported.principal_id = Some(translation.grid_account.id.clone());
    }
    for (hub_id, principal) in &translation.people {
        core.store.add_principal(principal, by, now)?;
        imported.people.push(Renamed { was: hub_id.clone(), now: principal.id.clone() });
    }
    for (index, device) in translation.devices.iter().enumerate() {
        core.store.enrol_device(device)?;
        imported.devices.push(Renamed { was: translation.device_ids[index].0.clone(), now: device.id.clone() });
    }
    for (index, credential) in translation.credentials.iter().enumerate() {
        core.store.put_credential(credential)?;
        imported.credentials.push(Renamed { was: translation.credential_ids[index].0.clone(), now: credential.id.clone() });
    }
    for grant in &translation.grants {
        core.store.put_grant(grant)?;
        imported.grants.push(grant.id.clone());
    }
    carry_the_log(core, &translation, record, activity, &mut imported, now)?;

    // What this import created, written into the realm itself, for the same reason the other
    // bridges write it: a value in memory cannot undo anything after a restart.
    core.store.put_bridge_import(&super::BridgeImport {
        id: super::BridgeImport::name("access", now),
        realm_id: imported.realm_id.clone(),
        grid_id: imported.grid_id.clone(),
        at: now,
        undo: super::Undone::Access(imported.clone()),
    })?;
    core.note(
        Entry::new(&imported.realm_id, by, "grid.access.imported", Decision::Allowed).about(Capability::Credentials, &record.id).because(&format!(
            "{} accounts, {} credentials and {} permissions from an Access Grid hub",
            imported.people.len(),
            imported.credentials.len(),
            imported.grants.len()
        )),
        now,
    )?;
    Ok(imported)
}

/// The decisions and the rest of the hub's log, written into the realm.
///
/// A decision becomes a request that was asked for and answered. The verdict is always the single
/// agreement and never a standing allowance, whatever the hub recorded: the hub's "for a while"
/// made a temporary rule of its own there, and minting a live standing permission during a
/// migration is exactly the thing a migration should not do.
fn carry_the_log(
    core: &mut Core,
    translation: &Translation,
    record: &hub::Record,
    activity: &[activity::Entry],
    imported: &mut AccessImported,
    now: i64,
) -> Result<(), String> {
    let principal_of = |username: &str| {
        record
            .people
            .iter()
            .find(|person| person.username == username)
            .and_then(|person| translation.people.iter().find(|(hub_id, _)| hub_id == &person.id))
            .map(|(_, principal)| principal.id.clone())
    };
    for (index, decided) in decisions_in(record, activity).into_iter().enumerate() {
        let (Some(requester), Some(approver)) = (principal_of(&decided.requester), principal_of(&decided.approver)) else { continue };
        let Some((_, credential_id)) = translation.credential_ids.iter().find(|(hub_id, _)| hub_id == &decided.credential_id) else { continue };
        let mut approval = Approval {
            id: format!("approval-{}", &crate::digest("access-approval", &format!("{}:{}:{index}", record.id, decided.at))[..16]),
            realm_id: core.realm().id.clone(),
            action: Action::ApproveCredential.name().to_owned(),
            resource_id: credential_id.clone(),
            method: decided.method.clone(),
            path: decided.path.clone(),
            requested_by: requester,
            requested_at: decided.at,
            expires_at: decided.at + crate::core::approval::WAIT,
            // Every one of these needed an approver on the hub, and nothing standing covered it.
            every_time: true,
            state: State::Waiting,
            decided_by: None,
            decided_at: None,
            self_issued: false,
            reason: String::new(),
        };
        core.store.put_request(&approval)?;
        approval.state = if decided.granted { State::Granted } else { State::Refused };
        approval.self_issued = decided.approver == decided.requester;
        approval.decided_by = Some(approver);
        approval.decided_at = Some(decided.at);
        approval.reason = "carried across from the Access Grid's own log".to_owned();
        core.store.record_decision(&approval, if decided.granted { "approve_once" } else { "deny" }, None, None)?;
        imported.approvals.push(approval.id);
    }

    for entry in activity.iter().filter(|entry| entry.action != "approve" && entry.action != "deny") {
        let refused = entry.outcome.contains("refused") || entry.outcome.contains("denied") || entry.outcome.starts_with("expired");
        let mut event = Entry::new(
            &core.realm().id,
            &principal_of(&entry.person).unwrap_or_else(|| translation.grid_account.id.clone()),
            &format!("access.{}", entry.action),
            if refused { Decision::Refused } else { Decision::Allowed },
        )
        // The address a use was sent to is not carried: the realm records where a credential may
        // go, and the Access Grid's own log keeps where each request actually went.
        .because(&format!("carried across from the Access Grid's own log: {}", entry.outcome));
        if let Some((_, credential_id)) =
            translation.credential_ids.iter().find(|(hub_id, _)| record.credentials.iter().any(|credential| &credential.id == hub_id && credential.name.eq_ignore_ascii_case(&entry.credential)))
        {
            event = event.about(Capability::Credentials, credential_id);
        }
        core.note(event, now)?;
    }
    Ok(())
}

/// Takes an Access Grid import back out again, leaving the realm as it was before it ran.
///
/// What the import created goes; what happened stays, because the history is never rewritten. It
/// refuses rather than taking anything else with it: once a credential has been used, once
/// somebody has enrolled a computer of their own, or once work has been placed, undoing the import
/// would leave a record naming something that is not there. It also refuses outright when the
/// import carried a decision, because a realm writes a decision once and never withdraws one.
pub fn roll_back(core: &mut Core, by: &str, imported: &AccessImported, now: i64) -> Result<(), String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageCredentials)?;
    if imported.realm_id != core.realm().id {
        return Err("That import was into another grid".into());
    }
    if !imported.approvals.is_empty() {
        return Err("This import carried decisions somebody made, and a realm writes a decision once and never withdraws one, so the import cannot be undone".into());
    }
    let credentials: Vec<String> = imported.credentials.iter().map(|renamed| renamed.now.clone()).collect();
    if core.store.any_credential_used(&credentials)? {
        return Err("A credential this import brought in has been used, so the import cannot be undone".into());
    }
    let devices: Vec<String> = imported.devices.iter().map(|renamed| renamed.now.clone()).collect();
    let people: Vec<String> = imported.people.iter().map(|renamed| renamed.now.clone()).collect();
    let mut accounts = people.clone();
    accounts.extend(imported.principal_id.clone());
    if core.store.any_other_device_of(&accounts, &devices)? {
        return Err("Somebody has enrolled a computer of their own against an account this import brought in, so the import cannot be undone".into());
    }
    // Every account this would delete, which is the people and the grid's own account, and not
    // the people alone. The grid's account is the one an import always creates and the one
    // anything running on the grid's behalf places work as, so leaving it out left exactly the
    // work most likely to exist unlooked-for. `workloads.principal_id` has no foreign key, so
    // nothing downstream would have caught it: the undo would have reported the realm put back
    // while leaving work naming an account that is gone.
    if !core.store.work_from(&devices, &accounts)?.is_empty() {
        return Err("Work in this grid was placed from a computer or an account this import brought in, so the import cannot be undone".into());
    }
    core.store.forget_imported_credentials(&imported.grants, &credentials, &imported.approvals)?;
    core.store.forget_imported(&accounts, &devices, &[], &[])?;
    core.store.forget_bridge_import(&super::BridgeImport::name("access", imported.at))?;
    core.note(
        Entry::new(&core.realm().id, by, "grid.access.import undone", Decision::Allowed)
            .about(Capability::Credentials, &imported.grid_id)
            .because(&format!("{} credentials, {} permissions and {} accounts taken back out", credentials.len(), imported.grants.len(), people.len())),
        now,
    )
}

// -------------------------------------------------------------------------------------------
// Observation mode
// -------------------------------------------------------------------------------------------

/// Runs the hub's own rule matching and the realm's permission check over the same question for
/// every person and every credential, and reports what each decided.
///
/// This is the one that runs beside a live grid. `policy::evaluate` is the hub's own decider,
/// called rather than copied, and the core's side is read off the credential and the permission
/// this bridge would write. Both answers are put in the same three words, so what is left is a
/// real disagreement and not two vocabularies.
///
/// Nothing is written and the hub's record is not touched. The question asked of each pair is the
/// one the hub can answer from its record alone: a bare request, with no method and no path, which
/// is the widest thing anybody could ask for.
pub fn compare(record: &hub::Record, now: i64) -> Result<AccessComparison, String> {
    let translation = translate(&record.id, record, now)?;
    let mut notes = translation.notes.clone();
    let mut decisions = Vec::new();
    for person in &record.people {
        for credential in &record.credentials {
            let hub = match policy::evaluate(&record.rules, person, credential, "GET", "/", now) {
                policy::Verdict::Allow { .. } => "at once",
                policy::Verdict::Ask { .. } => "an approver decides",
                policy::Verdict::Refused(_) => "nothing",
            };
            let Some((_, credential_id)) = translation.credential_ids.iter().find(|(hub_id, _)| hub_id == &credential.id) else { continue };
            let Some((_, principal)) = translation.people.iter().find(|(hub_id, _)| hub_id == &person.id) else { continue };
            let held = translation.credentials.iter().find(|held| &held.id == credential_id);
            let grant = translation.grants.iter().find(|grant| &grant.credential_id == credential_id && grant.principal_id == principal.id);
            let core = match (held, grant) {
                (Some(held), Some(grant)) if held.allows("GET", "/") && grant.covers("GET", "/", now) => {
                    if held.every_time {
                        "an approver decides"
                    } else {
                        "at once"
                    }
                }
                _ => "nothing",
            };
            decisions.push(Decided { subject: format!("{}:{}", person.id, credential.id), hub: hub.to_owned(), core: core.to_owned() });
        }
    }
    notes.push(
        "this asks each person about a bare request with no method and no path, which is the widest thing anybody could ask for; a narrower request is decided by the methods and paths on both sides and is not asked here"
            .to_owned(),
    );
    let uncrossed = record.credentials.len() - translation.credential_ids.len();
    if uncrossed > 0 {
        notes.push(format!(
            "{uncrossed} credentials are left out of this comparison because a realm would not hold them as they stand, so there is no answer on the core's side to put beside the hub's; the observation ledger carries a line for each of them saying so"
        ));
    }
    Ok(AccessComparison { grid_id: record.id.clone(), decisions, notes })
}

/// Both paths asked the six questions, for the credentials profile.
///
/// Two of the six can be asked from a record on disk and four cannot, and saying which is which is
/// the point of returning a line for every one of them. A ledger that simply omitted the four
/// would read as though the credentials profile had been observed, and it would not have been.
pub fn observe(record: &hub::Record, now: i64) -> Vec<Observation> {
    let Ok(comparison) = compare(record, now) else {
        return Heading::all()
            .iter()
            .map(|heading| {
                Observation::new(
                    now,
                    Profile::Credentials,
                    *heading,
                    &record.id,
                    "an Access Grid record",
                    "nothing: this record holds something a realm will not hold",
                    Verdict::Unobserved("this grid's record did not translate, so neither side was asked anything; the rehearsal says which credential and why".to_owned()),
                )
            })
            .collect();
    };
    let Ok(translation) = translate(&record.id, record, now) else { return Vec::new() };
    let notes = comparison.notes.clone();
    let judge = crate::core::compat::observe::judge;
    let mut observations = Vec::new();

    // Plans: the rules the administrator wrote. A path is a path, so what is compared is a digest
    // of it; two sides holding the same path have the same digest and two sides holding different
    // paths do not, which is the whole question.
    //
    // A grid with no rules at all still answers under this heading, because a ledger that said
    // nothing about the plans would read as though they had been looked at and agreed.
    if record.rules.is_empty() {
        observations.push(Observation::new(
            now,
            Profile::Credentials,
            Heading::Plans,
            &record.id,
            "no rules",
            "no permissions",
            Verdict::Unobserved("this grid has written no rule, so there is nothing under this heading for either side to answer".to_owned()),
        ));
    }
    for rule in &record.rules {
        if !translation.credential_ids.iter().any(|(hub_id, _)| hub_id == &rule.credential) {
            observations.push(Observation::new(
                now,
                Profile::Credentials,
                Heading::Plans,
                &rule.id,
                &format!("{} {} methods under {}", word_of(rule.decision), rule.methods.len(), short(&rule.path)),
                "not in the realm",
                Verdict::Unobserved("this rule is about a credential a realm holds none of, so there is no answer on the core's side to put beside the hub's".to_owned()),
            ));
            continue;
        }
        let hub = format!("{} {} methods under {}", word_of(rule.decision), rule.methods.len(), short(&rule.path));
        let covered: Vec<&policy::Person> = record.people.iter().filter(|person| rule.who.covers(person)).collect();
        let core = match translation.grants.iter().find(|grant| {
            covered.iter().any(|person| grant.principal_id == same_tail("principal", &person.id)) && grant.credential_id == same_tail("credential", &rule.credential)
        }) {
            Some(grant) => format!(
                "{} {} methods under {}",
                if translation.credentials.iter().any(|credential| credential.id == grant.credential_id && credential.every_time) { "ask" } else { "allow" },
                grant.methods.len(),
                short(grant.paths.first().map(String::as_str).unwrap_or_default())
            ),
            None => "nobody is granted anything by this rule".to_owned(),
        };
        let verdict = judge(Heading::Plans, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Credentials, Heading::Plans, &rule.id, &hub, &core, verdict));
    }

    // Permissions: what each person may do, both sides said in the realm's words.
    for (person, (_, principal)) in record.people.iter().zip(translation.people.iter()) {
        let hub = on_the_hub(person.permission);
        let mut names: Vec<&str> = principal.roles.iter().map(|role| role.name()).collect();
        names.sort_unstable();
        let core = names.join(", ");
        let verdict = judge(Heading::Permissions, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Credentials, Heading::Permissions, &person.id, &hub, &core, verdict));
    }

    // Workloads: what each side would decide about one person using one credential. A brokered
    // request is the only workload this profile has, and this is the decision that starts one.
    if record.credentials.is_empty() {
        observations.push(Observation::new(
            now,
            Profile::Credentials,
            Heading::Workloads,
            &record.id,
            "no credentials",
            "no credentials",
            Verdict::Unobserved("this grid holds no credential, so there is no request for either side to decide".to_owned()),
        ));
    }
    for decided in &comparison.decisions {
        let verdict = judge(Heading::Workloads, &decided.hub, &decided.core, &notes);
        observations.push(Observation::new(now, Profile::Credentials, Heading::Workloads, &decided.subject, &decided.hub, &decided.core, verdict));
    }
    // And a line for each credential the comparison could not ask about, so the ledger says the
    // question was not asked rather than being silent about it.
    for credential in record.credentials.iter().filter(|credential| !translation.credential_ids.iter().any(|(hub_id, _)| hub_id == &credential.id)) {
        observations.push(Observation::new(
            now,
            Profile::Credentials,
            Heading::Workloads,
            &credential.id,
            "the hub holds this one",
            "not in the realm",
            Verdict::Unobserved(
                "this credential did not cross, because a realm checks what a credential needs before it holds it and this one did not pass; the rehearsal says which check and why, and neither side can be asked about it until it does"
                    .to_owned(),
            ),
        ));
    }

    // The three nothing here can ask, each with the reason it cannot.
    let unobservable = [
        (
            Heading::Assignments,
            "the hub makes every request itself",
            "nothing: a realm places no work for a credential yet",
            "a brokered request is made by whichever of the two holds the credential and is never placed on another computer, so there is no placement on either side to compare",
        ),
        (
            Heading::Audit,
            "a chain sealed with the hub's own key",
            "a chain sealed with the realm's key",
            "neither chain can verify the other, and the lines this bridge carries are sealed by the realm as lines it was told rather than as events it witnessed, so comparing the two would look like proof without being any",
        ),
        (
            Heading::Answers,
            "the hub's own credential endpoint",
            "nothing: no request reaches a realm yet",
            "comparing what an agent asking would be told needs both paths brokering, and no page and no command reads a realm's credentials yet",
        ),
    ];
    for (heading, hub, core, why) in unobservable {
        observations.push(Observation::new(now, Profile::Credentials, heading, &record.id, hub, core, Verdict::Unobserved(why.to_owned())));
    }
    observations
}

/// Whether any rule lets anybody use this credential at all, once the rules that forbid have had
/// their say. A credential nobody may use is still recorded, because the hub records it; what it
/// does not get is a permission.
fn grants_would_cover(allowances: &[(String, String, Allowed)], forbidden: &[(String, String)], credential_ids: &[(String, String)], core_id: &str) -> bool {
    let Some((hub_id, _)) = credential_ids.iter().find(|(_, known)| known == core_id) else { return false };
    allowances
        .iter()
        .any(|(credential, who, _)| credential == hub_id && !forbidden.iter().any(|(forbidden_credential, forbidden_who)| forbidden_credential == credential && forbidden_who == who))
}

fn word_of(decision: policy::Decision) -> &'static str {
    match decision {
        policy::Decision::Allow => "allow",
        policy::Decision::Ask => "ask",
        policy::Decision::Never => "never",
    }
}
