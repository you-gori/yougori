//! What admins, approvers and auditors see and change: people, credentials (never their values),
//! rules, grid settings, single sign-on, and the activity log. Every change is checked against
//! the actor's current permission, saved atomically and logged.
use super::{find_credential, find_person, label, lock, new_id, note, now, requests, save, text, valid_key, Caller, Record, Refusal, Shared};
use crate::access::{
    forward, mint,
    policy::{self, Credential, Decision, Kind, Person, Rule, Settings, Sso, Who},
};
use hyper::StatusCode;
use serde_json::{json, Value};
use std::sync::Arc;

fn deciders(record: &Record) -> usize {
    record.people.iter().filter(|person| person.permission.decides()).count()
}

/// Whether `approver` may decide a request `requester` made: never their own, unless nobody else
/// can approve anything in this grid.
pub(super) fn may_decide(record: &Record, approver: &Person, requester: &str) -> bool {
    approver.permission.decides() && (approver.id != requester || deciders(record) == 1)
}

fn who_label(record: &Record, who: &Who) -> String {
    match who {
        Who::Everyone => "everyone".into(),
        Who::Team(team) => format!("team {team}"),
        Who::Person(id) => record.people.iter().find(|person| person.id == *id).map_or_else(|| "a removed person".into(), |person| person.username.clone()),
    }
}

fn rule_view(record: &Record, rule: &Rule) -> Value {
    let mut view = serde_json::to_value(rule).unwrap_or_default();
    view["credentialName"] = json!(record.credentials.iter().find(|credential| credential.id == rule.credential).map(|credential| credential.name.clone()));
    view["whoLabel"] = json!(who_label(record, &rule.who));
    view
}

/// What one person may use, credential by credential, with the rules that cover them.
fn available(record: &Record, person: &Person) -> Vec<Value> {
    let at = now();
    record
        .credentials
        .iter()
        .filter_map(|credential| {
            let uses: Vec<Value> = record
                .rules
                .iter()
                .filter(|rule| rule.credential == credential.id && rule.live(at) && rule.who.covers(person))
                .map(|rule| json!({"ruleId": rule.id, "decision": rule.decision, "methods": rule.methods, "path": rule.path, "reveal": rule.reveal, "expiresAt": rule.expires_at, "limit": rule.limit}))
                .collect();
            (!uses.is_empty()).then(|| json!({"id": credential.id, "name": credential.name, "kind": credential.kind, "destinations": credential.destinations, "note": credential.note, "shortLived": credential.kind.mints(), "uses": uses}))
        })
        .collect()
}

pub(super) fn overview(shared: &Shared) -> Value {
    let waiting = requests::waiting(shared);
    let record = lock(&shared.record);
    json!({
        "owner": record.owner,
        "people": record.people.iter().map(Person::public).collect::<Vec<_>>(),
        "credentials": record.credentials.iter().map(|credential| {
            let mut view = credential.public();
            view["rules"] = json!(record.rules.iter().filter(|rule| rule.credential == credential.id).count());
            view
        }).collect::<Vec<_>>(),
        "rules": record.rules.iter().map(|rule| rule_view(&record, rule)).collect::<Vec<_>>(),
        "waiting": waiting,
        "settings": record.settings,
        "sso": record.sso,
        "activity": shared.log.recent(300),
    })
}

/// Everything a signed-in person sees: who they are, what they may use, their own requests, and
/// for approvers, auditors and admins the whole grid.
pub(super) fn me(shared: &Arc<Shared>, caller: &Caller) -> Value {
    let person = &caller.person;
    let (company, id, uses, can_approve_own, required, sso) = {
        let record = lock(&shared.record);
        (record.company.clone(), record.id.clone(), available(&record, person), may_decide(&record, person, &person.id), record.settings.require_two_step, record.sso.as_ref().map(|sso| json!({"issuer": sso.issuer, "passwordless": sso.passwordless})))
    };
    let blocked = required && !caller.strong;
    let mut view = json!({
        "person": person.public(), "company": company, "accessId": id, "available": if blocked { json!([]) } else { json!(uses) },
        "requests": requests::mine(shared, &person.id), "canApproveOwn": can_approve_own, "strong": caller.strong, "device": caller.device,
        "twoStepRequired": required, "blocked": blocked, "sso": sso,
    });
    if person.permission.reads_all() && !blocked {
        view["overview"] = overview(shared);
    }
    view
}

fn strings(body: &Value, key: &str) -> Result<Option<Vec<String>>, String> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(vec![text.clone()])),
        Some(Value::Array(items)) => items.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(|| format!("{key} must be a list of text"))).collect::<Result<Vec<_>, _>>().map(Some),
        Some(_) => Err(format!("{key} must be a list of text")),
    }
}

fn destinations(list: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for item in list.iter().flat_map(|item| item.split([',', '\n'])).map(str::trim).filter(|item| !item.is_empty()) {
        let place = forward::destination(item)?;
        if !out.contains(&place) {
            out.push(place);
        }
    }
    if out.is_empty() {
        return Err("Give at least one destination the credential may be sent to, such as https://api.github.com".into());
    }
    if out.len() > policy::MAX_DESTINATIONS {
        return Err(format!("A credential can have at most {} destinations", policy::MAX_DESTINATIONS));
    }
    Ok(out)
}

fn who(record: &Record, text: &str) -> Result<Who, String> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("everyone") {
        return Ok(Who::Everyone);
    }
    if let Some(team) = text.strip_prefix("team:") {
        return Ok(Who::Team(policy::team_name(team)?));
    }
    let name = text.strip_prefix("person:").unwrap_or(text);
    find_person(record, name).map(|person| Who::Person(person.id.clone())).ok_or_else(|| format!("No person '{name}' in this Access Grid; give everyone, team:NAME or a username"))
}

fn hours(body: &Value) -> Result<Option<i64>, String> {
    match body.get("hours") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_f64().filter(|hours| *hours > 0.0 && *hours <= 24.0 * 366.0).map(|hours| Some(now() + (hours * 3600.0) as i64)).ok_or_else(|| "hours must be a number of hours up to a year".into()),
    }
}

fn limit(body: &Value) -> Result<Option<u32>, String> {
    match body.get("limit") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().filter(|limit| (1..=100_000).contains(limit)).map(|limit| Some(limit as u32)).ok_or_else(|| "limit is a number of uses an hour, from 1 to 100000".into()),
    }
}

/// A credential's value checked for its kind, including that a GitHub App key can sign.
fn checked_value(kind: Kind, value: &str) -> Result<(), String> {
    policy::value(kind, value)?;
    if kind == Kind::GithubApp {
        mint::check_github_key(value)?;
    }
    Ok(())
}

fn person_index(record: &Record, body: &Value) -> Result<usize, Refusal> {
    let id = find_person(record, text(body, "person").unwrap_or_default()).map(|person| person.id.clone()).ok_or_else(|| Refusal::missing("No such person"))?;
    Ok(record.people.iter().position(|person| person.id == id).expect("found above"))
}

/// Changes the grid as `caller`, after checking their permission against the current record.
pub(super) fn manage(shared: &Arc<Shared>, caller: &Caller, body: Value) -> Result<Value, Refusal> {
    let actor = &caller.person;
    let action = text(&body, "action").unwrap_or_default().to_owned();
    match action.as_str() {
        "overview" | "activityExport" | "activityVerify" if !actor.permission.reads_all() => return Err(Refusal::forbidden("Only approvers, auditors and admins see the whole Access Grid")),
        "overview" => return Ok(overview(shared)),
        "activityExport" => {
            let count = body.get("limit").and_then(Value::as_u64).unwrap_or(10_000).clamp(1, 100_000) as usize;
            shared.change(actor, "exported the activity log".into());
            // A log that cannot be read is said so, never handed over as an empty export.
            let entries = shared.log.export(count).map_err(|reason| Refusal(StatusCode::INTERNAL_SERVER_ERROR, "unreadable", reason))?;
            return Ok(json!({"entries": entries}));
        }
        "activityVerify" => return Ok(shared.log.verify()),
        "decide" => return requests::decide(shared, actor, &body),
        "" => return Err(Refusal::bad("Say which action to take")),
        _ => {}
    }
    if !actor.permission.manages() {
        return Err(Refusal::forbidden("Only Access Grid admins change people, credentials, rules and settings"));
    }
    let mut record = lock(&shared.record);
    let mut next = record.clone();
    let at = now();
    let mut forget_minted = None;
    let (message, result) = match action.as_str() {
        "personAdd" => {
            let username = policy::username(text(&body, "username").unwrap_or_default())?;
            if find_person(&next, &username).is_some() {
                return Err(Refusal(StatusCode::CONFLICT, "exists", format!("{username} is already in this Access Grid")));
            }
            if next.people.len() >= policy::MAX_PEOPLE {
                return Err(Refusal::bad(format!("An Access Grid holds at most {} people", policy::MAX_PEOPLE)));
            }
            let (salt, key) = (text(&body, "salt").unwrap_or_default(), text(&body, "key").unwrap_or_default());
            if salt.is_empty() || salt.len() > 128 || !valid_key(key) {
                return Err(Refusal::bad("A password is required"));
            }
            let email = policy::email(text(&body, "email").unwrap_or_default())?;
            if email.is_some() && next.people.iter().any(|person| person.email == email) {
                return Err(Refusal(StatusCode::CONFLICT, "exists", "Someone in this Access Grid already has that email".into()));
            }
            let person = Person {
                id: new_id("person"),
                name: label(text(&body, "name").filter(|name| !name.trim().is_empty()).unwrap_or(&username), "The name")?,
                permission: policy::Permission::parse(text(&body, "permission").unwrap_or_default())?,
                teams: policy::teams(&strings(&body, "teams")?.unwrap_or_default())?,
                username,
                salt: salt.to_owned(),
                key_hash: policy::key_hash(key),
                created_at: at,
                last_seen_at: None,
                email,
                sso_subject: None,
                two_step: None,
                generation: 0,
                devices: Vec::new(),
            };
            let message = format!("added {} ({})", person.username, person.permission.label());
            let id = person.id.clone();
            next.people.push(person);
            (message, json!({"personId": id}))
        }
        "personUpdate" => {
            let index = person_index(&next, &body)?;
            let owner = next.owner.clone();
            if let Some(email) = text(&body, "email") {
                let email = policy::email(email)?;
                if email.is_some() && next.people.iter().enumerate().any(|(other, person)| other != index && person.email == email) {
                    return Err(Refusal(StatusCode::CONFLICT, "exists", "Someone in this Access Grid already has that email".into()));
                }
                // A new address unties them from their account at the identity provider, and ends
                // their sign-ins (they belonged to the old identity); their next company sign-in ties
                // the account it comes from. Saving the same address (the admin screen sends it
                // with every edit) leaves everything alone.
                if next.people[index].email != email {
                    let person = &mut next.people[index];
                    person.sso_subject = None;
                    person.generation += 1;
                    person.devices.clear();
                }
                next.people[index].email = email;
            }
            let person = &mut next.people[index];
            if let Some(name) = text(&body, "name") {
                person.name = label(name, "The name")?;
            }
            if let Some(permission) = text(&body, "permission") {
                let permission = policy::Permission::parse(permission)?;
                if person.id == owner && permission != policy::Permission::Admin {
                    return Err(Refusal::forbidden("The person who runs the Access Grid on its computer stays an admin"));
                }
                person.permission = permission;
            }
            if let Some(teams) = strings(&body, "teams")? {
                person.teams = policy::teams(&teams)?;
            }
            let message = format!("updated {} ({}{})", person.username, person.permission.label(), if person.teams.is_empty() { String::new() } else { format!(", teams {}", person.teams.join(", ")) });
            (message, json!({"personId": person.id}))
        }
        "personPassword" => {
            let index = person_index(&next, &body)?;
            let (salt, key) = (text(&body, "salt").unwrap_or_default(), text(&body, "key").unwrap_or_default());
            if salt.is_empty() || salt.len() > 128 || !valid_key(key) {
                return Err(Refusal::bad("A password is required"));
            }
            let person = &mut next.people[index];
            person.salt = salt.to_owned();
            person.key_hash = policy::key_hash(key);
            person.generation += 1;
            person.devices.clear();
            (format!("changed the password of {}; their sign-ins ended", person.username), json!({"personId": person.id}))
        }
        "personTwoStepReset" => {
            let index = person_index(&next, &body)?;
            let person = &mut next.people[index];
            person.two_step = None;
            person.generation += 1;
            person.devices.clear();
            (format!("reset two-step sign-in for {}; their sign-ins ended", person.username), json!({"personId": person.id}))
        }
        "personSignOut" => {
            let index = person_index(&next, &body)?;
            let person = &mut next.people[index];
            person.generation += 1;
            person.devices.clear();
            // Also forgets their account at the identity provider, for when it was replaced: the
            // next company sign-in ties the account it comes from.
            person.sso_subject = None;
            (format!("signed {} out on every computer and untied their company account", person.username), json!({"personId": person.id}))
        }
        "deviceRevoke" => {
            let index = person_index(&next, &body)?;
            let device = text(&body, "device").unwrap_or_default().to_owned();
            let person = &mut next.people[index];
            let before = person.devices.len();
            person.devices.retain(|known| known.id != device);
            if person.devices.len() == before {
                return Err(Refusal::missing("That computer is not signed in"));
            }
            lock(&shared.live).sessions.retain(|_, session| session.device.as_deref() != Some(device.as_str()));
            (format!("signed one of {}'s computers out", person.username), json!({"personId": person.id}))
        }
        "personRemove" => {
            let person = find_person(&next, text(&body, "person").unwrap_or_default()).cloned().ok_or_else(|| Refusal::missing("No such person"))?;
            if person.id == next.owner {
                return Err(Refusal::forbidden("The person who runs the Access Grid on its computer cannot be removed; delete the grid instead"));
            }
            next.people.retain(|own| own.id != person.id);
            next.rules.retain(|rule| rule.who != Who::Person(person.id.clone()));
            (format!("removed {}; their sign-ins, waiting requests and personal rules are gone", person.username), json!({"personId": person.id}))
        }
        "credentialAdd" => {
            let name = label(text(&body, "name").unwrap_or_default(), "The credential name")?;
            if find_credential(&next, &name).is_some() {
                return Err(Refusal(StatusCode::CONFLICT, "exists", format!("A credential named {name} already exists")));
            }
            if next.credentials.len() >= policy::MAX_CREDENTIALS {
                return Err(Refusal::bad(format!("An Access Grid holds at most {} credentials", policy::MAX_CREDENTIALS)));
            }
            let kind = Kind::parse(text(&body, "kind").unwrap_or_default())?;
            let field = policy::field(kind, text(&body, "field").unwrap_or_default())?;
            let config = policy::config(kind, body.get("config").unwrap_or(&Value::Null))?;
            let places = destinations(&strings(&body, "destinations")?.unwrap_or_default())?;
            let value = text(&body, "value").unwrap_or_default();
            checked_value(kind, value)?;
            let id = new_id("cred");
            let credential = Credential {
                sealed: shared.sealer.seal(&id, value)?,
                hint: if kind == Kind::GithubApp { String::new() } else { policy::hint(value) },
                id: id.clone(),
                name,
                kind,
                field,
                destinations: places,
                note: note(text(&body, "note"), 200),
                created_at: at,
                created_by: actor.username.clone(),
                updated_at: at,
                config,
            };
            let message = format!("added credential {} for {}", credential.name, credential.destinations.join(", "));
            next.credentials.push(credential);
            (message, json!({"credentialId": id}))
        }
        "credentialUpdate" => {
            let id = find_credential(&next, text(&body, "credential").unwrap_or_default()).map(|credential| credential.id.clone()).ok_or_else(|| Refusal::missing("No such credential"))?;
            if let Some(name) = text(&body, "name") {
                let name = label(name, "The credential name")?;
                if next.credentials.iter().any(|credential| credential.id != id && credential.name.eq_ignore_ascii_case(&name)) {
                    return Err(Refusal(StatusCode::CONFLICT, "exists", format!("A credential named {name} already exists")));
                }
                next.credentials.iter_mut().find(|credential| credential.id == id).expect("found above").name = name;
            }
            let places = strings(&body, "destinations")?.map(|list| destinations(&list)).transpose()?;
            let credential = next.credentials.iter_mut().find(|credential| credential.id == id).expect("found above");
            let mut changed = Vec::new();
            if let Some(kind) = text(&body, "kind") {
                let kind = Kind::parse(kind)?;
                if kind != credential.kind && text(&body, "value").is_none() {
                    return Err(Refusal::bad("Give the value again when changing how a credential is sent"));
                }
                credential.kind = kind;
                changed.push("how it is sent");
            }
            if body.get("field").is_some() || body.get("kind").is_some() {
                credential.field = policy::field(credential.kind, text(&body, "field").unwrap_or(&credential.field))?;
            }
            if body.get("config").is_some() || body.get("kind").is_some() {
                let merged = match body.get("config") {
                    Some(Value::Object(given)) => {
                        let mut merged = credential.config.clone();
                        merged.extend(given.clone());
                        Value::Object(merged)
                    }
                    _ => Value::Object(credential.config.clone()),
                };
                credential.config = policy::config(credential.kind, &merged)?;
                changed.push("settings");
            }
            if let Some(places) = places {
                credential.destinations = places;
                changed.push("destinations");
            }
            if body.get("note").is_some() {
                credential.note = note(text(&body, "note"), 200);
            }
            if let Some(value) = text(&body, "value") {
                checked_value(credential.kind, value)?;
                credential.sealed = shared.sealer.seal(&id, value)?;
                credential.hint = if credential.kind == Kind::GithubApp { String::new() } else { policy::hint(value) };
                changed.push("value");
            }
            credential.updated_at = at;
            forget_minted = Some(id.clone());
            (format!("updated credential {}{}", credential.name, if changed.is_empty() { String::new() } else { format!(": {}", changed.join(", ")) }), json!({"credentialId": id}))
        }
        "credentialRemove" => {
            let credential = find_credential(&next, text(&body, "credential").unwrap_or_default()).cloned().ok_or_else(|| Refusal::missing("No such credential"))?;
            next.credentials.retain(|own| own.id != credential.id);
            next.rules.retain(|rule| rule.credential != credential.id);
            forget_minted = Some(credential.id.clone());
            (format!("removed credential {} and its rules", credential.name), json!({"credentialId": credential.id}))
        }
        "ruleAdd" => {
            let credential = find_credential(&next, text(&body, "credential").unwrap_or_default()).cloned().ok_or_else(|| Refusal::missing("No such credential"))?;
            if next.rules.len() >= policy::MAX_RULES {
                return Err(Refusal::bad(format!("An Access Grid holds at most {} rules", policy::MAX_RULES)));
            }
            let rule = Rule {
                id: new_id("rule"),
                credential: credential.id.clone(),
                who: who(&next, text(&body, "who").unwrap_or_default())?,
                methods: policy::methods(&strings(&body, "methods")?.unwrap_or_default())?,
                path: policy::rule_path(text(&body, "path").unwrap_or_default())?,
                decision: Decision::parse(text(&body, "decision").unwrap_or_default())?,
                reveal: body.get("reveal").and_then(Value::as_bool).unwrap_or(false),
                expires_at: hours(&body)?,
                limit: limit(&body)?,
                note: note(text(&body, "note"), 200),
                created_at: at,
                created_by: actor.username.clone(),
            };
            if rule.limit.is_some() && rule.decision != Decision::Allow {
                return Err(Refusal::bad("An hourly limit belongs to an allow rule: past it, an approver decides"));
            }
            let message = format!("added a rule: {} {} {}", who_label(&next, &rule.who), match rule.decision { Decision::Allow => "may use", Decision::Ask => "may ask to use", Decision::Never => "may never use" }, credential.name);
            let id = rule.id.clone();
            next.rules.push(rule);
            (message, json!({"ruleId": id}))
        }
        "ruleRemove" => {
            let id = text(&body, "rule").unwrap_or_default();
            let rule = next.rules.iter().find(|rule| rule.id == id).cloned().ok_or_else(|| Refusal::missing("No such rule"))?;
            next.rules.retain(|own| own.id != rule.id);
            (format!("removed a rule for {} on {}", who_label(&next, &rule.who), next.credentials.iter().find(|credential| credential.id == rule.credential).map_or("a removed credential", |credential| credential.name.as_str())), json!({"ruleId": rule.id}))
        }
        "settingsSet" => {
            let mut settings: Settings = next.settings.clone();
            if let Some(required) = body.get("requireTwoStep").and_then(Value::as_bool) {
                settings.require_two_step = required;
            }
            next.settings = settings;
            (format!("set two-step sign-in {}", if next.settings.require_two_step { "required for everyone" } else { "optional" }), json!({"settings": next.settings}))
        }
        "ssoSet" => {
            let sso = Sso::checked(&body)?;
            let message = format!("set single sign-on through {}{}", sso.issuer, if sso.passwordless { "; passwords no longer sign people in" } else { "" });
            // Accounts at another provider (or another app there) are other accounts: everyone is
            // tied afresh at their next company sign-in.
            if next.sso.as_ref().is_none_or(|old| old.issuer != sso.issuer || old.client_id != sso.client_id) {
                for person in &mut next.people {
                    person.sso_subject = None;
                }
            }
            next.sso = Some(sso);
            (message, json!({"sso": next.sso}))
        }
        "ssoClear" => {
            for person in &mut next.people {
                person.sso_subject = None;
            }
            next.sso = None;
            ("turned off single sign-on".to_owned(), json!({"sso": null}))
        }
        other => return Err(Refusal::bad(format!("Unknown Access Grid action '{other}'"))),
    };
    save(&shared.path, &next)?;
    *record = next;
    let current: Vec<(String, u64)> = record.people.iter().map(|person| (person.id.clone(), person.generation)).collect();
    let credentials: Vec<String> = record.credentials.iter().map(|credential| credential.id.clone()).collect();
    drop(record);
    if action == "ssoSet" || action == "ssoClear" {
        lock(&shared.live).sso = super::SsoCache::default();
    }
    if let Some(credential) = forget_minted {
        shared.mint.forget(&credential);
    }
    {
        // Sign-ins and requests of removed people and credentials end now.
        let mut live = lock(&shared.live);
        live.sessions.retain(|_, session| current.iter().any(|(person, generation)| *person == session.person && *generation == session.generation));
        requests::forget(&mut live, &current.iter().map(|(person, _)| person.clone()).collect::<Vec<_>>(), &credentials, at);
    }
    shared.change(actor, message.clone());
    let mut result = result;
    result["message"] = json!(message);
    Ok(result)
}
