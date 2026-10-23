//! Where a new word goes, and which old word it stands beside.
//!
//! Two things live here. `product_call` turns one typed command into the wire method a product
//! already has, so the new door and the old door are one behaviour rather than two
//! implementations that look alike. `ALIASES` is the table of what the four products shipped and
//! what each is now also called, which the migration tests read.
//!
//! The direction matters and is deliberate: new onto old, never old onto new. A shipped client
//! that types `yougori grid add-plan` reaches exactly the handler it reached before this phase.

use super::fault::{Code, Fault};
use super::{Capability, Product};
use serde_json::{json, Map, Value};

/// Whether an old command says it is old. It does not, and it will not until the two doors have
/// been shown to be one behaviour in the field. Turning this on is a change of its own.
pub const SAY_OLD_IS_OLD: bool = false;

/// One old spelling and the new one beside it.
#[derive(Clone, Copy, Debug)]
pub struct Alias {
    /// The words a person types today.
    pub old: &'static [&'static str],
    /// The wire method those words reach.
    pub old_method: &'static str,
    /// The noun of the new namespace.
    pub noun: &'static str,
    /// The verb of the new namespace.
    pub verb: &'static str,
}

macro_rules! alias {
    ($old:expr, $method:literal, $noun:literal, $verb:literal) => {
        Alias { old: $old, old_method: $method, noun: $noun, verb: $verb }
    };
}

/// Every command the four products shipped, and what it is now also called. Nothing in this
/// table changes what an old command does.
pub const ALIASES: &[Alias] = &[
    // Closed Neo Grid
    alias!(&["create", "grid"], "grid_create", "realm", "new"),
    alias!(&["join", "grid"], "grid_join", "realm", "join"),
    alias!(&["grid", "create"], "grid_create", "realm", "new"),
    alias!(&["grid", "join"], "grid_join", "realm", "join"),
    alias!(&["grid", "status"], "grid_status", "realm", "status"),
    alias!(&["grid", "password"], "grid_password", "realm", "password"),
    alias!(&["grid", "leave"], "grid_leave", "realm", "leave"),
    alias!(&["grid", "delete"], "grid_delete", "realm", "delete"),
    alias!(&["grid", "restore"], "grid_restore", "realm", "restore"),
    alias!(&["grid", "remove"], "grid_member_remove", "computers", "remove"),
    alias!(&["grid", "exclude"], "grid_member_exclude", "share", "drain"),
    alias!(&["grid", "include"], "grid_member_include", "share", "bring-back"),
    alias!(&["grid", "add-plan"], "grid_plan_add", "models", "add"),
    alias!(&["grid", "change-plan"], "grid_plan_update", "models", "set"),
    alias!(&["grid", "remove-plan"], "grid_plan_remove", "models", "remove"),
    alias!(&["grid", "add-swarm"], "grid_swarm_add", "models", "add-team"),
    alias!(&["grid", "remove-swarm"], "grid_swarm_remove", "models", "remove-team"),
    alias!(&["grid", "run-swarm"], "grid_swarm_run", "models", "run-team"),
    alias!(&["grid", "add-key"], "grid_key_create", "models", "add-key"),
    alias!(&["grid", "revoke-key"], "grid_key_revoke", "models", "revoke-key"),
    // Sandbox Grid
    alias!(&["desks", "create"], "desks_create", "realm", "new"),
    alias!(&["desks", "join"], "desks_join", "realm", "join"),
    alias!(&["desks", "status"], "desks_status", "realm", "status"),
    alias!(&["desks", "leave"], "desks_leave", "realm", "leave"),
    alias!(&["desks", "delete"], "desks_delete", "realm", "delete"),
    alias!(&["desks", "restore"], "desks_restore", "realm", "restore"),
    alias!(&["desks", "adopt"], "desks_adopt_membership", "realm", "join"),
    alias!(&["desks", "manage"], "desks_manage", "realm", "manage"),
    alias!(&["desks", "remove"], "desks_member_remove", "computers", "remove"),
    alias!(&["desks", "share"], "desks_member_share", "share", "set"),
    alias!(&["desks", "add-person"], "desks_person_add", "people", "add"),
    alias!(&["desks", "person-password"], "desks_person_password", "people", "password"),
    alias!(&["desks", "remove-person"], "desks_person_remove", "people", "remove"),
    alias!(&["desks", "add-desk"], "desks_add", "desks", "add"),
    alias!(&["desks", "assign-desk"], "desks_assign", "desks", "assign"),
    alias!(&["desks", "retry-desk"], "desks_retry", "desks", "retry"),
    alias!(&["desks", "remove-desk"], "desks_remove", "desks", "remove"),
    alias!(&["desk", "login"], "desk_login", "desks", "sign-in"),
    alias!(&["desk", "refresh"], "desk_refresh", "desks", "refresh"),
    alias!(&["desk", "logout"], "desk_logout", "desks", "sign-out"),
    // Access Grid
    alias!(&["access", "status"], "access_status", "realm", "status"),
    alias!(&["access", "create"], "access_create", "realm", "new"),
    alias!(&["access", "delete"], "access_delete", "realm", "delete"),
    alias!(&["access", "restore"], "access_restore", "realm", "restore"),
    alias!(&["access", "backup"], "access_backup", "realm", "backup"),
    alias!(&["access", "restore-backup"], "access_restore_backup", "realm", "restore-backup"),
    alias!(&["access", "settings"], "access_manage", "realm", "settings"),
    alias!(&["access", "signin"], "access_signin", "people", "sign-in"),
    alias!(&["access", "signout"], "access_signout", "people", "sign-out"),
    alias!(&["access", "add-person"], "access_manage", "people", "add"),
    alias!(&["access", "set-person"], "access_manage", "people", "set"),
    alias!(&["access", "person-password"], "access_manage", "people", "password"),
    alias!(&["access", "remove-person"], "access_manage", "people", "remove"),
    alias!(&["access", "sign-out-person"], "access_manage", "people", "sign-out"),
    alias!(&["access", "reset-two-step"], "access_manage", "people", "reset-two-step"),
    alias!(&["access", "two-step"], "access_account", "people", "two-step"),
    alias!(&["access", "password"], "access_account", "people", "my-password"),
    alias!(&["access", "sign-out-others"], "access_account", "people", "sign-out-others"),
    alias!(&["access", "sso"], "access_manage", "people", "sso"),
    alias!(&["access", "computers"], "access_status", "computers", "list"),
    alias!(&["access", "forget-computer"], "access_account", "computers", "forget"),
    alias!(&["access", "add-credential"], "access_manage", "credentials", "add"),
    alias!(&["access", "rotate-credential"], "access_manage", "credentials", "rotate"),
    alias!(&["access", "remove-credential"], "access_manage", "credentials", "remove"),
    alias!(&["access", "allow"], "access_manage", "credentials", "allow"),
    alias!(&["access", "remove-rule"], "access_manage", "credentials", "remove-rule"),
    alias!(&["access", "use"], "access_use", "credentials", "use"),
    alias!(&["access", "requests"], "access_status", "requests", "list"),
    alias!(&["access", "approve"], "access_manage", "requests", "approve"),
    alias!(&["access", "deny"], "access_manage", "requests", "deny"),
    alias!(&["access", "check"], "access_check", "requests", "check"),
    alias!(&["access", "log"], "access_manage", "log", "show"),
    // Swarm Mining workers. `yougori start bounty` is not here: starting a worker stays where it
    // is, under its own guided setup, and this namespace never starts one.
    alias!(&["bounty", "workers"], "swarm_dispatch", "research", "list"),
    alias!(&["bounty", "status"], "swarm_dispatch", "research", "show"),
    alias!(&["bounty", "doctor"], "swarm_dispatch", "research", "check"),
    alias!(&["bounty", "offers"], "swarm_dispatch", "research", "offers"),
    alias!(&["bounty", "details"], "swarm_dispatch", "research", "details"),
    alias!(&["bounty", "skip"], "swarm_dispatch", "research", "skip"),
    alias!(&["bounty", "bounties"], "swarm_dispatch", "research", "bounties"),
    alias!(&["bounty", "rewards"], "swarm_dispatch", "research", "rewards"),
    alias!(&["bounty", "reports"], "swarm_dispatch", "research", "reports"),
    alias!(&["bounty", "messages"], "swarm_dispatch", "research", "messages"),
    alias!(&["bounty", "chat"], "swarm_dispatch", "research", "chat"),
    alias!(&["bounty", "pause"], "swarm_dispatch", "research", "pause"),
    alias!(&["bounty", "resume"], "swarm_dispatch", "research", "resume"),
    alias!(&["bounty", "stop"], "swarm_dispatch", "research", "stop"),
    alias!(&["bounty", "leave"], "swarm_dispatch", "research", "leave"),
    alias!(&["bounty", "delete"], "swarm_dispatch", "research", "remove"),
    alias!(&["bounty", "memory"], "swarm_dispatch", "research", "memory"),
    // Closed Bounty host
    alias!(&["bounty", "hosted"], "bounty_status", "realm", "status"),
    alias!(&["bounty", "remove-hunter"], "bounty_member_remove", "computers", "remove"),
    alias!(&["bounty", "unhost"], "bounty_delete", "realm", "delete"),
];

/// The deprecation line an old command would print once this is turned on. It is not, so there
/// is none. Written down here so that turning it on is one constant and not a rewrite.
pub fn deprecation_line(old: &[&str]) -> Option<String> {
    if !SAY_OLD_IS_OLD {
        return None;
    }
    let row = ALIASES.iter().find(|alias| alias.old == old)?;
    Some(format!("{} is now grids {} {}. The old words keep working.", old.join(" "), row.noun, row.verb))
}

fn missing(said: &str) -> Fault {
    Fault::new(Code::MissingWords, said)
}

fn not_here(product: Product, said: &str) -> Fault {
    Fault::new(Code::NotYetOnThisDoor, said).about(product.product_name())
}

fn need<'a>(request: &'a Map<String, Value>, key: &str, said: &str) -> Result<&'a Value, Fault> {
    request.get(key).filter(|value| !value.is_null()).ok_or_else(|| missing(said))
}

fn text(request: &Map<String, Value>, key: &str, said: &str) -> Result<String, Fault> {
    Ok(need(request, key, said)?.as_str().unwrap_or_default().to_owned())
}

/// Copies what was typed onto the parameter names the old method already has. A value that was
/// not typed is not sent, so every old default still applies.
fn carry(into: &mut Map<String, Value>, request: &Map<String, Value>, pairs: &[(&str, &str)]) {
    for (new, old) in pairs {
        if let Some(value) = request.get(*new).filter(|value| !value.is_null()) {
            into.insert((*old).to_owned(), value.clone());
        }
    }
}

fn admin(action: &str, request: &Map<String, Value>, pairs: &[(&str, &str)]) -> Value {
    let mut body = Map::new();
    body.insert("action".into(), json!(action));
    carry(&mut body, request, pairs);
    json!({ "request": Value::Object(body) })
}

/// Which product handler one typed command reaches, and with what.
///
/// Every arm names a method that exists today. As each product moves onto Grid Core its arm
/// changes here and nowhere else, and not one word anybody types changes on that day.
pub fn product_call(product: Product, noun: &str, verb: &str, request: &Map<String, Value>) -> Result<(&'static str, Value), Fault> {
    let status = match product {
        Product::Neo => "grid_status",
        Product::Desks => "desks_status",
        Product::Access => "access_status",
        Product::Bounty => "bounty_status",
    };
    match (noun, verb) {
        // ---- The grid itself ----
        ("realm", "list") => Err(Fault::new(Code::UnknownWords, "Every grid on this computer is listed by the engine itself, not by one of them.")),
        // `--full` is the administrator's whole view, which two of the four keep behind their
        // own door; the other two have nothing more to show than their status already does.
        ("realm", "status") if request.get("full").is_some_and(|value| value == &json!(true)) => match product {
            Product::Access => Ok(("access_manage", admin("overview", request, &[]))),
            Product::Desks => Ok(("desks_manage", admin("status", request, &[]))),
            _ => Ok((status, json!({}))),
        },
        ("realm", "status") => Ok((status, json!({}))),
        ("realm", "address") => Ok(("grid_suggested_address", json!({}))),
        ("realm", "new") => match product {
            Product::Neo => {
                let mut params = Map::new();
                params.insert("name".into(), json!(text(request, "name", "Give the company a name: yougori grids new COMPANY.")?));
                params.insert("address".into(), json!(text(request, "ip", "Give this computer's address on the company network with --ip.")?));
                params.insert("password".into(), json!(text(request, "password", "The grid needs a password.")?));
                carry(&mut params, request, &[("port", "port"), ("hostname", "hostname"), ("tunnel", "tunnel")]);
                Ok(("grid_create", Value::Object(params)))
            }
            Product::Desks => {
                let mut params = Map::new();
                params.insert("name".into(), json!(text(request, "name", "Give the company a name: yougori grids new COMPANY.")?));
                params.insert("address".into(), json!(text(request, "ip", "Give this computer's address on the company network with --ip.")?));
                params.insert("password".into(), json!(text(request, "password", "The grid needs a password.")?));
                carry(&mut params, request, &[("tunnel", "tunnel")]);
                Ok(("desks_create", Value::Object(params)))
            }
            Product::Access => {
                let mut params = Map::new();
                params.insert("company".into(), json!(text(request, "name", "Give the company a name: yougori grids new COMPANY.")?));
                params.insert("address".into(), json!(text(request, "ip", "Give this computer's address on the company network with --ip.")?));
                params.insert("username".into(), json!(text(request, "username", "Name the first administrator with --username.")?));
                params.insert("password".into(), json!(text(request, "password", "The first administrator needs a password.")?));
                carry(&mut params, request, &[("person-name", "name"), ("tunnel", "tunnel")]);
                Ok(("access_create", Value::Object(params)))
            }
            Product::Bounty => Err(not_here(
                product,
                "A closed bounty is published with its source, which this door cannot carry. Use yougori bounty host, which keeps every word it has today.",
            )),
        },
        ("realm", "join") => match product {
            Product::Neo => {
                let mut params = Map::new();
                carry(&mut params, request, &[("invite", "invite"), ("password", "password"), ("person-name", "name"), ("name", "company"), ("ip", "address"), ("port", "port"), ("fingerprint", "fingerprint")]);
                if !params.contains_key("invite") && !params.contains_key("company") {
                    return Err(missing("Give the invite the admin sent with --invite, or the company and its address."));
                }
                Ok(("grid_join", Value::Object(params)))
            }
            Product::Desks if request.get("ready-made").is_some_and(|value| value == &json!(true)) => {
                let membership = need(request, "file", "Read the ready-made membership from a private file with --file -.")?.clone();
                Ok(("desks_adopt_membership", json!({ "membership": membership })))
            }
            Product::Desks => {
                let mut params = Map::new();
                params.insert("invite".into(), json!(text(request, "invite", "Give the invite the admin sent with --invite.")?));
                params.insert("password".into(), json!(text(request, "password", "The grid needs its password.")?));
                carry(&mut params, request, &[("person-name", "name")]);
                Ok(("desks_join", Value::Object(params)))
            }
            Product::Access => Err(not_here(product, "A person signs in to an Access Grid rather than joining it: yougori grids people sign-in --invite INVITE.")),
            Product::Bounty => Err(not_here(product, "A worker joins a closed bounty through its invite: yougori bounty workers shows what this computer has.")),
        },
        ("realm", "password") => match product {
            Product::Neo => Ok(("grid_password", json!({ "password": text(request, "password", "The grid needs a new password.")? }))),
            _ => Err(not_here(product, "Only the Closed Neo Grid has one password for every computer. In this grid each person has their own.")),
        },
        ("realm", "leave") => match product {
            Product::Neo => Ok(("grid_leave", json!({}))),
            Product::Desks => Ok(("desks_leave", json!({}))),
            Product::Access => Err(not_here(product, "Sign out of an Access Grid rather than leaving it: yougori grids people sign-out.")),
            Product::Bounty => Err(not_here(product, "A closed bounty is hosted here rather than joined; delete it to stop.")),
        },
        ("realm", "delete") => match product {
            Product::Neo => Ok(("grid_delete", {
                let mut params = Map::new();
                carry(&mut params, request, &[("when", "when")]);
                Value::Object(params)
            })),
            Product::Desks => Ok(("desks_delete", {
                let mut params = Map::new();
                carry(&mut params, request, &[("when", "when")]);
                Value::Object(params)
            })),
            Product::Access => Ok(("access_delete", {
                let mut params = Map::new();
                carry(&mut params, request, &[("when", "when")]);
                Value::Object(params)
            })),
            Product::Bounty => Ok(("bounty_delete", json!({}))),
        },
        ("realm", "restore") => match product {
            Product::Neo => Ok(("grid_restore", json!({}))),
            Product::Desks => Ok(("desks_restore", json!({}))),
            Product::Access => Ok(("access_restore", json!({}))),
            Product::Bounty => Err(not_here(product, "A closed bounty is not deleted later, so there is nothing to undo.")),
        },
        ("realm", "backup") => Ok((
            "access_backup",
            json!({
                "output": text(request, "output", "Say where the backup goes with --output FILE.")?,
                "passphrase": text(request, "passphrase", "A backup is sealed with a passphrase; read it from stdin with --passphrase -.")?,
            }),
        )),
        ("realm", "restore-backup") => Ok((
            "access_restore_backup",
            json!({
                "file": text(request, "file", "Name the backup file.")?,
                "passphrase": text(request, "passphrase", "Read the backup's passphrase from stdin with --passphrase -.")?,
                "address": text(request, "ip", "Give this computer's address on the company network with --ip.")?,
            }),
        )),
        ("realm", "settings") => Ok(("access_manage", admin("settingsSet", request, &[("require-two-step", "requireTwoStep")]))),
        ("realm", "manage") => {
            let body = need(request, "file", "Read the administrator's request from a private file with --file -.")?.clone();
            match product {
                Product::Desks => Ok(("desks_manage", json!({ "request": body }))),
                Product::Access => Ok(("access_manage", json!({ "request": body }))),
                Product::Bounty => Ok(("bounty_dispatch", json!({ "request": body }))),
                Product::Neo => Err(not_here(product, "The Closed Neo Grid has no raw administrator's door; every one of its changes has words of its own.")),
            }
        }
        // ---- People ----
        ("people", "list" | "show") => match product {
            Product::Desks => Ok(("desks_manage", admin("status", request, &[]))),
            Product::Access => Ok(("access_manage", admin("overview", request, &[]))),
            _ => Err(not_here(product, "This grid has computers rather than people.")),
        },
        ("people", "add") => match product {
            Product::Desks => {
                let mut params = Map::new();
                params.insert("username".into(), json!(text(request, "person", "Name the person: yougori grids people add USERNAME.")?));
                params.insert("password".into(), json!(text(request, "password", "A person needs a password; read it from stdin with --password -.")?));
                carry(&mut params, request, &[("person-name", "name"), ("kind", "kind"), ("cpu", "cpu"), ("memory-gb", "memoryGb"), ("disk-gb", "diskGb"), ("gpu", "gpu")]);
                Ok(("desks_person_add", Value::Object(params)))
            }
            Product::Access => {
                let mut body = Map::new();
                body.insert("action".into(), json!("personAdd"));
                body.insert("username".into(), json!(text(request, "person", "Name the person: yougori grids people add USERNAME.")?));
                body.insert("password".into(), json!(text(request, "password", "A person needs a password; read it from stdin with --password -.")?));
                carry(&mut body, request, &[("person-name", "name"), ("email", "email"), ("permission", "permission"), ("teams", "teams")]);
                Ok(("access_manage", json!({ "request": Value::Object(body) })))
            }
            _ => Err(not_here(product, "This grid has computers rather than people.")),
        },
        ("people", "set") => match product {
            Product::Desks => Ok(("desks_manage", admin("personUpdate", request, &[("person", "id"), ("person-name", "name"), ("email", "email"), ("permission", "permission"), ("teams", "teams")]))),
            Product::Access => Ok(("access_manage", admin("personUpdate", request, &[("person", "person"), ("person-name", "name"), ("email", "email"), ("permission", "permission"), ("teams", "teams")]))),
            _ => Err(not_here(product, "This grid has computers rather than people.")),
        },
        ("people", "password") => match product {
            Product::Desks => Ok((
                "desks_person_password",
                json!({
                    "person": text(request, "person", "Name the person.")?,
                    "password": text(request, "password", "Read the new password from stdin with --password -.")?,
                }),
            )),
            Product::Access => Ok(("access_manage", admin("personPassword", request, &[("person", "person"), ("password", "password")]))),
            _ => Err(not_here(product, "This grid has computers rather than people.")),
        },
        ("people", "remove") => match product {
            Product::Desks => Ok(("desks_person_remove", json!({ "person": text(request, "person", "Name the person.")? }))),
            Product::Access => Ok(("access_manage", admin("personRemove", request, &[("person", "person")]))),
            _ => Err(not_here(product, "This grid has computers rather than people.")),
        },
        ("people", "sign-in") => match product {
            Product::Access => {
                let mut params = Map::new();
                params.insert("invite".into(), json!(text(request, "invite", "Give the invite an administrator sent with --invite.")?));
                carry(&mut params, request, &[("person", "username"), ("password", "password"), ("code", "code"), ("sso", "sso")]);
                Ok(("access_signin", Value::Object(params)))
            }
            Product::Desks => Err(not_here(product, "A person signs in to their desk: yougori grids desks sign-in --invite INVITE --person USERNAME.")),
            _ => Err(not_here(product, "Nobody signs in to this grid; its computers join it.")),
        },
        ("people", "sign-out") => match (product, request.get("person")) {
            (Product::Access, None) => Ok(("access_signout", json!({}))),
            (Product::Access, Some(_)) => Ok(("access_manage", admin("personSignOut", request, &[("person", "person")]))),
            (Product::Desks, _) => Ok(("desk_logout", json!({}))),
            _ => Err(not_here(product, "Nobody signs in to this grid; its computers join it.")),
        },
        ("people", "sign-out-others") => Ok(("access_account", admin("signOutOthers", request, &[]))),
        ("people", "two-step") => {
            let action = match text(request, "step", "Say on, confirm or off.")?.as_str() {
                "on" => "twoStepStart",
                "confirm" => "twoStepConfirm",
                "off" => "twoStepOff",
                _ => return Err(Fault::new(Code::ValueUnusable, "Two-step sign-in is turned on, confirmed or turned off.")),
            };
            Ok(("access_account", admin(action, request, &[("code", "code")])))
        }
        ("people", "reset-two-step") => match product {
            Product::Access => Ok(("access_manage", admin("personTwoStepReset", request, &[("person", "person")]))),
            Product::Desks => Ok(("desks_manage", admin("mfaReset", request, &[("person", "id")]))),
            _ => Err(not_here(product, "Nobody signs in to this grid; its computers join it.")),
        },
        ("people", "my-password") => Ok(("access_account", admin("password", request, &[("password", "password"), ("code", "code")]))),
        ("people", "sso") => {
            let off = request.get("off").is_some_and(|value| value == &json!(true));
            let action = if off { "ssoClear" } else { "ssoSet" };
            let pairs: &[(&str, &str)] = if off { &[] } else { &[("issuer", "issuer"), ("client-id", "clientId"), ("claim", "claim"), ("redirect-port", "redirectPort"), ("passwordless", "passwordless")] };
            match product {
                Product::Access => Ok(("access_manage", admin(action, request, pairs))),
                Product::Desks => Ok(("desks_manage", admin(action, request, pairs))),
                _ => Err(not_here(product, "Nobody signs in to this grid; its computers join it.")),
            }
        }
        // ---- Computers ----
        ("computers", "list" | "show") => Ok((status, json!({}))),
        ("computers", "remove") => {
            let which = json!(text(request, "computer", "Give the computer's ID. yougori grids computers list shows each computer with its ID.")?);
            match product {
                Product::Neo => Ok(("grid_member_remove", json!({ "memberId": which }))),
                Product::Desks => Ok(("desks_member_remove", json!({ "memberId": which }))),
                Product::Bounty => Ok(("bounty_member_remove", json!({ "memberId": which }))),
                Product::Access => Err(not_here(product, "An Access Grid has people and their computers; forget a computer with yougori grids computers forget.")),
            }
        }
        ("computers", "forget") => Ok(("access_account", admin("deviceForget", request, &[("device", "device")]))),
        ("computers", "cloud-fallback") => {
            let action = match text(request, "step", "Say set or clear.")?.as_str() {
                "set" => "cloudFallbackSet",
                "clear" => "cloudFallbackClear",
                _ => return Err(Fault::new(Code::ValueUnusable, "The cloud fallback is set or cleared.")),
            };
            let mut body = match request.get("file") {
                Some(Value::Object(settings)) => settings.clone(),
                _ if action == "cloudFallbackClear" => Map::new(),
                _ => return Err(missing("Read the cloud fallback's settings from a private file with --file -.")),
            };
            body.insert("action".into(), json!(action));
            Ok(("desks_manage", json!({ "request": Value::Object(body) })))
        }
        // ---- What a computer gives ----
        ("share", "show") => Ok((status, json!({}))),
        ("share", "set") => {
            let mut params = Map::new();
            params.insert("memberId".into(), json!(text(request, "computer", "Give the computer's ID. yougori grids computers list shows each computer with its ID.")?));
            carry(&mut params, request, &[("cpu", "cpu"), ("memory-gb", "memoryGb"), ("disk-gb", "diskGb"), ("gpu", "gpu"), ("idle-only", "idleOnly"), ("suggested", "suggested")]);
            Ok(("desks_member_share", Value::Object(params)))
        }
        ("share", "drain") => Ok(("grid_member_exclude", json!({ "memberId": text(request, "computer", "Give the computer's ID. yougori grids computers list shows each computer with its ID.")? }))),
        ("share", "bring-back") => Ok(("grid_member_include", json!({ "memberId": text(request, "computer", "Give the computer's ID. yougori grids computers list shows each computer with its ID.")? }))),
        // ---- Models ----
        ("models", "list" | "show") => Ok(("grid_status", json!({}))),
        ("models", "gpus") => Ok(("grid_neocloud_status", json!({}))),
        ("models", "add-gpu") => Ok(("grid_neocloud_add", json!({ "environmentId": text(request, "gpu", "Give the rented GPU's ID. yougori grids models gpus lists the ones you could add, each with its ID.")? }))),
        ("models", "remove-gpu") => Ok(("grid_neocloud_remove", json!({ "environmentId": text(request, "gpu", "Give the ID of the rented GPU to take out. yougori grids models gpus lists the ones in the grid, each with its ID.")? }))),
        ("models", "stop-gpus") => Ok(("grid_neocloud_stop_all", json!({}))),
        ("models", "add") => {
            let mut params = Map::new();
            params.insert("model".into(), json!(text(request, "model", "Name the model with --model hf.co/OWNER/MODEL.")?));
            carry(&mut params, request, &[("percent", "percent"), ("schedule", "schedule"), ("idle-after", "idleAfter"), ("quant", "quant"), ("scope", "scope"), ("computers", "computers")]);
            Ok(("grid_plan_add", Value::Object(params)))
        }
        ("models", "set") => {
            let mut params = Map::new();
            params.insert("planId".into(), json!(text(request, "plan", "Give the plan's ID. yougori grids models list shows each plan with its ID.")?));
            carry(&mut params, request, &[("model", "model"), ("percent", "percent"), ("schedule", "schedule"), ("idle-after", "idleAfter"), ("quant", "quant")]);
            Ok(("grid_plan_update", Value::Object(params)))
        }
        ("models", "remove") => Ok(("grid_plan_remove", json!({ "planId": text(request, "plan", "Give the plan's ID. yougori grids models list shows each plan with its ID.")? }))),
        ("models", "add-team") => {
            let mut params = Map::new();
            params.insert("name".into(), json!(text(request, "team", "Give the team a name with --team.")?));
            params.insert("lead".into(), json!(text(request, "lead", "Name the lead model with --lead hf.co/OWNER/MODEL.")?));
            params.insert("workers".into(), need(request, "workers", "List the worker models with --workers.")?.clone());
            params.insert("computers".into(), need(request, "computers", "Say how many computers answer at once with --computers.")?.clone());
            carry(&mut params, request, &[("strategy", "strategy"), ("tasks", "tasks"), ("rounds", "rounds")]);
            Ok(("grid_swarm_add", Value::Object(params)))
        }
        ("models", "remove-team") => Ok(("grid_swarm_remove", json!({ "harnessId": text(request, "team", "Name the team, or give its ID. yougori grids models list shows both.")? }))),
        ("models", "run-team") => Ok((
            "grid_swarm_run",
            json!({
                "harness": text(request, "team", "Name the team, or give its ID. yougori grids models list shows both.")?,
                "prompt": text(request, "prompt", "Say what to ask it with --prompt.")?,
            }),
        )),
        ("models", "add-key") => Ok(("grid_key_create", json!({ "name": text(request, "app", "Name the app the key is for with --app.")? }))),
        ("models", "revoke-key") => Ok(("grid_key_revoke", json!({ "keyId": text(request, "key", "Give the key's ID. yougori grids models list shows each key with its ID.")? }))),
        // ---- Desks ----
        ("desks", "list" | "show" | "mine") => Ok(("desks_status", json!({}))),
        ("desks", "add") if request.contains_key("size") => Ok(("desks_manage", admin("deskOrder", request, &[("desk", "name"), ("size", "roleId"), ("person", "person")]))),
        ("desks", "add") => {
            let mut params = Map::new();
            params.insert("name".into(), json!(text(request, "desk", "Give the desk a name.")?));
            carry(&mut params, request, &[("person", "person"), ("kind", "kind"), ("cpu", "cpu"), ("memory-gb", "memoryGb"), ("disk-gb", "diskGb"), ("gpu", "gpu"), ("image", "image")]);
            Ok(("desks_add", Value::Object(params)))
        }
        ("desks", "assign") => {
            let mut params = Map::new();
            params.insert("desk".into(), json!(text(request, "desk", "Give the desk's ID. yougori grids desks list shows each desk with its ID.")?));
            carry(&mut params, request, &[("person", "person")]);
            Ok(("desks_assign", Value::Object(params)))
        }
        ("desks", "retry") => Ok(("desks_retry", json!({ "desk": text(request, "desk", "Give the desk's ID. yougori grids desks list shows each desk with its ID.")? }))),
        ("desks", "remove") => Ok(("desks_remove", json!({ "desk": text(request, "desk", "Give the desk's ID. yougori grids desks list shows each desk with its ID.")? }))),
        ("desks", "sign-in") => {
            let mut params = Map::new();
            params.insert("invite".into(), json!(text(request, "invite", "Give the invite an administrator sent with --invite.")?));
            carry(&mut params, request, &[("person", "username"), ("password", "password"), ("code", "code"), ("sso", "sso")]);
            Ok(("desk_login", Value::Object(params)))
        }
        ("desks", "refresh") => Ok(("desk_refresh", json!({}))),
        ("desks", "sign-out") => Ok(("desk_logout", json!({}))),
        ("desks", "portal") => Ok(("desks_manage", admin("portal", request, &[]))),
        ("desks", "add-image") => Ok(("desks_manage", admin("imageAdd", request, &[("image", "name"), ("from", "url"), ("sha256", "sha256")]))),
        ("desks", "import-image") => Ok(("desks_manage", admin("imageImport", request, &[("path", "path"), ("image", "name")]))),
        ("desks", "remove-image") => Ok(("desks_manage", admin("imageRemove", request, &[("image", "id")]))),
        // A size is a workspace role: a name over a prepared image, which sets its resources.
        ("desks", "add-size") => Ok(("desks_manage", admin("roleAdd", request, &[("size", "name"), ("kind", "kind"), ("cpu", "cpu"), ("memory-gb", "memoryGb"), ("disk-gb", "diskGb"), ("gpu", "gpu"), ("image", "imageId")]))),
        ("desks", "remove-size") => Ok(("desks_manage", admin("roleRemove", request, &[("size", "id")]))),
        ("desks", "parking") => {
            let action = match text(request, "step", "Say set or clear.")?.as_str() {
                "set" => "parkingSet",
                "clear" => "parkingClear",
                _ => return Err(Fault::new(Code::ValueUnusable, "Parking is set or cleared.")),
            };
            let mut body = match request.get("file") {
                Some(Value::Object(settings)) => settings.clone(),
                _ if action == "parkingClear" => Map::new(),
                _ => return Err(missing("Read the parking settings from a private file with --file -.")),
            };
            body.insert("action".into(), json!(action));
            Ok(("desks_manage", json!({ "request": Value::Object(body) })))
        }
        // ---- Credentials ----
        ("credentials", "list" | "show") => Ok(("access_status", json!({}))),
        ("credentials", "add") => {
            let mut body = Map::new();
            body.insert("action".into(), json!("credentialAdd"));
            body.insert("name".into(), json!(text(request, "credential", "Give the credential a name.")?));
            body.insert("kind".into(), json!(text(request, "kind", "Say what kind of credential it is with --kind.")?));
            body.insert("destinations".into(), json!([text(request, "destination", "Say where it may be sent with --destination URL.")?]));
            body.insert("value".into(), json!(text(request, "value", "Read the credential's value from stdin with --value -.")?));
            carry(&mut body, request, &[("field", "field"), ("note", "note"), ("config", "config")]);
            Ok(("access_manage", json!({ "request": Value::Object(body) })))
        }
        ("credentials", "set") => Ok(("access_manage", admin("credentialUpdate", request, &[("credential", "credential"), ("credential-name", "name"), ("kind", "kind"), ("field", "field"), ("note", "note"), ("config", "config")]))),
        ("credentials", "rotate") => Ok((
            "access_manage",
            admin("credentialUpdate", request, &[("credential", "credential"), ("value", "value")]),
        )),
        ("credentials", "remove") => Ok(("access_manage", admin("credentialRemove", request, &[("credential", "credential")]))),
        ("credentials", "allow") => {
            let decision = if request.get("never").is_some_and(|value| value == &json!(true)) {
                "never"
            } else if request.get("ask").is_some_and(|value| value == &json!(true)) {
                "ask"
            } else {
                "allow"
            };
            let mut body = Map::new();
            body.insert("action".into(), json!("ruleAdd"));
            body.insert("decision".into(), json!(decision));
            carry(&mut body, request, &[("credential", "credential"), ("who", "who"), ("methods", "methods"), ("path", "path"), ("reveal", "reveal"), ("limit", "limit"), ("hours", "hours"), ("note", "note")]);
            Ok(("access_manage", json!({ "request": Value::Object(body) })))
        }
        ("credentials", "remove-rule") => Ok(("access_manage", admin("ruleRemove", request, &[("rule", "rule")]))),
        ("credentials", "use") => {
            let mut params = Map::new();
            params.insert("credential".into(), json!(text(request, "credential", "Name the credential.")?));
            params.insert("url".into(), json!(text(request, "url", "Say where the call goes.")?));
            carry(&mut params, request, &[("request-method", "method"), ("body", "body"), ("agent", "agent")]);
            // `--header 'Name: value'`, given again for another, is the shape the hub takes.
            if let Some(Value::Array(lines)) = request.get("header") {
                let mut headers = Map::new();
                for line in lines.iter().filter_map(Value::as_str) {
                    let (name, value) = line.split_once(':').ok_or_else(|| Fault::new(Code::ValueUnusable, "Write a header as --header 'Name: value'."))?;
                    headers.insert(name.trim().to_owned(), json!(value.trim()));
                }
                params.insert("headers".into(), Value::Object(headers));
            }
            Ok(("access_use", Value::Object(params)))
        }
        ("credentials", "reveal") => {
            let mut params = Map::new();
            params.insert("credential".into(), json!(text(request, "credential", "Name the credential.")?));
            carry(&mut params, request, &[("reason", "reason"), ("agent", "agent")]);
            Ok(("access_reveal", Value::Object(params)))
        }
        // ---- Approvals ----
        ("requests", "list") => Ok(("access_status", json!({}))),
        ("requests", "show" | "check") => Ok(("access_check", json!({ "id": text(request, "request", "Name the request.")? }))),
        ("requests", "approve") => {
            let mut body = Map::new();
            body.insert("action".into(), json!("decide"));
            body.insert("approve".into(), json!(true));
            carry(&mut body, request, &[("request", "request"), ("hours", "hours")]);
            Ok(("access_manage", json!({ "request": Value::Object(body) })))
        }
        ("requests", "deny") => {
            let mut body = Map::new();
            body.insert("action".into(), json!("decide"));
            body.insert("approve".into(), json!(false));
            carry(&mut body, request, &[("request", "request"), ("reason", "reason")]);
            Ok(("access_manage", json!({ "request": Value::Object(body) })))
        }
        // ---- Research ----
        ("research", _) => research_call(noun, verb, request),
        // ---- Connectors ----
        ("connectors", "list" | "show") => Ok(("desks_manage", admin("status", request, &[]))),
        ("connectors", "add" | "credential") => {
            let action = if verb == "add" { "connectionAdd" } else { "connectionCredential" };
            let mut body = match need(request, "file", "Read the connector's details from a private file with --file -.")? {
                Value::Object(settings) => settings.clone(),
                _ => return Err(missing("The connector's file holds a JSON object.")),
            };
            body.insert("action".into(), json!(action));
            if let Some(connector) = request.get("connector") {
                body.insert("id".into(), connector.clone());
            }
            Ok(("desks_manage", json!({ "request": Value::Object(body) })))
        }
        ("connectors", "test") => Ok(("desks_manage", admin("connectionTest", request, &[("connector", "id")]))),
        ("connectors", "provision") => Ok(("desks_manage", admin("connectionProvision", request, &[("connector", "id"), ("person", "personId")]))),
        ("connectors", "revoke") => Ok(("desks_manage", admin("connectionRevoke", request, &[("connector", "id"), ("person", "personId")]))),
        ("connectors", "remove") => Ok(("desks_manage", admin("connectionRemove", request, &[("connector", "id")]))),
        // ---- The engine's own record of queued work ----
        ("work", "list") => Ok(("jobs_list", json!({}))),
        ("work", "show") => Ok(("jobs_get", json!({ "jobId": text(request, "work", "Name the work.")? }))),
        ("work", "cancel") => Ok(("jobs_cancel", json!({ "jobId": text(request, "work", "Name the work.")? }))),
        // ---- The record ----
        // Asking what one named command caused is a question only Grid Core's record can answer,
        // and no product hub has moved onto it yet. Saying so is better than answering with
        // everything and letting somebody believe it was filtered.
        ("log", "show") if request.contains_key("command") => Err(not_here(
            product,
            "This grid's record does not yet say which command caused an event. Grid Core keeps that, and this grid still keeps its own record.",
        )),
        ("log", "show") => match product {
            Product::Access => Ok(("access_manage", admin("activityExport", request, &[("limit", "limit")]))),
            _ => {
                let mut params = Map::new();
                carry(&mut params, request, &[("since", "since"), ("limit", "limit")]);
                Ok(("security_audit", Value::Object(params)))
            }
        },
        ("log", "export") => Ok(("access_manage", admin("activityExport", request, &[("limit", "limit")]))),
        ("log", "verify") => match product {
            Product::Access => Ok(("access_manage", admin("activityVerify", request, &[]))),
            _ => Ok(("security_audit", json!({ "verify": true, "limit": 1000 }))),
        },
        _ => Err(Fault::new(Code::UnknownWords, format!("There is no such thing as grids {noun} {verb}. Run yougori grids {noun} --help."))),
    }
}

/// Swarm Mining, which this door reads and steers but never starts.
///
/// Starting a worker keeps its own guided setup, `yougori start bounty`, with every word it has
/// today. There is deliberately no `grids research start`: a worker is started in one place.
fn research_call(noun: &str, verb: &str, request: &Map<String, Value>) -> Result<(&'static str, Value), Fault> {
    let action = match verb {
        "list" => "workers",
        "show" => "status",
        "check" => "doctor",
        "activity" => "activity",
        "offers" => "offers",
        "details" => "details",
        "skip" => "skip",
        "bounties" => "bounties",
        "rewards" => "rewards",
        "reports" => "reports",
        "messages" => "messages",
        "chat" => "chat",
        "pause" => "pause",
        "resume" => "resume",
        "stop" => "stop",
        "leave" => "leave",
        "remove" => "delete",
        "memory" => "memory",
        "start" => {
            return Err(not_here(
                Product::Bounty,
                "A research worker is started in one place, with its questions asked one at a time: yougori start bounty.",
            ))
        }
        _ => return Err(Fault::new(Code::UnknownWords, format!("There is no such thing as grids {noun} {verb}. Run yougori grids research --help."))),
    };
    let mut body = Map::new();
    body.insert("action".into(), json!(action));
    carry(&mut body, request, &[("worker", "worker"), ("offer", "offer"), ("message", "message"), ("after", "after"), ("budget-minutes", "budgetMinutes"), ("step", "mode")]);
    Ok(("swarm_dispatch", json!({ "request": Value::Object(body) })))
}

/// Verbs the engine answers from its own register of the grids on this computer, without asking
/// any one grid.
///
/// Listing them is one: no single product knows about the others. Health and the endpoint that
/// serves it are the others, for the same reason and one more. A checkup is read from a realm's
/// own database rather than from a product hub, so there is no product handler to translate to,
/// and an operator asking whether their grids are healthy has to get an answer on a computer
/// where a product is in trouble, which is exactly when asking a product would fail.
pub fn answered_by_the_register(noun: &str, verb: &str) -> bool {
    noun == "realm" && matches!(verb, "list" | "health" | "observe")
}

/// Starting a grid, joining one, or asking this computer for an address to host on: there is no
/// grid on this computer to look up yet, so the words say which product answers rather than the
/// register of what is already here.
pub fn chosen_by_the_words(noun: &str, verb: &str) -> bool {
    noun == "realm" && matches!(verb, "new" | "join" | "address")
}

/// Which capability a product's grid has, for the registry and for the refusals.
pub fn capability_of(product: Product) -> Capability {
    product.capability()
}
