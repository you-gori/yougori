//! `yougori access …`: the company's Access Grid from the CLI, and `yougori access mcp`, the MCP
//! server agents connect to. Agents send requests with a company credential through the hub and
//! never see the value. Passwords and credential values come from a hidden prompt or stdin
//! (`--password -`, `--value -`), never from an argument.
use crate::{client, grid, public::call};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    io::{BufRead, IsTerminal, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const USAGE: &str = "Usage: yougori access status
       yougori access create COMPANY --ip THIS_PC_IP --username NAME [--name FULL_NAME] [--tunnel quick|DOMAIN] [--password -] --yes
       yougori access signin --invite INVITE --username NAME [--code 123456] [--password -] | signin --invite INVITE --sso
       yougori access signout --yes
       yougori access delete [--when later|now|forget] --yes | restore
       yougori access backup --output FILE [--passphrase -] | restore-backup FILE --ip THIS_PC_IP [--passphrase -] --yes
       yougori access two-step on | confirm --code 123456 | off --code 123456
       yougori access password [--code 123456] [--password -] | computers | forget-computer DEVICE_ID --yes | sign-out-others --yes
       yougori access add-person USERNAME [--name NAME] [--email EMAIL] [--permission member|approver|auditor|admin] [--team TEAM] [--password -]
       yougori access set-person USERNAME [--name NAME] [--email EMAIL] [--permission P] [--team TEAM] | person-password USERNAME [--password -]
       yougori access reset-two-step USERNAME --yes | sign-out-person USERNAME --yes | remove-person USERNAME --yes
       yougori access add-credential NAME --kind bearer|header|basic|query|oauth|github-app|aws --destination URL [--field NAME] [--note TEXT] [--value - | --value-file FILE]
                [--token-url URL --client-id ID [--scope S] [--audience A] [--auth basic|body]]
                [--app-id CLIENT_ID|APP_ID --installation-id N [--api-url URL]]
                [--region R [--service S] [--role-arn ARN] [--external-id ID] [--session-seconds N]]
       yougori access rotate-credential NAME [--value - | --value-file FILE] | remove-credential NAME --yes
       yougori access allow CREDENTIAL [--who everyone|team:NAME|USERNAME] [--methods GET,POST] [--path /PREFIX] [--ask|--never] [--reveal] [--limit N] [--hours N]
       yougori access remove-rule RULE_ID --yes
       yougori access settings --require-two-step true|false
       yougori access sso --issuer URL --client-id ID [--claim email] [--redirect-port N] [--passwordless] | sso --off --yes
       yougori access requests | approve REQUEST_ID [--hours N] | deny REQUEST_ID [--reason TEXT]
       yougori access log [--export FILE] [--verify]
       yougori access use CREDENTIAL URL [--method GET] [--header 'Name: value'] [--body TEXT | --body-file FILE]
       yougori access check REQUEST_ID
       yougori access mcp

--team, --destination and --header may be repeated.";

/// How long the CLI and an agent's tool call wait for an approver before handing back the
/// request ID to check later.
const TOOL_WAIT: Duration = Duration::from_secs(25);

pub fn requested(args: &[String]) -> bool {
    args.first().is_some_and(|word| word == "access")
}

#[derive(Debug, Default, PartialEq)]
struct Options {
    words: Vec<String>,
    yes: bool,
    /// `None`: not given; `Some(None)`: prompt; `Some(Some("-"))`: stdin.
    password: Option<Option<String>>,
    value: Option<Option<String>>,
    passphrase: Option<Option<String>>,
    flags: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
}

impl Options {
    fn one(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|values| values.last()).map(String::as_str)
    }
    fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| flag == name)
    }
    fn only(&self, allowed: &[&str]) -> Result<(), String> {
        let given = self.values.keys().map(String::as_str).chain(self.flags.iter().map(String::as_str));
        let mut extra = given.filter(|name| !allowed.contains(name));
        match extra.next() {
            Some(name) => Err(format!("--{name} does not apply here.\n{USAGE}")),
            None => Ok(()),
        }
    }
}

const REPEATED: &[&str] = &["team", "destination", "header"];
const VALUED: &[&str] = &[
    "ip", "username", "name", "tunnel", "invite", "permission", "team", "kind", "field", "destination", "note", "who", "methods", "path", "hours", "reason", "method", "header", "body", "body-file",
    "code", "email", "when", "output", "value-file", "limit", "token-url", "client-id", "scope", "audience", "auth", "app-id", "installation-id", "api-url", "region", "service", "role-arn", "external-id",
    "session-seconds", "issuer", "claim", "redirect-port", "require-two-step", "export",
];
const FLAGS: &[&str] = &["ask", "never", "reveal", "sso", "passwordless", "off", "verify"];

fn options(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let Some(flag) = arg.strip_prefix("--") else {
            options.words.push(arg.clone());
            index += 1;
            continue;
        };
        let (name, inline) = flag.split_once('=').map_or((flag, None), |(name, value)| (name, Some(value.to_owned())));
        let next = |index: &mut usize| inline.clone().or_else(|| args.get(*index + 1).filter(|next| !next.starts_with("--")).inspect(|_| *index += 1).cloned());
        match name {
            "yes" if inline.is_none() => options.yes = true,
            "password" | "value" | "passphrase" => {
                let value = next(&mut index);
                if value.as_deref().is_some_and(|value| value != "-") {
                    return Err(format!("Never type the {name} into the command: leave it out to be asked for it, or use --{name} - to read it from stdin."));
                }
                match name {
                    "password" => options.password = Some(value),
                    "value" => options.value = Some(value),
                    _ => options.passphrase = Some(value),
                }
            }
            flag if FLAGS.contains(&flag) && inline.is_none() => {
                if !options.flags.iter().any(|own| own == flag) {
                    options.flags.push(flag.to_owned());
                }
            }
            valued if VALUED.contains(&valued) => {
                let value = next(&mut index).filter(|value| !value.trim().is_empty()).ok_or_else(|| format!("--{valued} needs a value"))?;
                let list = options.values.entry(valued.to_owned()).or_default();
                if !list.is_empty() && !REPEATED.contains(&valued) {
                    return Err(format!("--{valued} is given twice. Use it once; the second one would be ignored and that is not worth guessing at."));
                }
                list.push(value);
            }
            _ => return Err(format!("Unknown option --{name}.\n{USAGE}")),
        }
        index += 1;
    }
    Ok(options)
}

fn secret(given: &Option<Option<String>>, prompt: &str, confirm: bool) -> Result<String, String> {
    match given {
        Some(Some(_)) => grid::stdin_line(&mut std::io::stdin().lock()),
        _ if std::io::stdin().is_terminal() => {
            let first = grid::hidden(prompt)?;
            if confirm && grid::hidden("Type it again: ")? != first {
                // Named, because this function asks for several different secrets and "they do
                // not match" leaves the reader working out which two it meant.
                let what = prompt.split('(').next().unwrap_or(prompt).trim().trim_end_matches(':').trim().to_ascii_lowercase();
                return Err(format!("The two entries for the {what} do not match. Nothing was changed; run it again."));
            }
            Ok(first)
        }
        _ => Err("Not in a terminal: supply it on stdin with - (for example --password -)".into()),
    }
}

fn word<'a>(options: &'a Options, index: usize, what: &str) -> Result<&'a str, String> {
    options.words.get(index).map(String::as_str).ok_or_else(|| format!("Give the {what}.\n{USAGE}"))
}

fn no_more_words(options: &Options, count: usize) -> Result<(), String> {
    match options.words.get(count) {
        Some(extra) => Err(format!("Unexpected '{extra}'.\n{USAGE}")),
        None => Ok(()),
    }
}

fn manage(request: Value) -> (String, Value) {
    ("access_manage".into(), json!({"request": request}))
}

fn account(request: Value) -> (String, Value) {
    ("access_account".into(), json!({"request": request}))
}

/// A credential's value: from a file (a GitHub App's .pem), stdin, or a hidden prompt.
fn credential_value(options: &Options, prompt: &str) -> Result<String, String> {
    if let Some(file) = options.one("value-file") {
        if options.value.is_some() {
            return Err("Use --value - or --value-file, not both".into());
        }
        return std::fs::read_to_string(file).map_err(|error| format!("Cannot read {file}: {error}"));
    }
    secret(&options.value, prompt, false)
}

/// The settings a minting credential kind takes from its options.
fn credential_config(options: &Options) -> Map<String, Value> {
    let mut config = Map::new();
    for (flag, key) in [("token-url", "tokenUrl"), ("client-id", "clientId"), ("scope", "scope"), ("audience", "audience"), ("auth", "auth"), ("app-id", "appId"), ("installation-id", "installationId"), ("api-url", "apiUrl"), ("region", "region"), ("service", "service"), ("role-arn", "roleArn"), ("external-id", "externalId"), ("session-seconds", "sessionSeconds")] {
        if let Some(value) = options.one(flag) {
            config.insert(key.into(), json!(value));
        }
    }
    config
}

const CREDENTIAL_SETTINGS: &[&str] = &["token-url", "client-id", "scope", "audience", "auth", "app-id", "installation-id", "api-url", "region", "service", "role-arn", "external-id", "session-seconds"];

fn positive(text: &str, what: &str) -> Result<f64, String> {
    text.parse::<f64>().ok().filter(|value| *value > 0.0).ok_or_else(|| format!("--{what} must be a positive number"))
}

/// The engine method and parameters for one command, asking for any password or value first.
fn plan(args: &[String]) -> Result<(String, Value), String> {
    let options = options(args.get(2..).unwrap_or_default())?;
    let action = args.get(1).map(String::as_str).unwrap_or("status");
    let confirm = |what: &str| -> Result<(), String> {
        if options.yes { Ok(()) } else { Err(format!("{what} Repeat with --yes if that is what you want.")) }
    };
    let people = |options: &Options, request: &mut Value| {
        if let Some(name) = options.one("name") {
            request["name"] = json!(name);
        }
        if let Some(email) = options.one("email") {
            request["email"] = json!(email);
        }
        if let Some(permission) = options.one("permission") {
            request["permission"] = json!(permission);
        }
        if options.values.contains_key("team") {
            request["teams"] = json!(options.all("team"));
        }
    };
    match action {
        "status" | "requests" => {
            options.only(&[])?;
            no_more_words(&options, 0)?;
            Ok(("access_status".into(), json!({})))
        }
        "log" => {
            options.only(&["export", "verify"])?;
            no_more_words(&options, 0)?;
            match (options.one("export"), options.flag("verify")) {
                (Some(_), true) => Err("Use --export or --verify, not both".into()),
                (Some(_), false) => Ok(manage(json!({"action": "activityExport"}))),
                (None, true) => Ok(manage(json!({"action": "activityVerify"}))),
                (None, false) => Ok(("access_status".into(), json!({}))),
            }
        }
        "create" => {
            options.only(&["ip", "username", "name", "tunnel"])?;
            let company = word(&options, 0, "company name")?;
            no_more_words(&options, 1)?;
            let ip = options.one("ip").ok_or("--ip THIS_PC_IP is required: this computer's address on the company network, such as 192.168.1.20")?;
            let username = options.one("username").ok_or("--username NAME is required: your own account as the first admin")?;
            confirm("Hosting an Access Grid opens a service on this computer's network that keeps the company's credentials.")?;
            let password = secret(&options.password, "Your Access Grid password (hidden): ", true)?;
            let mut params = json!({"company": company, "address": ip, "username": username, "password": password});
            for key in ["name", "tunnel"] {
                if let Some(value) = options.one(key) {
                    params[key] = json!(value);
                }
            }
            Ok(("access_create".into(), params))
        }
        "signin" => {
            options.only(&["invite", "username", "code", "sso"])?;
            no_more_words(&options, 0)?;
            let invite = options.one("invite").ok_or("--invite INVITE is required: the access-invite: code your admin shared")?;
            if options.flag("sso") {
                if options.one("username").is_some() || options.password.is_some() {
                    return Err("--sso signs you in through your company's identity provider in the browser; leave out --username and --password".into());
                }
                return Ok(("access_signin".into(), json!({"invite": invite, "sso": true})));
            }
            let username = options.one("username").ok_or("--username NAME is required, or --sso to sign in with your company account")?;
            let password = secret(&options.password, "Your Access Grid password (hidden): ", false)?;
            let mut params = json!({"invite": invite, "username": username, "password": password});
            if let Some(code) = options.one("code") {
                params["code"] = json!(code);
            }
            Ok(("access_signin".into(), params))
        }
        "restore" => {
            options.only(&[])?;
            no_more_words(&options, 0)?;
            Ok(("access_restore".into(), json!({})))
        }
        "backup" => {
            options.only(&["output"])?;
            no_more_words(&options, 0)?;
            let output = options.one("output").ok_or("--output FILE is required: where to write the encrypted backup")?;
            let passphrase = secret(&options.passphrase, "Backup passphrase (hidden): ", true)?;
            Ok(("access_backup".into(), json!({"output": output, "passphrase": passphrase})))
        }
        "restore-backup" => {
            options.only(&["ip"])?;
            let file = word(&options, 0, "backup file")?;
            no_more_words(&options, 1)?;
            let ip = options.one("ip").ok_or("--ip THIS_PC_IP is required: this computer's address on the company network")?;
            confirm("This computer will run the Access Grid from the backup, with every credential it holds.")?;
            let passphrase = secret(&options.passphrase, "Backup passphrase (hidden): ", false)?;
            Ok(("access_restore_backup".into(), json!({"file": file, "passphrase": passphrase, "address": ip})))
        }
        "two-step" => {
            options.only(&["code"])?;
            let step = word(&options, 0, "two-step step: on, confirm or off")?;
            no_more_words(&options, 1)?;
            match step {
                "on" => Ok(account(json!({"action": "twoStepStart"}))),
                "confirm" => Ok(account(json!({"action": "twoStepConfirm", "code": options.one("code").ok_or("--code is the six digits your authenticator app shows")?}))),
                "off" => Ok(account(json!({"action": "twoStepOff", "code": options.one("code").ok_or("--code is the six digits your authenticator app shows")?}))),
                other => Err(format!("There is no two-step step called '{other}'. It is on, confirm, or off.")),
            }
        }
        "password" => {
            options.only(&["code"])?;
            no_more_words(&options, 0)?;
            let password = secret(&options.password, "Your new Access Grid password (hidden): ", true)?;
            let mut request = json!({"action": "password", "password": password});
            if let Some(code) = options.one("code") {
                request["code"] = json!(code);
            }
            Ok(account(request))
        }
        "computers" => {
            options.only(&[])?;
            no_more_words(&options, 0)?;
            Ok(("access_status".into(), json!({})))
        }
        "forget-computer" => {
            options.only(&[])?;
            let device = word(&options, 0, "computer's ID from yougori access computers")?;
            no_more_words(&options, 1)?;
            confirm("That computer is signed out of the Access Grid.")?;
            Ok(account(json!({"action": "deviceForget", "device": device})))
        }
        "sign-out-others" => {
            options.only(&[])?;
            no_more_words(&options, 0)?;
            confirm("Every other computer you signed in on must sign in again.")?;
            Ok(account(json!({"action": "signOutOthers"})))
        }
        "reset-two-step" | "sign-out-person" => {
            options.only(&[])?;
            let person = word(&options, 0, "username")?;
            no_more_words(&options, 1)?;
            confirm(&format!("{person} is signed out on every computer{}.", if action == "reset-two-step" { " and two-step sign-in is turned off" } else { "" }))?;
            Ok(manage(json!({"action": if action == "reset-two-step" { "personTwoStepReset" } else { "personSignOut" }, "person": person})))
        }
        "settings" => {
            options.only(&["require-two-step"])?;
            no_more_words(&options, 0)?;
            let required = match options.one("require-two-step") {
                Some("true") => true,
                Some("false") => false,
                _ => return Err("--require-two-step takes true or false: true asks everyone for a code as well as a password.".into()),
            };
            Ok(manage(json!({"action": "settingsSet", "requireTwoStep": required})))
        }
        "sso" => {
            options.only(&["issuer", "client-id", "claim", "redirect-port", "passwordless", "off"])?;
            no_more_words(&options, 0)?;
            if options.flag("off") {
                confirm("People sign in with their passwords again.")?;
                return Ok(manage(json!({"action": "ssoClear"})));
            }
            let issuer = options.one("issuer").ok_or("--issuer URL is required: your identity provider's address, such as https://login.microsoftonline.com/TENANT/v2.0")?;
            let client = options.one("client-id").ok_or("--client-id ID is required: the app registered at your identity provider")?;
            let mut request = json!({"action": "ssoSet", "issuer": issuer, "clientId": client, "claim": options.one("claim").unwrap_or("email"), "passwordless": options.flag("passwordless")});
            if let Some(port) = options.one("redirect-port") {
                request["redirectPort"] = json!(port.parse::<u16>().ok().filter(|port| *port >= 1024).ok_or("--redirect-port is a number from 1024 to 65535")?);
            }
            Ok(manage(request))
        }
        "signout" => {
            options.only(&[])?;
            confirm("Agents on this computer will no longer be able to use the company's credentials.")?;
            Ok(("access_signout".into(), json!({})))
        }
        "delete" => {
            options.only(&["when"])?;
            no_more_words(&options, 0)?;
            let when = options.one("when").unwrap_or("later");
            confirm(match when {
                "later" => "The Access Grid is paused for three days, then deleted with every credential, person and rule; `yougori access restore` takes it back until then.",
                "now" => "The Access Grid's credentials, people and rules are deleted at once.",
                _ => "The Access Grid is removed from this computer with its credentials, people, rules and activity log.",
            })?;
            Ok(("access_delete".into(), json!({"when": when})))
        }
        "add-person" => {
            options.only(&["name", "email", "permission", "team"])?;
            let username = word(&options, 0, "username")?;
            no_more_words(&options, 1)?;
            let password = secret(&options.password, &format!("Password for {username} (hidden): "), true)?;
            let mut request = json!({"action": "personAdd", "username": username, "password": password});
            people(&options, &mut request);
            Ok(manage(request))
        }
        "set-person" => {
            options.only(&["name", "email", "permission", "team"])?;
            let person = word(&options, 0, "username")?;
            no_more_words(&options, 1)?;
            let mut request = json!({"action": "personUpdate", "person": person});
            people(&options, &mut request);
            Ok(manage(request))
        }
        "person-password" => {
            options.only(&[])?;
            let person = word(&options, 0, "username")?;
            no_more_words(&options, 1)?;
            let password = secret(&options.password, &format!("New password for {person} (hidden): "), true)?;
            Ok(manage(json!({"action": "personPassword", "person": person, "password": password})))
        }
        "remove-person" => {
            options.only(&[])?;
            let person = word(&options, 0, "username")?;
            no_more_words(&options, 1)?;
            confirm(&format!("{person} can no longer sign in, and their personal rules are removed."))?;
            Ok(manage(json!({"action": "personRemove", "person": person})))
        }
        "add-credential" => {
            options.only(&[&["kind", "field", "destination", "note", "value-file"][..], CREDENTIAL_SETTINGS].concat())?;
            let name = word(&options, 0, "credential name")?;
            no_more_words(&options, 1)?;
            let destinations = options.all("destination");
            if destinations.is_empty() {
                return Err("--destination URL is required: where the credential may be sent, such as https://api.github.com".into());
            }
            let value = credential_value(&options, &format!("Value of {name} (hidden): "))?;
            let mut request = json!({"action": "credentialAdd", "name": name, "kind": options.one("kind").unwrap_or("bearer"), "destinations": destinations, "value": value, "config": credential_config(&options)});
            for key in ["field", "note"] {
                if let Some(text) = options.one(key) {
                    request[key] = json!(text);
                }
            }
            Ok(manage(request))
        }
        "rotate-credential" => {
            options.only(&["value-file"])?;
            let name = word(&options, 0, "credential name")?;
            no_more_words(&options, 1)?;
            let value = credential_value(&options, &format!("New value of {name} (hidden): "))?;
            Ok(manage(json!({"action": "credentialUpdate", "credential": name, "value": value})))
        }
        "remove-credential" => {
            options.only(&[])?;
            let name = word(&options, 0, "credential name")?;
            no_more_words(&options, 1)?;
            confirm(&format!("{name} and its rules are deleted; agents can no longer use it."))?;
            Ok(manage(json!({"action": "credentialRemove", "credential": name})))
        }
        "allow" => {
            options.only(&["who", "methods", "path", "hours", "note", "ask", "never", "reveal", "limit"])?;
            let credential = word(&options, 0, "credential name")?;
            no_more_words(&options, 1)?;
            if options.flag("ask") && options.flag("never") {
                return Err("Use --ask or --never, not both".into());
            }
            let decision = if options.flag("never") { "never" } else if options.flag("ask") { "ask" } else { "allow" };
            let mut request = json!({"action": "ruleAdd", "credential": credential, "who": options.one("who").unwrap_or("everyone"), "decision": decision, "reveal": options.flag("reveal")});
            if let Some(methods) = options.one("methods") {
                request["methods"] = json!(methods.split(',').map(str::trim).filter(|method| !method.is_empty()).collect::<Vec<_>>());
            }
            for key in ["path", "note"] {
                if let Some(text) = options.one(key) {
                    request[key] = json!(text);
                }
            }
            if let Some(hours) = options.one("hours") {
                request["hours"] = json!(positive(hours, "hours")?);
            }
            if let Some(limit) = options.one("limit") {
                request["limit"] = json!(limit.parse::<u32>().ok().filter(|limit| *limit > 0).ok_or("--limit is a number of uses an hour")?);
            }
            Ok(manage(request))
        }
        "remove-rule" => {
            options.only(&[])?;
            let rule = word(&options, 0, "rule ID")?;
            no_more_words(&options, 1)?;
            confirm("The rule stops applying at once.")?;
            Ok(manage(json!({"action": "ruleRemove", "rule": rule})))
        }
        "approve" | "deny" => {
            options.only(if action == "approve" { &["hours"] } else { &["reason"] })?;
            let request = word(&options, 0, "request ID")?;
            no_more_words(&options, 1)?;
            let mut decision = json!({"action": "decide", "request": request, "approve": action == "approve"});
            if let Some(hours) = options.one("hours") {
                decision["hours"] = json!(hours.parse::<f64>().ok().filter(|hours| *hours > 0.0).ok_or("--hours must be a positive number")?);
            }
            if let Some(reason) = options.one("reason") {
                decision["reason"] = json!(reason);
            }
            Ok(manage(decision))
        }
        "use" => {
            options.only(&["method", "header", "body", "body-file"])?;
            let credential = word(&options, 0, "credential name")?;
            let url = word(&options, 1, "URL")?;
            no_more_words(&options, 2)?;
            let mut params = json!({"credential": credential, "url": url, "method": options.one("method").unwrap_or("GET"), "agent": "yougori CLI"});
            let mut headers = Map::new();
            for header in options.all("header") {
                let (name, value) = header.split_once(':').ok_or_else(|| format!("--header '{header}' must look like 'Name: value'"))?;
                headers.insert(name.trim().to_owned(), json!(value.trim()));
            }
            if !headers.is_empty() {
                params["headers"] = Value::Object(headers);
            }
            match (options.one("body"), options.one("body-file")) {
                (Some(_), Some(_)) => return Err("Use --body or --body-file, not both".into()),
                (Some(body), None) => params["body"] = json!(body),
                (None, Some(file)) => {
                    let bytes = std::fs::read(file).map_err(|error| format!("Cannot read {file}: {error}"))?;
                    match String::from_utf8(bytes) {
                        Ok(text) => params["body"] = json!(text),
                        Err(error) => params["bodyBase64"] = json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, error.into_bytes())),
                    }
                }
                (None, None) => {}
            }
            Ok(("access_use".into(), params))
        }
        "check" => {
            options.only(&[])?;
            let id = word(&options, 0, "request ID")?;
            no_more_words(&options, 1)?;
            Ok(("access_check".into(), json!({"id": id})))
        }
        other => Err(format!("Unknown access command '{other}'.\n{USAGE}")),
    }
}

async fn waiting<T>(label: &str, work: impl std::future::Future<Output = Result<T, String>>) -> Result<T, String> {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        crate::cli_ui::busy(label, work).await
    } else {
        work.await
    }
}

/// Asks about a request until it is no longer waiting or running, for at most `limit`.
async fn settle(mut value: Value, limit: Duration) -> Result<Value, String> {
    let started = Instant::now();
    while matches!(value["state"].as_str(), Some("waiting" | "running")) && started.elapsed() < limit {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let id = value["id"].as_str().ok_or("The Access Grid sent a request without an ID")?.to_owned();
        value = call("access_check", json!({"id": id})).await?;
    }
    Ok(value)
}

/// Runs one `yougori access` command (not `mcp`) and returns the engine's answer.
pub async fn run(args: &[String]) -> Result<Value, String> {
    let (method, params) = plan(args)?;
    waiting("Starting Yougori", client::start(None)).await?;
    let label = match method.as_str() {
        "access_create" => "Starting the Access Grid",
        "access_signin" => "Signing in",
        "access_use" => "Sending the request through the Access Grid",
        _ => "Asking the Access Grid",
    };
    let starting = params["request"]["action"] == "twoStepStart";
    let export = (params["request"]["action"] == "activityExport").then(|| {
        let at = args.iter().position(|arg| arg == "--export" || arg.starts_with("--export="));
        at.and_then(|at| args[at].strip_prefix("--export=").map(str::to_owned).or_else(|| args.get(at + 1).cloned())).unwrap_or_default()
    });
    let value = waiting(label, call(&method, params)).await?;
    if method == "access_use" {
        // A person at the CLI waits for an approver as long as the request does.
        return waiting("Waiting for an approver", settle(value, Duration::from_secs(15 * 60))).await;
    }
    if let Some(file) = export {
        let entries = value["entries"].as_array().cloned().unwrap_or_default();
        let lines: String = entries.iter().map(|entry| format!("{entry}\n")).collect();
        std::fs::write(&file, lines).map_err(|error| format!("Cannot write {file}: {error}"))?;
        return Ok(json!({"exported": entries.len(), "file": file, "message": format!("Wrote {} activity entries to {file}, oldest first, each with its MAC.", entries.len())}));
    }
    if starting {
        return confirm_two_step(value).await;
    }
    Ok(value)
}

/// Shows the new two-step secret and, at a terminal, asks for the first code to turn it on.
async fn confirm_two_step(started: Value) -> Result<Value, String> {
    let (secret, link) = (started["secret"].as_str().unwrap_or_default(), started["link"].as_str().unwrap_or_default());
    if !std::io::stdin().is_terminal() {
        return Ok(json!({"secret": secret, "link": link, "message": "Add the secret to your authenticator app, then run yougori access two-step confirm --code 123456 within ten minutes."}));
    }
    eprintln!("Add this to your authenticator app (scan the link as a QR code, or type the secret):\n  {link}\n  Secret: {secret}");
    eprint!("Six-digit code it shows: ");
    let _ = std::io::stderr().flush();
    let mut code = String::new();
    std::io::stdin().read_line(&mut code).map_err(|_| "Cannot read the code")?;
    waiting("Turning on two-step sign-in", call("access_account", json!({"request": {"action": "twoStepConfirm", "code": code.trim()}}))).await
}

/// "in 2 d 4 h" until a time.
fn left(until: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs() as i64).unwrap_or_default();
    let seconds = (until - now).max(0);
    format!("in {} d {} h", seconds / 86_400, seconds % 86_400 / 3600)
}

/// "just now", "5 min ago", "3 h ago" or "2 d ago".
fn ago(at: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs() as i64).unwrap_or_default();
    match (now - at).max(0) {
        seconds if seconds < 60 => "just now".into(),
        seconds if seconds < 3600 => format!("{} min ago", seconds / 60),
        seconds if seconds < 86_400 => format!("{} h ago", seconds / 3600),
        seconds => format!("{} d ago", seconds / 86_400),
    }
}

fn line(text: &mut String, value: impl AsRef<str>) {
    text.push_str(value.as_ref());
    text.push('\n');
}

fn rule_text(rule: &Value) -> String {
    let methods = rule["methods"].as_array().filter(|methods| !methods.is_empty()).map(|methods| methods.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")).unwrap_or_else(|| "any method".into());
    let path = rule["path"].as_str().filter(|path| !path.is_empty()).unwrap_or("any path");
    let decision = match rule["decision"].as_str() {
        Some("allow") => "at once",
        Some("ask") => "an approver decides",
        _ => "never",
    };
    let reveal = if rule["reveal"] == true { " · may ask to see the value" } else { "" };
    let limit = rule["limit"].as_u64().map(|limit| format!(" · {limit} an hour, then an approver decides")).unwrap_or_default();
    format!("{methods} {path} · {decision}{limit}{reveal}")
}

/// A readable view for a person at a terminal; scripts get the JSON.
pub fn render(args: &[String], value: &Value) -> String {
    let action = args.get(1).map(String::as_str).unwrap_or("status");
    let mut text = String::new();
    let me = &value["me"];
    match action {
        "status" => {
            if value["hub"].is_object() {
                let hub = &value["hub"];
                line(&mut text, format!("Hosting     {}'s Access Grid on {}:{}", hub["company"].as_str().unwrap_or_default(), hub["address"].as_str().unwrap_or_default(), hub["port"]));
                line(&mut text, format!("            {} people · {} credentials · {} rules · {} waiting", hub["people"], hub["credentials"], hub["rules"], hub["waiting"]));
                if let Some(invite) = hub["invite"].as_str() {
                    line(&mut text, format!("Invite      {invite}"));
                }
                if hub["closing"]["gone"] == true {
                    line(&mut text, "Deleted     its computers are told for 30 days; yougori access delete --when forget --yes removes it now");
                } else if let Some(until) = hub["closing"]["until"].as_i64() {
                    line(&mut text, format!("Paused      deleted {} unless restored: yougori access restore", left(until)));
                }
            }
            if let Some(error) = value["hubError"].as_str() {
                line(&mut text, format!("Hub         {error}"));
            }
            match value["member"].is_object().then_some(&value["member"]) {
                Some(member) => {
                    line(&mut text, format!("Signed in   {} at {}'s Access Grid ({})", member["username"].as_str().unwrap_or_default(), member["company"].as_str().unwrap_or_default(), me["person"]["permission"].as_str().unwrap_or("not reachable")));
                    if let Some(error) = member["error"].as_str() {
                        line(&mut text, format!("            {error}"));
                    }
                    if me["blocked"] == true {
                        line(&mut text, "            Your company requires two-step sign-in: run yougori access two-step on, then sign in again.");
                    }
                }
                None if value["hub"].is_null() => line(&mut text, "Not set up. Sign in with yougori access signin --invite INVITE --username NAME, or host one with yougori access create."),
                None => {}
            }
            if let Some(available) = me["available"].as_array() {
                line(&mut text, if available.is_empty() { "You may use  nothing yet; ask an admin for a rule".to_owned() } else { "You may use".to_owned() });
                for credential in available {
                    line(&mut text, format!("  {}  {}", credential["name"].as_str().unwrap_or_default(), credential["destinations"].as_array().map(|list| list.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()));
                    for rule in credential["uses"].as_array().into_iter().flatten() {
                        line(&mut text, format!("    {}", rule_text(rule)));
                    }
                }
            }
            if me["overview"].is_object() {
                if let Some(rules) = me["overview"]["rules"].as_array().filter(|rules| !rules.is_empty()) {
                    line(&mut text, "Rules");
                    for rule in rules {
                        line(&mut text, format!("  {}  {} → {}  {}", rule["id"].as_str().unwrap_or_default(), rule["whoLabel"].as_str().unwrap_or_default(), rule["credentialName"].as_str().unwrap_or_default(), rule_text(rule)));
                    }
                }
            }
            if !me["requests"].as_array().is_none_or(Vec::is_empty) || !me["overview"]["waiting"].as_array().is_none_or(Vec::is_empty) {
                line(&mut text, "Requests: yougori access requests");
            }
        }
        "requests" => {
            let waiting = me["overview"]["waiting"].as_array().cloned().unwrap_or_default();
            if waiting.is_empty() {
                line(&mut text, "Nothing waits for an approver.");
            }
            for request in &waiting {
                let what = if request["kind"] == "reveal" { format!("to see the value · {}", request["reason"].as_str().unwrap_or_default()) } else { format!("{} {}", request["method"].as_str().unwrap_or_default(), request["url"].as_str().unwrap_or_default()) };
                line(&mut text, format!("{}  {} via {} · {} · {}", request["id"].as_str().unwrap_or_default(), request["person"].as_str().unwrap_or_default(), request["agent"].as_str().filter(|agent| !agent.is_empty()).unwrap_or("an agent"), request["credential"].as_str().unwrap_or_default(), what));
            }
            if !waiting.is_empty() {
                line(&mut text, "Decide with yougori access approve REQUEST_ID [--hours N] or yougori access deny REQUEST_ID");
            }
            for request in me["requests"].as_array().into_iter().flatten() {
                line(&mut text, format!("Yours  {}  {} · {}", request["id"].as_str().unwrap_or_default(), request["credential"].as_str().unwrap_or_default(), request["state"].as_str().unwrap_or_default()));
            }
        }
        "log" if value.get("ok").is_some() => {
            if value["ok"] == true {
                line(&mut text, format!("The activity log's chain checks out: {} entries.", value["entries"]));
            } else {
                line(&mut text, format!("The activity log's chain breaks at entry {} of {}: {}.", value["brokenAt"], value["entries"], value["reason"].as_str().unwrap_or_default()));
            }
        }
        "computers" => {
            let devices = me["person"]["devices"].as_array().cloned().unwrap_or_default();
            let current = value["member"]["deviceId"].as_str().unwrap_or_default();
            if devices.is_empty() {
                line(&mut text, "No computers stay signed in.");
            }
            for device in devices {
                let id = device["id"].as_str().unwrap_or_default();
                line(&mut text, format!("{id}  {}{} · last used {}{}", device["computer"].as_str().filter(|name| !name.is_empty()).unwrap_or("a computer"), if id == current { " (this one)" } else { "" }, ago(device["lastUsedAt"].as_i64().unwrap_or_default()), if device["strong"] == true { " · two-step" } else { "" }));
            }
        }
        "two-step" if value.get("secret").is_some() => {
            line(&mut text, format!("Secret: {}", value["secret"].as_str().unwrap_or_default()));
            line(&mut text, format!("Link:   {}", value["link"].as_str().unwrap_or_default()));
            line(&mut text, value["message"].as_str().unwrap_or_default());
        }
        "log" => {
            let entries = me["overview"]["activity"].as_array().cloned().unwrap_or_default();
            if entries.is_empty() {
                line(&mut text, "No activity yet, or your permission does not show it.");
            }
            for entry in entries.iter().rev() {
                let at = ago(entry["at"].as_i64().unwrap_or_default());
                let detail = [entry["credential"].as_str(), entry["target"].as_str()].into_iter().flatten().filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ");
                line(&mut text, format!("{at}  {} {} {detail} · {}", entry["person"].as_str().unwrap_or_default(), entry["action"].as_str().unwrap_or_default(), entry["outcome"].as_str().unwrap_or_default()));
            }
        }
        "use" | "check" => match value["state"].as_str() {
            Some("done") if value.get("answer").is_some() => {
                line(&mut text, format!("HTTP {}", value["answer"]["status"]));
                match value["answer"]["body"].as_str() {
                    Some(body) => line(&mut text, body),
                    None => line(&mut text, "(binary answer; use --json-free piping to read bodyBase64)"),
                }
            }
            Some("done") => line(&mut text, value["value"].as_str().unwrap_or_default()),
            Some("denied") => line(&mut text, format!("Denied: {}", value["reason"].as_str().unwrap_or_default())),
            Some("failed") => line(&mut text, format!("Failed: {}", value["error"].as_str().unwrap_or_default())),
            Some(state) => line(&mut text, format!("{state}: check later with yougori access check {}", value["id"].as_str().unwrap_or_default())),
            None => line(&mut text, plainly(value)),
        },
        _ => line(&mut text, value["message"].as_str().map(str::to_owned).unwrap_or_else(|| plainly(value))),
    }
    text.trim_end().to_owned()
}

/// Whatever the lines above do not name, as words rather than as JSON.
///
/// Every action that changes something here ends in this arm unless the engine happened to send
/// a `message`, and what it printed was the reply itself: braces, quotes, camelCase keys and an
/// identifier or two, after somebody typed a sentence like `yougori access rule add`. That is
/// the engine talking to the CLI, and a person reading it has to translate it before they can
/// tell whether it worked.
///
/// Field names that look like a secret are shown as `hidden`. Nothing that has to be read —
/// a two-step secret, a revealed credential — comes through here; those have lines of their
/// own above, so masking here can only ever prevent an accident.
fn plainly(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(true) => "Done.".to_owned(),
        Value::Bool(false) => "That did not happen.".to_owned(),
        Value::String(said) if said.trim().is_empty() => "Done.".to_owned(),
        Value::String(said) => said.clone(),
        Value::Number(number) => number.to_string(),
        Value::Array(items) if items.is_empty() => "Nothing here.".to_owned(),
        Value::Array(items) => items.iter().map(plainly).collect::<Vec<_>>().join("\n"),
        Value::Object(fields) => {
            let shown: Vec<String> = fields
                .iter()
                .filter(|(_, field)| !field.is_null())
                .map(|(name, field)| format!("{}  {}", in_words(name), if secret_sounding(name) { "hidden".to_owned() } else { briefly(field) }))
                .collect();
            if shown.is_empty() { "Done.".to_owned() } else { shown.join("\n") }
        }
    }
}

/// A field name as a person would say it: `requireTwoStep` becomes `Require two step`.
fn in_words(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (at, letter) in name.char_indices() {
        if letter == '_' || letter == '-' {
            out.push(' ');
        } else if letter.is_ascii_uppercase() && at > 0 {
            out.push(' ');
            out.push(letter.to_ascii_lowercase());
        } else if at == 0 {
            out.extend(letter.to_uppercase());
        } else {
            out.push(letter);
        }
    }
    out
}

/// Whether a field's name says it holds something that must not be printed by accident.
fn secret_sounding(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["secret", "password", "token", "apikey", "credentialvalue", "privatekey"].iter().any(|word| lower.replace('_', "").contains(word))
}

/// One value on one line: a nested thing is counted rather than unfolded, because the point of
/// this is a person reading an answer at a glance.
fn briefly(value: &Value) -> String {
    match value {
        Value::Bool(yes) => if *yes { "yes" } else { "no" }.to_owned(),
        Value::String(said) => said.clone(),
        Value::Array(items) => match items.len() {
            0 => "none".to_owned(),
            1 => "1".to_owned(),
            many => many.to_string(),
        },
        Value::Object(fields) => match fields.len() {
            0 => "none".to_owned(),
            many => format!("{many} fields"),
        },
        other => other.to_string(),
    }
}

/// The tools this grid offers, in the order `tools()` declares them. One list, so a refusal can
/// name them without a second copy drifting out of step with the first.
const TOOL_NAMES: [&str; 4] = ["list_company_access", "company_request", "check_company_request", "reveal_company_credential"];

fn tools() -> Value {
    json!([
        {
            "name": "list_company_access",
            "description": "List the company credentials you may use through Yougori Access Grid: each one's name, where it may be sent (destinations) and whether a use runs at once or waits for an approver. Values are never shown.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        },
        {
            "name": "company_request",
            "description": "Send an HTTPS request with a company credential. Yougori Access Grid adds the credential itself, sends the request to one of the credential's destinations and returns the service's answer with the credential hidden; you never see or need the value. Do not put credentials in headers yourself. If a rule says an approver decides, the call waits briefly and otherwise returns a request id for check_company_request.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "credential": {"type": "string", "description": "The credential's name from list_company_access."},
                    "url": {"type": "string", "description": "The full URL, inside one of the credential's destinations."},
                    "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Other headers, such as Accept or Content-Type. Authorization is set by Access Grid."},
                    "body": {"type": "string", "description": "The request body as text, such as JSON."},
                },
                "required": ["credential", "url"],
                "additionalProperties": false,
            },
        },
        {
            "name": "check_company_request",
            "description": "Check a company_request or reveal_company_credential that waits for an approver or for the service. Returns its answer once it is done (an answer is handed over only once), or that it still waits. Do not call it in a tight loop; an approver may take minutes.",
            "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": false},
        },
        {
            "name": "reveal_company_credential",
            "description": "Ask for a company credential to use outside Access Grid. Only where a rule allows it, and an approver always decides. OAuth, GitHub App and AWS credentials hand out a short-lived token or temporary keys, never the credential itself; others hand out the value, which leaves the company's control and cannot be recalled. Use company_request instead whenever an HTTP request will do.",
            "inputSchema": {"type": "object", "properties": {"credential": {"type": "string"}, "reason": {"type": "string", "description": "Why the value itself is needed; the approver reads this."}}, "required": ["credential", "reason"], "additionalProperties": false},
        },
    ])
}

const INSTRUCTIONS: &str = "Yougori Access Grid lets you use your company's API credentials without seeing them. Call list_company_access first, then company_request with a credential name and a URL inside its destinations. Never ask the person for a key that Access Grid holds. Some uses wait for an approver: tell the person, and check back later with check_company_request.";

/// The text an agent reads for one tool call.
async fn tool(name: &str, arguments: &Value, agent: &str) -> Result<Value, String> {
    let text = |key: &str| arguments.get(key).and_then(Value::as_str).map(str::to_owned);
    match name {
        "list_company_access" => {
            let status = call("access_status", json!({})).await?;
            if status["member"].is_null() {
                return Err("This computer is not signed in to a company Access Grid. Ask the person to sign in in Yougori (Access Grid) or with yougori access signin.".into());
            }
            let me = &status["me"];
            if me.is_null() {
                return Err(status["member"]["error"].as_str().unwrap_or("The company Access Grid is not reachable right now").to_owned());
            }
            Ok(json!({"company": me["company"], "you": {"username": me["person"]["username"], "permission": me["person"]["permission"]}, "credentials": me["available"]}))
        }
        "company_request" => {
            let started = call("access_use", json!({"credential": text("credential").unwrap_or_default(), "url": text("url").unwrap_or_default(), "method": text("method").unwrap_or_else(|| "GET".into()), "headers": arguments.get("headers").filter(|headers| headers.is_object()), "body": text("body"), "agent": agent})).await?;
            settle(started, TOOL_WAIT).await
        }
        "check_company_request" => settle(call("access_check", json!({"id": text("id").unwrap_or_default()})).await?, TOOL_WAIT).await,
        "reveal_company_credential" => {
            let started = call("access_reveal", json!({"credential": text("credential").unwrap_or_default(), "reason": text("reason"), "agent": agent})).await?;
            settle(started, TOOL_WAIT).await
        }
        other => Err(format!("There is no tool called {other}. This grid offers {}.", TOOL_NAMES.join(", "))),
    }
}

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn failure(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// One MCP message; `None` for notifications, which get no answer.
async fn handle(message: Value, agent: Arc<Mutex<String>>, started: Arc<tokio::sync::OnceCell<Result<(), String>>>) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message["method"].as_str().unwrap_or_default().to_owned();
    let id = id.filter(|id| id.is_string() || id.is_number())?;
    if message["jsonrpc"] != "2.0" {
        return Some(failure(&id, -32600, "Invalid request"));
    }
    match method.as_str() {
        "initialize" => {
            let client = &message["params"]["clientInfo"];
            let label = [client["name"].as_str(), client["version"].as_str()].into_iter().flatten().collect::<Vec<_>>().join(" ");
            if !label.is_empty() {
                *agent.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = label.chars().filter(|c| !c.is_control()).take(100).collect();
            }
            let version = yougori_vault::protocol::negotiate(message["params"]["protocolVersion"].as_str());
            Some(reply(&id, json!({"protocolVersion": version, "capabilities": {"tools": {"listChanged": false}}, "serverInfo": {"name": "Yougori Access Grid", "version": env!("CARGO_PKG_VERSION")}, "instructions": INSTRUCTIONS})))
        }
        "ping" => Some(reply(&id, json!({}))),
        "tools/list" => Some(reply(&id, json!({"tools": tools()}))),
        "tools/call" => {
            let name = message["params"]["name"].as_str().unwrap_or_default().to_owned();
            let arguments = message["params"].get("arguments").cloned().unwrap_or(json!({}));
            let label = agent.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
            let ready = started.get_or_init(|| async { client::start(None).await.map(|_| ()) }).await.clone();
            let outcome = match ready {
                Ok(()) => tool(&name, &arguments, &label).await,
                Err(error) => Err(format!("Yougori is not running, and starting it failed: {error}. Open Yougori, or run yougori status, and try again.")),
            };
            let (text, error) = match outcome {
                Ok(value) => (serde_json::to_string_pretty(&value).unwrap_or_default(), false),
                Err(message) => (message, true),
            };
            Some(reply(&id, json!({"content": [{"type": "text", "text": text}], "isError": error})))
        }
        _ => Some(failure(&id, -32601, "Method not found")),
    }
}

/// `yougori access mcp`: an MCP server on stdin and stdout, one JSON message per line.
pub async fn mcp(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("Usage: yougori access mcp".into());
    }
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<String>(64);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            if sender.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let write = |out: &Arc<Mutex<std::io::Stdout>>, value: &Value| {
        let mut out = out.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = writeln!(out, "{value}");
        let _ = out.flush();
    };
    let agent = Arc::new(Mutex::new(String::new()));
    let started = Arc::new(tokio::sync::OnceCell::new());
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = receiver.recv().await {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > 1024 * 1024 {
            write(&out, &failure(&Value::Null, -32600, "MCP message exceeds 1 MB"));
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            write(&out, &failure(&Value::Null, -32700, "Parse error"));
            continue;
        };
        let (out, agent, started) = (out.clone(), agent.clone(), started.clone());
        tasks.spawn(async move {
            if let Some(answer) = handle(message, agent, started).await {
                write(&out, &answer);
            }
        });
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|word| word.to_string()).collect()
    }

    /// PROVES that an action whose answer has no line of its own is still read as words, and
    /// that a field whose name says it holds a secret is not printed by accident.
    ///
    /// Everything that changes something here landed in the last arm of `render` unless the
    /// engine happened to send a `message`, and that arm printed the reply itself — braces,
    /// quotes, camelCase keys — to somebody who had typed a sentence. It is the engine talking
    /// to the CLI, and a person has to translate it before they can tell whether it worked.
    #[test]
    fn an_answer_with_no_line_of_its_own_is_still_read_as_words() {
        assert_eq!(render(&words(&["access", "rule", "add"]), &json!({"ok": true})), "Ok  yes");
        assert_eq!(render(&words(&["access", "settings"]), &json!({"message": "Two-step is now required."})), "Two-step is now required.");
        // Nothing to say is "Done.", never an empty answer or a pair of braces.
        for nothing in [json!({}), json!(null), json!(true), json!("")] {
            assert_eq!(render(&words(&["access", "grant"]), &nothing), "Done.");
        }

        // camelCase becomes words, lists and nested objects are counted rather than unfolded,
        // and a null field is left out instead of being shown as "null".
        let said = plainly(&json!({"requireTwoStep": true, "people": ["ada", "grace"], "rule": {"who": "everyone"}, "note": null}));
        assert_eq!(said, "People  2
Require two step  yes
Rule  1 fields");

        // A field whose name says it holds a secret is never printed here. The two places that
        // must show one — a new two-step secret, a revealed credential — have their own lines.
        for name in ["secret", "password", "apiKey", "api_key", "token", "privateKey"] {
            let said = plainly(&json!({name: "FIXTURE-SEALED-VALUE"}));
            assert!(said.ends_with("hidden"), "{name} was printed: {said}");
            assert!(!said.contains("FIXTURE-SEALED"), "{name} was printed: {said}");
        }
        // And a two-step secret still reaches the person who just asked for one.
        let shown = render(&words(&["access", "two-step", "on"]), &json!({"secret": "ABCD", "link": "otpauth://x", "message": "Scan it."}));
        assert!(shown.contains("ABCD"), "{shown}");
    }

    #[test]
    fn secrets_never_come_from_arguments() {
        for args in [&["access", "signin", "--invite", "x", "--username", "ada", "--password", "hunter2"][..], &["access", "add-credential", "GitHub", "--destination", "https://api.github.com", "--value=ghp_x"]] {
            assert!(plan(&words(args)).unwrap_err().contains("Never type"), "{args:?}");
        }
    }

    #[test]
    fn commands_become_engine_requests() {
        let (method, params) = plan(&words(&["access", "allow", "GitHub", "--who", "team:Research", "--methods", "GET, POST", "--path", "/repos/acme", "--ask", "--hours", "8"])).unwrap();
        assert_eq!(method, "access_manage");
        assert_eq!(params["request"], json!({"action": "ruleAdd", "credential": "GitHub", "who": "team:Research", "decision": "ask", "reveal": false, "methods": ["GET", "POST"], "path": "/repos/acme", "hours": 8.0}));
        let (_, params) = plan(&words(&["access", "approve", "req-1", "--hours", "1"])).unwrap();
        assert_eq!(params["request"], json!({"action": "decide", "request": "req-1", "approve": true, "hours": 1.0}));
        let (method, params) = plan(&words(&["access", "use", "GitHub", "https://api.github.com/user", "--header", "Accept: application/json", "--method", "GET"])).unwrap();
        assert_eq!((method.as_str(), params["headers"]["Accept"].as_str()), ("access_use", Some("application/json")));
        assert_eq!(plan(&words(&["access"])).unwrap().0, "access_status");
        assert!(plan(&words(&["access", "remove-person", "ada"])).unwrap_err().contains("--yes"));
        assert!(plan(&words(&["access", "allow", "GitHub", "--ask", "--never"])).is_err());
        assert!(plan(&words(&["access", "allow", "GitHub", "--colour", "red"])).unwrap_err().contains("Unknown option"));
        assert!(plan(&words(&["access", "status", "--who", "x"])).unwrap_err().contains("does not apply"));
        assert!(plan(&words(&["access", "add-credential", "GitHub"])).unwrap_err().contains("--destination"));
        assert!(plan(&words(&["access", "check"])).is_err());
    }

    #[test]
    fn account_grid_and_credential_commands_become_engine_requests() {
        assert_eq!(plan(&words(&["access", "signin", "--invite", "access-invite:x", "--sso"])).unwrap(), ("access_signin".into(), json!({"invite": "access-invite:x", "sso": true})));
        assert!(plan(&words(&["access", "signin", "--invite", "x", "--sso", "--username", "ada"])).is_err());
        assert_eq!(plan(&words(&["access", "two-step", "on"])).unwrap(), ("access_account".into(), json!({"request": {"action": "twoStepStart"}})));
        assert_eq!(plan(&words(&["access", "two-step", "confirm", "--code", "123456"])).unwrap().1["request"], json!({"action": "twoStepConfirm", "code": "123456"}));
        assert!(plan(&words(&["access", "two-step", "off"])).unwrap_err().contains("--code"));
        assert_eq!(plan(&words(&["access", "forget-computer", "device-1", "--yes"])).unwrap().1["request"], json!({"action": "deviceForget", "device": "device-1"}));
        assert_eq!(plan(&words(&["access", "reset-two-step", "ada", "--yes"])).unwrap().1["request"], json!({"action": "personTwoStepReset", "person": "ada"}));
        assert_eq!(plan(&words(&["access", "settings", "--require-two-step", "true"])).unwrap().1["request"], json!({"action": "settingsSet", "requireTwoStep": true}));
        assert_eq!(plan(&words(&["access", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--passwordless"])).unwrap().1["request"], json!({"action": "ssoSet", "issuer": "https://acme.okta.com", "clientId": "app", "claim": "email", "passwordless": true}));
        assert_eq!(plan(&words(&["access", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--redirect-port", "8765"])).unwrap().1["request"]["redirectPort"], 8765);
        assert!(plan(&words(&["access", "sso", "--issuer", "https://acme.okta.com", "--client-id", "app", "--redirect-port", "80"])).is_err());
        assert_eq!(plan(&words(&["access", "delete", "--when", "now", "--yes"])).unwrap(), ("access_delete".into(), json!({"when": "now"})));
        assert_eq!(plan(&words(&["access", "delete", "--yes"])).unwrap().1, json!({"when": "later"}));
        assert_eq!(plan(&words(&["access", "restore"])).unwrap().0, "access_restore");
        assert_eq!(plan(&words(&["access", "log", "--verify"])).unwrap().1["request"], json!({"action": "activityVerify"}));
        assert!(plan(&words(&["access", "backup", "--output", "x.backup", "--passphrase", "hunter22222"])).unwrap_err().contains("Never type"));
        let folder = tempfile::tempdir().unwrap();
        let pem = folder.path().join("app.pem");
        std::fs::write(&pem, "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n").unwrap();
        let (_, params) = plan(&words(&["access", "add-credential", "GitHub", "--kind", "github-app", "--destination", "https://api.github.com", "--app-id", "42", "--installation-id", "99", "--value-file", pem.to_str().unwrap()])).unwrap();
        assert_eq!(params["request"]["config"], json!({"appId": "42", "installationId": "99"}));
        assert!(params["request"]["value"].as_str().unwrap().contains("PRIVATE KEY"));
        let (_, params) = plan(&words(&["access", "allow", "AWS", "--limit", "20"])).unwrap();
        assert_eq!(params["request"]["limit"], 20);
    }

    #[test]
    fn repeated_options_are_kept_and_single_ones_refused_twice() {
        let options = options(&words(&["--team", "Ops", "--team", "Research", "--destination", "https://a.example", "--destination", "https://b.example"])).unwrap();
        assert_eq!(options.all("team"), ["Ops", "Research"]);
        assert_eq!(options.all("destination").len(), 2);
        assert!(super::options(&words(&["--who", "a", "--who", "b"])).unwrap_err().contains("twice"));
    }

    #[tokio::test]
    async fn the_mcp_server_introduces_itself_and_lists_its_tools() {
        let agent = Arc::new(Mutex::new(String::new()));
        let started = Arc::new(tokio::sync::OnceCell::new());
        let hello = handle(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "Claude Code", "version": "2.1"}}}), agent.clone(), started.clone()).await.unwrap();
        assert_eq!(hello["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(hello["result"]["serverInfo"]["name"], "Yougori Access Grid");
        assert_eq!(*agent.lock().unwrap(), "Claude Code 2.1");
        let listed = handle(json!({"jsonrpc": "2.0", "id": "a", "method": "tools/list"}), agent.clone(), started.clone()).await.unwrap();
        let names: Vec<&str> = listed["result"]["tools"].as_array().unwrap().iter().map(|tool| tool["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["list_company_access", "company_request", "check_company_request", "reveal_company_credential"]);
        assert!(handle(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}), agent.clone(), started.clone()).await.is_none());
        assert_eq!(handle(json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}), agent.clone(), started.clone()).await.unwrap()["error"]["code"], -32601);
    }

    #[test]
    fn terminal_views_read_plainly() {
        let status = json!({"hub": null, "member": {"username": "ada", "company": "Acme"}, "me": {"person": {"permission": "member"}, "available": [{"name": "GitHub", "destinations": ["https://api.github.com"], "uses": [{"decision": "ask", "methods": ["POST"], "path": "", "reveal": false}]}], "requests": []}});
        let text = render(&words(&["access", "status"]), &status);
        assert!(text.contains("Signed in   ada at Acme's Access Grid (member)") && text.contains("POST any path · an approver decides"), "{text}");
        let answer = render(&words(&["access", "use"]), &json!({"state": "done", "answer": {"status": 200, "body": "{\"ok\":true}"}}));
        assert_eq!(answer, "HTTP 200\n{\"ok\":true}");
    }
}
