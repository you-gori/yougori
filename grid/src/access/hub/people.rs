//! Signing people in, and what they change about their own account. A sign-in is a password
//! (its scrypt key) with a six-digit code when two-step is on, or the company's identity
//! provider. Either way the computer gets a session for eight hours and a device token that
//! signs it in again by itself for thirty days after its last use, until the person's password
//! changes, two-step is reset, they sign out everywhere or an admin removes the computer.
use super::{
    change_record, digest, error, find_person, forgive, fresh_code, json_response, lock, name_throttled, new_id, note, now, rate_limited, refuse, refuse_name, text, throttled, token, valid_key, Caller, Refusal, Session, Shared, MAX_SESSIONS, SESSION, SMALL,
};
use crate::{
    access::{activity::Entry, forward, policy},
    net::{self, Body},
    totp,
};
use hyper::{body::Incoming, Request, Response, StatusCode};
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

const DISCOVERY_FOR: Duration = Duration::from_secs(24 * 60 * 60);
const KEYS_FOR: Duration = Duration::from_secs(60 * 60);
const KEYS_REFRESH_GAP: Duration = Duration::from_secs(60);

/// Starts a session for `person` and, with `remember`, a new device token for this computer.
fn issue(shared: &Shared, person: &policy::Person, computer: &str, strong: bool, remember: bool) -> Result<Value, Refusal> {
    let session_token = token();
    let expires = now() + SESSION;
    let device = remember.then(|| (new_id("device"), token()));
    {
        let mut live = lock(&shared.live);
        if live.sessions.len() >= MAX_SESSIONS {
            let at = now();
            live.sessions.retain(|_, session| session.expires > at);
            if live.sessions.len() >= MAX_SESSIONS {
                return Err(Refusal(StatusCode::SERVICE_UNAVAILABLE, "busy", "Too many people are signed in; try again later".into()));
            }
        }
        live.sessions.insert(digest("access-session", &session_token), Session { person: person.id.clone(), generation: person.generation, expires, strong, device: device.as_ref().map(|(id, _)| id.clone()) });
    }
    let at = now();
    let (company, id, current) = change_record(shared, |record| {
        let own = record.people.iter_mut().find(|own| own.id == person.id).ok_or_else(|| Refusal::forbidden("This account was removed"))?;
        own.last_seen_at = Some(at);
        if let Some((device, secret)) = &device {
            let generation = own.generation;
            own.devices.retain(|known| known.generation == generation && known.last_used_at + policy::DEVICE_LIFETIME > at);
            if own.devices.len() >= policy::MAX_DEVICES {
                own.devices.sort_by_key(|known| known.last_used_at);
                own.devices.remove(0);
            }
            own.devices.push(policy::Device { id: device.clone(), hash: digest("access-device", secret), computer: computer.to_owned(), created_at: at, last_used_at: at, strong, generation });
        }
        Ok((record.company.clone(), record.id.clone(), own.clone()))
    })?;
    let mut answer = json!({"sessionToken": session_token, "expiresAt": expires, "strong": strong, "person": current.public(), "company": company, "accessId": id});
    if let Some((device, secret)) = device {
        answer["deviceId"] = json!(device);
        answer["deviceToken"] = json!(secret);
    }
    Ok(answer)
}

pub(super) async fn salt(shared: &Arc<Shared>, _peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let body = net::json_body(request.into_body(), SMALL).await.unwrap_or(Value::Null);
    let Ok(username) = policy::username(text(&body, "username").unwrap_or_default()) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "Give your username");
    };
    // Not rate limited, on purpose. A salt is not a secret: it is what the person's own computer
    // needs to turn their password into a key, an unknown name gets a decoy that cannot be told
    // from a real one, and a salt never changes — so anybody guessing has kept theirs from the
    // first attempt and is slowed by nothing here. Refusing it only stops the real person reaching
    // their password prompt, from an address somebody else has been guessing from.
    // The decoy is worked out whether or not it is used, so the time an answer takes says
    // nothing about who exists either.
    let decoy = shared.sealer.decoy_salt(&username);
    let record = lock(&shared.record);
    let salt = find_person(&record, &username).map(|person| person.salt.clone()).unwrap_or(decoy);
    json_response(StatusCode::OK, &json!({"salt": salt}))
}

/// A two-step code checked against a person's sealed secret. Each code works once.
fn code_ok(shared: &Shared, person: &policy::Person, code: &str) -> bool {
    person.two_step.as_ref().and_then(|sealed| shared.sealer.open(&format!("two-step:{}", person.id), sealed).ok()).and_then(|secret| totp::step_of(&secret, code, now())).is_some_and(|step| fresh_code(shared, &person.id, step))
}

pub(super) async fn signin(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    let body = match net::json_body(request.into_body(), SMALL).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
    };
    let username = policy::username(text(&body, "username").unwrap_or_default()).unwrap_or_default();
    // Guessing has to be capped, and a cap only works by refusing attempts before knowing whether
    // they are right. The question is what a cap is keyed on. This account AS GUESSED AT FROM THIS
    // ADDRESS: to shut somebody out you would have to be sitting at their address, so a stranger
    // who merely knows a username cannot do it, and a colleague guessing at Bob never gates Ada.
    // The address's own count sits behind it with far more room, for one machine working through
    // many accounts.
    if name_throttled(shared, peer, &username) {
        return rate_limited(shared, peer, &username, "signin", "this username");
    }
    if throttled(shared, peer) {
        return rate_limited(shared, peer, &username, "signin", "this address");
    }
    let key = text(&body, "key").unwrap_or_default();
    let code = text(&body, "code").unwrap_or_default().trim().to_owned();
    let computer = note(text(&body, "computer"), 64);
    let (found, passwordless, owner) = {
        let record = lock(&shared.record);
        let found = find_person(&record, &username).filter(|person| valid_key(key) && policy::same_hash(&policy::key_hash(key), &person.key_hash)).cloned();
        (found, record.sso.as_ref().is_some_and(|sso| sso.passwordless), record.owner.clone())
    };
    let refused = |outcome: String| {
        refuse(shared, peer);
        refuse_name(shared, peer, &username);
        shared.log(Entry { at: now(), person: username.clone(), computer: computer.clone(), action: "signin".into(), outcome, ..Entry::default() });
    };
    let Some(person) = found else {
        refused(format!("refused from {peer}: wrong username or password"));
        return error(StatusCode::FORBIDDEN, "password_wrong", "The username or password is wrong");
    };
    if passwordless && person.id != owner {
        // The password was right; it is the policy that refuses. Worth recording: it is how an
        // admin sees that somebody is still using a password after the company moved to SSO.
        shared.log(Entry { at: now(), person: person.username.clone(), computer: computer.clone(), action: "signin".into(), outcome: format!("refused from {peer}: this company signs in through its identity provider"), ..Entry::default() });
        return error(StatusCode::FORBIDDEN, "sso_only", "Your company signs you in through its identity provider: choose Sign in with your company account");
    }
    if person.two_step.is_some() {
        if code.is_empty() {
            return error(StatusCode::UNAUTHORIZED, "two_step_required", crate::access::member::TWO_STEP);
        }
        if !code_ok(shared, &person, &code) {
            refused(format!("refused from {peer}: wrong two-step code"));
            return error(StatusCode::FORBIDDEN, "code_wrong", "The two-step code is wrong or too old; use the newest one");
        }
    }
    let strong = person.two_step.is_some();
    let answer = issue(shared, &person, &computer, strong, true);
    if answer.is_ok() {
        // They proved who they are, so earlier mistypes stop counting against them or their address.
        forgive(shared, peer, &username);
        shared.log(Entry { at: now(), person: person.username.clone(), computer, action: "signin".into(), outcome: if strong { "signed in with two-step".into() } else { "signed in".into() }, ..Entry::default() });
    }
    super::answer(answer)
}

/// A remembered computer signs in again with its device token.
pub(super) async fn resume(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return rate_limited(shared, peer, "", "signin", "this address");
    }
    let body = match net::json_body(request.into_body(), SMALL).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
    };
    let secret = text(&body, "device").unwrap_or_default();
    let computer = note(text(&body, "computer"), 64);
    if !crate::is_token(secret) {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "Give this computer's device token");
    }
    let hash = digest("access-device", secret);
    let at = now();
    let found = {
        let record = lock(&shared.record);
        record.people.iter().find_map(|person| person.devices.iter().find(|device| policy::same_hash(&device.hash, &hash) && device.live(person, at)).map(|device| (person.clone(), device.clone())))
    };
    let Some((person, device)) = found else {
        refuse(shared, peer);
        return error(StatusCode::FORBIDDEN, "device_ended", "This computer's sign-in has ended: the password changed, two-step was reset, it was signed out, or it was not used for 30 days. Sign in again.");
    };
    // Note when it was last used, at most once an hour, so a busy computer does not rewrite the record.
    if device.last_used_at + 3600 < at {
        let _ = change_record(shared, |record| {
            if let Some(own) = record.people.iter_mut().find(|own| own.id == person.id).and_then(|own| own.devices.iter_mut().find(|own| own.id == device.id)) {
                own.last_used_at = at;
                if !computer.is_empty() {
                    own.computer = computer.clone();
                }
            }
            Ok(())
        });
    }
    let answer = issue(shared, &person, &computer, device.strong, false).map(|mut answer| {
        answer["deviceId"] = json!(device.id);
        answer
    });
    if let Ok(value) = &answer {
        if let Some(session) = value["sessionToken"].as_str() {
            if let Some(own) = lock(&shared.live).sessions.get_mut(&digest("access-session", session)) {
                own.device = Some(device.id.clone());
            }
        }
    }
    super::answer(answer)
}

/// The identity provider's discovery document, fetched by the hub from the issuer itself and
/// kept for a day.
async fn discovery(shared: &Arc<Shared>) -> Result<(policy::Sso, Value), Refusal> {
    let sso = lock(&shared.record).sso.clone().ok_or_else(|| Refusal(StatusCode::NOT_FOUND, "sso_off", "This Access Grid does not sign people in through an identity provider".into()))?;
    {
        let live = lock(&shared.live);
        if live.sso.issuer == sso.issuer {
            if let Some((found, at)) = &live.sso.discovery {
                if at.elapsed() < DISCOVERY_FOR {
                    return Ok((sso, found.clone()));
                }
            }
        }
    }
    let unreachable = |message: String| Refusal(StatusCode::BAD_GATEWAY, "sso_unreachable", message);
    let fetched = forward::fetch("GET", &format!("{}/.well-known/openid-configuration", sso.issuer), &[("accept", "application/json".into())], None).await.map_err(unreachable)?;
    if !fetched.ok() {
        return Err(unreachable(format!("The identity provider's discovery document could not be read ({})", fetched.said())));
    }
    let found = fetched.json();
    if !found["jwks_uri"].is_string() || !found["authorization_endpoint"].is_string() || !found["token_endpoint"].is_string() {
        return Err(unreachable("The identity provider's discovery document names no endpoints".into()));
    }
    let mut live = lock(&shared.live);
    if live.sso.issuer != sso.issuer {
        live.sso = super::SsoCache { issuer: sso.issuer.clone(), ..super::SsoCache::default() };
    }
    live.sso.discovery = Some((found.clone(), Instant::now()));
    Ok((sso, found))
}

/// The provider's signing keys, kept for an hour; `refresh` fetches them again (a key the token
/// names may be new), at most once a minute.
async fn keys(shared: &Arc<Shared>, found: &Value, refresh: bool) -> Result<Value, Refusal> {
    {
        let live = lock(&shared.live);
        if let Some((keys, at)) = &live.sso.keys {
            let fresh = at.elapsed() < KEYS_FOR;
            let gap = live.sso.refreshed.is_some_and(|last| last.elapsed() < KEYS_REFRESH_GAP);
            if (fresh && !refresh) || (refresh && gap) {
                return Ok(keys.clone());
            }
        }
    }
    let unreachable = |message: String| Refusal(StatusCode::BAD_GATEWAY, "sso_unreachable", message);
    let fetched = forward::fetch("GET", found["jwks_uri"].as_str().unwrap_or_default(), &[("accept", "application/json".into())], None).await.map_err(unreachable)?;
    if !fetched.ok() || !fetched.json()["keys"].is_array() {
        return Err(unreachable("The identity provider's signing keys could not be read".into()));
    }
    let keys = fetched.json();
    let mut live = lock(&shared.live);
    live.sso.keys = Some((keys.clone(), Instant::now()));
    live.sso.refreshed = Some(Instant::now());
    Ok(keys)
}

/// What a person's computer needs to start the sign-in: who the provider is and where to send
/// the browser. Public, like the salt; the client ID of a public app is not a secret.
pub(super) async fn sso_config(shared: &Arc<Shared>) -> Response<Body> {
    super::answer(discovery(shared).await.map(|(sso, found)| json!({"issuer": sso.issuer, "clientId": sso.client_id, "authorizationEndpoint": found["authorization_endpoint"], "tokenEndpoint": found["token_endpoint"], "passwordless": sso.passwordless, "redirectPort": sso.redirect_port})))
}

/// A sign-in through the identity provider: the person's computer brings the ID token the
/// provider issued for it; the hub checks its signature against the provider's keys, its claims
/// against the setup, and the named email (or username) against its people. The provider's own
/// second factor counts as this sign-in's.
pub(super) async fn sso_signin(shared: &Arc<Shared>, peer: IpAddr, request: Request<Incoming>) -> Response<Body> {
    if throttled(shared, peer) {
        return rate_limited(shared, peer, "", "signin", "this address");
    }
    let body = match net::json_body(request.into_body(), 32 * 1024).await {
        Ok(body) => body,
        Err(message) => return error(StatusCode::BAD_REQUEST, "invalid_request", message),
    };
    let id_token = text(&body, "idToken").unwrap_or_default().trim().to_owned();
    let nonce = text(&body, "nonce").unwrap_or_default().trim().to_owned();
    let computer = note(text(&body, "computer"), 64);
    if id_token.is_empty() || nonce.is_empty() {
        return error(StatusCode::BAD_REQUEST, "invalid_request", "The sign-in needs the provider's token and the nonce it was asked for");
    }
    let (sso, found) = match discovery(shared).await {
        Ok(found) => found,
        Err(refused) => return super::answer(Err(refused)),
    };
    let mut keys_now = match keys(shared, &found, false).await {
        Ok(keys) => keys,
        Err(refused) => return super::answer(Err(refused)),
    };
    let mut verified = crate::jwt::verify(&id_token, &keys_now);
    if matches!(verified, Err(crate::jwt::Reject::UnknownKey(_))) {
        keys_now = match keys(shared, &found, true).await {
            Ok(keys) => keys,
            Err(refused) => return super::answer(Err(refused)),
        };
        verified = crate::jwt::verify(&id_token, &keys_now);
    }
    let rejected = |why: String| {
        refuse(shared, peer);
        shared.log(Entry { at: now(), computer: computer.clone(), action: "signin".into(), outcome: format!("refused from {peer}: {why}"), ..Entry::default() });
        error(StatusCode::FORBIDDEN, "token_rejected", format!("The identity provider's token was refused: {why}"))
    };
    let claims = match verified {
        Ok(claims) => claims,
        Err(crate::jwt::Reject::UnknownKey(_)) => return rejected("it was signed with a key the provider does not publish".into()),
        Err(crate::jwt::Reject::Invalid(message)) => return rejected(message),
    };
    let discovered = found["issuer"].as_str().map(|issuer| issuer.trim_end_matches('/')).filter(|issuer| !issuer.contains('{'));
    let issuer_ok = claims["iss"].as_str().map(|iss| iss.trim_end_matches('/')).is_some_and(|iss| iss == sso.issuer || Some(iss) == discovered);
    let audience_ok = match &claims["aud"] {
        Value::String(aud) => aud == &sso.client_id,
        Value::Array(list) => list.iter().any(|aud| aud == &sso.client_id),
        _ => false,
    };
    let at = now();
    if !issuer_ok {
        return rejected("its issuer is not the one this grid trusts".into());
    }
    if !audience_ok {
        return rejected("it was issued for another app".into());
    }
    if claims["exp"].as_i64().is_none_or(|exp| exp <= at - 60) {
        return rejected("it has expired".into());
    }
    if claims["nonce"].as_str() != Some(nonce.as_str()) {
        return rejected("it was not issued for this sign-in".into());
    }
    // Microsoft Entra leaves `email` out unless an optional claim is configured; its sign-in name
    // is in `preferred_username` (or `upn`), so those stand in when the default claim is missing.
    let named = |claim: &str| claims[claim].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_ascii_lowercase);
    let fallbacks: &[&str] = if sso.claim == "email" { &["preferred_username", "upn"] } else { &[] };
    let identity = named(&sso.claim).or_else(|| fallbacks.iter().find_map(|claim| named(claim))).unwrap_or_default();
    if identity.is_empty() {
        return rejected(format!("it carries no {} claim", sso.claim));
    }
    // An email the provider itself says it has not verified proves nothing about who holds it.
    // Some providers send it as text ("False") or as 0.
    let from_email = sso.claim == "email" && named("email").is_some();
    let verified = &claims["email_verified"];
    let unverified = *verified == Value::Bool(false) || verified.as_str().is_some_and(|text| text.trim().eq_ignore_ascii_case("false") || text.trim() == "0") || verified.as_i64() == Some(0);
    if from_email && unverified {
        return rejected(format!("the identity provider has not verified {identity}"));
    }
    // The provider's own ID for the account, which unlike an email is never handed to someone else.
    let Some(subject) = claims["sub"].as_str().map(str::trim).filter(|sub| !sub.is_empty() && sub.len() <= 255).map(str::to_owned) else {
        return rejected("it names no account (no sub claim)".into());
    };
    // The account a person is tied to signs them in whatever email it carries now; otherwise the
    // email (or username) finds them, and a first sign-in ties them to the account it came from.
    // Found and tied in one step, so an admin untying them meanwhile is not undone.
    let found = change_record(shared, |record| {
        let index = record.people.iter().position(|person| person.sso_subject.as_deref() == Some(subject.as_str()))
            .or_else(|| record.people.iter().position(|person| person.email.as_deref() == Some(identity.as_str())))
            .or_else(|| record.people.iter().position(|person| person.username == identity))
            .ok_or_else(|| Refusal::forbidden(format!("{identity} is not a person in this Access Grid; ask an admin to add them with that email")))?;
        let own = &mut record.people[index];
        match own.sso_subject.as_deref() {
            Some(tied) if tied == subject => {}
            Some(_) => return Err(Refusal::forbidden(format!("it is for another account at the identity provider than the one {} signs in with; an admin can sign them out everywhere to tie the new one", own.username))),
            None => own.sso_subject = Some(subject.clone()),
        }
        Ok(own.clone())
    });
    let person = match found {
        Ok(person) => person,
        Err(Refusal(_, _, why)) => return rejected(why),
    };
    let answer = issue(shared, &person, &computer, true, true);
    if answer.is_ok() {
        shared.log(Entry { at, person: person.username.clone(), computer, action: "signin".into(), outcome: "signed in through the identity provider".into(), ..Entry::default() });
    }
    super::answer(answer)
}

/// What a signed-in person changes about their own account: two-step sign-in, their password,
/// and the computers that stay signed in.
pub(super) fn account(shared: &Arc<Shared>, caller: &Caller, body: Value) -> Result<Value, Refusal> {
    let person = &caller.person;
    let computer = note(text(&body, "computer"), 64);
    match text(&body, "action").unwrap_or_default() {
        "twoStepStart" => {
            if person.two_step.is_some() {
                return Err(Refusal::bad("Two-step sign-in is already on; turn it off first to move it to another app"));
            }
            let secret = totp::new_secret();
            let company = lock(&shared.record).company.clone();
            lock(&shared.live).two_step.insert(person.id.clone(), (secret.clone(), now() + 600));
            Ok(json!({"secret": secret, "link": totp::otpauth(&secret, &format!("{company} Access Grid"), &person.username), "message": "Add it to your authenticator app, then confirm with the six-digit code it shows"}))
        }
        "twoStepConfirm" => {
            let code = text(&body, "code").unwrap_or_default();
            let pending = lock(&shared.live).two_step.get(&person.id).filter(|(_, until)| *until > now()).map(|(secret, _)| secret.clone()).ok_or_else(|| Refusal::bad("Start turning on two-step sign-in again; the last start expired"))?;
            // The confirming code is spent too, so it cannot also sign someone in afterwards.
            if !totp::step_of(&pending, code, now()).is_some_and(|step| fresh_code(shared, &person.id, step)) {
                return Err(Refusal::forbidden("The code is wrong or too old; use the newest one your app shows"));
            }
            let sealed = shared.sealer.seal(&format!("two-step:{}", person.id), &pending)?;
            change_record(shared, |record| {
                let own = record.people.iter_mut().find(|own| own.id == person.id).ok_or_else(|| Refusal::forbidden("This account was removed"))?;
                own.two_step = Some(sealed);
                // The computer that proved the code counts as signed in with it from now on.
                if let Some(device) = own.devices.iter_mut().find(|device| caller.device.as_deref() == Some(device.id.as_str())) {
                    device.strong = true;
                }
                Ok(())
            })?;
            {
                let mut live = lock(&shared.live);
                live.two_step.remove(&person.id);
                if let Some(session) = live.sessions.get_mut(&caller.session) {
                    session.strong = true;
                }
            }
            shared.change(person, "turned on two-step sign-in".into());
            Ok(json!({"twoStep": true, "message": "Two-step sign-in is on. This computer counts as signed in with it; other computers already signed in stay signed in, and new sign-ins ask for a code."}))
        }
        "twoStepOff" => {
            if person.two_step.is_none() {
                return Err(Refusal::bad("Two-step sign-in is not on"));
            }
            let required = {
                let record = lock(&shared.record);
                record.settings.require_two_step && record.sso.is_none()
            };
            if required {
                return Err(Refusal::forbidden("Your company requires two-step sign-in, so it stays on"));
            }
            if !code_ok(shared, person, text(&body, "code").unwrap_or_default()) {
                return Err(Refusal::forbidden("The code is wrong or too old; use the newest one your app shows"));
            }
            change_record(shared, |record| {
                if let Some(own) = record.people.iter_mut().find(|own| own.id == person.id) {
                    own.two_step = None;
                }
                Ok(())
            })?;
            shared.change(person, "turned off two-step sign-in".into());
            Ok(json!({"twoStep": false, "message": "Two-step sign-in is off"}))
        }
        "password" => {
            let (salt, key) = (text(&body, "salt").unwrap_or_default(), text(&body, "key").unwrap_or_default());
            if salt.is_empty() || salt.len() > 128 || !valid_key(key) {
                return Err(Refusal::bad("A new password is required"));
            }
            if person.two_step.is_some() && !code_ok(shared, person, text(&body, "code").unwrap_or_default()) {
                return Err(Refusal(StatusCode::FORBIDDEN, "two_step_required", "Give the code from your authenticator app to change your password".into()));
            }
            let updated = change_record(shared, |record| {
                let own = record.people.iter_mut().find(|own| own.id == person.id).ok_or_else(|| Refusal::forbidden("This account was removed"))?;
                own.salt = salt.to_owned();
                own.key_hash = policy::key_hash(key);
                own.generation += 1;
                own.devices.clear();
                Ok(own.clone())
            })?;
            shared.change(person, "changed their password; their other sign-ins ended".into());
            let mut answer = issue(shared, &updated, &computer, caller.strong, true)?;
            answer["message"] = json!("Your password is changed. Your other computers must sign in again.");
            Ok(answer)
        }
        "signOutOthers" => {
            let updated = change_record(shared, |record| {
                let own = record.people.iter_mut().find(|own| own.id == person.id).ok_or_else(|| Refusal::forbidden("This account was removed"))?;
                own.generation += 1;
                own.devices.clear();
                Ok(own.clone())
            })?;
            shared.change(person, "signed out on every other computer".into());
            let mut answer = issue(shared, &updated, &computer, caller.strong, true)?;
            answer["message"] = json!("Signed out on every other computer.");
            Ok(answer)
        }
        "deviceForget" => {
            let device = text(&body, "device").unwrap_or_default().to_owned();
            change_record(shared, |record| {
                let own = record.people.iter_mut().find(|own| own.id == person.id).ok_or_else(|| Refusal::forbidden("This account was removed"))?;
                let before = own.devices.len();
                own.devices.retain(|known| known.id != device);
                if own.devices.len() == before {
                    return Err(Refusal::missing("No such computer is signed in"));
                }
                Ok(())
            })?;
            lock(&shared.live).sessions.retain(|_, session| session.device.as_deref() != Some(device.as_str()));
            shared.change(person, "signed one of their computers out".into());
            Ok(json!({"message": "That computer is signed out"}))
        }
        other => Err(Refusal::bad(format!("Unknown account action '{other}'"))),
    }
}
