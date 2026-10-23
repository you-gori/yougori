//! The short-lived credentials the broker makes from a long-lived value, so that what actually
//! goes on the wire expires on its own.
//!
//! Three of the seven ways a credential travels are not the value at all. An OAuth 2 client
//! credential buys an access token from a token endpoint; a GitHub App signs a short assertion
//! with its private key and trades it for an installation token; an AWS key signs each request in
//! place, or buys temporary keys from STS when the credential names a role. The long-lived value
//! never leaves this process in any of the three.
//!
//! This is the same work the shipped Access Grid does in `crate::access::mint`, and it is written
//! again here rather than called, because that function takes the hub's own credential record and
//! reads the value out of the hub's sealing key. What is not written again is the part that
//! decides what goes on the wire: `forward::Prepared`, `forward::fetch` and `sigv4::sign` are the
//! shipped ones, so a fix to a signature or to hiding a value in an answer reaches both.
//!
//! Three things are worth reading before the code.
//!
//! **A minted token is a secret with an expiry, so it is never written down.** The cache below is
//! in memory, it is handed to the broker by whoever starts it, and no column anywhere could hold
//! one of these: there is no table for them, no backup carries one, and the realm's database never
//! sees one. An entry is overwritten in place when it is dropped, exactly as `Held` and `Sealed`
//! are, whether it was dropped because it lapsed, because the credential moved on or because the
//! process is going away.
//!
//! **The cache key is the credential and the version of it.** A rotation raises the generation and
//! the vault version, so a token made from the old value cannot be handed out after it: the key
//! simply no longer matches and the next request mints again. Nothing has to be found and deleted,
//! which is the same mechanism revocation uses everywhere else in the core. `forget` is there for
//! a credential that was retired, where no further request should mint at all.
//!
//! **What this code cannot wipe is written down rather than glossed over.** The form body that
//! carries an OAuth client secret, and the authorization header that carries it under basic, are
//! handed to hyper, which copies them into its own buffers, into a TLS record and into a socket
//! buffer. None of those is owned here and none of them is wiped. What is owned here is wiped.
use super::{
    credential::{checked_settings, Credential, Kind},
    vault,
};
use crate::access::{
    forward::{self, Auth, Prepared, Target},
    sigv4::{self, Keys},
};
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

/// A token is made again when less than this is left of it, so a request is never sent with one
/// that lapses while it is in flight. The same margin the Access Grid uses.
pub const MARGIN: i64 = 5 * 60;

/// The most tokens held at once. A realm holds at most `limits::MAX_CREDENTIALS` credentials and
/// an AWS role mints one per person, so this is a ceiling on memory and not a policy: past it the
/// oldest are dropped, which costs a fresh mint and nothing else.
pub const MOST_HELD: usize = 4_096;

/// Overwrites everything in a prepared request that came from a value, in place.
///
/// `forward::Prepared` keeps its strings as ordinary `String`s, which are freed without being
/// cleared. This is the one function that empties one, so the broker's `Sealed` and this cache
/// cannot drift apart about which of them holds a secret.
pub(crate) fn wipe_prepared(prepared: &mut Prepared) {
    fn wipe(text: &mut String) {
        // Safety: the bytes of a String are overwritten with zeroes, which is valid UTF-8, and
        // the string is emptied immediately afterwards.
        let bytes = unsafe { text.as_mut_vec() };
        vault::wipe(bytes);
        bytes.clear();
    }
    match &mut prepared.auth {
        Auth::Header(_, value) | Auth::Query(_, value) => wipe(value),
        Auth::Aws { keys, .. } => {
            wipe(&mut keys.secret_key);
            if let Some(token) = &mut keys.session_token {
                wipe(token);
            }
        }
    }
    for secret in &mut prepared.secrets {
        wipe(secret);
    }
}

/// One token this grid made, and the moment it stops being usable.
struct Minted {
    prepared: Prepared,
    until: i64,
    made_at: i64,
}

impl Drop for Minted {
    fn drop(&mut self) {
        wipe_prepared(&mut self.prepared);
    }
}

/// The tokens this grid has made and not yet used up. In memory, never on disk.
///
/// It is handed to the broker rather than kept inside the realm, for the same reason the vault is:
/// which secrets this computer is holding at this instant is a property of the computer, not of
/// the realm's portable record, and a realm that carried one in a backup would be a realm that
/// carried a live credential out of the building.
#[derive(Default)]
pub struct Cache {
    entries: Mutex<HashMap<String, Minted>>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&format!("Cache({} held, hidden)", self.held()))
    }
}

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Minted>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn get(&self, key: &str, now: i64) -> Option<Prepared> {
        self.lock().get(key).filter(|held| held.until - MARGIN > now).map(|held| held.prepared.clone())
    }

    fn put(&self, key: String, prepared: Prepared, until: i64, now: i64) {
        let mut entries = self.lock();
        // Anything that has run out goes first, so an idle grid does not hold a lapsed token in
        // memory until something else happens to need the cache.
        entries.retain(|_, held| held.until > now);
        while entries.len() >= MOST_HELD {
            let Some(oldest) = entries.iter().min_by_key(|(_, held)| held.made_at).map(|(key, _)| key.clone()) else { break };
            entries.remove(&oldest);
        }
        entries.insert(key, Minted { prepared, until, made_at: now });
    }

    /// Drops everything made from one credential, for a credential that has been retired or whose
    /// settings an administrator has changed.
    pub fn forget(&self, credential_id: &str) {
        self.lock().retain(|key, _| key.split('\u{1}').next() != Some(credential_id));
    }

    pub fn forget_all(&self) {
        self.lock().clear();
    }

    /// How many are held. For a status line, and for the test that proves a token is dropped and
    /// overwritten rather than kept.
    pub fn held(&self) -> usize {
        self.lock().len()
    }
}

/// What minting needs to know about a credential. There is no value in it, and its `Debug` can be
/// printed anywhere.
#[derive(Clone, Copy, Debug)]
pub struct Recipe<'a> {
    pub credential_id: &'a str,
    /// Which realm this credential belongs to. Two realms on one computer have their own
    /// databases and their own keys, and one cache may serve both, so the realm is part of what a
    /// token is held under rather than being taken on trust from the identifier alone.
    pub realm_id: &'a str,
    /// Raised by every rotation and by retirement, so a token made from the old value is never
    /// handed out after one.
    pub generation: u32,
    pub vault_version: u32,
    pub presentation: Kind,
    pub field: &'a str,
    pub settings: &'a std::collections::BTreeMap<String, String>,
    /// Whose request this is. AWS names the session after them, so AWS's own logs say who, which
    /// means one person's temporary keys are never handed to another.
    pub person: &'a str,
}

impl Recipe<'_> {
    fn setting(&self, key: &str) -> Option<&str> {
        self.settings.get(key).map(String::as_str).filter(|value| !value.is_empty())
    }

    /// Which token this is in the cache.
    ///
    /// Everything that decides what a token is bought with is in the key, so a token made under
    /// one answer is never handed out under another and nothing has to be found and deleted. The
    /// generation and the vault version move on every rotation. The settings are in it because an
    /// administrator moving a token endpoint, a client identifier or a role changes neither of
    /// those, and a token bought from the old endpoint is not a token for the new one. The person
    /// is in it only where the token is theirs rather than the grid's, which is AWS, where the
    /// session is assumed in their name.
    fn key(&self) -> String {
        let person = if self.presentation == Kind::Aws { self.person } else { "" };
        let settings: Vec<String> = self.settings.iter().map(|(key, value)| format!("{key}={value}")).collect();
        let shape = crate::digest("mint-shape", &format!("{:?}\u{2}{}", self.presentation, settings.join("\u{3}")));
        format!("{}\u{1}{}\u{1}{}\u{1}{}\u{1}{shape}\u{1}{person}", self.credential_id, self.realm_id, self.generation, self.vault_version)
    }
}

/// Hides a value wherever a service happened to put it in what it said back.
///
/// A token endpoint that refuses often echoes what it was sent, and that answer becomes a refusal
/// a person reads and the realm records. Short values are left alone, because replacing a
/// three-character string would redact unrelated text.
fn hide_in(message: String, secret: &str) -> String {
    if secret.len() >= 4 {
        message.replace(secret, "[withheld]")
    } else {
        message
    }
}

fn wipe_text(text: &mut String) {
    // Safety: as in `wipe_prepared`, zeroes are valid UTF-8 and the string is emptied after.
    let bytes = unsafe { text.as_mut_vec() };
    vault::wipe(bytes);
    bytes.clear();
}

fn encode(text: &str) -> String {
    text.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    fields.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value))).collect::<Vec<_>>().join("&").into_bytes()
}

/// Where this grid itself will connect to make a credential of this kind, so the realm's own
/// outbound rules can be asked about it before any value is read.
///
/// An empty list means nothing is reached: an AWS credential with no role is signed in place, and
/// the four plain kinds mint nothing at all.
pub fn endpoints(presentation: Kind, settings: &std::collections::BTreeMap<String, String>) -> Result<Vec<Target>, String> {
    let read = |key: &str| settings.get(key).map(String::as_str).filter(|value| !value.is_empty());
    let address = match presentation {
        Kind::Oauth => read("tokenUrl").map(str::to_owned),
        Kind::GithubApp => Some(read("apiUrl").unwrap_or(GITHUB).to_owned()),
        Kind::Aws if read("roleArn").is_some() => Some(sts_url(read("stsUrl"), read("region").unwrap_or_default())),
        _ => None,
    };
    match address {
        Some(address) => Ok(vec![forward::target(&address)?]),
        None => Ok(Vec::new()),
    }
}

const GITHUB: &str = "https://api.github.com";

fn sts_url(stated: Option<&str>, region: &str) -> String {
    stated.map(str::to_owned).unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"))
}

/// An OAuth 2 access token for the client credentials, and when it lapses.
async fn oauth(recipe: &Recipe<'_>, secret: &str, now: i64) -> Result<(String, i64), String> {
    let url = recipe.setting("tokenUrl").ok_or("This credential has no token URL, so there is nowhere to ask for a token")?;
    let client = recipe.setting("clientId").ok_or("This credential has no client ID")?;
    let mut fields = vec![("grant_type", "client_credentials")];
    for key in ["scope", "audience"] {
        if let Some(value) = recipe.setting(key) {
            fields.push((key, value));
        }
    }
    let mut headers = vec![("content-type", "application/x-www-form-urlencoded".to_owned()), ("accept", "application/json".to_owned())];
    if recipe.setting("auth") == Some("body") {
        fields.push(("client_id", client));
        fields.push(("client_secret", secret));
    } else {
        let mut pair = format!("{}:{}", encode(client), encode(secret));
        headers.push(("authorization", format!("Basic {}", STANDARD.encode(&pair))));
        wipe_text(&mut pair);
    }
    let answer = forward::fetch("POST", url, &headers, Some(form(&fields))).await;
    for (_, value) in &mut headers {
        wipe_text(value);
    }
    let answer = answer.map_err(|said| hide_in(said, secret))?;
    if !answer.ok() {
        return Err(hide_in(format!("The token endpoint refused to issue a token ({})", answer.said()), secret));
    }
    let json = answer.json();
    let token = json["access_token"].as_str().filter(|token| !token.is_empty()).ok_or("The token endpoint sent no access_token")?.to_owned();
    let lifetime = json["expires_in"].as_i64().or_else(|| json["expires_in"].as_str().and_then(|text| text.parse().ok())).unwrap_or(3600).clamp(60, 86_400);
    Ok((token, now + lifetime))
}

/// The DER inside a PEM block, and whether it is PKCS#8 (`PRIVATE KEY`) rather than PKCS#1.
fn pem(text: &str) -> Result<(Vec<u8>, bool), String> {
    let invalid = || "What the vault holds for this credential is not a PEM private key".to_owned();
    let pkcs8 = text.contains("-----BEGIN PRIVATE KEY-----");
    let rsa = text.contains("-----BEGIN RSA PRIVATE KEY-----");
    if !pkcs8 && !rsa {
        return Err(invalid());
    }
    let body: String = text.lines().filter(|line| !line.starts_with("-----")).map(str::trim).collect();
    let der = STANDARD.decode(body).map_err(|_| invalid())?;
    Ok((der, pkcs8))
}

fn rsa(text: &str) -> Result<ring::signature::RsaKeyPair, String> {
    let (der, pkcs8) = pem(text)?;
    let pair = if pkcs8 { ring::signature::RsaKeyPair::from_pkcs8(&der) } else { ring::signature::RsaKeyPair::from_der(&der) };
    pair.map_err(|_| "This GitHub App's private key is not an RSA key this build can sign with (2048 bits or more)".to_owned())
}

/// The JWT a GitHub App signs to ask for an installation token: RS256, nine minutes, which is
/// inside GitHub's ten-minute ceiling with a minute of clock skew on either side.
fn github_jwt(app_id: &str, key: &str, now: i64) -> Result<String, String> {
    let pair = rsa(key)?;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(json!({"iat": now - 60, "exp": now + 540, "iss": app_id}).to_string());
    let message = format!("{header}.{claims}");
    let mut signature = vec![0u8; pair.public().modulus_len()];
    pair.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), message.as_bytes(), &mut signature)
        .map_err(|_| "Cannot sign with this GitHub App's private key")?;
    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// A GitHub App installation token, and when it lapses (an hour after it was made).
///
/// The assertion is signed against the wall clock this grid was handed, because GitHub checks
/// `iat` and `exp` against its own. That is the one place in the broker where a clock correction
/// matters, and what it costs is a refused mint rather than a wrong send.
async fn github(recipe: &Recipe<'_>, key: &str, now: i64) -> Result<(String, i64), String> {
    let app = recipe.setting("appId").ok_or("This credential has no GitHub App ID")?;
    let installation = recipe.setting("installationId").ok_or("This credential has no GitHub installation ID")?;
    let api = recipe.setting("apiUrl").unwrap_or(GITHUB);
    let mut jwt = github_jwt(app, key, now)?;
    let headers = [("authorization", format!("Bearer {jwt}")), ("accept", "application/vnd.github+json".to_owned())];
    let answer = forward::fetch("POST", &format!("{api}/app/installations/{installation}/access_tokens"), &headers, None).await;
    wipe_text(&mut jwt);
    let answer = answer?;
    if !answer.ok() {
        return Err(format!("GitHub refused to make an installation token ({})", answer.said()));
    }
    let json = answer.json();
    let token = json["token"].as_str().filter(|token| !token.is_empty()).ok_or("GitHub sent no installation token")?.to_owned();
    let expires = json["expires_at"].as_str().and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok()).map(|at| at.timestamp()).unwrap_or(now + 3600);
    Ok((token, expires))
}

/// The two halves of an AWS key, as the vault holds them.
fn aws_keys(value: &str) -> Result<Keys, String> {
    let (access_key, secret_key) = value.split_once(':').ok_or("What the vault holds for this credential is not ACCESS_KEY_ID:SECRET_ACCESS_KEY")?;
    if access_key.trim().is_empty() || secret_key.trim().is_empty() {
        return Err("What the vault holds for this credential is not ACCESS_KEY_ID:SECRET_ACCESS_KEY".into());
    }
    Ok(Keys { access_key: access_key.to_owned(), secret_key: secret_key.to_owned(), session_token: None })
}

/// Calls STS with the long-lived key for temporary keys, with AssumeRole because the credential
/// names a role. The session is named after the person, so AWS's own logs say who.
///
/// The moment the request is signed at comes from the wall clock, because AWS checks it against
/// its own, and when the temporary keys lapse is whatever AWS said rather than a time computed
/// here. So this is the one mint whose expiry is not relative to the clock the broker was handed.
async fn sts(recipe: &Recipe<'_>, keys: &Keys) -> Result<(Keys, i64), String> {
    let region = recipe.setting("region").ok_or("This credential has no AWS region")?;
    let role = recipe.setting("roleArn").ok_or("This credential names no AWS role")?;
    let seconds = recipe.setting("sessionSeconds").unwrap_or("3600").to_owned();
    let session = format!("grid-{}", recipe.person.chars().filter(|letter| letter.is_ascii_alphanumeric() || "_+=,.@-".contains(*letter)).take(50).collect::<String>());
    let mut fields = vec![
        ("Version", "2011-06-15"),
        ("DurationSeconds", seconds.as_str()),
        ("Action", "AssumeRole"),
        ("RoleArn", role),
        ("RoleSessionName", session.as_str()),
    ];
    if let Some(external) = recipe.setting("externalId") {
        fields.push(("ExternalId", external));
    }
    let body = form(&fields);
    let url = sts_url(recipe.setting("stsUrl"), region);
    let target = forward::target(&url)?;
    let host = if (target.https && target.port == 443) || (!target.https && target.port == 80) { target.host.clone() } else { format!("{}:{}", target.host, target.port) };
    let mut headers = vec![("content-type".to_owned(), "application/x-www-form-urlencoded; charset=utf-8".to_owned())];
    headers.extend(sigv4::sign("POST", &host, &target.path, target.query.as_deref(), &body, keys, region, "sts", &sigv4::amz_date(), true));
    let borrowed: Vec<(&str, String)> = headers.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
    let answer = forward::fetch("POST", &url, &borrowed, Some(body)).await;
    for (_, value) in &mut headers {
        wipe_text(value);
    }
    let answer = answer.map_err(|said| hide_in(said, &keys.secret_key))?;
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    if !answer.ok() {
        let message = sigv4::xml_text(&text, "Message").unwrap_or_else(|| answer.said());
        return Err(hide_in(format!("AWS STS refused to make temporary keys (HTTP {}): {message}", answer.status), &keys.secret_key));
    }
    sigv4::credentials(&text).ok_or_else(|| "AWS STS sent no temporary keys".to_owned())
}

/// The credential ready for one request: the value itself for the four plain kinds, a cached
/// short-lived token or temporary keys for the three that mint.
///
/// `value` is borrowed from the `Held` the broker read and is never copied anywhere but into the
/// request this builds.
pub async fn prepare(cache: &Cache, recipe: &Recipe<'_>, value: &str, now: i64) -> Result<Prepared, String> {
    // Asked again here, at the moment it matters, rather than trusted from whatever wrote the
    // credential down: a settings map that reached the realm as a line of JSON never met a builder.
    checked_settings(recipe.presentation, recipe.settings)?;
    match recipe.presentation {
        Kind::Bearer | Kind::Header | Kind::Basic | Kind::Query => Ok(Prepared::plain(recipe.presentation, recipe.field, value)),
        Kind::Oauth | Kind::GithubApp => {
            let key = recipe.key();
            if let Some(prepared) = cache.get(&key, now) {
                return Ok(prepared);
            }
            let (token, until) = if recipe.presentation == Kind::Oauth { oauth(recipe, value, now).await? } else { github(recipe, value, now).await? };
            if until <= now {
                return Err("The token endpoint answered with a token that had already run out, so nothing was sent with it".into());
            }
            let prepared = Prepared::bearer(&token, value);
            // Kept only while there is enough of it left to be worth reusing. A token with less
            // than the margin on it is used for this one request and not held: handing it to the
            // next request would be handing out something that may lapse while it is in flight.
            if until - MARGIN > now {
                cache.put(key, prepared.clone(), until, now);
            }
            Ok(prepared)
        }
        Kind::Aws => {
            let keys = aws_keys(value)?;
            let region = recipe.setting("region").ok_or("This credential has no AWS region")?.to_owned();
            let service = recipe.setting("service").map(str::to_owned);
            // No role means the request is signed with the long-lived key in place: nothing is
            // fetched, nothing is cached, and the key still never leaves this process.
            if recipe.setting("roleArn").is_none() {
                return Ok(Prepared { secrets: vec![keys.secret_key.clone()], auth: Auth::Aws { keys, region, service } });
            }
            let key = recipe.key();
            if let Some(prepared) = cache.get(&key, now) {
                return Ok(prepared);
            }
            let (temporary, until) = sts(recipe, &keys).await?;
            if until <= now {
                return Err("AWS answered with temporary keys that had already run out, so nothing was sent with them".into());
            }
            let secrets = vec![keys.secret_key.clone(), temporary.secret_key.clone(), temporary.session_token.clone().unwrap_or_default()];
            let prepared = Prepared { secrets, auth: Auth::Aws { keys: temporary, region, service } };
            if until - MARGIN > now {
                cache.put(key, prepared.clone(), until, now);
            }
            Ok(prepared)
        }
    }
}

/// The value as a credential of this kind needs it, out of what the vault handed back.
///
/// Everything but a GitHub App puts the value itself on the request, so it has to be one line: a
/// line break in a header, a parameter or a username could end the header early. A GitHub App's
/// private key is a PEM block, which is several lines on purpose and never goes on a request at
/// all, so it is taken as it is.
///
/// One platform limit is worth knowing here. Windows keeps a credential blob to 2560 bytes, so a
/// GitHub App key longer than that cannot be written into that computer's vault at all, and
/// `core_vault::OsVault::write` refuses it rather than writing half of one.
pub fn value_in(presentation: Kind, held: &vault::Held) -> Result<&str, vault::Trouble> {
    match presentation {
        Kind::GithubApp => held.as_text(),
        _ => held.one_line(),
    }
}

/// The recipe for one credential, for a caller that holds the credential itself.
pub fn recipe_for<'a>(credential: &'a Credential, person: &'a str) -> Recipe<'a> {
    Recipe {
        credential_id: &credential.id,
        realm_id: &credential.realm_id,
        generation: credential.generation,
        vault_version: credential.vault.version,
        presentation: credential.presentation,
        field: &credential.field,
        settings: &credential.settings,
        person,
    }
}
