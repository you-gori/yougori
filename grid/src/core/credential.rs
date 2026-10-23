//! A credential the realm holds on someone's behalf, and who may use it where.
//!
//! The value is never here. What is stored is where the secret lives in the operating system's
//! vault, a fingerprint for telling one credential from another, the places it may be sent to,
//! how it travels when it gets there, and who may use it for what. A workload never receives the
//! value: it receives a short-lived permission naming this credential, and the broker makes the
//! request on its behalf.
//!
//! Nothing in this file takes a secret as an argument except `fingerprint_of`, which returns a
//! digest and keeps nothing. Everything that is written is checked first, so a value cannot be
//! put in by mistake where a reference belongs.
//!
//! How a value travels and where it may go are decided by the forwarder, not here: `Kind` is the
//! one enum that says how, `forward::destination` is the one way an address is written down, and
//! `within_path` is the one way a path prefix is matched. A second copy of any of those would be
//! a second set of rules for the same question.
use crate::access::{forward, policy::within_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a value travels on a request. One enum decides this, and it is the forwarder's, because
/// the forwarder is what switches on it when the value goes on the wire. Four of the seven send
/// the value as it is; the other three make a short-lived credential from it first, and what each
/// of those needs besides the value is in `settings`.
pub use crate::access::policy::Kind;

/// The longest a vault entry's name may be here, so `grid-core.{name}.v{version}` still fits the
/// 80 characters the operating system's vault layer accepts.
pub const MAX_VAULT_NAME: usize = 48;

fn bearer() -> Kind {
    Kind::Bearer
}

fn first_generation() -> u32 {
    1
}

/// The name of a vault entry, checked by the same rule the operating system's vault layer uses,
/// so a credential this grid accepts can actually be read at the moment it is sent.
pub fn vault_entry(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_VAULT_NAME || !name.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '.' | '-' | '_')) {
        return Err(format!("A vault entry is named in 1 to {MAX_VAULT_NAME} letters, digits, dots, dashes or underscores"));
    }
    Ok(name.to_owned())
}

/// A destination as this grid writes one down: scheme, host, port and an optional path prefix,
/// in the one shape the forwarder matches against.
///
/// Plain http is accepted for a private address, because an internal service on the company's own
/// network is reached that way and the forwarder already allows it. A public address must be
/// HTTPS, and says so.
pub fn destination_of(text: &str) -> Result<String, String> {
    forward::destination(text).map_err(|trouble| {
        if trouble.contains("https://") {
            "A credential names one destination, over HTTPS; plain http is only for a private address such as http://10.0.0.8:8080".to_owned()
        } else {
            trouble
        }
    })
}

/// What kind of credential this is. It changes how the broker presents it, never where it goes.
///
/// There were five of these and there are four. A client certificate is gone, because a client
/// certificate is not a value that goes in a header, a parameter or a username: it is a key the
/// outgoing TLS handshake proves possession of, and the forwarder this grid sends through builds
/// its TLS with no client authentication at all. Keeping the word would have been the type
/// promising something the broker cannot do, and a credential that cannot be brokered is worse
/// than one that was never offered, because somebody records it and then finds out. A company
/// that authenticates with a client certificate is told that plainly rather than being allowed to
/// write the credential down and discover it at the moment of use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Secret {
    ApiKey,
    Password,
    Token,
    /// A service account: the long-lived secret of a machine identity, which the broker usually
    /// turns into a short-lived token before it sends anything. See `Kind::mints`.
    ServiceAccount,
}

impl Secret {
    pub fn name(self) -> &'static str {
        match self {
            Secret::ApiKey => "API key",
            Secret::Password => "password",
            Secret::Token => "token",
            Secret::ServiceAccount => "service account",
        }
    }
}

/// How long one of a minting credential's settings may be. A token endpoint, a role name and a
/// region are all addresses and names; nothing here is ever a value.
pub const MAX_SETTING: usize = 512;

/// What a credential of each kind needs besides its value, and what it may also be given.
///
/// None of it is secret, and that is the whole point of the list: the secret is in the vault and
/// the broker reads it at the moment it mints. These are the same names the shipped Access Grid
/// uses for the same three kinds, so a credential brought across by the bridge keeps its settings
/// rather than being re-entered by hand.
pub fn settings_for(kind: Kind) -> (&'static [&'static str], &'static [&'static str]) {
    match kind {
        Kind::Oauth => (&["tokenUrl", "clientId"], &["scope", "audience", "auth"]),
        Kind::GithubApp => (&["appId", "installationId"], &["apiUrl"]),
        Kind::Aws => (&["region"], &["service", "roleArn", "externalId", "sessionSeconds", "stsUrl"]),
        _ => (&[], &[]),
    }
}

/// Whether every setting a credential of this kind needs is there, and whether what is there is a
/// name or an address rather than a value.
///
/// A credential that sends its value as it is has no settings at all, and a map on one of those is
/// refused rather than ignored: a setting nothing reads is a setting somebody believes in.
pub fn checked_settings(kind: Kind, settings: &BTreeMap<String, String>) -> Result<(), String> {
    let (needed, allowed) = settings_for(kind);
    if !kind.mints() {
        return if settings.is_empty() {
            Ok(())
        } else {
            Err("A credential that travels as it is takes no settings; only a credential this grid mints a short-lived one from has any".into())
        };
    }
    for (key, value) in settings {
        if !needed.contains(&key.as_str()) && !allowed.contains(&key.as_str()) {
            return Err(format!("{key} is not a setting this kind of credential has; it takes {}", [needed, allowed].concat().join(", ")));
        }
        if value.is_empty() || value.trim() != value.as_str() || value.len() > MAX_SETTING || value.chars().any(char::is_control) {
            return Err(format!("{key} is one line of at most {MAX_SETTING} characters, with no space around it"));
        }
        if looks_like_a_secret(value) {
            return Err(format!("{key} is a name or an address, not the secret itself; the value lives in the vault"));
        }
    }
    for key in needed {
        if !settings.contains_key(*key) {
            return Err(format!("This credential has no {key}, and it cannot make a token without one"));
        }
    }
    let read = |key: &str| settings.get(key).map(String::as_str);
    // A token endpoint and an STS endpoint are whole addresses, path and all, because that is
    // where the request goes. An API root is a place things hang off, so it is written the way a
    // destination is written, without a trailing slash, and the path is built onto it.
    for (key, written) in [("tokenUrl", true), ("stsUrl", true), ("apiUrl", false)] {
        if let Some(address) = read(key) {
            let one_way = if written { forward::token_url(address) } else { forward::destination(address) };
            let one_way = one_way.map_err(|why| format!("{key}: {why}"))?;
            if one_way != address {
                return Err(format!("{key} is written the way this grid writes an address: {one_way}"));
            }
        }
    }
    if let Some(auth) = read("auth") {
        if auth != "basic" && auth != "body" {
            return Err("auth is basic, which sends the client secret in the authorization header, or body, which sends it in the form".into());
        }
    }
    for key in ["appId", "installationId"] {
        if let Some(digits) = read(key) {
            if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|letter| letter.is_ascii_digit()) {
                return Err(format!("{key} is the number GitHub gives it"));
            }
        }
    }
    if let Some(seconds) = read("sessionSeconds") {
        match seconds.parse::<i64>() {
            Ok(seconds) if (900..=43_200).contains(&seconds) => {}
            _ => return Err("sessionSeconds is how long AWS's temporary keys last, between 900 and 43200".into()),
        }
    }
    for key in ["region", "service"] {
        if let Some(name) = read(key) {
            if name.len() > 64 || !name.bytes().all(|letter| letter.is_ascii_lowercase() || letter.is_ascii_digit() || letter == b'-') {
                return Err(format!("{key} is written in lower-case letters, digits and dashes, the way AWS writes one"));
            }
        }
    }
    if let Some(role) = read("roleArn") {
        if !role.starts_with("arn:") || role.len() > 2048 {
            return Err("roleArn is the full name of an AWS role, which begins arn:".into());
        }
    }
    Ok(())
}

/// Where the secret actually is: an entry in the operating system's vault, and which version of
/// it. The value is read by the broker at the moment it is needed and is never written here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vault {
    pub id: String,
    pub version: u32,
}

/// The one blessed way to fingerprint a secret, so two credentials can be told apart and a
/// rotation can be noticed without the value being kept anywhere.
///
/// It is a plain digest over a fixed purpose and the value: unsalted and unkeyed, because it has
/// to be computable by an administrator's tool that holds the value and by this grid, which never
/// does. That means a fingerprint is a hash somebody holding a backup could test guesses against,
/// which matters for a weak password and not for a random key. It is here to tell one credential
/// from another and to notice that a value changed, and the threat model says so in those words.
pub fn fingerprint_of(secret: &str) -> String {
    crate::digest("credential", secret)
}

/// Whether a piece of text looks like a secret value rather than a name or a reference. Used to
/// refuse anything that would put a value where a reference belongs.
pub fn looks_like_a_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.contains("-----BEGIN") || trimmed.contains("PRIVATE KEY") {
        return true;
    }
    let lowered = trimmed.to_ascii_lowercase();
    for marker in ["password=", "secret=", "api_key=", "apikey=", "token=", "bearer "] {
        if lowered.contains(marker) {
            return true;
        }
    }
    for prefix in ["sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "aws_secret", "akia"] {
        if lowered.starts_with(prefix) {
            return true;
        }
    }
    // A long unbroken run of random-looking characters is a value, not a name.
    trimmed.len() >= 32 && trimmed.chars().all(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_' | '+' | '/' | '='))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|letter| letter.is_ascii_hexdigit())
}

/// One credential, as the realm knows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub id: String,
    pub realm_id: String,
    pub name: String,
    pub kind: Secret,
    /// Where the value is. Never the value.
    pub vault: Vault,
    pub fingerprint: String,
    /// The place it was first given, and the one a permission is pinned to unless the caller
    /// names another. A credential without a destination is not stored at all.
    pub destination: String,
    /// Every place it may be sent, the first of which is `destination`. Written the way the
    /// forwarder writes one, so there is a single spelling to compare against.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destinations: Vec<String>,
    /// How the value travels on a request.
    #[serde(default = "bearer")]
    pub presentation: Kind,
    /// The header or parameter name the value travels in, or the username for basic; empty for
    /// bearer and for every kind that mints. A name, never a value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub field: String,
    /// What a minting kind needs besides its value: a token endpoint, a client identifier, a
    /// region, a role. Names and addresses, checked on the way in by `checked_settings`, and empty
    /// for the four kinds that send the value as it is.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, String>,
    /// Who said this credential's value may travel in the URL, and when.
    ///
    /// A query credential is the one way of travelling that leaves a copy of the value in somebody
    /// else's records: the service's own access log keeps the whole URL, and so does every proxy
    /// between here and it. This grid cannot reach any of those copies, so the decision to make
    /// them is an administrator's and is written down with their name on it. The broker refuses a
    /// query credential that has no name here, at both looks, and says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_allowed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_allowed_at: Option<i64>,
    /// Raised by every rotation and by retirement, so permissions issued before it are refused
    /// the next time they are used.
    #[serde(default = "first_generation")]
    pub generation: u32,
    /// Which methods it may be used with; empty means any.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Which paths it may touch, by prefix; empty means any.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_bytes: Option<u64>,
    pub owner_id: String,
    /// Every use needs an approver; no standing allowance covers it. Revealing a value is always
    /// of this kind, and a credential may be marked this way as well.
    #[serde(default)]
    pub every_time: bool,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<i64>,
    /// When it should next be rotated, for the admin to see; nothing is rotated automatically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_by: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<i64>,
}

impl Credential {
    /// Records a credential. `vault_id` names the vault entry holding the value, and
    /// `fingerprint` comes from `fingerprint_of`. Anything that looks like a value is refused.
    pub fn new(realm_id: &str, name: &str, kind: Secret, vault_id: &str, fingerprint: &str, destination: &str, owner_id: &str, now: i64) -> Result<Credential, String> {
        let name = crate::label(name, "credential name")?;
        if looks_like_a_secret(&name) {
            return Err("A credential's name is a name, not the secret itself".into());
        }
        if vault_id.trim().is_empty() {
            return Err("Say which vault entry holds this credential".into());
        }
        if looks_like_a_secret(vault_id) {
            return Err("That is the secret itself, not the name of the vault entry holding it".into());
        }
        let vault_id = vault_entry(vault_id)?;
        if !is_digest(fingerprint) {
            return Err("A credential's fingerprint comes from fingerprint_of; the value is never stored".into());
        }
        if looks_like_a_secret(destination) {
            return Err("A destination is an address, not a secret".into());
        }
        // Normalised on the way in, so what is stored is the one spelling everything else
        // compares against: lower-case host, the default port dropped, no trailing slash.
        let destination = destination_of(destination)?;
        Ok(Credential {
            id: format!("credential-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            name,
            kind,
            vault: Vault { id: vault_id, version: 1 },
            fingerprint: fingerprint.to_owned(),
            destinations: vec![destination.clone()],
            destination,
            presentation: Kind::Bearer,
            field: String::new(),
            settings: BTreeMap::new(),
            query_allowed_by: None,
            query_allowed_at: None,
            generation: 1,
            methods: Vec::new(),
            paths: Vec::new(),
            maximum_bytes: None,
            owner_id: owner_id.to_owned(),
            every_time: false,
            created_at: now,
            rotated_at: None,
            rotate_by: None,
            retired_at: None,
        })
    }

    /// The checks `new` makes, re-run on a credential that reached the realm some other way.
    ///
    /// Every field here is public and the type deserialises, so `new` is not the only way one of
    /// these can be built: a struct literal or a line of JSON builds one just as well, and neither
    /// goes past the rules above. What is written here is then repeated by every brokered
    /// request's row, by every backup, and by the sentence a vault failure puts in the history, so
    /// a value put where a reference belongs is sealed into a record that is insert-only by
    /// design. The realm's write door asks this before any of that happens.
    pub fn is_a_reference(&self) -> Result<(), String> {
        if looks_like_a_secret(&self.name) {
            return Err("A credential's name is a name, not the secret itself".into());
        }
        if self.vault.id.trim().is_empty() {
            return Err("Say which vault entry holds this credential".into());
        }
        if looks_like_a_secret(&self.vault.id) {
            return Err("That is the secret itself, not the name of the vault entry holding it".into());
        }
        vault_entry(&self.vault.id)?;
        if !is_digest(&self.fingerprint) {
            return Err("A credential's fingerprint comes from fingerprint_of; the value is never stored".into());
        }
        if looks_like_a_secret(&self.destination) {
            return Err("A destination is an address, not a secret".into());
        }
        if looks_like_a_secret(&self.field) {
            return Err("That is the value itself, not the name it travels under".into());
        }
        // Every place it may be sent is written the one way the forwarder writes one, because that
        // spelling is what the broker compares a request against. A credential carrying a place
        // written any other way is one that would be sent somewhere nothing has agreed on.
        if destination_of(&self.destination)? != self.destination {
            return Err("A credential's destination is written the way this grid writes an address".into());
        }
        for place in &self.destinations {
            if destination_of(place)? != *place {
                return Err("A credential's destinations are written the way this grid writes an address".into());
            }
        }
        // How it travels, with the same rules the two builders apply, for the same reason: a
        // credential that arrived as a line of JSON never met either of them.
        if self.presentation.mints() && !self.field.is_empty() {
            return Err("A credential this grid mints a short-lived one from travels in the authorization header and takes no field".into());
        }
        checked_settings(self.presentation, &self.settings)?;
        if self.query_allowed_by.is_some() != self.query_allowed_at.is_some() {
            return Err("Letting a credential travel in the URL records who allowed it and when; one without the other says nothing".into());
        }
        if let Some(by) = &self.query_allowed_by {
            if by.trim().is_empty() || by.len() > 64 {
                return Err("Letting a credential travel in the URL records the account that allowed it".into());
            }
        }
        Ok(())
    }

    /// Narrows it to certain methods and path prefixes, and a largest body.
    pub fn narrowed_to(mut self, methods: &[&str], paths: &[&str], maximum_bytes: Option<u64>) -> Credential {
        self.methods = methods.iter().map(|method| method.to_ascii_uppercase()).collect();
        self.paths = paths.iter().map(|path| (*path).to_owned()).collect();
        self.maximum_bytes = maximum_bytes;
        self
    }

    /// Marks it as one that needs an approver every single time it is used.
    pub fn every_time(mut self) -> Credential {
        self.every_time = true;
        self
    }

    /// How the value travels as it is, and which header or parameter carries it.
    ///
    /// This is the door for the four kinds that put the value on the request unchanged. The three
    /// that make a short-lived credential from it first go through `minting_as`, which takes the
    /// settings each of them needs in the same breath, because a credential recorded as minting
    /// with nothing to mint from would be refused at the moment somebody tried to use it.
    ///
    /// A field that looks like a value, or is not a header or parameter name, is refused, and
    /// bearer takes no field.
    ///
    /// One of the four is worse than the others and this is the only place to say so. A query
    /// credential travels in the URL, which is where the service's own access log and every proxy
    /// between here and it will keep a copy. Nothing this grid writes carries that query, and the
    /// broker keeps it out of the record and the audit reason, but the copies at the far end are
    /// not ours to stop. So choosing query here is not enough on its own: an administrator has to
    /// say in so many words that this credential may travel that way, through
    /// `in_the_url_allowed_by` or `Core::allow_query_credential`, and until one has, the broker
    /// refuses the send and says that is why.
    pub fn travelling_as(mut self, presentation: Kind, field: &str) -> Result<Credential, String> {
        if presentation.mints() {
            return Err("A credential this grid mints a short-lived one from is recorded with minting_as, which takes the token endpoint or the region it needs".into());
        }
        let field = field.trim();
        if presentation == Kind::Bearer {
            if !field.is_empty() {
                return Err("A bearer credential travels in the authorization header and takes no field".into());
            }
            self.presentation = presentation;
            self.field = String::new();
            self.settings.clear();
            return Ok(self);
        }
        if field.is_empty() || field.len() > 64 || !field.bytes().all(|letter| letter.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&letter)) {
            return Err("Name the header, parameter or username the value travels in, in up to 64 printable characters".into());
        }
        if looks_like_a_secret(field) {
            return Err("That is the value itself, not the name it travels under".into());
        }
        self.presentation = presentation;
        self.field = field.to_owned();
        self.settings.clear();
        Ok(self)
    }

    /// A credential this grid makes a short-lived one from: OAuth 2 client credentials, a GitHub
    /// App's installation tokens, or an AWS key the request is signed with.
    ///
    /// The settings arrive with the kind rather than one at a time, because every one of these is
    /// useless without them: an OAuth credential with no token endpoint has nowhere to ask, and a
    /// credential recorded that way would be a row that reads as working and refuses on first use.
    /// What each kind takes is in `settings_for`, and none of it is secret.
    pub fn minting_as(mut self, presentation: Kind, settings: &[(&str, &str)]) -> Result<Credential, String> {
        if !presentation.mints() {
            return Err("A credential that sends its value as it is goes through travelling_as".into());
        }
        let mut written = BTreeMap::new();
        for (key, value) in settings {
            written.insert((*key).trim().to_owned(), (*value).trim().to_owned());
        }
        checked_settings(presentation, &written)?;
        self.presentation = presentation;
        self.field = String::new();
        self.settings = written;
        Ok(self)
    }

    /// Records that an administrator allowed this credential's value to travel in the URL. See the
    /// field it writes for why this is a decision somebody has to make by name.
    pub fn in_the_url_allowed_by(mut self, by: &str, now: i64) -> Credential {
        self.query_allowed_by = Some(by.to_owned());
        self.query_allowed_at = Some(now);
        self
    }

    /// Whether this credential may be put on a request at all, before anybody's permission or any
    /// address is considered.
    ///
    /// The broker asks this twice: once before any value is read, and again in the last look
    /// before the send, so an administrator taking back the permission to travel in the URL stops
    /// the next request the way every other withdrawal does.
    pub fn ready_to_send(&self) -> Result<(), String> {
        if self.presentation == Kind::Query && self.query_allowed_by.is_none() {
            return Err(
                "This credential's value would travel in the URL, where the service's own access log and every proxy in between keeps a copy of it. An administrator has to allow that for this credential before anything can be sent with it."
                    .into(),
            );
        }
        checked_settings(self.presentation, &self.settings)
    }

    /// Everything about how this credential travels, as one digest.
    ///
    /// The broker takes this when it clears a request and takes it again in the last look, so a
    /// token endpoint moved, a region changed or the permission to travel in the URL taken back
    /// between the two refuses the send rather than going out under the old answer. It covers only
    /// what decides the shape of the request; where it may go and who may use it are checked
    /// against the realm directly.
    pub fn shape(&self) -> String {
        let settings: Vec<String> = self.settings.iter().map(|(key, value)| format!("{key}={value}")).collect();
        crate::digest(
            "credential-shape",
            &format!("{:?}\u{1}{}\u{1}{}\u{1}{}", self.presentation, self.field, settings.join("\u{2}"), self.query_allowed_by.as_deref().unwrap_or_default()),
        )
    }

    /// Another place it may be sent, written the way the forwarder writes one.
    pub fn also_to(mut self, destination: &str) -> Result<Credential, String> {
        let destination = destination_of(destination)?;
        if !self.destinations.contains(&destination) {
            self.destinations.push(destination);
        }
        Ok(self)
    }

    /// Every place this credential may be sent.
    ///
    /// A credential read from an older record carries no list, and the one destination it does
    /// carry stands in for it. A destination that the forwarder will not accept gives an empty
    /// list rather than a loose one, so such a credential is refused rather than sent somewhere
    /// nothing has agreed on.
    pub fn places(&self) -> Vec<String> {
        if !self.destinations.is_empty() {
            return self.destinations.clone();
        }
        destination_of(&self.destination).ok().into_iter().collect()
    }

    pub fn live(&self, now: i64) -> bool {
        let _ = now;
        self.retired_at.is_none()
    }

    /// Whether this credential may be used that way at all, before anyone's permission is
    /// considered.
    ///
    /// A path prefix is matched on a segment boundary, by the forwarder's own matcher, so a
    /// credential scoped to `/v1` covers `/v1` and `/v1/charge` and never `/v1admin`.
    pub fn allows(&self, method: &str, path: &str) -> bool {
        let method = method.to_ascii_uppercase();
        (self.methods.is_empty() || self.methods.iter().any(|allowed| allowed == &method))
            && (self.paths.is_empty() || self.paths.iter().any(|allowed| within_path(path, allowed)))
    }

    /// Whether it is past the day its owner said it should be rotated by.
    pub fn due_for_rotation(&self, now: i64) -> bool {
        self.rotate_by.is_some_and(|by| now >= by)
    }
}

/// Who may use a credential, and for what. Holding one is not permission on its own: a use still
/// needs someone's agreement unless a standing allowance already covers it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub realm_id: String,
    pub credential_id: String,
    pub principal_id: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub granted_by: String,
    pub granted_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Grant {
    pub fn new(credential: &Credential, principal_id: &str, methods: &[&str], paths: &[&str], granted_by: &str, expires_at: Option<i64>, now: i64) -> Grant {
        Grant {
            id: format!("grant-{}", &crate::token()[..16]),
            realm_id: credential.realm_id.clone(),
            credential_id: credential.id.clone(),
            principal_id: principal_id.to_owned(),
            methods: methods.iter().map(|method| method.to_ascii_uppercase()).collect(),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            granted_by: granted_by.to_owned(),
            granted_at: now,
            expires_at,
        }
    }

    /// Whether this grant covers that use at that moment. The path prefix is matched on a segment
    /// boundary, by the same matcher the credential's own paths go through.
    pub fn covers(&self, method: &str, path: &str, now: i64) -> bool {
        let method = method.to_ascii_uppercase();
        self.expires_at.is_none_or(|expires| now < expires)
            && (self.methods.is_empty() || self.methods.iter().any(|allowed| allowed == &method))
            && (self.paths.is_empty() || self.paths.iter().any(|allowed| within_path(path, allowed)))
    }
}
