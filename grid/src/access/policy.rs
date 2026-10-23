//! Who may use which company credential, for what, and whether someone must approve it first.
//! A rule names a credential, the people it covers (everyone, a team or one person), optionally
//! the HTTP methods and the path it is limited to, and a decision: allow at once, ask an
//! approver, or never. A matching `never` wins over everything; otherwise `allow` wins over
//! `ask`; with no matching rule the request is refused.
use crate::digest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

pub const MAX_PEOPLE: usize = 1024;
pub const MAX_CREDENTIALS: usize = 512;
pub const MAX_RULES: usize = 4096;
pub const MAX_TEAMS: usize = 16;
pub const MAX_DESTINATIONS: usize = 16;
/// A credential value is one line, as it travels in a header or query string; a GitHub App's
/// private key (PEM) is the one value with several lines.
pub const MAX_VALUE: usize = 16 * 1024;
/// Computers a person stays signed in on at once.
pub const MAX_DEVICES: usize = 20;
/// A computer stays signed in this long after it last used its sign-in.
pub const DEVICE_LIFETIME: i64 = 30 * 24 * 60 * 60;
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// What a person may do in the Access Grid besides using what the rules allow them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Uses what the rules allow; sees their own requests.
    #[default]
    Member,
    /// Also approves or denies other people's requests, and reads the grid.
    Approver,
    /// Reads people, credentials (never values), rules and activity; changes nothing.
    Auditor,
    /// Everything: people, credentials, rules, and approvals.
    Admin,
}

impl Permission {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "member" | "" => Ok(Permission::Member),
            "approver" => Ok(Permission::Approver),
            "auditor" => Ok(Permission::Auditor),
            "admin" | "administrator" => Ok(Permission::Admin),
            other => Err(format!("'{other}' is not a permission; use member, approver, auditor or admin")),
        }
    }
    pub fn decides(self) -> bool {
        matches!(self, Permission::Approver | Permission::Admin)
    }
    pub fn reads_all(self) -> bool {
        self != Permission::Member
    }
    pub fn manages(self) -> bool {
        self == Permission::Admin
    }
    pub fn label(self) -> &'static str {
        match self {
            Permission::Member => "Member",
            Permission::Approver => "Approver",
            Permission::Auditor => "Auditor",
            Permission::Admin => "Administrator",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: String,
    pub username: String,
    pub name: String,
    pub permission: Permission,
    #[serde(default)]
    pub teams: Vec<String>,
    pub salt: String,
    pub key_hash: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    /// The address the company's identity provider knows them by, for single sign-on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Their account at the identity provider (its `sub`), tied at their first company sign-in:
    /// from then on only that account signs in as them, whatever email another account carries.
    /// An admin giving them a new email, or signing them out everywhere, unties it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_subject: Option<String>,
    /// Their authenticator app's secret, sealed like a credential; set once two-step sign-in is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_step: Option<String>,
    /// Raised when their password changes, two-step is reset or they are signed out everywhere:
    /// every sign-in and remembered computer from before stops working.
    #[serde(default)]
    pub generation: u64,
    /// Computers that stay signed in: each keeps a token only it has, kept here as a hash.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
}

/// A computer a person signed in on, which signs in again by itself until it lapses or is removed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub hash: String,
    pub computer: String,
    pub created_at: i64,
    pub last_used_at: i64,
    /// Signed in with a second factor: two-step codes or the company's identity provider.
    #[serde(default)]
    pub strong: bool,
    #[serde(default)]
    pub generation: u64,
}

impl Device {
    pub fn live(&self, person: &Person, now: i64) -> bool {
        self.generation == person.generation && self.last_used_at + DEVICE_LIFETIME > now
    }
}

impl Person {
    /// Everything but the password's salt and hash, the two-step secret and device tokens.
    pub fn public(&self) -> Value {
        let at = crate::now();
        let devices: Vec<Value> = self.devices.iter().filter(|device| device.live(self, at)).map(|device| json!({"id": device.id, "computer": device.computer, "createdAt": device.created_at, "lastUsedAt": device.last_used_at, "strong": device.strong})).collect();
        json!({"id": self.id, "username": self.username, "name": self.name, "permission": self.permission, "teams": self.teams, "createdAt": self.created_at, "lastSeenAt": self.last_seen_at, "email": self.email, "twoStep": self.two_step.is_some(), "devices": devices})
    }
    pub fn in_team(&self, team: &str) -> bool {
        self.teams.iter().any(|own| own.eq_ignore_ascii_case(team))
    }
}

/// How the hub puts a credential on a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// `Authorization: Bearer VALUE`.
    Bearer,
    /// `FIELD: VALUE`, such as `X-Api-Key`.
    Header,
    /// `Authorization: Basic base64(FIELD:VALUE)`; FIELD is the username.
    Basic,
    /// `?FIELD=VALUE` added to the URL.
    Query,
    /// OAuth 2 client credentials: the value is the client secret; the hub fetches short-lived
    /// access tokens from the token URL and sends those.
    Oauth,
    /// A GitHub App: the value is its private key; the hub makes one-hour installation tokens.
    GithubApp,
    /// AWS: the value is `ACCESS_KEY_ID:SECRET_ACCESS_KEY`; the hub signs each request (SigV4),
    /// with temporary credentials from a role when one is set.
    Aws,
}

impl Kind {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "bearer" | "" => Ok(Kind::Bearer),
            "header" => Ok(Kind::Header),
            "basic" => Ok(Kind::Basic),
            "query" => Ok(Kind::Query),
            "oauth" | "oauth2" => Ok(Kind::Oauth),
            "github-app" | "githubapp" | "github_app" => Ok(Kind::GithubApp),
            "aws" => Ok(Kind::Aws),
            other => Err(format!("'{other}' is not a way to send a credential; use bearer, header, basic, query, oauth, github-app or aws")),
        }
    }
    /// The hub makes short-lived credentials from this kind's value, and hands out only those.
    pub fn mints(self) -> bool {
        matches!(self, Kind::Oauth | Kind::GithubApp | Kind::Aws)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// The header name (header), query parameter (query) or username (basic).
    #[serde(default)]
    pub field: String,
    /// URL prefixes the value may be sent to, such as `https://api.github.com`.
    pub destinations: Vec<String>,
    #[serde(default)]
    pub note: String,
    /// The value's last four characters, so an admin can tell keys apart; empty for short values.
    #[serde(default)]
    pub hint: String,
    /// The value, encrypted with the hub's sealing key (see `seal`).
    pub sealed: String,
    pub created_at: i64,
    pub created_by: String,
    pub updated_at: i64,
    /// What a minting kind needs besides its secret, none of it secret: `tokenUrl`, `clientId`,
    /// `scope`, `audience`, `auth` (oauth); `appId`, `installationId`, `apiUrl` (github-app);
    /// `region`, `service`, `roleArn`, `externalId`, `sessionSeconds` (aws).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub config: Map<String, Value>,
}

impl Credential {
    /// Everything but the value.
    pub fn public(&self) -> Value {
        json!({"id": self.id, "name": self.name, "kind": self.kind, "field": self.field, "destinations": self.destinations, "note": self.note, "hint": self.hint, "createdAt": self.created_at, "createdBy": self.created_by, "updatedAt": self.updated_at, "config": self.config})
    }
    pub fn setting(&self, key: &str) -> Option<&str> {
        self.config.get(key).and_then(Value::as_str).filter(|value| !value.is_empty())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Never,
}

impl Decision {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "allow" | "" => Ok(Decision::Allow),
            "ask" => Ok(Decision::Ask),
            "never" | "deny" => Ok(Decision::Never),
            other => Err(format!("'{other}' is not a decision; use allow, ask or never")),
        }
    }
}

/// The people a rule covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Who {
    Everyone,
    Team(String),
    /// A person's ID.
    Person(String),
}

impl TryFrom<String> for Who {
    type Error = String;
    fn try_from(text: String) -> Result<Self, String> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("everyone") {
            return Ok(Who::Everyone);
        }
        if let Some(team) = text.strip_prefix("team:") {
            return team_name(team).map(Who::Team);
        }
        if let Some(person) = text.strip_prefix("person:").filter(|id| !id.is_empty() && id.len() <= 64) {
            return Ok(Who::Person(person.to_owned()));
        }
        Err("A rule is for everyone, team:NAME or a person".into())
    }
}

impl From<Who> for String {
    fn from(who: Who) -> String {
        match who {
            Who::Everyone => "everyone".into(),
            Who::Team(team) => format!("team:{team}"),
            Who::Person(id) => format!("person:{id}"),
        }
    }
}

impl Who {
    pub fn covers(&self, person: &Person) -> bool {
        match self {
            Who::Everyone => true,
            Who::Team(team) => person.in_team(team),
            Who::Person(id) => *id == person.id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub id: String,
    pub credential: String,
    pub who: Who,
    /// Upper-case HTTP methods; empty means any.
    #[serde(default)]
    pub methods: Vec<String>,
    /// A path prefix inside the credential's destinations, such as `/repos/acme`; empty means any.
    #[serde(default)]
    pub path: String,
    pub decision: Decision,
    /// The person may also ask to see the value itself; an approver always decides that.
    #[serde(default)]
    pub reveal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// At most this many uses an hour per person go through at once; past it, an approver decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default)]
    pub note: String,
    pub created_at: i64,
    pub created_by: String,
}

impl Rule {
    pub fn live(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
    fn applies(&self, person: &Person, credential: &str, method: &str, path: &str, now: i64) -> bool {
        self.credential == credential
            && self.live(now)
            && self.who.covers(person)
            && (self.methods.is_empty() || self.methods.iter().any(|own| own == method))
            && within_path(path, &self.path)
    }
}

/// An allow rule with an hourly limit that let a request through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub rule: String,
    pub per_hour: u32,
    pub path: String,
}

/// What the hub does with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// At once; `limits` lists the matching allow rules when every one of them has an hourly
    /// limit (empty when one has none), so the hub can count uses against them.
    Allow { limits: Vec<Limit> },
    /// An approver decides; `path` is the asking rule's path, which an approval for an hour widens to.
    Ask { path: String },
    Refused(String),
}

/// The decision for `person` sending `method path` with `credential`.
///
/// Servers disagree about `;parameters` in a segment: some keep them (`/admin;x` is its own
/// path), others drop them (`/admin;x/users` is `/admin/users`). So a `never` rule refuses a
/// path it covers either way, and any other rule counts only when it covers both readings.
pub fn evaluate(rules: &[Rule], person: &Person, credential: &Credential, method: &str, path: &str, now: i64) -> Verdict {
    let bare = without_parameters(path);
    let readings = [path, bare.as_str()];
    if rules.iter().any(|rule| rule.decision == Decision::Never && readings.iter().any(|reading| rule.applies(person, &credential.id, method, reading, now))) {
        return Verdict::Refused(format!("A rule forbids {} {method} {path} with {}", person.username, credential.name));
    }
    let matching: Vec<&Rule> = rules.iter().filter(|rule| readings.iter().all(|reading| rule.applies(person, &credential.id, method, reading, now))).collect();
    let allowing: Vec<&&Rule> = matching.iter().filter(|rule| rule.decision == Decision::Allow).collect();
    if !allowing.is_empty() {
        let limits = if allowing.iter().any(|rule| rule.limit.is_none()) { Vec::new() } else { allowing.iter().map(|rule| Limit { rule: rule.id.clone(), per_hour: rule.limit.unwrap_or_default(), path: rule.path.clone() }).collect() };
        return Verdict::Allow { limits };
    }
    if let Some(rule) = matching.iter().find(|rule| rule.decision == Decision::Ask) {
        return Verdict::Ask { path: rule.path.clone() };
    }
    Verdict::Refused(format!("No rule lets {} use {} for {method} {path}. Ask an Access Grid admin for a rule.", person.username, credential.name))
}

/// Whether `person` may ask to see `credential`'s value. An approver still decides each time.
pub fn may_reveal(rules: &[Rule], person: &Person, credential: &Credential, now: i64) -> Result<(), String> {
    let covering = || rules.iter().filter(|rule| rule.credential == credential.id && rule.live(now) && rule.who.covers(person));
    if covering().any(|rule| rule.decision == Decision::Never && rule.methods.is_empty() && rule.path.is_empty()) {
        return Err(format!("A rule forbids {} from using {}", person.username, credential.name));
    }
    if covering().any(|rule| rule.reveal && rule.decision != Decision::Never) {
        return Ok(());
    }
    Err(format!("No rule lets {} see the value of {}; agents use it through company_request instead", person.username, credential.name))
}

/// Whether `path` lies under `prefix` on a segment boundary: `/repos/acme` covers `/repos/acme`
/// and `/repos/acme/x`, never `/repos/acmecorp`.
pub fn within_path(path: &str, prefix: &str) -> bool {
    let (path, prefix) = (canonical(path), canonical(prefix));
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/'))
}

/// A path as servers may read it, for matching only: percent-encoded printable characters
/// decoded (`/%61dmin` is `/admin`, `/users/%40me` is `/users/@me`) and letters in lower case, so
/// neither spelling slips past a `never` rule on a server that ignores case.
pub fn canonical(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len() {
            // Every printable escape a server decodes (`%40me` is `@me`), but not the ones that
            // change the path's shape: those are refused as ambiguous before a request gets here.
            if let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok()).filter(|byte| (0x21..=0x7e).contains(byte) && !b"/\\?#%;".contains(byte)) {
                out.push(byte.to_ascii_lowercase());
                index += 3;
                continue;
            }
        }
        out.push(bytes[index].to_ascii_lowercase());
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `path` with each segment's `;parameters` dropped, as Tomcat and Spring read it:
/// `/admin;x/users` is `/admin/users`. A segment that was only parameters (`/;x/admin`) goes
/// with them, as those servers also merge the slashes around it.
pub fn without_parameters(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        let bare = segment.split(';').next().unwrap_or_default();
        if index == 0 {
            out.push_str(bare);
        } else if !(bare.is_empty() && !segment.is_empty()) {
            out.push('/');
            out.push_str(bare);
        }
    }
    out
}

/// A dot segment, also with path parameters some servers drop (`..;x`).
pub fn dot_segment(segment: &str) -> bool {
    matches!(segment.split(';').next().unwrap_or_default(), "." | "..")
}

/// A rule's path: empty, or `/` followed by plain segments, without a query or dot segments.
pub fn rule_path(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text == "/" {
        return Ok(String::new());
    }
    let invalid = || "A rule's path is like /repos/acme: it starts with /, has no ?, # or .. and no encoded slashes".to_owned();
    if !text.starts_with('/') || text.len() > 512 || text.contains(['?', '#', '\\', ' ']) || text.contains("//") || text.chars().any(char::is_control) {
        return Err(invalid());
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || lower.contains("%2e") || text.split('/').any(dot_segment) {
        return Err(invalid());
    }
    Ok(text.trim_end_matches('/').to_owned())
}

/// Upper-case, known HTTP methods without repeats; empty means any.
pub fn methods(list: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for method in list.iter().flat_map(|item| item.split(',')).map(|method| method.trim().to_ascii_uppercase()).filter(|method| !method.is_empty()) {
        if method == "ANY" || method == "*" {
            return Ok(Vec::new());
        }
        if !METHODS.contains(&method.as_str()) {
            return Err(format!("{method} is not an HTTP method Access Grid sends; use {}", METHODS.join(", ")));
        }
        if !out.contains(&method) {
            out.push(method);
        }
    }
    Ok(out)
}

/// 3–32 lower-case letters, digits, dots, dashes or underscores, starting with a letter or digit.
pub fn username(text: &str) -> Result<String, String> {
    let name = text.trim().to_ascii_lowercase();
    let fits = (3..=32).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) && name.starts_with(|c: char| c.is_ascii_alphanumeric());
    fits.then_some(name).ok_or_else(|| "A username is 3–32 letters, digits, dots, dashes or underscores, starting with a letter or digit".into())
}

/// A team: 1–40 printable characters without `:` or `,`.
pub fn team_name(text: &str) -> Result<String, String> {
    let name = text.trim();
    if name.is_empty() || name.chars().count() > 40 || name.contains([':', ',']) || name.chars().any(char::is_control) {
        return Err("A team name is 1–40 characters without : or ,".into());
    }
    Ok(name.to_owned())
}

pub fn teams(list: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for team in list.iter().flat_map(|item| item.split(',')).filter(|team| !team.trim().is_empty()) {
        let team = team_name(team)?;
        if !out.iter().any(|own| own.eq_ignore_ascii_case(&team)) {
            out.push(team);
        }
    }
    if out.len() > MAX_TEAMS {
        return Err(format!("A person can be in at most {MAX_TEAMS} teams"));
    }
    Ok(out)
}

/// The header name, query parameter or username a credential kind needs.
pub fn field(kind: Kind, text: &str) -> Result<String, String> {
    let text = text.trim();
    match kind {
        Kind::Bearer | Kind::Oauth | Kind::GithubApp | Kind::Aws => Ok(String::new()),
        Kind::Header => {
            let lower = text.to_ascii_lowercase();
            if text.is_empty() || text.len() > 64 || !text.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')) {
                return Err("Name the header the value goes in, such as X-Api-Key".into());
            }
            if crate::access::forward::RESERVED_HEADERS.contains(&lower.as_str()) {
                return Err(format!("{text} cannot carry a credential; use bearer or basic for Authorization"));
            }
            Ok(text.to_owned())
        }
        Kind::Query => {
            if text.is_empty() || text.len() > 64 || !text.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')) {
                return Err("Name the query parameter the value goes in, such as api_key".into());
            }
            Ok(text.to_owned())
        }
        Kind::Basic => {
            if text.is_empty() || text.len() > 128 || text.contains(':') || text.chars().any(char::is_control) {
                return Err("Give the username sent with the value, without :".into());
            }
            Ok(text.to_owned())
        }
    }
}

/// A credential value for its kind: one line of up to 8 KiB, a GitHub App's PEM private key, or
/// AWS's `ACCESS_KEY_ID:SECRET_ACCESS_KEY`.
pub fn value(kind: Kind, text: &str) -> Result<(), String> {
    if kind == Kind::GithubApp {
        if text.len() > MAX_VALUE || !text.contains("PRIVATE KEY-----") || text.contains('\0') {
            return Err("Paste the GitHub App's private key: the whole .pem file GitHub gave you".into());
        }
        return Ok(());
    }
    if text.is_empty() || text.len() > 8192 || text.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err("A credential value is one line of 1–8192 characters".into());
    }
    if kind == Kind::Aws {
        let (id, secret) = text.split_once(':').ok_or("Give the AWS key as ACCESS_KEY_ID:SECRET_ACCESS_KEY")?;
        if !(16..=128).contains(&id.len()) || !id.bytes().all(|c| c.is_ascii_alphanumeric()) || secret.len() < 16 || secret.len() > 256 {
            return Err("Give the AWS key as ACCESS_KEY_ID:SECRET_ACCESS_KEY".into());
        }
    }
    Ok(())
}

/// What a minting kind needs besides its secret, checked; other kinds take none.
pub fn config(kind: Kind, given: &Value) -> Result<Map<String, Value>, String> {
    let text = |key: &str| given.get(key).and_then(Value::as_str).map(str::trim).filter(|text| !text.is_empty()).map(str::to_owned);
    let printable = |value: &str, max: usize| value.len() <= max && !value.chars().any(|c| c.is_control() || c.is_whitespace());
    let mut out = Map::new();
    match kind {
        Kind::Bearer | Kind::Header | Kind::Basic | Kind::Query => {}
        Kind::Oauth => {
            let token_url = text("tokenUrl").ok_or("Give the token URL, such as https://login.example.com/oauth2/token")?;
            crate::access::forward::token_url(&token_url)?;
            let client_id = text("clientId").filter(|id| printable(id, 256)).ok_or("Give the client ID")?;
            out.insert("tokenUrl".into(), json!(token_url));
            out.insert("clientId".into(), json!(client_id));
            for key in ["scope", "audience"] {
                if let Some(value) = text(key) {
                    if value.len() > 1024 || value.chars().any(char::is_control) {
                        return Err(format!("The {key} is one line of at most 1024 characters"));
                    }
                    out.insert(key.into(), json!(value));
                }
            }
            match text("auth").as_deref() {
                None | Some("basic") => out.insert("auth".into(), json!("basic")),
                Some("body") => out.insert("auth".into(), json!("body")),
                Some(_) => return Err("auth is basic (client ID and secret in the Authorization header) or body".into()),
            };
        }
        Kind::GithubApp => {
            let digits = |key: &str, what: &str| text(key).filter(|value| value.len() <= 20 && value.bytes().all(|c| c.is_ascii_digit())).ok_or_else(|| format!("Give the GitHub App's {what} (digits)"));
            let app = text("appId").filter(|value| value.len() <= 64 && value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.')).ok_or("Give the GitHub App's client ID (Iv23…) or its numeric App ID")?;
            out.insert("appId".into(), json!(app));
            out.insert("installationId".into(), json!(digits("installationId", "installation ID")?));
            let api = text("apiUrl").unwrap_or_else(|| "https://api.github.com".into());
            crate::access::forward::token_url(&api)?;
            out.insert("apiUrl".into(), json!(api.trim_end_matches('/')));
        }
        Kind::Aws => {
            let region = text("region").filter(|region| printable(region, 32) && region.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')).ok_or("Give the AWS region, such as us-east-1")?;
            out.insert("region".into(), json!(region));
            if let Some(service) = text("service") {
                if !printable(&service, 64) || !service.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
                    return Err("The AWS service is its signing name, such as s3 or execute-api".into());
                }
                out.insert("service".into(), json!(service));
            }
            if let Some(role) = text("roleArn") {
                if !role.starts_with("arn:aws") || !role.contains(":role/") || !printable(&role, 2048) {
                    return Err("The role is its ARN, such as arn:aws:iam::123456789012:role/agents".into());
                }
                out.insert("roleArn".into(), json!(role));
            }
            if let Some(sts) = text("stsUrl") {
                out.insert("stsUrl".into(), json!(crate::access::forward::token_url(&sts)?));
            }
            if let Some(external) = text("externalId") {
                if !printable(&external, 1224) {
                    return Err("The external ID is one word".into());
                }
                out.insert("externalId".into(), json!(external));
            }
            let seconds = match given.get("sessionSeconds") {
                None | Some(Value::Null) => 3600,
                Some(value) => value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).filter(|seconds| (900..=43_200).contains(seconds)).ok_or("sessionSeconds is between 900 and 43200")?,
            };
            out.insert("sessionSeconds".into(), json!(seconds));
        }
    }
    Ok(out)
}

/// An email the identity provider names a person by.
pub fn email(text: &str) -> Result<Option<String>, String> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Ok(None);
    }
    if text.len() > 254 || text.chars().any(|c| c.is_control() || c.is_whitespace()) || text.split('@').count() != 2 || text.starts_with('@') || text.ends_with('@') {
        return Err("Give the email the company's identity provider uses for them".into());
    }
    Ok(Some(text))
}

/// Single sign-on through the company's identity provider (OpenID Connect): a public native app
/// with PKCE, so no client secret exists. The hub checks the provider's ID tokens against keys
/// it fetches from the issuer itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sso {
    /// `https://login.microsoftonline.com/TENANT/v2.0`, `https://acme.okta.com`, …
    pub issuer: String,
    pub client_id: String,
    /// The claim matched against people's emails (or usernames): `email` unless set otherwise.
    #[serde(default = "default_claim")]
    pub claim: String,
    /// Passwords no longer sign anyone in, except the person who runs the grid, so it can never
    /// lock itself out when the provider is down.
    #[serde(default)]
    pub passwordless: bool,
    /// The loopback port people's computers wait on for the browser. Unset, any free port is
    /// used, which Entra allows; providers that match the redirect address exactly, port
    /// included (Okta), need one fixed port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<u16>,
}

fn default_claim() -> String {
    "email".into()
}

impl Sso {
    pub fn checked(given: &Value) -> Result<Sso, String> {
        let text = |key: &str| given.get(key).and_then(Value::as_str).unwrap_or_default().trim().trim_end_matches('/').to_owned();
        let issuer = text("issuer");
        let usable = crate::access::forward::token_url(&issuer).is_ok() && !issuer.contains(['?', '#']) && issuer.len() <= 512;
        if !usable {
            return Err("The issuer is the provider's https:// address, as its discovery document names it".into());
        }
        let client_id = text("clientId");
        if client_id.is_empty() || client_id.len() > 256 || client_id.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("Give the client ID of the app registered at the provider".into());
        }
        let claim = given.get("claim").and_then(Value::as_str).map(str::trim).filter(|claim| !claim.is_empty()).unwrap_or("email");
        if claim.len() > 64 || !claim.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err("The claim name is letters, digits and underscores".into());
        }
        let redirect_port = match given.get("redirectPort") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) if text.trim().is_empty() => None,
            Some(port) => Some(port.as_u64().or_else(|| port.as_str().and_then(|text| text.trim().parse().ok())).and_then(|port| u16::try_from(port).ok()).filter(|port| *port >= 1024).ok_or("The sign-in port is a number from 1024 to 65535")?),
        };
        Ok(Sso { issuer, client_id, claim: claim.into(), passwordless: given.get("passwordless").and_then(Value::as_bool).unwrap_or(false), redirect_port })
    }
}

/// Grid-wide settings an admin chooses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// People must sign in with a second factor (two-step codes or the identity provider) before
    /// they or their agents use, see or manage anything.
    #[serde(default)]
    pub require_two_step: bool,
}

/// The last four characters of a value long enough that they reveal little.
pub fn hint(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() < 16 {
        return String::new();
    }
    chars[chars.len() - 4..].iter().collect()
}

/// The hash a person's derived key is kept as.
pub fn key_hash(key: &str) -> String {
    digest("access-person", key)
}


/// Compares two hashes without an early exit on the first differing byte.
pub fn same_hash(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut difference = (a.len() ^ b.len()) as u8;
    for index in 0..a.len().max(b.len()) {
        difference |= a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: &str, teams: &[&str]) -> Person {
        Person { id: id.into(), username: id.into(), name: id.into(), permission: Permission::Member, teams: teams.iter().map(|team| team.to_string()).collect(), salt: String::new(), key_hash: String::new(), created_at: 0, last_seen_at: None, email: None, sso_subject: None, two_step: None, generation: 0, devices: Vec::new() }
    }

    fn credential() -> Credential {
        Credential { id: "cred-1".into(), name: "GitHub".into(), kind: Kind::Bearer, field: String::new(), destinations: vec!["https://api.github.com".into()], note: String::new(), hint: String::new(), sealed: String::new(), created_at: 0, created_by: String::new(), updated_at: 0, config: Map::new() }
    }

    fn rule(who: Who, methods: &[&str], path: &str, decision: Decision) -> Rule {
        Rule { id: "rule".into(), credential: "cred-1".into(), who, methods: methods.iter().map(|m| m.to_string()).collect(), path: path.into(), decision, reveal: false, expires_at: None, limit: None, note: String::new(), created_at: 0, created_by: String::new() }
    }

    #[test]
    fn never_wins_then_allow_then_ask_and_nothing_matching_is_refused() {
        let (ada, credential) = (person("ada", &["Research"]), credential());
        assert!(matches!(evaluate(&[], &ada, &credential, "GET", "/user", 0), Verdict::Refused(_)));
        let ask = rule(Who::Everyone, &[], "", Decision::Ask);
        assert_eq!(evaluate(std::slice::from_ref(&ask), &ada, &credential, "GET", "/user", 0), Verdict::Ask { path: String::new() });
        let allow = rule(Who::Team("research".into()), &["GET"], "/repos/acme", Decision::Allow);
        assert_eq!(evaluate(&[ask.clone(), allow.clone()], &ada, &credential, "GET", "/repos/acme/app", 0), Verdict::Allow { limits: Vec::new() });
        assert_eq!(evaluate(&[ask.clone(), allow.clone()], &ada, &credential, "POST", "/repos/acme/app", 0), Verdict::Ask { path: String::new() }, "the allow rule is GET only");
        assert_eq!(evaluate(&[ask.clone(), allow.clone()], &ada, &credential, "GET", "/repos/acmecorp", 0), Verdict::Ask { path: String::new() }, "paths match on segment boundaries");
        let never = rule(Who::Person("ada".into()), &["DELETE"], "", Decision::Never);
        assert!(matches!(evaluate(&[ask.clone(), allow, never], &ada, &credential, "DELETE", "/repos/acme/app", 0), Verdict::Refused(_)));
        // Another spelling of the same path still meets the never rule.
        let admin = rule(Who::Everyone, &[], "/admin", Decision::Never);
        for spelling in ["/admin", "/ADMIN/users", "/%61dmin", "/Ad%6Din/x"] {
            assert!(matches!(evaluate(&[ask.clone(), admin.clone()], &ada, &credential, "GET", spelling, 0), Verdict::Refused(_)), "{spelling}");
        }
        // Encoded punctuation a server decodes meets the rule too.
        let me = rule(Who::Everyone, &[], "/users/@me", Decision::Never);
        for spelling in ["/users/@me", "/users/%40me", "/users/%40ME/keys"] {
            assert!(matches!(evaluate(&[ask.clone(), me.clone()], &ada, &credential, "GET", spelling, 0), Verdict::Refused(_)), "{spelling}");
        }
        assert!(rule_path("/a/..;x/b").is_err());
    }

    #[test]
    fn path_parameters_do_not_slip_past_a_never_rule_or_widen_an_allow_rule() {
        let (ada, credential) = (person("ada", &[]), credential());
        let everything = rule(Who::Everyone, &[], "", Decision::Allow);
        let admin = rule(Who::Everyone, &[], "/admin", Decision::Never);
        // Servers such as Tomcat and Spring drop a segment's `;parameters`, so each of these is /admin there.
        // A segment of only parameters goes too, with the slash beside it: `/;/admin` is `/admin`.
        for spelling in ["/admin;x", "/admin;x/users", "/admin;/users", "/ADMIN;jsessionid=1/users", "/;/admin", "/;x/admin/keys"] {
            assert!(matches!(evaluate(&[everything.clone(), admin.clone()], &ada, &credential, "GET", spelling, 0), Verdict::Refused(_)), "{spelling}");
        }
        // An allow rule counts only when it covers the path both as written and without parameters:
        // a server that keeps `;` literally reads `acme;v=1` as another repository.
        let acme = rule(Who::Everyone, &[], "/repos/acme", Decision::Allow);
        assert!(matches!(evaluate(std::slice::from_ref(&acme), &ada, &credential, "GET", "/repos/acme;v=1/app", 0), Verdict::Refused(_)));
        assert_eq!(evaluate(std::slice::from_ref(&acme), &ada, &credential, "GET", "/repos/acme/app;v=1", 0), Verdict::Allow { limits: Vec::new() });
    }

    #[test]
    fn a_decoy_salt_is_shaped_like_a_real_one_and_cannot_be_worked_out() {
        use crate::access::seal::{new_key, Sealer};
        // A real salt is a UUID v4 in hex: version 4 at index 12, and 8, 9, a or b at index 16.
        let shaped = |salt: &str| salt.len() == 32 && salt.bytes().all(|c| c.is_ascii_hexdigit()) && salt.as_bytes()[12] == b'4' && b"89ab".contains(&salt.as_bytes()[16]);
        for _ in 0..32 {
            assert!(shaped(&crate::password::new_salt()));
        }
        let (hub, other) = (Sealer::new(&new_key().unwrap()).unwrap(), Sealer::new(&new_key().unwrap()).unwrap());
        for name in 0..256 {
            let decoy = hub.decoy_salt(&format!("nobody{name}"));
            assert!(shaped(&decoy), "{decoy}");
        }
        assert_eq!(hub.decoy_salt("nobody"), hub.decoy_salt("nobody"));
        // Keyed with the hub's sealing key, which never leaves its computer: knowing the grid's ID
        // and the name (both public) is not enough to tell a decoy from a real salt.
        assert_ne!(hub.decoy_salt("nobody"), other.decoy_salt("nobody"));
        assert_ne!(hub.decoy_salt("nobody"), crate::password::shaped_like_a_salt(&digest("access-person-salt", "access-1:nobody")));
    }

    #[test]
    fn rules_cover_only_their_people_and_lapse_when_they_expire() {
        let credential = credential();
        let mut allow = rule(Who::Team("Ops".into()), &[], "", Decision::Allow);
        assert!(matches!(evaluate(&[allow.clone()], &person("bob", &["Research"]), &credential, "GET", "/", 0), Verdict::Refused(_)));
        assert_eq!(evaluate(&[allow.clone()], &person("cy", &["ops"]), &credential, "GET", "/", 0), Verdict::Allow { limits: Vec::new() });
        allow.expires_at = Some(100);
        assert_eq!(evaluate(&[allow.clone()], &person("cy", &["ops"]), &credential, "GET", "/", 99), Verdict::Allow { limits: Vec::new() });
        assert!(matches!(evaluate(&[allow], &person("cy", &["ops"]), &credential, "GET", "/", 100), Verdict::Refused(_)));
    }

    #[test]
    fn seeing_a_value_needs_a_rule_that_says_so_and_no_blanket_never() {
        let (ada, credential) = (person("ada", &[]), credential());
        let mut allow = rule(Who::Everyone, &[], "", Decision::Allow);
        assert!(may_reveal(&[allow.clone()], &ada, &credential, 0).is_err());
        allow.reveal = true;
        assert!(may_reveal(&[allow.clone()], &ada, &credential, 0).is_ok());
        let narrow_never = rule(Who::Everyone, &["DELETE"], "", Decision::Never);
        assert!(may_reveal(&[allow.clone(), narrow_never], &ada, &credential, 0).is_ok());
        let never = rule(Who::Person("ada".into()), &[], "", Decision::Never);
        assert!(may_reveal(&[allow, never], &ada, &credential, 0).is_err());
    }

    #[test]
    fn names_paths_methods_and_fields_are_checked() {
        assert_eq!(rule_path(" /repos/acme/ ").unwrap(), "/repos/acme");
        assert_eq!(rule_path("/").unwrap(), "");
        for bad in ["repos", "/a/../b", "/a?b", "/a%2Fb", "/a//b", "/a/%2e%2e/b"] {
            assert!(rule_path(bad).is_err(), "{bad}");
        }
        assert_eq!(methods(&["get, Post".into(), "GET".into()]).unwrap(), ["GET", "POST"]);
        assert!(methods(&["any".into()]).unwrap().is_empty());
        assert!(methods(&["TRACE".into()]).is_err());
        assert_eq!(username(" Ada.L ").unwrap(), "ada.l");
        assert!(username("a").is_err() && username("-ada").is_err());
        assert_eq!(teams(&["Ops, research".into(), "ops".into()]).unwrap(), ["Ops", "research"]);
        assert!(team_name("a:b").is_err());
        assert_eq!(field(Kind::Header, "X-Api-Key").unwrap(), "X-Api-Key");
        assert!(field(Kind::Header, "Authorization").is_err() && field(Kind::Header, "Host").is_err() && field(Kind::Header, "X Key").is_err());
        assert!(field(Kind::Basic, "a:b").is_err());
        assert_eq!(field(Kind::Bearer, "ignored").unwrap(), "");
        assert!(value(Kind::Bearer, "line\nbreak").is_err() && value(Kind::Bearer, "").is_err() && value(Kind::Bearer, "sk-123").is_ok());
        assert!(value(Kind::Aws, "AKIAEXAMPLE000000000:wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY").is_ok() && value(Kind::Aws, "short:x").is_err());
        assert!(value(Kind::GithubApp, "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n").is_ok() && value(Kind::GithubApp, "ghp_x").is_err());
        assert_eq!(serde_json::to_value(Kind::GithubApp).unwrap(), json!("github-app"));
        assert_eq!(config(Kind::Oauth, &json!({"tokenUrl": "https://login.example.com/token", "clientId": "app"})).unwrap()["auth"], "basic");
        assert!(config(Kind::Oauth, &json!({"tokenUrl": "http://login.example.com/token", "clientId": "app"})).is_err());
        assert!(config(Kind::GithubApp, &json!({"appId": "12", "installationId": "x"})).is_err());
        assert_eq!(config(Kind::GithubApp, &json!({"appId": "Iv23liAbc.12", "installationId": "99"})).unwrap()["appId"], "Iv23liAbc.12");
        assert!(config(Kind::GithubApp, &json!({"appId": "Iv23 li", "installationId": "99"})).is_err());
        assert_eq!(config(Kind::Aws, &json!({"region": "eu-west-1", "roleArn": "arn:aws:iam::123456789012:role/agents"})).unwrap()["sessionSeconds"], 3600);
        assert!(config(Kind::Aws, &json!({"region": "EU West"})).is_err());
        assert_eq!(email(" Ada@Acme.Example ").unwrap().as_deref(), Some("ada@acme.example"));
        assert!(email("not an email").is_err() && email("").unwrap().is_none());
        assert_eq!(Sso::checked(&json!({"issuer": "https://acme.okta.com/", "clientId": "app"})).unwrap().issuer, "https://acme.okta.com");
        assert!(Sso::checked(&json!({"issuer": "http://acme.okta.com", "clientId": "app"})).is_err());
        assert_eq!(Sso::checked(&json!({"issuer": "https://acme.okta.com", "clientId": "app", "redirectPort": "8765"})).unwrap().redirect_port, Some(8765));
        assert_eq!(Sso::checked(&json!({"issuer": "https://acme.okta.com", "clientId": "app", "redirectPort": ""})).unwrap().redirect_port, None);
        assert!(Sso::checked(&json!({"issuer": "https://acme.okta.com", "clientId": "app", "redirectPort": 80})).is_err());
        assert_eq!(hint("sk-live-0123456789abcd"), "abcd");
        assert_eq!(hint("short"), "");
        assert!(serde_json::from_value::<Who>(json!("team:")).is_err());
        assert_eq!(serde_json::to_value(Who::Team("Ops".into())).unwrap(), json!("team:Ops"));
        assert!(Permission::parse("root").is_err() && Permission::parse("Admin").unwrap().manages());
    }
}
