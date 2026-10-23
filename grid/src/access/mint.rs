//! Short-lived credentials the hub makes from a long-lived secret, so even what it sends, or
//! hands out on an approved reveal, expires on its own: OAuth 2 access tokens (client
//! credentials), GitHub App installation tokens, and AWS temporary keys (STS). The long-lived
//! secret never leaves the hub; for AWS without a role, requests are signed with it in place.
use super::{
    forward::{self, Auth, Prepared},
    policy::{Credential, Kind},
    sigv4::{self, Keys},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

/// A token is made again when less than this is left of it.
const MARGIN: i64 = 5 * 60;

/// Tokens the hub made, by credential (and person, for AWS roles), until they near their end.
#[derive(Default)]
pub struct Cache {
    entries: Mutex<HashMap<String, (Prepared, i64)>>,
}

impl Cache {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, (Prepared, i64)>> {
        self.entries.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn get(&self, key: &str) -> Option<Prepared> {
        self.lock().get(key).filter(|(_, until)| *until - MARGIN > crate::now()).map(|(prepared, _)| prepared.clone())
    }
    fn put(&self, key: String, prepared: Prepared, until: i64) {
        let mut entries = self.lock();
        let now = crate::now();
        entries.retain(|_, (_, at)| *at > now);
        entries.insert(key, (prepared, until));
    }
    /// Drops what was made from a credential that changed or went.
    pub fn forget(&self, credential: &str) {
        self.lock().retain(|key, _| key.split(':').next() != Some(credential));
    }
    pub fn forget_all(&self) {
        self.lock().clear();
    }
}

fn hide_in(message: String, secret: &str) -> String {
    if secret.len() >= 4 {
        message.replace(secret, "[hidden by Access Grid]")
    } else {
        message
    }
}

fn encode(text: &str) -> String {
    text.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn form(fields: &[(&str, &str)]) -> Vec<u8> {
    fields.iter().map(|(key, value)| format!("{}={}", encode(key), encode(value))).collect::<Vec<_>>().join("&").into_bytes()
}

/// An OAuth 2 access token for the client credentials, and when it lapses.
async fn oauth(credential: &Credential, secret: &str) -> Result<(String, i64), String> {
    let url = credential.setting("tokenUrl").ok_or("This OAuth credential has no token URL")?;
    let client = credential.setting("clientId").ok_or("This OAuth credential has no client ID")?;
    let mut fields = vec![("grant_type", "client_credentials")];
    for key in ["scope", "audience"] {
        if let Some(value) = credential.setting(key) {
            fields.push((key, value));
        }
    }
    let mut headers = vec![("content-type", "application/x-www-form-urlencoded".to_owned()), ("accept", "application/json".to_owned())];
    if credential.setting("auth") == Some("body") {
        fields.push(("client_id", client));
        fields.push(("client_secret", secret));
    } else {
        headers.push(("authorization", format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", encode(client), encode(secret))))));
    }
    let answer = forward::fetch("POST", url, &headers, Some(form(&fields))).await?;
    if !answer.ok() {
        return Err(hide_in(format!("The token endpoint refused to issue a token ({})", answer.said()), secret));
    }
    let json = answer.json();
    let token = json["access_token"].as_str().filter(|token| !token.is_empty()).ok_or("The token endpoint sent no access_token")?.to_owned();
    let lifetime = json["expires_in"].as_i64().or_else(|| json["expires_in"].as_str().and_then(|text| text.parse().ok())).unwrap_or(3600).clamp(60, 86_400);
    Ok((token, crate::now() + lifetime))
}

/// The DER inside a PEM block, and whether it is PKCS#8 (`PRIVATE KEY`) rather than PKCS#1.
fn pem(text: &str) -> Result<(Vec<u8>, bool), String> {
    let invalid = || "The GitHub App's private key is not a PEM private key".to_owned();
    let pkcs8 = text.contains("-----BEGIN PRIVATE KEY-----");
    let rsa = text.contains("-----BEGIN RSA PRIVATE KEY-----");
    if !pkcs8 && !rsa {
        return Err(invalid());
    }
    let body: String = text.lines().filter(|line| !line.starts_with("-----")).map(str::trim).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body).map_err(|_| invalid())?;
    Ok((der, pkcs8))
}

/// Checks that a GitHub App private key can sign, before it is saved.
pub fn check_github_key(text: &str) -> Result<(), String> {
    rsa(text).map(|_| ())
}

fn rsa(text: &str) -> Result<ring::signature::RsaKeyPair, String> {
    let (der, pkcs8) = pem(text)?;
    let pair = if pkcs8 { ring::signature::RsaKeyPair::from_pkcs8(&der) } else { ring::signature::RsaKeyPair::from_der(&der) };
    pair.map_err(|_| "The GitHub App's private key is not an RSA key ring can use (2048 bits or more)".to_owned())
}

/// The JWT a GitHub App signs to ask for an installation token: RS256, ten minutes at most.
fn github_jwt(app_id: &str, key: &str, now: i64) -> Result<String, String> {
    let pair = rsa(key)?;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(json!({"iat": now - 60, "exp": now + 540, "iss": app_id}).to_string());
    let message = format!("{header}.{claims}");
    let mut signature = vec![0u8; pair.public().modulus_len()];
    pair.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), message.as_bytes(), &mut signature).map_err(|_| "Cannot sign with the GitHub App's private key")?;
    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// A GitHub App installation token, and when it lapses (an hour after it was made).
async fn github(credential: &Credential, key: &str) -> Result<(String, i64), String> {
    let app = credential.setting("appId").ok_or("This GitHub App credential has no App ID")?;
    let installation = credential.setting("installationId").ok_or("This GitHub App credential has no installation ID")?;
    let api = credential.setting("apiUrl").unwrap_or("https://api.github.com");
    let jwt = github_jwt(app, key, crate::now())?;
    let headers = [("authorization", format!("Bearer {jwt}")), ("accept", "application/vnd.github+json".to_owned())];
    let answer = forward::fetch("POST", &format!("{api}/app/installations/{installation}/access_tokens"), &headers, None).await?;
    if !answer.ok() {
        return Err(format!("GitHub refused to make an installation token ({})", answer.said()));
    }
    let json = answer.json();
    let token = json["token"].as_str().filter(|token| !token.is_empty()).ok_or("GitHub sent no installation token")?.to_owned();
    let expires = json["expires_at"].as_str().and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok()).map(|at| at.timestamp()).unwrap_or(crate::now() + 3600);
    Ok((token, expires))
}

fn aws_keys(value: &str) -> Result<Keys, String> {
    let (access_key, secret_key) = value.split_once(':').ok_or("The AWS credential's value is not ACCESS_KEY_ID:SECRET_ACCESS_KEY")?;
    Ok(Keys { access_key: access_key.to_owned(), secret_key: secret_key.to_owned(), session_token: None })
}

/// Calls STS with the long-lived key for temporary keys: AssumeRole when the credential names a
/// role (the session is named after the person, so AWS's own logs say who), else GetSessionToken.
async fn sts(credential: &Credential, keys: &Keys, person: &str) -> Result<(Keys, i64), String> {
    let region = credential.setting("region").ok_or("This AWS credential has no region")?;
    let seconds = credential.config.get("sessionSeconds").and_then(Value::as_u64).unwrap_or(3600).to_string();
    let session = format!("access-{}", person.chars().filter(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(*c)).take(50).collect::<String>());
    let mut fields = vec![("Version", "2011-06-15"), ("DurationSeconds", seconds.as_str())];
    match credential.setting("roleArn") {
        Some(role) => {
            fields.push(("Action", "AssumeRole"));
            fields.push(("RoleArn", role));
            fields.push(("RoleSessionName", session.as_str()));
            if let Some(external) = credential.setting("externalId") {
                fields.push(("ExternalId", external));
            }
        }
        None => fields.push(("Action", "GetSessionToken")),
    }
    let body = form(&fields);
    let url = credential.setting("stsUrl").map(str::to_owned).unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"));
    let target = forward::target(&url)?;
    let host = if (target.https && target.port == 443) || (!target.https && target.port == 80) { target.host.clone() } else { format!("{}:{}", target.host, target.port) };
    let mut headers = vec![("content-type".to_owned(), "application/x-www-form-urlencoded; charset=utf-8".to_owned())];
    headers.extend(sigv4::sign("POST", &host, &target.path, target.query.as_deref(), &body, keys, region, "sts", &sigv4::amz_date(), true));
    let headers: Vec<(&str, String)> = headers.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
    let answer = forward::fetch("POST", &url, &headers, Some(body)).await?;
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    if !answer.ok() {
        let message = sigv4::xml_text(&text, "Message").unwrap_or_else(|| answer.said());
        return Err(hide_in(format!("AWS STS refused to make temporary keys (HTTP {}): {message}", answer.status), &keys.secret_key));
    }
    sigv4::credentials(&text).ok_or_else(|| "AWS STS sent no temporary keys".to_owned())
}

/// The credential ready for one request by `person`: the value itself for the plain kinds, a
/// cached short-lived token or temporary keys for the minting ones.
pub async fn prepare(cache: &Cache, credential: &Credential, value: &str, person: &str) -> Result<Prepared, String> {
    match credential.kind {
        Kind::Bearer | Kind::Header | Kind::Basic | Kind::Query => Ok(Prepared::plain(credential.kind, &credential.field, value)),
        Kind::Oauth | Kind::GithubApp => {
            if let Some(prepared) = cache.get(&credential.id) {
                return Ok(prepared);
            }
            let (token, until) = if credential.kind == Kind::Oauth { oauth(credential, value).await? } else { github(credential, value).await? };
            let prepared = Prepared::bearer(&token, value);
            cache.put(credential.id.clone(), prepared.clone(), until);
            Ok(prepared)
        }
        Kind::Aws => {
            let keys = aws_keys(value)?;
            let region = credential.setting("region").ok_or("This AWS credential has no region")?.to_owned();
            let service = credential.setting("service").map(str::to_owned);
            if credential.setting("roleArn").is_none() {
                return Ok(Prepared { secrets: vec![keys.secret_key.clone()], auth: Auth::Aws { keys, region, service } });
            }
            let key = format!("{}:{person}", credential.id);
            if let Some(prepared) = cache.get(&key) {
                return Ok(prepared);
            }
            let (temporary, until) = sts(credential, &keys, person).await?;
            let secrets = vec![keys.secret_key.clone(), temporary.secret_key.clone(), temporary.session_token.clone().unwrap_or_default()];
            let prepared = Prepared { secrets, auth: Auth::Aws { keys: temporary, region, service } };
            cache.put(key, prepared.clone(), until);
            Ok(prepared)
        }
    }
}

/// What an approved reveal hands out: the value for the plain kinds; for the minting kinds a
/// fresh short-lived token or temporary keys, never the long-lived secret.
pub async fn handout(credential: &Credential, value: &str, person: &str) -> Result<Value, String> {
    let gone = "It is now outside Access Grid's control and cannot be recalled.";
    match credential.kind {
        Kind::Bearer | Kind::Header | Kind::Basic | Kind::Query => Ok(json!({"value": value, "warning": format!("{gone} Rotate it when the task is done.")})),
        Kind::Oauth | Kind::GithubApp => {
            let (token, until) = if credential.kind == Kind::Oauth { oauth(credential, value).await? } else { github(credential, value).await? };
            Ok(json!({"value": token, "tokenType": "Bearer", "expiresAt": until, "shortLived": true, "warning": format!("A short-lived token, not the credential itself. {gone} It lapses by itself.")}))
        }
        Kind::Aws => {
            let (temporary, until) = sts(credential, &aws_keys(value)?, person).await?;
            Ok(json!({"value": {"accessKeyId": temporary.access_key, "secretAccessKey": temporary.secret_key, "sessionToken": temporary.session_token, "region": credential.setting("region")}, "expiresAt": until, "shortLived": true, "warning": format!("Temporary AWS keys, not the credential itself. {gone} They lapse by themselves.")}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_are_encoded_and_secrets_hidden_in_messages() {
        assert_eq!(String::from_utf8(form(&[("grant_type", "client_credentials"), ("scope", "a b/c")])).unwrap(), "grant_type=client_credentials&scope=a%20b%2Fc");
        assert_eq!(hide_in("bad secret-value here".into(), "secret-value"), "bad [hidden by Access Grid] here");
        assert!(pem("ghp_123").is_err());
        assert!(check_github_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----").is_err());
    }
}
