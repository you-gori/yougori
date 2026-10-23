//! Plain HTTPS to the outside world: the company's identity provider and its desktop providers'
//! APIs. Publicly trusted roots; `http://` is allowed only to this computer, for the mock
//! servers in tests. Answers are bounded and never logged with their bodies.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{header, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::time::Duration;
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

const ANSWER_LIMIT: usize = 4 * 1024 * 1024;

pub struct Answer {
    pub status: StatusCode,
    pub body: Bytes,
    /// The answer's headers, with their names lowercased. Kept because a few providers put what
    /// matters in one rather than in the body: OpenStack's Keystone returns the token it issued in
    /// `X-Subject-Token`, and reading it out of the body is not an option because it is not there.
    pub headers: Vec<(String, String)>,
}

impl Answer {
    pub fn ok(&self) -> bool {
        self.status.is_success()
    }
    /// One header by name, or nothing when the answer did not carry it.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(had, _)| had == name).map(|(_, value)| value.as_str())
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    /// What the other side said, for a note shown to the admin: the status and a short, printable
    /// piece of the body, never a whole document.
    pub fn said(&self) -> String {
        let text = String::from_utf8_lossy(&self.body);
        let message = self.json()["error"]["message"].as_str().map(str::to_owned).or_else(|| self.json()["error_description"].as_str().map(str::to_owned)).unwrap_or_else(|| text.chars().filter(|c| !c.is_control()).take(160).collect());
        format!("HTTP {}: {}", self.status.as_u16(), message.chars().take(200).collect::<String>())
    }
}

/// `scheme`, `host`, `port`, `path?query` of a URL, without a user part.
pub fn parse(url: &str) -> Result<(bool, String, u16, String), String> {
    let url = url.trim();
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err("The address must start with https://".into());
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || authority.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("The address has no host, or carries credentials".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(']') || host.ends_with(']') => (host, port.parse::<u16>().map_err(|_| "The address has an invalid port")?),
        _ => (authority, if secure { 443 } else { 80 }),
    };
    let host = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    if !secure && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Err("Only https:// addresses are reached outside this computer".into());
    }
    Ok((secure, host, port, path.to_owned()))
}

/// One request, answered within `wait`. `body` is `(content type, bytes)`.
pub async fn call(method: &str, url: &str, headers: &[(&str, String)], body: Option<(&str, Vec<u8>)>, wait: Duration) -> Result<Answer, String> {
    let (secure, host, port, path) = parse(url)?;
    let unreachable = |what: &str| format!("{host} could not be reached: {what}");
    let socket = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect((host.as_str(), port))).await.map_err(|_| unreachable("timed out"))?.map_err(|error| unreachable(&error.to_string()))?;
    let mut request = Request::builder().method(method).uri(&path).header(header::HOST, if (secure && port == 443) || (!secure && port == 80) { host.clone() } else { format!("{host}:{port}") }).header(header::USER_AGENT, concat!("yougori-grid/", env!("CARGO_PKG_VERSION"))).header(header::ACCEPT, "application/json");
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let send = |request: Request<Full<Bytes>>| async {
        if secure {
            let name = ServerName::try_from(host.clone()).map_err(|_| unreachable("invalid host name"))?;
            let stream = tokio::time::timeout(Duration::from_secs(10), TlsConnector::from(crate::tunnel::web()).connect(name, socket)).await.map_err(|_| unreachable("TLS timed out"))?.map_err(|error| unreachable(&format!("TLS failed: {error}")))?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|error| unreachable(&error.to_string()))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            tokio::time::timeout(wait, sender.send_request(request)).await.map_err(|_| unreachable("no answer in time"))?.map_err(|error| unreachable(&error.to_string()))
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.map_err(|error| unreachable(&error.to_string()))?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            tokio::time::timeout(wait, sender.send_request(request)).await.map_err(|_| unreachable("no answer in time"))?.map_err(|error| unreachable(&error.to_string()))
        }
    };
    let request = match body {
        Some((content_type, bytes)) => request.header(header::CONTENT_TYPE, content_type).body(Full::new(Bytes::from(bytes))),
        None => request.body(Full::new(Bytes::new())),
    }
    .map_err(|error| error.to_string())?;
    let response = send(request).await?;
    let status = response.status();
    let headers = response.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))).collect();
    let body = tokio::time::timeout(wait, http_body_util::Limited::new(response.into_body(), ANSWER_LIMIT).collect()).await.map_err(|_| unreachable("the answer was interrupted"))?.map_err(|_| unreachable("the answer was too long or interrupted"))?.to_bytes();
    Ok(Answer { status, body, headers })
}

/// A GET or JSON POST with an optional bearer token.
pub async fn json(method: &str, url: &str, bearer: Option<&str>, extra: &[(&str, String)], body: Option<&Value>, wait: Duration) -> Result<Answer, String> {
    let mut headers: Vec<(&str, String)> = extra.to_vec();
    if let Some(bearer) = bearer {
        headers.push(("authorization", format!("Bearer {bearer}")));
    }
    call(method, url, &headers, body.map(|value| ("application/json", value.to_string().into_bytes())), wait).await
}

/// A form POST, as OAuth token endpoints take.
pub async fn form(url: &str, fields: &[(&str, &str)], extra: &[(&str, String)], wait: Duration) -> Result<Answer, String> {
    call("POST", url, extra, Some(("application/x-www-form-urlencoded", encode_form(fields).into_bytes())), wait).await
}

pub fn encode_form(fields: &[(&str, &str)]) -> String {
    fields.iter().map(|(name, value)| format!("{}={}", encode(name), encode(value))).collect::<Vec<_>>().join("&")
}

/// Percent-encoding for query strings and form fields.
pub fn encode(text: &str) -> String {
    text.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match u8::from_str_radix(&text[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                        continue;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fields of a query string or form body.
pub fn fields(query: &str) -> Vec<(String, String)> {
    query.split('&').filter(|pair| !pair.is_empty()).map(|pair| match pair.split_once('=') {
        Some((name, value)) => (decode(name), decode(value)),
        None => (decode(pair), String::new()),
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn urls_are_taken_apart_and_plain_http_stays_on_this_computer() {
        assert_eq!(parse("https://login.microsoftonline.com/tenant/v2.0").unwrap(), (true, "login.microsoftonline.com".into(), 443, "/tenant/v2.0".into()));
        assert_eq!(parse("https://api.example:8443").unwrap(), (true, "api.example".into(), 8443, "/".into()));
        assert_eq!(parse("http://127.0.0.1:5000/x?y=1").unwrap(), (false, "127.0.0.1".into(), 5000, "/x?y=1".into()));
        assert!(parse("http://api.example/x").is_err());
        assert!(parse("https://user:pw@api.example/x").is_err());
        assert!(parse("ftp://api.example").is_err());
    }
    #[test]
    fn forms_round_trip() {
        let encoded = encode_form(&[("grant_type", "authorization_code"), ("code", "a b&c=d/é")]);
        assert_eq!(encoded, "grant_type=authorization_code&code=a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(fields(&encoded), vec![("grant_type".to_string(), "authorization_code".to_string()), ("code".into(), "a b&c=d/é".into())]);
        assert_eq!(decode("a+b%2"), "a b%2");
    }
}
