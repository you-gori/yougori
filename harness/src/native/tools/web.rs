//! webfetch: an HTTP(S) GET of a page, as readable text. Offered only when the sandbox reaches
//! beyond the inference; goes through HTTPS_PROXY / HTTP_PROXY / ALL_PROXY unless NO_PROXY
//! names the host. Bounded in size (5 MB) and time (30 s).
use super::{required, Output, Tool, ToolCtx};
use crate::native::html;
use crate::native::permissions::Subject;
use crate::native::shell;
use crate::native::util;
use crate::protocol::{ToolContent, ToolKind};
use crate::spec::Reach;
use async_trait::async_trait;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const MAX_BODY: usize = 5 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

/// Hosts the proxy settings leave alone.
#[derive(Clone, Debug, Default)]
struct Bypass {
    all: bool,
    hosts: Vec<String>,
}

impl Bypass {
    fn parse(text: &str) -> Bypass {
        let mut bypass = Bypass::default();
        for entry in text.split([',', ' ']).map(str::trim).filter(|e| !e.is_empty()) {
            if entry == "*" {
                bypass.all = true;
                continue;
            }
            let host = entry.trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase();
            let host = match host.rsplit_once(':') {
                Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) && !name.contains(':') => name.to_owned(),
                _ => host,
            };
            bypass.hosts.push(host.trim_matches(['[', ']']).to_owned());
        }
        bypass
    }

    fn covers(&self, host: &str) -> bool {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if self.all || host == "localhost" || host == "::1" || host.starts_with("127.") {
            return true;
        }
        self.hosts.iter().any(|h| host == *h || host.ends_with(&format!(".{h}")))
    }
}

fn setting(env: &BTreeMap<String, String>, name: &str) -> Option<String> {
    [name.to_owned(), name.to_ascii_lowercase()]
        .iter()
        .find_map(|key| env.get(key).cloned())
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn proxy_url(value: Option<String>) -> Result<Option<reqwest::Url>, String> {
    let Some(value) = value else { return Ok(None) };
    let value = if value.contains("://") { value } else { format!("http://{value}") };
    reqwest::Url::parse(&value).map(Some).map_err(|e| format!("The proxy setting {value} is not a valid address: {e}."))
}

/// An HTTP client for the web (not for the relay), with the environment's proxy settings.
pub fn client(env: &BTreeMap<String, String>) -> Result<reqwest::Client, String> {
    let https = proxy_url(setting(env, "HTTPS_PROXY").or_else(|| setting(env, "ALL_PROXY")))?;
    let http = proxy_url(setting(env, "HTTP_PROXY").or_else(|| setting(env, "ALL_PROXY")))?;
    let bypass = Bypass::parse(&setting(env, "NO_PROXY").unwrap_or_default());
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("yougori-harness/", env!("CARGO_PKG_VERSION")));
    if https.is_some() || http.is_some() {
        builder = builder.proxy(reqwest::Proxy::custom(move |url| {
            if bypass.covers(url.host_str().unwrap_or("")) {
                return None;
            }
            if url.scheme() == "https" {
                https.clone()
            } else {
                http.clone()
            }
        }));
    }
    builder.build().map_err(|e| format!("Cannot set up web access: {e}."))
}

/// The host part of a site or target as the person wrote it.
fn host_of(entry: &str) -> String {
    let entry = entry.trim();
    let entry = entry.split_once("://").map(|(_, rest)| rest).unwrap_or(entry);
    let entry = entry.split(['/', '?', '#']).next().unwrap_or(entry);
    let host = if let Some(rest) = entry.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        match entry.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => entry,
        }
    };
    host.trim_start_matches("*.").to_ascii_lowercase()
}

/// Whether the sandbox's reach takes in this URL (the VM enforces it; this only explains).
fn within(reach: &Reach, url: &reqwest::Url) -> Result<(), String> {
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']).to_ascii_lowercase();
    // The sandbox's own servers (the app being built) are always within reach.
    if host == "localhost" || host == "::1" || host.starts_with("127.") {
        return Ok(());
    }
    let (list, what) = match reach.mode.as_str() {
        "sites" => (&reach.sites, "sites"),
        "targets" => (&reach.targets, "targets"),
        _ => return Ok(()),
    };
    if list.iter().map(|e| host_of(e)).any(|h| host == h || host.ends_with(&format!(".{h}"))) {
        Ok(())
    } else {
        Err(format!("This sandbox reaches only these {what}: {}.", list.join(", ")))
    }
}

pub struct WebFetch;

#[async_trait]
impl Tool for WebFetch {
    fn name(&self) -> &str {
        "webfetch"
    }

    fn description(&self) -> String {
        "Fetch a web page (http or https) and get its text. Use it for documentation, issues or APIs the task needs.".into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "url": { "type": "string", "description": "The address, starting with https:// or http://." } },
            "required": ["url"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Fetch
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("Fetch {}", util::one_line(&super::text_arg(args, &["url", "uri", "link"]).unwrap_or_default(), 80))
    }

    fn subjects(&self, args: &Value, _ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let url = parse(&required(args, &["url", "uri", "link"])?)?;
        let origin = format!("{}://{}/", url.scheme(), url.host_str().unwrap_or(""));
        Ok(vec![Subject::new("webfetch", url.to_string(), format!("{}*", shell::escape(&origin)))])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let url = parse(&required(&args, &["url", "uri", "link"])?)?;
        within(&ctx.shared().spec.reach, &url)?;
        let client = ctx.shared().web.as_ref().ok_or("This sandbox has no web access.")?;
        let send = client
            .get(url.clone())
            .header(ACCEPT, "text/html, text/markdown, text/plain, application/json;q=0.9, */*;q=0.5")
            .timeout(TIMEOUT)
            .send();
        let mut response = tokio::select! {
            _ = ctx.cancel().cancelled() => return Err("Stopped.".into()),
            sent = send => sent.map_err(|e| fetch_error(&url, &e))?,
        };
        let status = response.status();
        let final_url = response.url().clone();
        let content_type =
            response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
        let mut body = Vec::new();
        let mut cut = false;
        loop {
            let chunk = tokio::select! {
                _ = ctx.cancel().cancelled() => return Err("Stopped.".into()),
                chunk = tokio::time::timeout(TIMEOUT, response.chunk()) => chunk,
            };
            match chunk {
                Err(_) => return Err(format!("{url} stopped sending the page.")),
                Ok(Err(e)) => return Err(fetch_error(&url, &e)),
                Ok(Ok(None)) => break,
                Ok(Ok(Some(bytes))) => {
                    body.extend_from_slice(&bytes);
                    if body.len() > MAX_BODY {
                        body.truncate(MAX_BODY);
                        cut = true;
                        break;
                    }
                }
            }
        }
        let raw = String::from_utf8_lossy(&body);
        let text = if content_type.contains("html") || (content_type.is_empty() && raw.trim_start().starts_with('<')) {
            html::to_text(&raw, Some(&final_url))
        } else if content_type.contains("json") {
            serde_json::from_str::<Value>(&raw).ok().and_then(|v| serde_json::to_string_pretty(&v).ok()).unwrap_or_else(|| raw.into_owned())
        } else if content_type.is_empty()
            || content_type.starts_with("text/")
            || content_type.contains("xml")
            || content_type.contains("javascript")
            || content_type.contains("yaml")
            || content_type.contains("toml")
        {
            if super::is_binary(&body) {
                return Err(format!("{final_url} is a binary file, not text."));
            }
            raw.into_owned()
        } else {
            return Err(format!("{final_url} is {content_type}, not text."));
        };
        let mut out = format!("{final_url} ({})\n\n{}", status.as_u16(), text.trim());
        if cut {
            out.push_str("\n\n[The page is longer than 5 MB; the rest was not fetched.]");
        }
        let failed = !status.is_success();
        if failed {
            out = format!("The page answered {status}.\n\n{out}");
        }
        Ok(Output {
            content: vec![ToolContent::Text { text: util::cut(&text, 1500).to_owned() }],
            title: Some(format!("Fetch {} ({} KB)", util::one_line(final_url.as_str(), 80), body.len().div_ceil(1024))),
            text: out,
            failed,
            ..Output::default()
        })
    }
}

fn parse(raw: &str) -> Result<reqwest::Url, String> {
    let raw = raw.trim();
    let text = if raw.contains("://") { raw.to_owned() } else { format!("https://{raw}") };
    let url = reqwest::Url::parse(&text).map_err(|e| format!("{raw} is not a web address: {e}."))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("Only http and https addresses can be fetched, not {}.", url.scheme()));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("{raw} has no host."));
    }
    Ok(url)
}

fn fetch_error(url: &reqwest::Url, error: &reqwest::Error) -> String {
    let cause = crate::native::llm::root_cause(error);
    if error.is_timeout() {
        format!("{url} did not answer within 30 s.")
    } else if error.is_connect() {
        format!("Cannot connect to {}: {cause}.", url.host_str().unwrap_or(""))
    } else if error.is_redirect() {
        format!("{url} redirects too many times.")
    } else {
        format!("Fetching {url} failed: {cause}.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_lists_and_loopback_bypass_the_proxy() {
        let bypass = Bypass::parse("example.com, .internal.net,10.0.0.5:8080 *.corp");
        assert!(bypass.covers("example.com") && bypass.covers("api.example.com"));
        assert!(bypass.covers("x.internal.net") && bypass.covers("10.0.0.5") && bypass.covers("a.corp"));
        assert!(!bypass.covers("example.org"));
        assert!(bypass.covers("localhost") && bypass.covers("127.0.0.1") && bypass.covers("[::1]"));
        assert!(Bypass::parse("*").covers("anything.io"));
        let env: BTreeMap<String, String> = [("https_proxy".to_owned(), "proxy.local:3128".to_owned())].into();
        assert!(client(&env).is_ok());
        let env: BTreeMap<String, String> = [("HTTPS_PROXY".to_owned(), "http://[bad".to_owned())].into();
        assert!(client(&env).is_err());
    }

    #[test]
    fn reach_limits_explain_themselves() {
        let reach = Reach { mode: "sites".into(), sites: vec!["https://docs.rs".into(), "github.com".into()], targets: vec![] };
        assert!(within(&reach, &parse("https://docs.rs/tokio").unwrap()).is_ok());
        assert!(within(&reach, &parse("api.github.com/repos").unwrap()).is_ok());
        assert!(within(&reach, &parse("https://example.com").unwrap()).unwrap_err().contains("docs.rs"));
        let reach = Reach { mode: "targets".into(), sites: vec![], targets: vec!["10.0.0.5:8080".into()] };
        assert!(within(&reach, &parse("http://10.0.0.5:8080/login").unwrap()).is_ok());
        assert!(within(&reach, &parse("http://localhost:3000/health").unwrap()).is_ok());
        assert!(within(&Reach { mode: "full".into(), ..reach }, &parse("https://any.where").unwrap()).is_ok());
        assert!(parse("ftp://x").unwrap_err().contains("http and https"));
        assert_eq!(host_of("https://Docs.RS:443/x"), "docs.rs");
    }

    #[tokio::test]
    async fn pages_are_fetched_as_text() {
        use crate::native::testutil::{FakeServer, Reply};
        let server = FakeServer::start(|_, request| match request.path.as_str() {
            "/page" => Reply::text(200, "text/html; charset=utf-8", "<h1>Hello</h1><p>World</p>"),
            _ => Reply::text(404, "text/plain", "nope"),
        })
        .await;
        let client = client(&BTreeMap::new()).unwrap();
        let response = client.get(format!("{}/page", server.url)).send().await.unwrap();
        let body = response.text().await.unwrap();
        assert_eq!(html::to_text(&body, None), "# Hello\n\nWorld");
    }
}
