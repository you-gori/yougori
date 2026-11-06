//! A PC or a rented server contributes an existing local model, through outbound
//! requests only. This never starts a cloud rental or executes a grid's shell code.
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};

fn checked_url(text: &str, local: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(text).map_err(|_| "Invalid service URL")?;
    let loopback = url
        .host_str()
        .and_then(|h| {
            h.trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    let development = url
        .host_str()
        .is_some_and(|host| host == "localhost" || host.ends_with(".localhost"));
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && (loopback || development)))
        || (local && !loopback)
    {
        return Err("Remote grids require HTTPS; model servers must use a loopback IP.".into());
    }
    Ok(url)
}
fn private_file(path: &str, limit: u64) -> Result<String, String> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|e| format!("Cannot open credential file: {e}"))?;
    let mut text = String::new();
    file.take(limit + 1)
        .read_to_string(&mut text)
        .map_err(|_| "Cannot read credential file")?;
    if text.len() as u64 > limit {
        return Err("Credential file is too large".into());
    }
    Ok(text)
}
async fn call(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let request = if let Some(body) = body {
        client.post(url).json(&body)
    } else {
        client.get(url)
    };
    let mut response = request.bearer_auth(key).send().await.map_err(|e| {
        format!(
            "Grid/model connection failed: {}",
            if e.is_timeout() {
                "timed out"
            } else {
                "network error"
            }
        )
    })?;
    if !response.status().is_success() {
        return Err(format!(
            "Grid/model returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Cannot read service response")?
    {
        if bytes.len().saturating_add(chunk.len()) > 1 << 20 {
            return Err("Service response exceeds 1 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "Service returned invalid JSON".into())
}
pub async fn run(args: &[String]) -> Result<i32, String> {
    const HELP: &str = "yougori grid contribute --server HTTPS_URL --join-file INVITE.json --model-url http://127.0.0.1:PORT/v1 --model MODEL [--cpu CORES] [--memory GIB] [--gpu COUNT] [--model-key-file FILE] [--name NAME]\nContributes an existing local model. No cloud rental, host commands or automatic model download. Inside a Sandbox VM, yougori grid also provides serve, status, invite and job tools.";
    if args.is_empty() || args.iter().any(|s| s == "--help" || s == "-h") {
        println!("{HELP}");
        return Ok(0);
    }
    if args[0] != "contribute" {
        return Err(HELP.into());
    }
    let mut flags = BTreeMap::new();
    let mut at = 1;
    while at < args.len() {
        let name = args[at].strip_prefix("--").ok_or(HELP)?;
        if ![
            "server",
            "join-file",
            "model-url",
            "model",
            "cpu",
            "memory",
            "gpu",
            "model-key-file",
            "name",
        ]
        .contains(&name)
        {
            return Err(HELP.into());
        }
        let value = args
            .get(at + 1)
            .filter(|v| !v.starts_with("--"))
            .ok_or(HELP)?;
        if flags.insert(name, value.as_str()).is_some() {
            return Err(format!("Duplicate --{name}"));
        }
        at += 2;
    }
    let required = |name: &str| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("Missing --{name}\n{HELP}"))
    };
    let server = required("server")?;
    let server_url = checked_url(server, false)?;
    let upstream = required("model-url")?;
    checked_url(upstream, true)?;
    let model = required("model")?;
    let number = |name: &str, max: f64| -> Result<f64, String> {
        let value = flags
            .get(name)
            .copied()
            .unwrap_or("0")
            .parse::<f64>()
            .map_err(|_| format!("Invalid --{name}"))?;
        if !value.is_finite() || value < 0.0 || value > max {
            return Err(format!("Invalid --{name}"));
        }
        Ok(value)
    };
    let cpu = number("cpu", 4096.0)?;
    let memory = number("memory", 65536.0)?;
    let gpu = number("gpu", 128.0)?;
    if gpu.fract() != 0.0 {
        return Err("--gpu must be a whole device count".into());
    }
    let invite: Value = serde_json::from_str(&private_file(required("join-file")?, 4096)?)
        .map_err(|_| "Invalid invitation file")?;
    let invitation = invite["token"]
        .as_str()
        .filter(|v| v.len() == 64)
        .ok_or("Invalid invitation token")?;
    let model_key = flags
        .get("model-key-file")
        .map(|p| private_file(p, 8192))
        .transpose()?
        .unwrap_or_default();
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60));
    if let Some(host) = server_url
        .host_str()
        .filter(|host| *host == "localhost" || host.ends_with(".localhost"))
    {
        builder = builder.resolve(
            host,
            std::net::SocketAddr::from((
                [127, 0, 0, 1],
                server_url.port_or_known_default().unwrap_or(80),
            )),
        );
    }
    let client = builder.build().map_err(|e| e.to_string())?;
    let catalog = call(&client, upstream, "/models", model_key.trim(), None).await?;
    if !catalog["data"]
        .as_array()
        .is_some_and(|models| models.iter().any(|m| m["id"] == model))
    {
        return Err("The model server does not advertise that model".into());
    }
    let joined = call(&client, server, "/worker/join", invitation, Some(json!({"name":flags.get("name").copied().unwrap_or("Yougori model worker"),"capacity":{"cpu":cpu,"memoryGb":memory,"gpu":gpu as u64},"models":[model],"kinds":["chat"]}))).await?;
    let key = joined["token"]
        .as_str()
        .filter(|v| v.len() == 64)
        .ok_or("Grid returned an invalid worker credential")?;
    println!("Contributing {model}. Ctrl+C disconnects. Capacity is reported by this contributor.");
    let work = async {
        loop {
            let claim = call(&client, server, "/worker/claim", key, Some(json!({}))).await?;
            if claim["job"].is_null() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let job = &claim["job"];
            let result = if job["kind"] != "chat" || job["model"] != model {
                Err("This worker accepts chat jobs for its configured model only".to_owned())
            } else if let Some(mut payload) = job["payload"].as_object().cloned() {
                payload.insert("model".into(), json!(model));
                payload.insert("stream".into(), json!(false));
                call(
                    &client,
                    upstream,
                    "/chat/completions",
                    model_key.trim(),
                    Some(Value::Object(payload)),
                )
                .await
            } else {
                Err("Invalid chat payload".into())
            };
            let (value, error) = match result {
                Ok(v) => (v, String::new()),
                Err(e) => (Value::Null, e),
            };
            call(
                &client,
                server,
                "/worker/complete",
                key,
                Some(json!({"id":job["id"],"result":value,"error":error})),
            )
            .await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    };
    tokio::select! { result = work => result?, _ = tokio::signal::ctrl_c() => println!("Contributor stopped.") }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_plain_remote_or_credential_redirects() {
        for url in [
            "http://remote.example",
            "https://user:pass@grid.example",
            "file:///secret",
            "https://grid.example/?key=x",
        ] {
            assert!(checked_url(url, false).is_err());
        }
        assert!(checked_url("https://grid.example", false).is_ok());
        assert!(checked_url("http://127.0.0.1:8000/v1", true).is_ok());
        assert!(checked_url("http://[::1]:8000/v1", true).is_ok());
        assert!(checked_url("http://grid-token.localhost:8000", false).is_ok());
        assert!(checked_url("https://remote.example", true).is_err());
    }
}
