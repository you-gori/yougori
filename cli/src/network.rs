//! Yougori Network from the command line. The engine holds the sign-in, so signing in here
//! also signs in the app on this computer, and the reverse.
use crate::{client, public::call};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub const USAGE: &str = "Usage: yougori login | yougori logout | yougori account";

/// `--now` shares paid, `--nowfree` shares free.
pub fn mode(flag: &str) -> Option<&'static str> {
    match flag {
        "--now" => Some("paid"),
        "--nowfree" => Some("free"),
        _ => None,
    }
}

/// Signs in through the browser. `show` receives the code and the address to approve it at.
pub async fn login(mut show: impl FnMut(&str, &str)) -> Result<Value, String> {
    client::start(None).await?;
    let status = call("market_sign_in", json!({})).await?;
    if status["signedIn"] == true {
        return Ok(json!({"signedIn": true, "alreadySignedIn": true, "account": status["account"], "website": status["website"]}));
    }
    let login = &status["login"];
    let code = login["userCode"].as_str().ok_or("The engine did not return a sign-in code")?;
    let address = login["verificationUrlComplete"].as_str().or(login["verificationUrl"].as_str()).unwrap_or("https://yougori.com/device");
    show(code, address);
    let deadline = Instant::now() + Duration::from_secs(login["expiresIn"].as_u64().unwrap_or(600) + 5);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = tokio::signal::ctrl_c() => return Err("Sign-in cancelled. Run yougori login again when you are ready.".into()),
        }
        let status = call("market_status", json!({})).await?;
        if status["signedIn"] == true {
            return Ok(json!({"signedIn": true, "account": status["account"], "website": status["website"]}));
        }
        if let Some(error) = status["login"]["error"].as_str() {
            return Err(error.to_owned());
        }
        if status["login"].is_null() || Instant::now() > deadline {
            return Err("The sign-in was not completed. Run yougori login again.".into());
        }
    }
}

pub async fn logout() -> Result<Value, String> {
    client::start(None).await?;
    let status = call("market_sign_out", json!({})).await?;
    Ok(json!({"signedIn": false, "website": status["website"]}))
}

pub async fn account() -> Result<Value, String> {
    client::start(None).await?;
    call("market_status", json!({})).await
}

pub async fn signed_in() -> Result<bool, String> {
    Ok(call("market_status", json!({})).await?["signedIn"] == true)
}

pub const SIGN_IN_FIRST: &str = "Sign in to the Yougori Network first: yougori login. Sign in or create a free account with your wallet in the browser, then approve the CLI or App.";

pub fn validate_listen(mode: Option<&str>, listen: bool) -> Result<(), String> {
    if listen && mode != Some("free") { return Err("--listen requires --nowfree".into()); }
    Ok(())
}

pub async fn share(environment_id: &str, mode: &str) -> Result<Value, String> {
    share_with_listen(environment_id, mode, false).await
}

pub async fn share_with_listen(environment_id: &str, mode: &str, listen: bool) -> Result<Value, String> {
    share_with_publication(environment_id, mode, listen, false).await
}

pub async fn share_with_publication(environment_id: &str, mode: &str, listen: bool, closed: bool) -> Result<Value,String> {
    validate_listen(Some(mode), listen)?;
    if !listen { eprintln!("Network privacy: providers and the Yougori gateway can read prompts and replies during inference. Hardware-enforced host privacy is unavailable. https://yougori.com/privacy"); }
    let result = call("market_share_model", json!({"environmentId": environment_id, "mode": mode, "listen": listen, "publish": closed})).await?;
    if listen {
        if let Some(path) = result["listenPath"].as_str() {
            eprintln!("Listening · prompts and replies saved in the model container: {path}");
            eprintln!("View: yougori terminal {environment_id}, then tail -F {}", shell_words::quote(path));
        } else {
            eprintln!("Listening requested · recording starts when the free model runner is ready; its container path will appear in model status.");
        }
    }
    Ok(result)
}

/// Caller text is printed as JSON so terminal control sequences remain escaped.
pub fn listen_command(path: &str) -> String {
    let formatter = "import sys,json\nfor line in sys.stdin:\n try:\n  record=json.loads(line); reply=record['response']; reply={k:v for k,v in reply.items() if k!='events'} if isinstance(reply,dict) else reply\n  print('\\nREQUEST '+record['id']+' | '+record['outcome']+'\\nPROMPT\\n'+json.dumps(record['request'],ensure_ascii=False,indent=2)+'\\nOUTPUT\\n'+json.dumps(reply,ensure_ascii=False,indent=2),flush=True)\n except (ValueError,KeyError): pass";
    format!("tail -n 10 -F -- {} | python3 -u -c {}",shell_words::quote(path),shell_words::quote(formatter))
}

/// This environment's share, once the engine has registered and checked it (up to `wait`).
pub async fn settled(environment_id: &str, wait: Duration) -> Result<Option<Value>, String> {
    let deadline = Instant::now() + wait;
    loop {
        let status = call("market_status", json!({})).await?;
        let share = status["shares"].as_array().into_iter().flatten().find(|share| share["environmentId"] == environment_id).cloned();
        let Some(share) = share else { return Ok(None) };
        let waiting = share["live"] != true && share["filesOnline"]!=true && (matches!(share["status"].as_str(), Some("starting" | "installing" | "downloading" | "verifying" | "loading"))
            || share["status"] == "ready" && share["message"].as_str().is_some_and(|m| m.starts_with("Checking") || m.contains("reconnecting")));
        if !waiting || Instant::now() >= deadline {
            return Ok(Some(share));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn money(micros: &Value) -> String {
    format!("${:.2}", micros.as_f64().unwrap_or(0.0) / 1e6)
}

fn price(node: &Value) -> String {
    match node["price"].as_object() {
        Some(price) => format!(
            "${}/${} per 1M tokens in/out",
            price.get("input").and_then(Value::as_f64).unwrap_or(0.0),
            price.get("output").and_then(Value::as_f64).unwrap_or(0.0)
        ),
        None => "free".into(),
    }
}

fn duration(seconds: &Value) -> String {
    let seconds = seconds.as_u64().unwrap_or(0);
    if seconds >= 3600 { format!("{}h {}m", seconds / 3600, seconds % 3600 / 60) } else { format!("{}m", seconds / 60) }
}

/// One line about a shared model, e.g. `Live on the Yougori Network · paid · $0.1/$0.34 per 1M tokens in/out`.
pub fn summary(share: &Value) -> String {
    let node = &share["node"];
    let mut parts = vec![share["message"].as_str().filter(|m| !m.is_empty()).unwrap_or("Shared on the Yougori Network").to_owned()];
    if node.is_object() {
        parts.push(if node["mode"] == "free" { "free for everyone".into() } else { price(node) });
        if let Some(tps) = node["tps"].as_f64() {
            parts.push(format!("{tps:.1} {}tok/s ({})", if node["speedMetric"] == "input_tokens" {"input "} else {""}, if node["tpsSource"] == "window" { "last 15 min" } else if node["tpsSource"] == "benchmark" { "connection benchmark" } else { "average" }));
        }
    }
    if share["listen"] == true {
        parts.push(share["listenPath"].as_str().map(|path|format!("recording to {path}")).unwrap_or_else(||"recording requested".into()));
    }
    parts.join(" · ")
}

/// Terminal text for login, logout and account.
pub fn render(command: &str, value: &Value) -> String {
    let website = value["website"].as_str().unwrap_or("https://yougori.com");
    match command {
        "logout" => "Signed out of the Yougori Network on this computer. Shared models stopped.".into(),
        "login" => format!(
            "{} as {}.\nThe Yougori App on this computer is signed in too.\nShare a model: yougori model run hf.co/google/gemma-4-31B --now (paid) or --nowfree (free).",
            if value["alreadySignedIn"] == true { "Already signed in" } else { "Signed in" },
            value["account"]["email"].as_str().unwrap_or("your account"),
        ),
        _ => {
            if value["signedIn"] != true {
                return format!("Not signed in to the Yougori Network.\nSign in: yougori login\nModels and providers: {website}/network");
            }
            let account = &value["account"];
            let mut lines = vec![
                format!("Yougori Network · {}", account["email"].as_str().unwrap_or("signed in")),
                format!("Wallet      {}", account["wallet"].as_str().map(str::to_owned).unwrap_or_else(|| format!("not connected · connect it at {website}/account"))),
                format!("Balance     {} credit · {} earnings", money(&account["creditMicros"]), money(&account["earningsMicros"])),
            ];
            let shares = value["shares"].as_array().cloned().unwrap_or_default();
            if shares.is_empty() {
                lines.push("Shared      none · yougori model run hf.co/OWNER/MODEL --now".into());
            }
            for share in shares {
                let node = &share["node"];
                lines.push(format!("Shared      {} ({})", share["model"].as_str().unwrap_or(""), if share["mode"] == "free" { "free" } else { "paid" }));
                lines.push(format!("            {}", summary(&share)));
                if node.is_object() {
                    lines.push(format!(
                        "            {} · up {} today, {} this week · availability {} · {} tokens in, {} out · earned {}",
                        node["gpu"].as_str().unwrap_or("GPU not reported"),
                        duration(&node["uptimeTodaySeconds"]),
                        duration(&node["uptimeWeekSeconds"]),
                        node["availability"].as_f64().map(|value| format!("{value:.1}%")).unwrap_or_else(|| "unknown".into()),
                        node["tokensIn"].as_u64().unwrap_or(0),
                        node["tokensOut"].as_u64().unwrap_or(0),
                        money(&node["earnedMicros"]),
                    ));
                }
            }
            lines.push(format!("Manage      {website}/account"));
            lines.join("\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_map_to_sharing_modes() {
        assert_eq!(mode("--now"), Some("paid"));
        assert_eq!(mode("--nowfree"), Some("free"));
        assert_eq!(mode("--api"), None);
    }
    #[test]
    fn summaries_show_price_speed_and_free_sharing() {
        let paid = json!({"message":"Live on the Yougori Network","node":{"mode":"paid","price":{"input":0.1,"output":0.34},"tps":41.25,"tpsSource":"window"}});
        assert_eq!(summary(&paid), "Live on the Yougori Network · $0.1/$0.34 per 1M tokens in/out · 41.2 tok/s (last 15 min)");
        let free = json!({"message":"","node":{"mode":"free","price":null}});
        assert_eq!(summary(&free), "Shared on the Yougori Network · free for everyone");
        let account = json!({"signedIn":true,"website":"https://yougori.com","account":{"email":"a@b.c","wallet":null,"creditMicros":1500000,"earningsMicros":0},"shares":[]});
        let text = render("account", &account);
        assert!(text.contains("a@b.c") && text.contains("$1.50 credit") && text.contains("not connected"));
        assert!(render("account", &json!({"signedIn":false})).contains("yougori login"));
    }
}

#[cfg(test)] mod listen_tests {
    #[test] fn recording_path_is_shell_quoted_as_data() {
        let path="/cache/owner's models/requests;bad.jsonl";
        let args=shell_words::split(&super::listen_command(path)).unwrap();
        assert_eq!(args[5],path);assert_eq!(args[6],"|");assert_eq!(args[9],"-c");
        assert!(args[10].contains("json.dumps"));
    }
}
