//! `yougori monitor`, `audit`, `lockdown` and `unlock`: what the engine observed and
//! recorded about each environment, and the manual kill switch. Views live in output.rs.
use crate::{
    client,
    public::{call, resolve, send},
};
use serde_json::{json, Value};

pub const MONITOR_USAGE: &str = "Usage: yougori monitor [ENV] [--once]";
pub const AUDIT_USAGE: &str = "Usage: yougori audit [ENV] [--since TIME] [--limit N] [--verify]";
pub const LOCKDOWN_USAGE: &str = "Usage: yougori lockdown ENV|--all --yes";
pub const UNLOCK_USAGE: &str = "Usage: yougori unlock ENV|--all --yes";

#[derive(Debug, Default, PartialEq)]
pub struct AuditRequest {
    pub environment: Option<String>,
    pub since: Option<String>,
    pub limit: Option<u64>,
    pub verify: bool,
}

fn value(args: &[String], index: &mut usize, name: &str, usage: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index).filter(|value| !value.starts_with("--")).cloned().ok_or_else(|| format!("{name} needs a value. {usage}"))
}

pub fn audit_request(args: &[String]) -> Result<AuditRequest, String> {
    let mut request = AuditRequest::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--since" if request.since.is_none() => request.since = Some(value(args, &mut index, "--since", AUDIT_USAGE)?),
            "--limit" if request.limit.is_none() => {
                let limit = value(args, &mut index, "--limit", AUDIT_USAGE)?;
                request.limit = Some(limit.parse().ok().filter(|limit| (1..=1000).contains(limit)).ok_or("--limit must be a whole number from 1 to 1000")?);
            }
            "--verify" if !request.verify => request.verify = true,
            name if !name.starts_with('-') && request.environment.is_none() => request.environment = Some(name.to_owned()),
            _ => return Err(AUDIT_USAGE.into()),
        }
        index += 1;
    }
    Ok(request)
}

/// `[ENV] [--once]`
pub fn monitor_request(args: &[String]) -> Result<(Option<String>, bool), String> {
    let (mut environment, mut once) = (None, false);
    for argument in args {
        match argument.as_str() {
            "--once" if !once => once = true,
            name if !name.starts_with('-') && environment.is_none() => environment = Some(name.to_owned()),
            _ => return Err(MONITOR_USAGE.into()),
        }
    }
    Ok((environment, once))
}

#[derive(Debug, PartialEq)]
pub enum Selection {
    One(String),
    All,
}

/// `ENV|--all --yes`: the kill switch always needs an explicit target and confirmation.
pub fn selection(args: &[String], usage: &str) -> Result<Selection, String> {
    let (mut target, mut all, mut yes) = (None, false, false);
    for argument in args {
        match argument.as_str() {
            "--yes" if !yes => yes = true,
            "--all" if !all => all = true,
            name if !name.starts_with('-') && target.is_none() => target = Some(name.to_owned()),
            _ => return Err(usage.into()),
        }
    }
    let selection = match (target, all) {
        (Some(target), false) => Selection::One(target),
        (None, true) => Selection::All,
        _ => return Err(usage.into()),
    };
    if !yes {
        return Err(format!("Explicit --yes confirmation is required. {usage}"));
    }
    Ok(selection)
}

/// A unique name or an ID; an ID of a deleted environment still selects its audit records.
async fn environment_id(name: &str) -> Result<String, String> {
    match resolve(name).await {
        Ok(id) => Ok(id),
        Err(_) if name.starts_with("env-") => Ok(name.to_owned()),
        Err(error) => Err(error),
    }
}

pub async fn audit(request: &AuditRequest) -> Result<Value, String> {
    client::start(None).await?;
    let mut params = json!({});
    if let Some(environment) = &request.environment {
        params["environmentId"] = environment_id(environment).await?.into();
    }
    if let Some(since) = &request.since {
        params["since"] = since.clone().into();
    }
    if let Some(limit) = request.limit {
        params["limit"] = limit.into();
    }
    if request.verify {
        params["verify"] = true.into();
    }
    call("security_audit", params).await
}

pub async fn monitor(environment: Option<&str>) -> Result<Value, String> {
    let mut params = json!({});
    if let Some(environment) = environment {
        params["environmentId"] = environment_id(environment).await?.into();
    }
    call("security_monitor", params).await
}

/// Lockdown or unlock; the caller has already required `--yes`.
pub async fn contain(selection: &Selection, unlock: bool) -> Result<Value, String> {
    client::start(None).await?;
    let params = match selection {
        Selection::All => json!({"all": true}),
        Selection::One(name) => json!({"environmentId": environment_id(name).await?}),
    };
    send(if unlock { "security_unlock" } else { "security_lockdown" }, params, true).await
}

/// One short status label per environment for `status` and `top`.
pub fn label(entry: &Value) -> String {
    if let Some(level) = entry["containment"]["level"].as_str() {
        return match level {
            "lockdown" => "locked down".into(),
            "paused" => "paused by kill switch".into(),
            _ => "internet cut".into(),
        };
    }
    match entry["alerts"].as_array().map(Vec::len).unwrap_or(0) {
        0 => "ok".into(),
        1 => "1 alert".into(),
        count => format!("{count} alerts"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn audit_options_parse_once_and_reject_unknown_flags() {
        assert_eq!(audit_request(&words("web --since 2h --limit 20 --verify")).unwrap(),
            AuditRequest { environment: Some("web".into()), since: Some("2h".into()), limit: Some(20), verify: true });
        assert_eq!(audit_request(&[]).unwrap(), AuditRequest::default());
        for bad in ["--limit 0", "--limit 1001", "--since", "--since 2h --since 3h", "a b", "--force", "--limit x"] {
            assert!(audit_request(&words(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn lockdown_requires_one_target_and_confirmation() {
        assert_eq!(selection(&words("web --yes"), LOCKDOWN_USAGE).unwrap(), Selection::One("web".into()));
        assert_eq!(selection(&words("--all --yes"), LOCKDOWN_USAGE).unwrap(), Selection::All);
        assert!(selection(&words("web"), LOCKDOWN_USAGE).unwrap_err().contains("--yes"));
        for bad in ["--yes", "web --all --yes", "a b --yes", "--all --all --yes"] {
            assert!(selection(&words(bad), LOCKDOWN_USAGE).is_err(), "{bad}");
        }
    }

    #[test]
    fn monitor_takes_an_optional_environment_and_once() {
        assert_eq!(monitor_request(&words("web --once")).unwrap(), (Some("web".into()), true));
        assert_eq!(monitor_request(&[]).unwrap(), (None, false));
        assert!(monitor_request(&words("a b")).is_err());
        assert!(monitor_request(&words("--json")).is_err());
    }

    #[test]
    fn labels_prefer_containment_over_alerts() {
        assert_eq!(label(&json!({"containment":{"level":"lockdown"},"alerts":[{}]})), "locked down");
        assert_eq!(label(&json!({"containment":{"level":"internetCut"}})), "internet cut");
        assert_eq!(label(&json!({"alerts":[{},{}]})), "2 alerts");
        assert_eq!(label(&json!({"alerts":[]})), "ok");
    }
}
