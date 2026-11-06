//! Validate network intent before creating resources. The current NAT backend
//! supports outgoing IPv4 traffic, not unsolicited all-port ingress.

use serde_json::Value;

pub(super) fn launch_internet(params: &Value) -> Result<bool, String> {
    let flag = |name: &str| -> Result<bool, String> {
        match params.get(name) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => Err(format!("{name} must be true or false.")),
        }
    };
    let internet = flag("internet")?;
    if flag("incoming")? {
        return Err("Incoming access to all VM ports is not supported by this backend. You can publish individual apps instead. No VM or host network changes were made for this request.".into());
    }
    if internet && params.get("routes").is_some_and(|value| !value.is_null()) {
        return Err("Choose unrestricted outgoing internet access or selected online requests, not both.".into());
    }
    Ok(internet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incoming_all_is_never_silently_downgraded_to_outgoing_or_published_apps() {
        for params in [
            json!({"incoming":true}),
            json!({"incoming":true,"internet":false}),
            json!({"incoming":true,"internet":true}),
            json!({"incoming":true,"publish":"web=3000"}),
        ] {
            assert!(launch_internet(&params).unwrap_err().contains("not supported"));
        }
    }

    #[test]
    fn absent_or_disabled_incoming_does_not_change_outgoing_permission() {
        for incoming in [Value::Null, json!(false)] {
            assert!(!launch_internet(&json!({"incoming":incoming})).unwrap());
            assert!(launch_internet(&json!({"incoming":incoming,"internet":true})).unwrap());
        }
        assert!(!launch_internet(&json!({})).unwrap());
        assert!(!launch_internet(&json!({"internet":false})).unwrap());
    }

    #[test]
    fn malformed_switches_and_conflicting_routes_are_refused() {
        for name in ["internet", "incoming"] {
            for value in [json!("false"), json!(1), json!([]), json!({})] {
                let params = Value::Object([(name.into(), value)].into_iter().collect());
                assert_eq!(launch_internet(&params), Err(format!("{name} must be true or false.")));
            }
        }
        assert!(launch_internet(&json!({"internet":true,"routes":[]})).is_err());
        assert!(launch_internet(&json!({"internet":true,"routes":null})).unwrap());
        assert!(!launch_internet(&json!({"internet":false,"routes":[{}]})).unwrap());
    }
}
