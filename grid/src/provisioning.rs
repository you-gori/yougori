//! Connectors to the desktop services a company already runs: with a credential the admin
//! entered, Yougori assigns a person at the provider when the admin asks and takes the
//! assignment back when the person goes. Each connector speaks the provider's own management
//! API; the providers' own policies stay theirs. Secrets are used here and appear in no note.
use crate::{enterprise::Provider, https};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};

const WAIT: Duration = Duration::from_secs(60);
/// Azure's "Desktop Virtualization User" role: may use the application group's desktops. Visible
/// to the crate so the seam's own test imitates Azure with the same role id rather than a second
/// copy of it that could drift from this one.
pub(crate) const AVD_USER_ROLE: &str = "1d18fff3-a72a-46b5-b4a9-9b93932cf3e9";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Assign,
    Revoke,
    /// Sign in with the credential and name what it reaches; nothing is changed.
    Test,
}

impl Want {
    pub fn parse(text: &str) -> Option<Want> {
        match text {
            "assign" => Some(Want::Assign),
            "revoke" => Some(Want::Revoke),
            "test" => Some(Want::Test),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Want::Assign => "assign",
            Want::Revoke => "revoke",
            Want::Test => "test",
        }
    }
}

/// One thing to do at one provider for one person.
pub struct Task {
    pub provider: Provider,
    /// The connection's portal address; Horizon's API lives under it.
    pub url: String,
    pub target: BTreeMap<String, String>,
    /// The secret part of the credential, from the vault: `clientSecret` or `password`.
    pub secret: Value,
    pub want: Want,
    pub email: String,
    pub name: String,
}

impl Task {
    fn target(&self, key: &str) -> Result<&str, String> {
        self.target.get(key).map(String::as_str).filter(|value| !value.is_empty()).ok_or_else(|| format!("The connection's credential lacks {key}; enter it again"))
    }
    fn secret(&self, key: &str) -> Result<&str, String> {
        self.secret[key].as_str().filter(|value| !value.is_empty()).ok_or_else(|| format!("The connection's {key} is not in this computer's vault; enter the credential again"))
    }
    /// Where the provider's APIs are. A test's mock servers are named in the target under
    /// `_login`, `_graph`, `_arm`, `_citrix`; only this computer's addresses are accepted there.
    fn base(&self, key: &str, standard: &str) -> String {
        match self.target.get(key) {
            Some(custom) if https::parse(custom).is_ok_and(|(secure, host, _, _)| !secure && matches!(host.as_str(), "127.0.0.1" | "localhost")) => custom.trim_end_matches('/').to_owned(),
            _ => standard.to_owned(),
        }
    }
}

/// Does the task; the note says what was done, for the admin, without any secret.
pub async fn run(task: &Task) -> Result<String, String> {
    if task.want != Want::Test && (task.email.is_empty() || !task.email.contains('@')) {
        return Err(format!("{} has no email; the provider knows people by their email", if task.name.is_empty() { "This person" } else { task.name.as_str() }));
    }
    match task.provider {
        Provider::AzureVirtualDesktop => azure_virtual_desktop(task).await,
        Provider::Windows365 => windows_365(task).await,
        Provider::Citrix => citrix(task).await,
        Provider::Horizon => horizon(task).await,
    }
}

fn said(what: &str, answer: &https::Answer) -> String {
    format!("{what}: {}", answer.said())
}

// ---- Microsoft: Entra ID tokens, Microsoft Graph for people and groups, Azure Resource Manager for Azure Virtual Desktop. ----

async fn microsoft_token(task: &Task, scope: &str) -> Result<String, String> {
    let url = format!("{}/{}/oauth2/v2.0/token", task.base("_login", "https://login.microsoftonline.com"), https::encode(task.target("tenantId")?));
    let answer = https::form(&url, &[("grant_type", "client_credentials"), ("client_id", task.target("clientId")?), ("client_secret", task.secret("clientSecret")?), ("scope", scope)], &[], WAIT).await?;
    if !answer.ok() {
        return Err(said("Entra ID refused the app's credential", &answer));
    }
    answer.json()["access_token"].as_str().map(str::to_owned).ok_or_else(|| "Entra ID answered without a token".into())
}

async fn graph_user(task: &Task, graph: &str, token: &str) -> Result<String, String> {
    let answer = https::json("GET", &format!("{graph}/v1.0/users/{}?$select=id,userPrincipalName", https::encode(&task.email)), Some(token), &[], None, WAIT).await?;
    if answer.status == hyper::StatusCode::NOT_FOUND {
        return Err(format!("{} is not in the Entra ID tenant", task.email));
    }
    if !answer.ok() {
        return Err(said("Microsoft Graph refused the lookup", &answer));
    }
    answer.json()["id"].as_str().map(str::to_owned).ok_or_else(|| "Microsoft Graph answered without the person's ID".into())
}

async fn azure_virtual_desktop(task: &Task) -> Result<String, String> {
    let (graph, arm) = (task.base("_graph", "https://graph.microsoft.com"), task.base("_arm", "https://management.azure.com"));
    let scope = format!("/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DesktopVirtualization/applicationGroups/{}", https::encode(task.target("subscriptionId")?), https::encode(task.target("resourceGroup")?), https::encode(task.target("applicationGroup")?));
    let arm_token = microsoft_token(task, &format!("{}/.default", task.base("_arm", "https://management.azure.com"))).await?;
    if task.want == Want::Test {
        let answer = https::json("GET", &format!("{arm}{scope}?api-version=2024-04-03"), Some(&arm_token), &[], None, WAIT).await?;
        if !answer.ok() {
            return Err(said("Azure refused to show the application group", &answer));
        }
        let value = answer.json();
        return Ok(format!("Reaches application group {} ({}) in host pool {}", value["name"].as_str().unwrap_or_default(), value["properties"]["applicationGroupType"].as_str().unwrap_or("desktop"), value["properties"]["hostPoolArmPath"].as_str().and_then(|path| path.rsplit('/').next()).unwrap_or("?")));
    }
    let graph_token = microsoft_token(task, &format!("{graph}/.default")).await?;
    let principal = graph_user(task, &graph, &graph_token).await?;
    let role = format!("/subscriptions/{}/providers/Microsoft.Authorization/roleDefinitions/{AVD_USER_ROLE}", task.target("subscriptionId")?);
    match task.want {
        Want::Assign => {
            let id = uuid::Uuid::new_v4().to_string();
            let body = json!({"properties": {"roleDefinitionId": role, "principalId": principal, "principalType": "User"}});
            let answer = https::json("PUT", &format!("{arm}{scope}/providers/Microsoft.Authorization/roleAssignments/{id}?api-version=2022-04-01"), Some(&arm_token), &[], Some(&body), WAIT).await?;
            if answer.status == hyper::StatusCode::CONFLICT {
                return Ok(format!("{} already had the application group", task.email));
            }
            if !answer.ok() {
                return Err(said("Azure refused the assignment", &answer));
            }
            Ok(format!("{} may now use the application group's desktops", task.email))
        }
        Want::Revoke => {
            // Azure writes an assignment's scope with the names as they are, and the request path
            // escapes them; `(`, `)` and letters beyond ASCII are legal in a resource group's name.
            // Matched against the path, no assignment at such a group was ever found, and every
            // revoke there said there was nothing to take back.
            let written = format!("/subscriptions/{}/resourceGroups/{}/providers/Microsoft.DesktopVirtualization/applicationGroups/{}", task.target("subscriptionId")?, task.target("resourceGroup")?, task.target("applicationGroup")?).to_lowercase();
            let unread = "so nothing was taken back. Try again; if this keeps happening, remove the person's Desktop Virtualization User assignment in the Azure portal.";
            let mut mine = Vec::new();
            let mut page = Some(format!("{arm}{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter={}", https::encode(&format!("principalId eq '{principal}'"))));
            let mut pages = 0;
            // Every page is read: "no assignment of ours" is only true of the whole list.
            while let Some(url) = page.take() {
                pages += 1;
                if pages > 20 {
                    return Err(format!("Azure's list of the person's assignments ran past 20 pages, {unread}"));
                }
                let answer = https::json("GET", &url, Some(&arm_token), &[], None, WAIT).await?;
                if !answer.ok() {
                    return Err(said("Azure refused to list the assignments", &answer));
                }
                let listed = answer.json();
                let Some(entries) = listed["value"].as_array() else {
                    return Err(format!("Azure's answer did not list the person's assignments, {unread}"));
                };
                mine.extend(entries.iter().filter(|entry| entry["properties"]["roleDefinitionId"].as_str().is_some_and(|definition| definition.to_ascii_lowercase().ends_with(AVD_USER_ROLE)) && entry["properties"]["scope"].as_str().is_some_and(|at| at.to_lowercase() == written)).filter_map(|entry| entry["id"].as_str().map(str::to_owned)));
                page = match listed["nextLink"].as_str() {
                    None => None,
                    Some(next) if next.starts_with(&format!("{arm}/")) => Some(next.to_owned()),
                    Some(_) => return Err(format!("Azure sent the rest of the list from somewhere other than Azure Resource Manager, {unread}")),
                };
            }
            if mine.is_empty() {
                return Ok(format!("{} had no assignment of ours to take back", task.email));
            }
            for id in &mine {
                // Azure's own id, written with the names as they are: escaped a part at a time for the path.
                let path = id.split('/').map(https::encode).collect::<Vec<_>>().join("/");
                let answer = https::json("DELETE", &format!("{arm}{path}?api-version=2022-04-01"), Some(&arm_token), &[], None, WAIT).await?;
                if !answer.ok() && answer.status != hyper::StatusCode::NO_CONTENT && answer.status != hyper::StatusCode::NOT_FOUND {
                    return Err(said("Azure refused to remove the assignment", &answer));
                }
            }
            Ok(format!("{} no longer has the application group", task.email))
        }
        Want::Test => unreachable!(),
    }
}

async fn windows_365(task: &Task) -> Result<String, String> {
    let graph = task.base("_graph", "https://graph.microsoft.com");
    let token = microsoft_token(task, &format!("{graph}/.default")).await?;
    let group = https::encode(task.target("groupId")?);
    if task.want == Want::Test {
        let answer = https::json("GET", &format!("{graph}/v1.0/groups/{group}?$select=id,displayName"), Some(&token), &[], None, WAIT).await?;
        if !answer.ok() {
            return Err(said("Microsoft Graph refused to show the group", &answer));
        }
        return Ok(format!("Reaches group {}; people added to it get a Cloud PC from its provisioning policy", answer.json()["displayName"].as_str().unwrap_or_default()));
    }
    let principal = graph_user(task, &graph, &token).await?;
    match task.want {
        Want::Assign => {
            let body = json!({"@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{principal}")});
            let answer = https::json("POST", &format!("{graph}/v1.0/groups/{group}/members/$ref"), Some(&token), &[], Some(&body), WAIT).await?;
            if answer.status == hyper::StatusCode::BAD_REQUEST && answer.said().to_ascii_lowercase().contains("already exist") {
                return Ok(format!("{} was already in the group", task.email));
            }
            if !answer.ok() {
                return Err(said("Microsoft Graph refused to add them to the group", &answer));
            }
            Ok(format!("{} is in the group; Windows 365 provisions their Cloud PC from its policy", task.email))
        }
        Want::Revoke => {
            let answer = https::json("DELETE", &format!("{graph}/v1.0/groups/{group}/members/{principal}/$ref"), Some(&token), &[], None, WAIT).await?;
            if !answer.ok() && answer.status != hyper::StatusCode::NOT_FOUND {
                return Err(said("Microsoft Graph refused to remove them from the group", &answer));
            }
            Ok(format!("{} is out of the group; Windows 365 retires their Cloud PC by its policy", task.email))
        }
        Want::Test => unreachable!(),
    }
}

// ---- Citrix Cloud: the DaaS management API, delivery groups' users. ----

async fn citrix(task: &Task) -> Result<String, String> {
    let base = task.base("_citrix", "https://api.cloud.com");
    let customer = task.target("customerId")?;
    let answer = https::form(&format!("{base}/cctrustoauth2/root/tokens/clients"), &[("grant_type", "client_credentials"), ("client_id", task.target("clientId")?), ("client_secret", task.secret("clientSecret")?)], &[], WAIT).await?;
    if !answer.ok() {
        return Err(said("Citrix Cloud refused the API client", &answer));
    }
    let token = answer.json()["access_token"].as_str().map(str::to_owned).ok_or("Citrix Cloud answered without a token")?;
    let mut headers = vec![("authorization", format!("CwsAuth Bearer={token}")), ("citrix-customerid", customer.to_owned())];
    let answer = https::json("GET", &format!("{base}/cvad/manage/me"), None, &headers, None, WAIT).await?;
    if !answer.ok() {
        return Err(said("Citrix DaaS refused to say which site this is", &answer));
    }
    let me = answer.json();
    let site = me["Customers"].as_array().into_iter().flatten().find(|entry| entry["Id"] == customer).or_else(|| me["Customers"].as_array().and_then(|list| list.first())).and_then(|entry| entry["Sites"][0]["Id"].as_str()).ok_or("Citrix DaaS lists no site for this customer")?.to_owned();
    headers.push(("citrix-instanceid", site));
    let group = format!("{base}/cvad/manage/DeliveryGroups/{}", https::encode(task.target("deliveryGroup")?));
    if task.want == Want::Test {
        let answer = https::json("GET", &group, None, &headers, None, WAIT).await?;
        if !answer.ok() {
            return Err(said("Citrix DaaS refused to show the delivery group", &answer));
        }
        let value = answer.json();
        return Ok(format!("Reaches delivery group {} ({} desktops)", value["Name"].as_str().unwrap_or_default(), value["TotalDesktops"].as_u64().unwrap_or_default()));
    }
    // Citrix DaaS "Edit delivery group": users to add, or to take off, by their identity.
    let body = match task.want {
        Want::Assign => json!({"Users": [task.email]}),
        _ => json!({"RemoveUsers": [task.email]}),
    };
    let answer = https::json("PATCH", &group, None, &headers, Some(&body), WAIT).await?;
    if !answer.ok() {
        return Err(said("Citrix DaaS refused the change", &answer));
    }
    Ok(match task.want {
        Want::Assign => format!("{} is in the delivery group", task.email),
        _ => format!("{} is out of the delivery group", task.email),
    })
}

// ---- Omnissa Horizon: the Connection Server REST API, pool entitlements. ----

async fn horizon(task: &Task) -> Result<String, String> {
    let base = task.url.trim_end_matches('/').to_owned();
    let answer = https::json("POST", &format!("{base}/rest/login"), None, &[], Some(&json!({"domain": task.target("domain")?, "username": task.target("username")?, "password": task.secret("password")?})), WAIT).await?;
    if !answer.ok() {
        return Err(said("Horizon refused the administrator sign-in", &answer));
    }
    let token = answer.json()["access_token"].as_str().map(str::to_owned).ok_or("Horizon answered without a token")?;
    let pool = task.target("pool")?.to_owned();
    if task.want == Want::Test {
        let answer = https::json("GET", &format!("{base}/rest/inventory/v1/desktop-pools/{}", https::encode(&pool)), Some(&token), &[], None, WAIT).await?;
        if !answer.ok() {
            return Err(said("Horizon refused to show the desktop pool", &answer));
        }
        let value = answer.json();
        return Ok(format!("Reaches desktop pool {} ({})", value["name"].as_str().unwrap_or_default(), value["type"].as_str().unwrap_or("?")));
    }
    let filter = json!({"type": "Equals", "name": "user_principal_name", "value": task.email});
    let answer = https::json("GET", &format!("{base}/rest/external/v1/ad-users-or-groups?filter={}", https::encode(&filter.to_string())), Some(&token), &[], None, WAIT).await?;
    if !answer.ok() {
        return Err(said("Horizon refused the directory lookup", &answer));
    }
    let user = answer.json().as_array().and_then(|list| list.iter().find(|entry| entry["group"] != true).and_then(|entry| entry["id"].as_str().map(str::to_owned))).ok_or_else(|| format!("{} is not in the directory Horizon uses", task.email))?;
    let body = json!([{"id": pool, "user_or_group_ids": [user]}]);
    let method = if task.want == Want::Assign { "POST" } else { "DELETE" };
    let answer = https::json(method, &format!("{base}/rest/entitlements/v1/desktop-pools"), Some(&token), &[], Some(&body), WAIT).await?;
    if !answer.ok() {
        return Err(said("Horizon refused the entitlement change", &answer));
    }
    if let Some(item) = answer.json().as_array().and_then(|list| list.first()) {
        let code = item["status_code"].as_u64().unwrap_or(200);
        if code >= 300 && !item["errors"].to_string().to_ascii_lowercase().contains("already") {
            return Err(format!("Horizon refused the entitlement change: {}", item["errors"][0]["error_message"].as_str().unwrap_or("see the Horizon console")));
        }
    }
    Ok(match task.want {
        Want::Assign => format!("{} is entitled to the desktop pool", task.email),
        _ => format!("{} is no longer entitled to the desktop pool", task.email),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request, Response};
    use hyper_util::rt::TokioIo;
    use std::sync::{Arc, Mutex};

    pub type Seen = Arc<Mutex<Vec<(String, String, String, String)>>>;

    /// A provider's API on loopback: records `(method, path, authorization, body)` and answers
    /// from `reply(method, path, body)`.
    pub async fn mock(reply: impl Fn(&str, &str, &Value) -> (u16, Value) + Send + Sync + 'static) -> (String, Seen) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let reply = Arc::new(reply);
        let recorder = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                let (reply, recorder) = (reply.clone(), recorder.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let (reply, recorder) = (reply.clone(), recorder.clone());
                        async move {
                            let method = request.method().to_string();
                            let path = request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
                            let authorization = request.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
                            let content_type = request.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let text = String::from_utf8_lossy(&bytes).into_owned();
                            let body: Value = if content_type.starts_with("application/json") { serde_json::from_slice(&bytes).unwrap_or(Value::Null) } else { Value::Object(https::fields(&text).into_iter().map(|(k, v)| (k, Value::String(v))).collect()) };
                            recorder.lock().unwrap().push((method.clone(), path.clone(), authorization, text));
                            let (status, value) = reply(&method, &path, &body);
                            Ok::<_, std::convert::Infallible>(Response::builder().status(status).header("content-type", "application/json").body(Full::new(bytes::Bytes::from(value.to_string()))).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                });
            }
        });
        (format!("http://{address}"), seen)
    }

    fn task(provider: Provider, url: &str, target: &[(&str, &str)], secret: Value, want: Want) -> Task {
        Task { provider, url: url.into(), target: target.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), secret, want, email: "ada@acme.example".into(), name: "Ada".into() }
    }

    /// Entra ID, Microsoft Graph and Azure Resource Manager in one mock, keyed by path.
    fn microsoft(method: &str, path: &str, body: &Value) -> (u16, Value) {
        match (method, path) {
            ("POST", "/tenant-1/oauth2/v2.0/token") => {
                if body["client_secret"] != "s3cret" {
                    return (401, json!({"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret"}));
                }
                let scope = body["scope"].as_str().unwrap_or_default();
                (200, json!({"access_token": if scope.contains("/.default") && scope.starts_with("http://127.0.0.1") { format!("token-for-{}", scope.split("/.default").next().unwrap().rsplit(':').next().unwrap()) } else { "token".into() }}))
            }
            ("GET", p) if p.starts_with("/v1.0/users/ada%40acme.example") => (200, json!({"id": "user-ada"})),
            ("GET", p) if p.starts_with("/v1.0/users/") => (404, json!({"error": {"code": "Request_ResourceNotFound", "message": "Resource does not exist"}})),
            ("GET", p) if p.starts_with("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag?") => (200, json!({"name": "ag", "properties": {"applicationGroupType": "Desktop", "hostPoolArmPath": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/finance"}})),
            ("PUT", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments/") => (201, json!({"id": p.split('?').next().unwrap(), "properties": body["properties"]})),
            ("GET", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments?") => (200, json!({"value": [
                {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag/providers/Microsoft.Authorization/roleAssignments/ra-1", "properties": {"roleDefinitionId": format!("/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/{AVD_USER_ROLE}"), "principalId": "user-ada", "scope": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag"}},
                {"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-other", "properties": {"roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/other", "principalId": "user-ada", "scope": "/subscriptions/sub-1"}},
            ]})),
            ("DELETE", p) if p.contains("/roleAssignments/ra-1?") => (200, json!({})),
            ("GET", "/v1.0/groups/group-1?$select=id,displayName") => (200, json!({"id": "group-1", "displayName": "Cloud PC users"})),
            ("POST", "/v1.0/groups/group-1/members/$ref") => (204, Value::Null),
            ("DELETE", "/v1.0/groups/group-1/members/user-ada/$ref") => (204, Value::Null),
            _ => (404, json!({"error": {"message": format!("no route {method} {path}")}})),
        }
    }

    #[tokio::test]
    async fn azure_virtual_desktop_assigns_the_desktop_user_role_and_takes_only_its_own_back() {
        let (base, seen) = mock(microsoft).await;
        let make = |want| task(Provider::AzureVirtualDesktop, "https://client.wvd.microsoft.com", &[("tenantId", "tenant-1"), ("clientId", "app-1"), ("subscriptionId", "sub-1"), ("resourceGroup", "rg"), ("applicationGroup", "ag"), ("_login", &base), ("_graph", &base), ("_arm", &base)], json!({"clientSecret": "s3cret"}), want);
        assert!(run(&make(Want::Test)).await.unwrap().contains("host pool finance"));
        let note = run(&make(Want::Assign)).await.unwrap();
        assert!(note.contains("may now use"), "{note}");
        let calls = seen.lock().unwrap().clone();
        let put = calls.iter().find(|(method, _, _, _)| method == "PUT").expect("a role assignment");
        assert!(put.1.starts_with("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag/providers/Microsoft.Authorization/roleAssignments/"));
        assert!(put.3.contains(AVD_USER_ROLE) && put.3.contains("user-ada"));
        assert_eq!(put.2, "Bearer token-for-arm".replace("arm", &base.rsplit(':').next().unwrap().to_string()), "ARM's token, not Graph's");
        assert!(calls.iter().all(|(_, _, _, body)| !body.contains("s3cret") || body.contains("client_secret=s3cret")), "the secret goes only to the token endpoint");
        assert!(run(&make(Want::Revoke)).await.unwrap().contains("no longer"));
        let deletes: Vec<_> = seen.lock().unwrap().iter().filter(|(method, _, _, _)| method == "DELETE").map(|(_, path, _, _)| path.clone()).collect();
        assert_eq!(deletes.len(), 1, "only the desktop-user assignment at this application group, not the other role");
        assert!(deletes[0].contains("/ra-1?"));
        let mut wrong = make(Want::Assign);
        wrong.secret = json!({"clientSecret": "nope"});
        let error = run(&wrong).await.unwrap_err();
        assert!(error.contains("Invalid client secret") && !error.contains("nope"), "{error}");
        let mut stranger = make(Want::Assign);
        stranger.email = "eve@else.example".into();
        assert!(run(&stranger).await.unwrap_err().contains("not in the Entra ID tenant"));
    }

    /// PROVES that an Azure Virtual Desktop revoke never reports done without taking anything back.
    ///
    /// Assignments were matched against the scope as written into the request path, where
    /// `https::encode` escapes `(` and `)`, while Azure returns the scope as the names are written.
    /// Parentheses are legal in a resource group's name, so for such a group no assignment ever
    /// matched and every revoke said "had no assignment of ours to take back" while the person kept
    /// the desktops. A 2xx answer with no list read the same way, and so did an assignment on a
    /// later page of the list.
    #[tokio::test]
    async fn azure_virtual_desktop_never_reports_a_revoke_it_did_not_carry_out() {
        let scope = "/subscriptions/sub-1/resourceGroups/finance(eu)/providers/Microsoft.DesktopVirtualization/applicationGroups/ag";
        let assignment = json!({"id": format!("{scope}/providers/Microsoft.Authorization/roleAssignments/ra-1"), "properties": {"roleDefinitionId": format!("/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/{AVD_USER_ROLE}"), "principalId": "user-ada", "scope": scope}});
        let other = json!({"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-other", "properties": {"roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/other", "principalId": "user-ada", "scope": "/subscriptions/sub-1"}});
        let address: Arc<Mutex<String>> = Arc::default();
        let next = address.clone();
        // The first page holds another role; the assignment to take back is on the second.
        let (base, seen) = mock(move |method, path, body| match (method, path) {
            ("GET", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments?") && p.contains("skiptoken") => (200, json!({"value": [assignment.clone()]})),
            ("GET", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments?") => {
                (200, json!({"value": [other.clone()], "nextLink": format!("{}{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$skiptoken=page-2", next.lock().unwrap())}))
            }
            _ => microsoft(method, path, body),
        })
        .await;
        *address.lock().unwrap() = base.clone();
        let make = |base: &str| task(Provider::AzureVirtualDesktop, "https://client.wvd.microsoft.com", &[("tenantId", "tenant-1"), ("clientId", "app-1"), ("subscriptionId", "sub-1"), ("resourceGroup", "finance(eu)"), ("applicationGroup", "ag"), ("_login", base), ("_graph", base), ("_arm", base)], json!({"clientSecret": "s3cret"}), Want::Revoke);
        let note = run(&make(&base)).await.unwrap();
        assert!(note.contains("no longer"), "{note}");
        let deletes: Vec<String> = seen.lock().unwrap().iter().filter(|(method, _, _, _)| method == "DELETE").map(|(_, path, _, _)| path.clone()).collect();
        assert_eq!(deletes.len(), 1, "the desktop-user assignment was taken back, and nothing else: {deletes:?}");
        assert!(deletes[0].contains("/roleAssignments/ra-1?"), "{deletes:?}");

        // A 2xx that is not a list of assignments is not an empty list.
        let (base, seen) = mock(|method, path, body| match (method, path) {
            ("GET", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments?") => (200, json!({"error": null})),
            _ => microsoft(method, path, body),
        })
        .await;
        let error = run(&make(&base)).await.unwrap_err();
        assert!(error.contains("nothing was taken back"), "{error}");
        assert!(seen.lock().unwrap().iter().all(|(method, _, _, _)| method != "DELETE"));
    }

    #[tokio::test]
    async fn windows_365_adds_people_to_the_provisioning_policys_group() {
        let (base, seen) = mock(microsoft).await;
        let make = |want| task(Provider::Windows365, "https://windows365.microsoft.com", &[("tenantId", "tenant-1"), ("clientId", "app-1"), ("groupId", "group-1"), ("_login", &base), ("_graph", &base)], json!({"clientSecret": "s3cret"}), want);
        assert!(run(&make(Want::Test)).await.unwrap().contains("Cloud PC users"));
        assert!(run(&make(Want::Assign)).await.unwrap().contains("in the group"));
        let calls = seen.lock().unwrap().clone();
        let add = calls.iter().find(|(method, path, _, _)| method == "POST" && path.ends_with("/members/$ref")).expect("a membership add");
        assert!(add.3.contains("directoryObjects/user-ada"));
        assert!(run(&make(Want::Revoke)).await.unwrap().contains("out of the group"));
        assert!(seen.lock().unwrap().iter().any(|(method, path, _, _)| method == "DELETE" && path == "/v1.0/groups/group-1/members/user-ada/$ref"));
    }

    #[tokio::test]
    async fn citrix_edits_the_delivery_groups_users_with_the_sites_instance_header() {
        let (base, seen) = mock(|method, path, body| match (method, path) {
            ("POST", "/cctrustoauth2/root/tokens/clients") => if body["client_secret"] == "cs" { (200, json!({"access_token": "ctx-token"})) } else { (401, json!({"error": "invalid_client"})) },
            ("GET", "/cvad/manage/me") => (200, json!({"Customers": [{"Id": "acme", "Sites": [{"Id": "site-1"}]}]})),
            ("GET", "/cvad/manage/DeliveryGroups/Desks") => (200, json!({"Name": "Desks", "TotalDesktops": 12})),
            ("PATCH", "/cvad/manage/DeliveryGroups/Desks") => (200, json!({"Name": "Desks"})),
            _ => (404, json!({"error": {"message": "no"}})),
        }).await;
        let make = |want| task(Provider::Citrix, "https://acme.cloud.com", &[("customerId", "acme"), ("clientId", "api-client"), ("deliveryGroup", "Desks"), ("_citrix", &base)], json!({"clientSecret": "cs"}), want);
        assert!(run(&make(Want::Test)).await.unwrap().contains("12 desktops"));
        assert!(run(&make(Want::Assign)).await.unwrap().contains("in the delivery group"));
        assert!(run(&make(Want::Revoke)).await.unwrap().contains("out of the delivery group"));
        let calls = seen.lock().unwrap().clone();
        let patches: Vec<_> = calls.iter().filter(|(method, _, _, _)| method == "PATCH").collect();
        assert_eq!(patches.len(), 2);
        assert!(patches[0].3.contains("\"Users\":[\"ada@acme.example\"]") && patches[1].3.contains("\"RemoveUsers\""));
        assert!(patches.iter().all(|(_, _, authorization, _)| authorization == "CwsAuth Bearer=ctx-token"));
    }

    #[tokio::test]
    async fn horizon_entitles_the_directory_user_to_the_pool() {
        let (base, seen) = mock(|method, path, body| match (method, path) {
            ("POST", "/rest/login") => if body["password"] == "pw" && body["domain"] == "ACME" { (200, json!({"access_token": "hz-token", "refresh_token": "r"})) } else { (401, json!({"error_message": "Invalid credentials"})) },
            ("GET", "/rest/inventory/v1/desktop-pools/pool-1") => (200, json!({"name": "Desks", "type": "AUTOMATED"})),
            ("GET", p) if p.starts_with("/rest/external/v1/ad-users-or-groups?filter=") => (200, json!([{"id": "ad-ada", "group": false, "user_principal_name": "ada@acme.example"}])),
            ("POST", "/rest/entitlements/v1/desktop-pools") | ("DELETE", "/rest/entitlements/v1/desktop-pools") => (200, json!([{"id": "pool-1", "status_code": 200}])),
            _ => (404, json!({"error_message": "no"})),
        }).await;
        let make = |want| task(Provider::Horizon, &base, &[("username", "admin"), ("domain", "ACME"), ("pool", "pool-1")], json!({"password": "pw"}), want);
        assert!(run(&make(Want::Test)).await.unwrap().contains("AUTOMATED"));
        assert!(run(&make(Want::Assign)).await.unwrap().contains("entitled"));
        assert!(run(&make(Want::Revoke)).await.unwrap().contains("no longer entitled"));
        let calls = seen.lock().unwrap().clone();
        let lookup = calls.iter().find(|(_, path, _, _)| path.starts_with("/rest/external/v1/ad-users-or-groups")).unwrap();
        assert!(https::decode(&lookup.1).contains("\"value\":\"ada@acme.example\""));
        let entitle = calls.iter().find(|(method, path, _, _)| method == "POST" && path == "/rest/entitlements/v1/desktop-pools").unwrap();
        assert!(entitle.3.contains("ad-ada") && entitle.2 == "Bearer hz-token");
        assert!(calls.iter().any(|(method, path, _, _)| method == "DELETE" && path == "/rest/entitlements/v1/desktop-pools"));
        let mut wrong = make(Want::Assign);
        wrong.secret = json!({"password": "other"});
        let error = run(&wrong).await.unwrap_err();
        assert!(error.contains("Invalid credentials") && !error.contains("other"));
    }

    #[test]
    fn a_task_without_an_email_is_refused_before_any_call() {
        let mut no_email = task(Provider::Horizon, "https://h", &[], json!({}), Want::Assign);
        no_email.email.clear();
        let error = tokio::runtime::Runtime::new().unwrap().block_on(run(&no_email)).unwrap_err();
        assert!(error.contains("no email"));
    }
}
