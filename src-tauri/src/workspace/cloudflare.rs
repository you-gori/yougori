//! Optional account tunnels. Secrets stay in native memory / the OS vault, never
//! platform JSON, command-line arguments, publication responses, or diagnostic logs.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::io::AsyncBufRead;

const VAULT_SERVICE: &str = "Yougori.CloudflareTunnel.v1";
const PREVIOUS_VAULT_SERVICE: &str = "OpenDock.CloudflareTunnel.v1";
const PUBLIC_PRESET_SCOPE: &str = "public-presets";

const QUICK_RATE_LIMIT: &str = "Cloudflare temporarily rate-limited Quick Tunnel creation (1015/429)";
// One budget for restoration, model sync and other Quick Tunnel callers.
static QUICK_RETRY: std::sync::LazyLock<tokio::sync::Mutex<QuickRetry>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(QuickRetry::default()));

#[derive(Default)]
struct QuickRetry {
    next: Option<std::time::Instant>,
    rate_failures: u32,
}
impl QuickRetry {
    fn remaining(&self, now: std::time::Instant) -> Option<Duration> {
        self.next.and_then(|next| next.checked_duration_since(now)).filter(|d| !d.is_zero())
    }
    fn finished(&mut self, now: std::time::Instant, succeeded: bool, rate_limited: bool) {
        let seconds = if succeeded {
            self.rate_failures = 0;
            15
        } else if rate_limited {
            self.rate_failures = self.rate_failures.saturating_add(1);
            (120u64 * (1u64 << self.rate_failures.saturating_sub(1).min(3))).min(900)
        } else { 30 };
        self.next = Some(now + Duration::from_secs(seconds));
    }
    fn deferred(&self, now: std::time::Instant) -> Option<String> {
        self.remaining(now).map(|remaining| format!(
            "{}; next public-link attempt in {} seconds. The local service keeps running.",
            if self.rate_failures > 0 { QUICK_RATE_LIMIT } else { "Cloudflare Quick Tunnel creation is cooling down" },
            remaining.as_secs().saturating_add(1)
        ))
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountOptions {
    pub hostname: String,
    pub token: Option<String>,
    #[serde(default)]
    pub preset_id: Option<String>,
    #[serde(default)]
    pub preset_source_environment_id: Option<String>,
    /// App port the saved setup was created for, when it now serves a different app port.
    #[serde(default)]
    pub preset_port: Option<u16>,
    #[serde(default)]
    pub remember: bool,
    #[serde(default)]
    pub routes_reviewed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Credentials {
    hostname: String,
    host_port: u16,
    token: String,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedAccount {
    saved: bool,
    hostname: String,
    host_port: Option<u16>,
}

pub(crate) struct Account {
    credentials: Credentials,
    pub tunnel_id: String,
    remember: bool,
}

fn credential_key(environment_id: &str, port: u16) -> Result<String, String> {
    if environment_id.is_empty()
        || environment_id.len() > 128
        || !environment_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || port == 0
        || port == 7443
    {
        return Err("Invalid environment or service port".into());
    }
    Ok(format!("{environment_id}:{port}"))
}

fn entry(environment_id: &str, port: u16) -> Result<keyring::Entry, String> {
    keyring::Entry::new(VAULT_SERVICE, &credential_key(environment_id, port)?)
        .map_err(|_| "Cannot open the OS credential vault".into())
}

fn migrated_password(account: &str) -> Result<Option<String>, String> {
    let current = keyring::Entry::new(VAULT_SERVICE, account)
        .map_err(|_| "Cannot open the OS credential vault")?;
    match current.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => {
            let previous = keyring::Entry::new(PREVIOUS_VAULT_SERVICE, account)
                .map_err(|_| "Cannot open the previous OS credential vault")?;
            match previous.get_password() {
                Ok(value) => {
                    current.set_password(&value)
                        .map_err(|_| "Cannot move saved tunnel credentials to Yougori")?;
                    Ok(Some(value))
                }
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(_) => Err("Cannot read the previous OS credential vault".into()),
            }
        }
        Err(_) => Err("Cannot read the OS credential vault".into()),
    }
}

fn delete_saved_password(account: &str) -> Result<(), String> {
    for service in [VAULT_SERVICE, PREVIOUS_VAULT_SERVICE] {
        let entry = keyring::Entry::new(service, account)
            .map_err(|_| "Cannot open the OS credential vault")?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(_) => return Err("Cannot remove the saved tunnel token".into()),
        }
    }
    Ok(())
}

fn preset_key(environment_id: &str, port: u16, preset_id: &str) -> Result<String, String> {
    let id = Uuid::parse_str(preset_id).map_err(|_| "Invalid saved setup ID")?;
    // Reuse the same environment and port validation as the legacy credential key.
    Ok(format!("{}:preset:{id}", credential_key(environment_id, port)?))
}

fn preset_entry(environment_id: &str, port: u16, preset_id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(VAULT_SERVICE, &preset_key(environment_id, port, preset_id)?)
        .map_err(|_| "Cannot open the OS credential vault".into())
}

fn load_preset(environment_id: &str, port: u16, preset_id: &str) -> Result<Credentials, String> {
    let value = migrated_password(&preset_key(environment_id, port, preset_id)?)?
        .ok_or("Saved tunnel token is unavailable. Edit this setup and paste the token again.")?;
    if value.len() > 4096 { return Err("Saved tunnel credentials exceed the size limit".into()); }
    serde_json::from_str(&value).map_err(|_| "Saved tunnel credentials are invalid".into())
}

fn load(environment_id: &str, port: u16) -> Result<Option<Credentials>, String> {
    match migrated_password(&credential_key(environment_id, port)?)? {
        Some(value) if value.len() <= 4096 => serde_json::from_str(&value).map(Some).map_err(|_| "Saved Cloudflare credentials are invalid. Forget them and enter a new tunnel token.".into()),
        Some(_) => Err("Saved Cloudflare credentials exceed the size limit".into()),
        None => Ok(None),
    }
}

pub(crate) fn hostname(value: &str) -> Result<String, String> {
    let name = value.trim().to_ascii_lowercase();
    if name.len() > 253
        || !name.contains('.')
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(
            "Enter a public hostname such as app.example.com, without https://, a port, or a path."
                .into(),
        );
    }
    if name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".trycloudflare.com")
    {
        return Err("Use a hostname on a domain you manage in Cloudflare, not a local address or Quick Tunnel link.".into());
    }
    Ok(name)
}

fn token_id(value: &str) -> Result<String, String> {
    let invalid = "Paste only the tunnel token (the eyJ… value), not the installation command, an API token, or your Cloudflare password.";
    if value.len() < 32 || value.len() > 2048 || value.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(invalid.into());
    }
    let decoded = STANDARD.decode(value).map_err(|_| invalid)?;
    let data: Value = serde_json::from_slice(&decoded).map_err(|_| invalid)?;
    let account = data["a"].as_str().ok_or(invalid)?;
    let secret = data["s"].as_str().ok_or(invalid)?;
    let id = Uuid::parse_str(data["t"].as_str().ok_or(invalid)?).map_err(|_| invalid)?;
    if account.len() != 32
        || !account.bytes().all(|b| b.is_ascii_hexdigit())
        || id.is_nil()
        // Cloudflared accepts a base64-encoded byte string, not a fixed-size key.
        || STANDARD.decode(secret).map_err(|_| invalid)?.is_empty()
    {
        return Err(invalid.into());
    }
    Ok(id.to_string())
}

impl Account {
    pub(crate) fn host_port(&self) -> u16 { self.credentials.host_port }
    pub(crate) fn resolve(
        environment_id: &str,
        port: u16,
        host_port: Option<u16>,
        options: AccountOptions,
    ) -> Result<Self, String> {
        if !options.routes_reviewed {
            return Err(
                "Review the dedicated tunnel's dashboard routes before connecting it.".into(),
            );
        }
        let host_port = host_port.filter(|p| *p != 0 && *p != 7443).ok_or(
            "Choose a fixed local tunnel port and configure that exact port in Cloudflare.",
        )?;
        let hostname = hostname(&options.hostname)?;
        let token = match options.token.filter(|value| !value.trim().is_empty()) {
            Some(value) => value.trim().to_owned(),
            None => {
                if let Some(preset_id) = options.preset_id.as_deref() {
                    let source = options.preset_source_environment_id.as_deref().unwrap_or(environment_id);
                    let saved = load_preset(source, options.preset_port.unwrap_or(port), preset_id)?;
                    if saved.hostname != hostname || saved.host_port != host_port {
                        return Err("Saved setup differs from its secure tunnel credentials. Edit and save it again.".into());
                    }
                    saved.token
                } else {
                    load(environment_id, port)?
                        .ok_or("Enter a tunnel token or save one first.")?
                        .token
                }
            }
        };
        let tunnel_id = token_id(&token)?;
        Ok(Self {
            credentials: Credentials {
                hostname,
                host_port,
                token,
            },
            tunnel_id,
            remember: options.remember,
        })
    }

    pub(crate) fn public_url(&self) -> String {
        format!("https://{}", self.credentials.hostname)
    }

    pub(crate) fn remember(&self, environment_id: &str, port: u16) -> Result<(), String> {
        if !self.remember {
            return Ok(());
        }
        let serialized = serde_json::to_string(&self.credentials)
            .map_err(|_| "Cannot encode tunnel credentials")?;
        entry(environment_id, port)?.set_password(&serialized).map_err(|_| "Connected, but credentials could not be saved in the OS vault. You will need to paste the token next time.".into())
    }
}

/// One hostname and one tunnel port per saved domain; at most 200.
fn domain_conflict(domains: &[crate::models::SavedDomain], domain: &crate::models::SavedDomain) -> Result<(), String> {
    if let Some(other) = domains.iter().find(|d| d.id != domain.id && d.hostname.eq_ignore_ascii_case(&domain.hostname)) {
        return Err(format!("{} is already a saved domain; edit it to change its ports", other.hostname));
    }
    if domains.iter().any(|d| d.id != domain.id && d.host_port == domain.host_port) {
        return Err(format!("Tunnel port {} is already used by another saved domain", domain.host_port));
    }
    if domains.len() >= 200 && !domains.iter().any(|d| d.id == domain.id) {
        return Err("Remove an unused saved domain first (200 maximum)".into());
    }
    Ok(())
}

/// Adds or replaces a saved domain in the shared list.
fn remember_domain(store: &PlatformStore, domain: crate::models::SavedDomain) -> Result<(), String> {
    store.mutate(|state| {
        domain_conflict(&state.saved_domains, &domain)?;
        state.saved_domains.retain(|d| d.id != domain.id);
        state.saved_domains.push(domain);
        Ok(())
    })
    .map(|_| ())
}

pub(crate) async fn save_preset(
    environment_id: &str, port: u16, preset_id: &str, hostname: &str, host_port: u16, token: &str,
    store: &PlatformStore, manager: &WorkspaceManager,
) -> Result<crate::models::SavedDomain, String> {
    let _operation = manager.operations.lock().await;
    if host_port == 0 || host_port == 7443 { return Err("Choose a valid local tunnel port, excluding 7443".into()); }
    let credentials = Credentials { hostname: self::hostname(hostname)?, host_port, token: token.trim().to_owned() };
    token_id(&credentials.token)?;
    let domain = crate::models::SavedDomain { id: preset_id.into(), credential_environment_id: environment_id.into(), port, hostname: credentials.hostname.clone(), host_port };
    // Check the shared list before touching the vault so a conflict leaves nothing behind.
    domain_conflict(&store.snapshot()?.saved_domains, &domain)?;
    let serialized = serde_json::to_string(&credentials).map_err(|_| "Cannot encode tunnel credentials")?;
    preset_entry(environment_id, port, preset_id)?.set_password(&serialized)
        .map_err(|_| "Cannot save this setup in the OS credential vault")?;
    remember_domain(store, domain.clone())?;
    Ok(domain)
}

#[tauri::command]
pub async fn save_cloudflare_preset(
    window: WebviewWindow, environment_id: String, port: u16, preset_id: String,
    hostname: String, host_port: u16, token: String,
    store: State<'_, PlatformStore>,
    manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    check_preset_scope(&window)?;
    save_preset(&environment_id, port, &preset_id, &hostname, host_port, &token, &store, &manager).await.map(|_| ())
}

#[tauri::command]
pub async fn copy_saved_cloudflare_to_preset(
    window: WebviewWindow,
    environment_id: String,
    port: u16,
    preset_id: String,
    store: State<'_, PlatformStore>,
    manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    check_scope(&window, &store, &environment_id)?;
    copy_saved_to_preset(&environment_id, port, &preset_id, &store, &manager).await.map(|_| ())
}

/// Reuse a node's already-vaulted tunnel credentials in the shared saved setups.
/// The CLI calls this only through the same-user control pipe; no token is returned.
pub(crate) async fn copy_saved_to_preset(
    environment_id: &str,
    port: u16,
    preset_id: &str,
    store: &PlatformStore,
    manager: &WorkspaceManager,
) -> Result<crate::models::SavedDomain, String> {
    if !store.snapshot()?.environments.iter().any(|env| env.id == environment_id) {
        return Err("Environment not found".into());
    }
    let _operation = manager.operations.lock().await;
    let credentials = load(environment_id, port)?
        .ok_or("The tunnel was connected, but its token was not saved for this node and port")?;
    hostname(&credentials.hostname)?;
    token_id(&credentials.token)?;
    if credentials.host_port == 0 || credentials.host_port == 7443 {
        return Err("The saved tunnel has an invalid local port".into());
    }
    let domain = crate::models::SavedDomain { id: preset_id.into(), credential_environment_id: PUBLIC_PRESET_SCOPE.into(), port, hostname: credentials.hostname.clone(), host_port: credentials.host_port };
    domain_conflict(&store.snapshot()?.saved_domains, &domain)?;
    let serialized = serde_json::to_string(&credentials)
        .map_err(|_| "Cannot encode tunnel credentials")?;
    preset_entry(PUBLIC_PRESET_SCOPE, port, preset_id)?
        .set_password(&serialized)
        .map_err(|_| "Cannot add this tunnel to Saved setups in the OS credential vault")?;
    remember_domain(store, domain.clone())?;
    Ok(domain)
}

/// Change a saved domain's app port and/or local tunnel port. The vaulted token
/// moves with it and node connections saved for this domain follow the new port.
/// A live publication holds the old tunnel port, so that must be disconnected first.
pub(crate) async fn update_preset(name: &str, port: u16, host_port: u16, store: &PlatformStore, manager: &WorkspaceManager) -> Result<crate::models::SavedDomain, String> {
    let _operation = manager.operations.lock().await;
    if port == 0 || port == 7443 { return Err("Choose a valid app port, excluding 7443".into()); }
    if host_port == 0 || host_port == 7443 { return Err("Choose a valid local tunnel port, excluding 7443".into()); }
    let old = find_domain(store, name)?;
    if old.port == port && old.host_port == host_port { return Ok(old); }
    let previous = migrated_password(&preset_key(&old.credential_environment_id, old.port, &old.id)?)?
        .ok_or("Saved tunnel token is unavailable. Remove this setup and add it again with its token.")?;
    let mut credentials: Credentials = serde_json::from_str(&previous).map_err(|_| "Saved tunnel credentials are invalid")?;
    if host_port != old.host_port {
        let tunnel_id = token_id(&credentials.token)?;
        if manager.publications.lock().await.values().any(|p| p.tunnel_id.as_deref() == Some(tunnel_id.as_str())) {
            return Err(format!("{} is connected to an environment. Disconnect it there, change the tunnel port, then connect it again.", old.hostname));
        }
    }
    let domain = crate::models::SavedDomain { port, host_port, ..old.clone() };
    domain_conflict(&store.snapshot()?.saved_domains, &domain)?;
    credentials.host_port = host_port;
    let serialized = serde_json::to_string(&credentials).map_err(|_| "Cannot encode tunnel credentials")?;
    // A setup connector is bound to the old tunnel port; the caller reconnects it.
    if host_port != old.host_port {
        if let Some(setup) = manager.setup_tunnels.lock().await.remove(&old.id) { setup.stop().await; }
    }
    preset_entry(&domain.credential_environment_id, port, &domain.id)?.set_password(&serialized)
        .map_err(|_| "Cannot update this setup in the OS credential vault")?;
    let saved = store.mutate(|state| {
        domain_conflict(&state.saved_domains, &domain)?;
        for item in state.saved_domains.iter_mut().filter(|d| d.id == domain.id) { *item = domain.clone(); }
        for service in state.saved_environment_services.iter_mut().filter(|s| s.domain.as_deref() == Some(domain.id.as_str())) {
            service.host_port = host_port;
        }
        Ok(())
    });
    if let Err(error) = saved {
        // Leave the vault exactly as the unchanged saved domain expects it.
        let _ = if port == old.port { preset_entry(&old.credential_environment_id, old.port, &old.id)?.set_password(&previous).map_err(|_| ()) }
            else { delete_saved_password(&preset_key(&domain.credential_environment_id, port, &domain.id)?).map_err(|_| ()) };
        return Err(error);
    }
    if port != old.port {
        let _ = delete_saved_password(&preset_key(&old.credential_environment_id, old.port, &old.id)?);
    }
    Ok(domain)
}

#[tauri::command]
pub async fn update_saved_domain(
    window: WebviewWindow, domain: String, port: u16, host_port: u16,
    store: State<'_, PlatformStore>, manager: State<'_, WorkspaceManager>,
) -> Result<crate::models::SavedDomain, String> {
    check_preset_scope(&window)?;
    update_preset(&domain, port, host_port, &store, &manager).await
}

pub(crate) async fn forget_preset(environment_id: &str, port: u16, preset_id: &str, store: &PlatformStore, manager: &WorkspaceManager) -> Result<(), String> {
    let _operation = manager.operations.lock().await;
    delete_saved_password(&preset_key(environment_id, port, preset_id)?)?;
    if let Some(setup) = manager.setup_tunnels.lock().await.remove(preset_id) {
        setup.stop().await;
    }
    store.mutate(|state| { state.saved_domains.retain(|d| d.id != preset_id); Ok(()) }).map(|_| ())
}

#[tauri::command]
pub async fn forget_cloudflare_preset(
    window: WebviewWindow, environment_id: String, port: u16, preset_id: String,
    store: State<'_, PlatformStore>,
    manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    check_preset_scope(&window)?;
    forget_preset(&environment_id, port, &preset_id, &store, &manager).await
}

/// Finds a saved domain by ID or hostname.
pub(crate) fn find_domain(store: &PlatformStore, name: &str) -> Result<crate::models::SavedDomain, String> {
    store.snapshot()?.saved_domains.into_iter()
        .find(|d| d.id == name || d.hostname.eq_ignore_ascii_case(name.trim()))
        .ok_or_else(|| format!("No saved domain named {name}. List them with `yougori domain list`."))
}

/// Account-tunnel options that reuse a saved domain's vaulted token, for any app port.
pub(crate) fn domain_account(store: &PlatformStore, name: &str) -> Result<(AccountOptions, u16), String> {
    let domain = find_domain(store, name)?;
    Ok((AccountOptions {
        hostname: domain.hostname,
        token: None,
        preset_id: Some(domain.id),
        preset_source_environment_id: Some(domain.credential_environment_id),
        preset_port: Some(domain.port),
        remember: false,
        routes_reviewed: true,
    }, domain.host_port))
}

/// A connector can register before a workload exists. Reserve its local port and
/// serve a fixed placeholder until a publication replaces it with a guest bridge.
pub(super) struct SetupTunnel {
    tunnel_id: String,
    hostname: String,
    host_port: u16,
    started: Started,
    origin: JoinHandle<()>,
}

impl Drop for SetupTunnel {
    fn drop(&mut self) {
        self.origin.abort();
        self.started.logs.abort();
    }
}

impl SetupTunnel {
    async fn connect(executable: &Path, root: &Path, account: &Account) -> Result<Self, String> {
        let host_port = account.credentials.host_port;
        let listener = TcpListener::bind(("127.0.0.1", host_port)).await
            .map_err(|_| format!("Local tunnel port {host_port} is already in use. Choose an unused port for this setup."))?;
        let started = start(executable, root, host_port, Some(account)).await?;
        Ok(Self {
            tunnel_id: account.tunnel_id.clone(), hostname: account.credentials.hostname.clone(), host_port,
            started, origin: setup_origin(listener),
        })
    }

    async fn stop(mut self) {
        self.origin.abort();
        let _ = (&mut self.origin).await;
        self.started.logs.abort();
        let _ = self.started.child.kill().await;
    }

    fn matches(&self, account: &Account) -> Result<(), String> {
        if self.hostname != account.credentials.hostname || self.host_port != account.credentials.host_port {
            return Err("This tunnel is connected for another saved setup. Use a dedicated Cloudflare tunnel for each domain.".into());
        }
        Ok(())
    }
}

fn setup_origin(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        const BODY: &str = "Yougori tunnel connected. Connect an environment to this saved domain to serve your app.\n";
        let response = format!("HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}", BODY.len());
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                // Consume the whole request head first: closing with unread
                // bytes can reset the connection before the reply arrives.
                let mut request = [0u8; 4096];
                let mut read = 0;
                while read < request.len() {
                    let count = stream.read(&mut request[read..]).await?;
                    read += count;
                    if count == 0 || request[..read].windows(4).any(|w| w == b"\r\n\r\n") { break; }
                }
                stream.write_all(response.as_bytes()).await?;
                stream.shutdown().await
            }).await;
        }
    })
}

pub(crate) async fn start_domain_tunnel(
    name: &str, store: &PlatformStore, manager: &WorkspaceManager,
) -> Result<Value, String> {
    let _operation = manager.operations.lock().await;
    let domain = find_domain(store, name)?;
    let (options, host_port) = domain_account(store, &domain.id)?;
    let account = Account::resolve(&domain.credential_environment_id, domain.port, Some(host_port), options)?;
    let result = |serving_app| json!({"hostname":domain.hostname,"hostPort":host_port,"status":"connected","servingApp":serving_app});
    if let Some(publication) = manager.publications.lock().await.values_mut()
        .find(|p| p.tunnel_id.as_deref() == Some(account.tunnel_id.as_str())) {
        if publication.info.host_port != host_port || publication.info.urls != vec![account.public_url()] {
            return Err("This tunnel is already publishing another service. Use a dedicated tunnel for this domain.".into());
        }
        if publication.cloudflare.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None))) {
            return Ok(result(true));
        }
        return Err("This domain's publication disconnected. Disconnect it from the environment, then connect it again.".into());
    }
    let mut setups = manager.setup_tunnels.lock().await;
    if let Some(setup) = setups.values_mut().find(|s| s.tunnel_id == account.tunnel_id) {
        setup.matches(&account)?;
        if matches!(setup.started.child.try_wait(), Ok(None)) { return Ok(result(false)); }
    }
    if let Some(stale) = setups.remove(&domain.id) { stale.stop().await; }
    let executable = super::cloudflared(&manager.root).await?;
    let setup = SetupTunnel::connect(&executable, &manager.root, &account).await?;
    setups.insert(domain.id, setup);
    Ok(result(false))
}

#[tauri::command]
pub async fn start_saved_domain_tunnel(
    window: WebviewWindow, domain: String,
    store: State<'_, PlatformStore>, manager: State<'_, WorkspaceManager>,
) -> Result<Value, String> {
    check_preset_scope(&window)?;
    start_domain_tunnel(&domain, &store, &manager).await
}

#[tauri::command]
pub async fn stop_saved_domain_tunnel(
    window: WebviewWindow, domain: String,
    store: State<'_, PlatformStore>, manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    check_preset_scope(&window)?;
    stop_domain_tunnel(&domain, &store, &manager).await
}

pub(crate) async fn stop_domain_tunnel(name: &str, store: &PlatformStore, manager: &WorkspaceManager) -> Result<(), String> {
    let _operation = manager.operations.lock().await;
    let domain = find_domain(store, name)?;
    if let Some(setup) = manager.setup_tunnels.lock().await.remove(&domain.id) { setup.stop().await; }
    Ok(())
}

/// Caller holds the operation lock. A publication takes over the same local port.
pub(crate) async fn finish_setup(manager: &WorkspaceManager, account: &Account) -> Result<(), String> {
    let mut setups = manager.setup_tunnels.lock().await;
    let id = setups.iter().find(|(_, setup)| setup.tunnel_id == account.tunnel_id)
        .map(|(id, setup)| setup.matches(account).map(|_| id.clone())).transpose()?;
    if let Some(id) = id {
        if let Some(setup) = setups.remove(&id) { setup.stop().await; }
    }
    Ok(())
}

#[tauri::command]
pub fn list_saved_domains(store: State<'_, PlatformStore>) -> Result<Vec<crate::models::SavedDomain>, String> {
    Ok(store.snapshot()?.saved_domains)
}

/// One-time move of saved domains from the app's browser storage. Only entries whose token is in the vault are kept.
#[tauri::command]
pub fn import_saved_domains(
    window: WebviewWindow, domains: Vec<crate::models::SavedDomain>, store: State<'_, PlatformStore>,
) -> Result<Vec<crate::models::SavedDomain>, String> {
    check_preset_scope(&window)?;
    for domain in domains.into_iter().take(200) {
        let known = store.snapshot()?.saved_domains.iter().any(|d| d.id == domain.id);
        let valid = hostname(&domain.hostname).is_ok() && domain.port != 0 && domain.host_port != 0 && domain.host_port != 7443
            && preset_key(&domain.credential_environment_id, domain.port, &domain.id).is_ok_and(|key| migrated_password(&key).is_ok_and(|value| value.is_some()));
        if !known && valid {
            // A conflicting duplicate is skipped rather than failing the whole import.
            let _ = remember_domain(&store, domain);
        }
    }
    Ok(store.snapshot()?.saved_domains)
}

fn check_scope(window: &WebviewWindow, store: &PlatformStore, id: &str) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Manage Cloudflare credentials from the main Yougori window".into());
    }
    if id != "remote-access" && !store
        .snapshot()?
        .environments
        .iter()
        .any(|env| env.id == id)
    {
        return Err("Environment not found".into());
    }
    Ok(())
}

fn check_preset_scope(window: &WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err("Manage Cloudflare credentials from the main Yougori window".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn saved_cloudflare_account(
    window: WebviewWindow,
    environment_id: String,
    port: u16,
    store: State<'_, PlatformStore>,
    manager: State<'_, WorkspaceManager>,
) -> Result<SavedAccount, String> {
    check_scope(&window, &store, &environment_id)?;
    saved_for_local_client(environment_id, port, &store, &manager).await
}

pub(crate) async fn saved_for_local_client(
    environment_id: String,
    port: u16,
    store: &PlatformStore,
    manager: &WorkspaceManager,
) -> Result<SavedAccount, String> {
    if environment_id != "remote-access" && !store.snapshot()?.environments.iter().any(|env| env.id == environment_id) {
        return Err("Environment not found".into());
    }
    let _operation = manager.operations.lock().await;
    Ok(match load(&environment_id, port)? {
        Some(value) => SavedAccount {
            saved: true,
            hostname: hostname(&value.hostname)?,
            host_port: Some(value.host_port),
        },
        None => SavedAccount::default(),
    })
}

#[tauri::command]
pub async fn forget_cloudflare_account(
    window: WebviewWindow,
    environment_id: String,
    port: u16,
    store: State<'_, PlatformStore>,
    manager: State<'_, WorkspaceManager>,
) -> Result<(), String> {
    check_scope(&window, &store, &environment_id)?;
    forget_for_local_client(environment_id, port, &store, &manager).await
}

pub(crate) async fn forget_for_local_client(
    environment_id: String,
    port: u16,
    store: &PlatformStore,
    manager: &WorkspaceManager,
) -> Result<(), String> {
    if environment_id != "remote-access" && !store.snapshot()?.environments.iter().any(|env| env.id == environment_id) {
        return Err("Environment not found".into());
    }
    let _operation = manager.operations.lock().await;
    delete_saved_password(&credential_key(&environment_id, port)?)
}

// A private, non-secret empty config prevents a user's global cloudflared config
// from changing Quick Tunnel behavior. Remove only this unique file on teardown.
pub(crate) struct ConfigFile(PathBuf);
impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl ConfigFile {
    async fn create(root: &Path) -> Result<Self, String> {
        let folder = root.join("tools/cloudflare-sessions");
        tokio::fs::create_dir_all(&folder)
            .await
            .map_err(|_| "Cannot prepare tunnel config directory")?;
        let path = folder.join(format!("{}.json", Uuid::new_v4().simple()));
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|_| "Cannot prepare tunnel config")?;
        let file = Self(path);
        output
            .write_all(b"{}\n")
            .await
            .map_err(|_| "Cannot write tunnel config")?;
        // Tokio file writes may still be queued when write_all returns. The
        // external tunnel process must not see an empty configuration file.
        output.flush().await.map_err(|_| "Cannot flush tunnel config")?;
        Ok(file)
    }
}

pub(crate) struct Started {
    pub child: Child,
    pub logs: JoinHandle<()>,
    pub url: String,
    pub config: ConfigFile,
}

fn command(
    executable: &Path,
    config: &Path,
    port: u16,
    account: Option<&Account>,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(executable);
    // Override only cloudflared-specific configuration, not normal OS networking.
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("TUNNEL_") || upper.starts_with("CLOUDFLARED_") {
            command.env_remove(name);
        }
    }
    command
        .args(["tunnel", "--no-autoupdate", "--config"])
        .arg(config)
        .args(["--output", "json"]);
    if let Some(account) = account {
        // Supported environment variable keeps the token out of process listings.
        command
            .arg("run")
            .env("TUNNEL_TOKEN", &account.credentials.token);
    } else {
        command.args(["--url", &format!("http://127.0.0.1:{port}")]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    background(&mut command);
    command
}

async fn bounded_line(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<String>, String> {
    let mut buffer = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| "Cannot read tunnel status")?;
        if available.is_empty() {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Ok(Some(String::from_utf8_lossy(&buffer).into_owned()))
            };
        }
        let take = available
            .iter()
            .position(|&b| b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if buffer.len() + take > 64 * 1024 {
            return Err("Cloudflare returned an oversized status message".into());
        }
        let complete = available[take - 1] == b'\n';
        buffer.extend_from_slice(&available[..take]);
        reader.consume(take);
        if complete {
            return Ok(Some(String::from_utf8_lossy(&buffer).into_owned()));
        }
    }
}

fn quick_url(line: &str) -> Option<String> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || ":/.-".contains(c)))
        .find_map(|word| {
            let url = url::Url::parse(word).ok()?;
            let host = url.host_str()?;
            let label = host.strip_suffix(".trycloudflare.com")?;
            (url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .then(|| format!("https://{host}"))
        })
}

pub(crate) async fn start(
    executable: &Path,
    root: &Path,
    port: u16,
    account: Option<&Account>,
) -> Result<Started, String> {
    let mut retry = if account.is_none() { Some(QUICK_RETRY.lock().await) } else { None };
    if let Some(error) = retry.as_ref().and_then(|retry| retry.deferred(std::time::Instant::now())) {
        return Err(error);
    }
    let result = start_once(executable, root, port, account).await;
    if let Some(retry) = &mut retry {
        let limited = result.as_ref().is_err_and(|error| error.contains(QUICK_RATE_LIMIT));
        retry.finished(std::time::Instant::now(), result.is_ok(), limited);
        if limited {
            return Err(retry.deferred(std::time::Instant::now()).unwrap());
        }
    }
    result
}

async fn start_once(executable: &Path, root: &Path, port: u16, account: Option<&Account>) -> Result<Started, String> {
    let config = ConfigFile::create(root).await?;
    let mut child = command(executable, &config.0, port, account)
        .spawn()
        .map_err(|_| "Could not start Cloudflare Tunnel")?;
    let mut reader = BufReader::new(child.stderr.take().ok_or("Missing tunnel status output")?);
    let status = tokio::time::timeout(
        Duration::from_secs(45),
        connected_url(&mut reader, account.map(Account::public_url)),
    )
    .await;
    let result = status
        .map_err(|_| startup_error(account.is_some(), true))
        .and_then(|r| r);
    let url = match result {
        Ok(url) => url,
        Err(error) => {
            let _ = child.kill().await;
            return Err(error);
        }
    };
    // Do not persist or expose raw helper logs: they may contain account details.
    let logs = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    });
    Ok(Started {
        child,
        logs,
        url,
        config,
    })
}

async fn connected_url(
    reader: &mut (impl AsyncBufRead + Unpin),
    account_url: Option<String>,
) -> Result<String, String> {
    let named = account_url.is_some();
    let mut url = account_url;
    let mut connected = false;
    while let Some(line) = bounded_line(reader).await? {
        if !named && quick_rate_limited(&line) {
            // Never expose raw helper output containing account details.
            return Err(QUICK_RATE_LIMIT.into());
        }
        if !named && url.is_none() {
            url = quick_url(&line);
        }
        if let Ok(value) = serde_json::from_str::<Value>(&line) {
            connected |= value["message"].as_str() == Some("Registered tunnel connection");
        }
        if connected {
            if let Some(url) = url {
                return Ok(url);
            }
        }
    }
    Err(startup_error(named, false))
}

fn quick_rate_limited(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("error code: 1015") || lower.contains("status code: 429")
        || lower.contains("429 too many requests") || lower.contains("too many requests")
}

fn startup_error(named: bool, timed_out: bool) -> String {
    let reason = if timed_out {
        "did not connect within 45 seconds"
    } else {
        "exited before connecting"
    };
    if named {
        format!("Cloudflare account tunnel {reason}. Check the tunnel token, dashboard configuration, and network access. No Quick Tunnel fallback was started.")
    } else {
        format!("Cloudflare Quick Tunnel {reason}. Check this PC's Internet connection and whether a firewall or VPN is blocking Cloudflare, then retry. No account or tunnel token is required.")
    }
}

#[cfg(test)]
mod tests;
