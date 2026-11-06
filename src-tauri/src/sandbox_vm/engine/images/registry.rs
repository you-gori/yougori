//! OCI Distribution pulls, resolving a selected tag to verified immutable content. No ambient login, cookies, proxies or host
//! extraction. Network I/O finishes before the shared catalog is locked. Only the
//! selected platform's declared objects are fetched; each is bounded and verified.
use super::*;
use crate::sandbox_contract::oci::{
    parse_index, parse_manifest, select_platform, MemoryBlobs, VerifiedBlob,
};
use reqwest::{header, Client, Response, StatusCode, Url};
use tokio::runtime::Handle;

const ACCEPT: &str =
    "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
const TOKEN_LIMIT: u64 = 32 << 10;

enum Selector {
    Digest(OciDigest),
    Tag(String),
}
impl std::fmt::Display for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest(digest) => write!(f, "{digest}"),
            Self::Tag(tag) => f.write_str(tag),
        }
    }
}

pub(super) struct Reference {
    origin: Url,
    repository: String,
    selector: Selector,
}

impl Reference {
    pub(super) fn parse(input: &str) -> Result<Self, String> {
        if input.len() > 1024
            || input.contains(['%', '\\', '?', '#'])
            || input.chars().any(char::is_control)
        {
            return Err("Use an HTTPS registry/repository@sha256:DIGEST without credentials or query parameters".into());
        }
        let (location, selector) = if let Some((location, digest)) = input.rsplit_once('@') {
            (
                location,
                Selector::Digest(OciDigest::parse(digest).map_err(|e| e.to_string())?),
            )
        } else {
            let slash = input
                .rfind('/')
                .ok_or("Include the registry and repository in the image reference")?;
            let (location, tag) = match input.rsplit_once(':') {
                Some((location, tag)) if location.len() > slash => (location, tag),
                _ => (input, "latest"),
            };
            if tag.is_empty()
                || tag.len() > 128
                || !tag.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_alphanumeric() || b == b'_' || (i > 0 && b".-".contains(&b))
                })
            {
                return Err("Invalid registry image tag".into());
            }
            (location, Selector::Tag(tag.to_owned()))
        };
        let url = Url::parse(&if location.starts_with("https://") {
            location.to_owned()
        } else {
            format!("https://{location}")
        })
        .map_err(|_| "Invalid registry reference")?;
        plain_https(&url)?;
        let repository = url.path().strip_prefix('/').unwrap_or_default();
        if repository.is_empty()
            || repository.len() > 255
            || repository.split('/').any(|part| {
                part.is_empty()
                    || !part.as_bytes()[0].is_ascii_alphanumeric()
                    || !part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                    || !part.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    })
            })
        {
            return Err("Invalid registry repository name".into());
        }
        // Url normalizes dot path components; reject them in the original input too.
        if location.split('/').any(|part| matches!(part, "." | "..")) {
            return Err("Registry paths cannot contain dot components".into());
        }
        let repository = repository.to_owned();
        let mut origin = Url::parse(&format!("{}/", url.origin().ascii_serialization()))
            .map_err(|_| "Invalid registry origin")?;
        // Docker Hub's image namespace and Distribution endpoint differ.
        if origin.host_str() == Some("docker.io") {
            origin
                .set_host(Some("registry-1.docker.io"))
                .map_err(|_| "Invalid registry host")?;
        }
        Ok(Self {
            origin,
            repository,
            selector,
        })
    }

    fn endpoint(&self, manifests: bool, digest: impl std::fmt::Display) -> Url {
        let mut url = self.origin.clone();
        url.set_path(&format!(
            "/v2/{}/{}/{digest}",
            self.repository,
            if manifests { "manifests" } else { "blobs" }
        ));
        url
    }

    pub(super) fn provenance(&self) -> Value {
        json!({"kind": "registry", "origin": self.origin.as_str(), "repository": self.repository,
            "reference": self.selector.to_string(), "selection": "owner_selected"})
    }
}

fn plain_https(url: &Url) -> Result<(), String> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Registry transfers require HTTPS without URL credentials or fragments".into());
    }
    Ok(())
}

fn bearer(secret: &str) -> Result<header::HeaderValue, String> {
    if secret.is_empty() || secret.len() > 16 << 10 || !secret.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("Invalid registry bearer token".into());
    }
    let mut value = header::HeaderValue::from_str(&format!("Bearer {secret}"))
        .map_err(|_| "Invalid registry bearer token")?;
    value.set_sensitive(true);
    Ok(value)
}

pub(super) struct Download {
    reference: Reference,
    client: Client,
    runtime: Handle,
    authorization: Option<header::HeaderValue>,
    supplied_token: bool,
    auth_origin: Url,
}

impl Download {
    pub(super) fn new(
        reference: Reference,
        secret: Option<String>,
        auth_origin: Option<&str>,
        runtime: Handle,
    ) -> Result<Self, String> {
        let supplied_token = secret.is_some();
        let authorization = secret.as_deref().map(bearer).transpose()?;
        let auth_origin = match auth_origin {
            Some(value) => {
                let url =
                    Url::parse(value).map_err(|_| "Invalid registry authentication origin")?;
                plain_https(&url)?;
                if url.path() != "/" || url.query().is_some() {
                    return Err("Use only the HTTPS origin of the registry token service".into());
                }
                url
            }
            None if reference.origin.host_str() == Some("registry-1.docker.io") => {
                Url::parse("https://auth.docker.io/")
                    .map_err(|_| "Invalid Docker authentication origin")?
            }
            None => reference.origin.clone(),
        };
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .cookie_store(false)
            .referer(false)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|_| "Cannot initialize the registry transport")?;
        Ok(Self {
            reference,
            client,
            runtime,
            authorization,
            supplied_token,
            auth_origin,
        })
    }

    pub(super) fn provenance(&self) -> Value {
        self.reference.provenance()
    }

    /// Called only on the existing blocking worker, after importer admission. The
    /// total deadline includes redirects and token requests; the VM lease also remains
    /// bounded. No catalog mutex is held across network I/O.
    pub(super) fn fetch(
        &mut self,
        platform: &Platform,
        alive: &dyn Fn() -> bool,
    ) -> Result<(BlobReference, MemoryBlobs), String> {
        let runtime = self.runtime.clone();
        runtime.block_on(async {
            tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(300), self.fetch_async(platform)) =>
                    result.map_err(|_| "Registry import exceeded its five-minute transfer budget".to_owned())?,
                _ = async {
                    while alive() { tokio::time::sleep(Duration::from_millis(250)).await; }
                } => Err("Registry download cancelled because its importer VM stopped".into()),
            }
        })
    }

    async fn fetch_async(
        &mut self,
        platform: &Platform,
    ) -> Result<(BlobReference, MemoryBlobs), String> {
        let bounds = limits();
        let response = self
            .get(self.reference.endpoint(true, &self.reference.selector))
            .await?;
        let media = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| MediaType::from_exact(v.split(';').next().unwrap_or_default().trim()))
            .filter(|m| m.is_index() || m.is_manifest())
            .ok_or("Registry root is not an OCI image index or manifest")?;
        let declared_digest = response
            .headers()
            .get("docker-content-digest")
            .map(|value| {
                value
                    .to_str()
                    .map_err(|_| "Invalid registry digest header")
                    .and_then(|value| {
                        OciDigest::parse(value).map_err(|_| "Invalid registry digest header")
                    })
            })
            .transpose()?;
        let bytes = body(response, bounds.max_document_bytes).await?;
        let digest = match &self.reference.selector {
            Selector::Digest(digest) => *digest,
            Selector::Tag(_) => OciDigest::of(&bytes),
        };
        if declared_digest.is_some_and(|value| value != digest) {
            return Err("Registry digest header does not match the selected image".into());
        }
        let root = BlobReference {
            media_type: media,
            digest,
            size_bytes: bytes.len() as u64,
        };
        let verified = VerifiedBlob::verify(root, bytes).map_err(|e| e.to_string())?;
        let mut blobs = MemoryBlobs::new();
        blobs.insert(verified.bytes().to_vec());
        let manifest = if media.is_index() {
            let index = parse_index(&verified, &bounds).map_err(|e| e.to_string())?;
            let selected = select_platform(&index, platform)
                .map_err(|e| e.to_string())?
                .reference();
            let blob = self
                .object(selected, true, bounds.max_document_bytes)
                .await?;
            blobs.insert(blob.bytes().to_vec());
            parse_manifest(&blob, &bounds).map_err(|e| e.to_string())?
        } else {
            parse_manifest(&verified, &bounds).map_err(|e| e.to_string())?
        };
        let total = manifest
            .layers
            .iter()
            .try_fold(0u64, |sum, layer| sum.checked_add(layer.size_bytes))
            .ok_or("Registry layer size overflow")?;
        if total > bounds.max_image_compressed_bytes
            || manifest
                .layers
                .iter()
                .any(|l| l.size_bytes > bounds.max_layer_compressed_bytes)
        {
            return Err("Registry image exceeds the compressed image budget".into());
        }
        let config = self
            .object(
                manifest.config.reference(),
                false,
                bounds.max_document_bytes,
            )
            .await?;
        blobs.insert(config.bytes().to_vec());
        for layer in &manifest.layers {
            let blob = self
                .object(layer.reference(), false, bounds.max_layer_compressed_bytes)
                .await?;
            blobs.insert(blob.bytes().to_vec());
        }
        Ok((root, blobs))
    }

    async fn object(
        &mut self,
        reference: BlobReference,
        manifest: bool,
        limit: u64,
    ) -> Result<VerifiedBlob, String> {
        if reference.size_bytes > limit {
            return Err("Registry object exceeds its declared budget".into());
        }
        let response = self
            .get(self.reference.endpoint(manifest, reference.digest))
            .await?;
        let bytes = body(response, reference.size_bytes).await?;
        VerifiedBlob::verify(reference, bytes).map_err(|e| e.to_string())
    }

    async fn get(&mut self, initial: Url) -> Result<Response, String> {
        let mut url = initial;
        let mut crossed_origin = false;
        let mut challenged = false;
        for _ in 0..=4 {
            let at_registry = url.origin() == self.reference.origin.origin();
            let mut request = self.client.get(url.clone()).header(header::ACCEPT, ACCEPT);
            if at_registry && !crossed_origin {
                if let Some(auth) = &self.authorization {
                    request = request.header(header::AUTHORIZATION, auth.clone());
                }
            }
            let response = request
                .send()
                .await
                .map_err(|_| "Registry request failed (connection, TLS or timeout)")?;
            if response.status() == StatusCode::UNAUTHORIZED
                && at_registry
                && !crossed_origin
                && !challenged
                && !self.supplied_token
            {
                let challenge = response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .and_then(|v| v.to_str().ok())
                    .ok_or("Registry requires a bearer token supplied through protected input")?;
                let token_url = challenge_url(challenge, &self.reference.repository)?;
                if token_url.origin() != self.auth_origin.origin() {
                    return Err("Registry token service uses another origin; explicitly choose authOrigin or supply a bearer token through protected input".into());
                }
                // Anonymous token exchange: never forward registry credentials to a
                // realm, never follow its redirects, never ask for push/refresh access.
                let response = self
                    .client
                    .get(token_url)
                    .send()
                    .await
                    .map_err(|_| "Registry token service unavailable")?;
                if response.status() != StatusCode::OK {
                    return Err(
                        "Registry requires a bearer token supplied through protected input".into(),
                    );
                }
                let bytes = body(response, TOKEN_LIMIT).await?;
                #[derive(Deserialize)]
                struct Token {
                    token: Option<String>,
                    access_token: Option<String>,
                }
                let token: Token = serde_json::from_slice(&bytes)
                    .map_err(|_| "Invalid registry token response")?;
                let token = match (token.token, token.access_token) {
                    (Some(a), Some(b)) if a != b => {
                        return Err("Registry returned conflicting tokens".into())
                    }
                    (Some(a), _) | (_, Some(a)) => a,
                    _ => return Err("Registry token response has no token".into()),
                };
                self.authorization = Some(bearer(&token)?);
                challenged = true;
                continue;
            }
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or("Registry redirect has no location")?;
                let next = url
                    .join(location)
                    .map_err(|_| "Invalid registry redirect")?;
                plain_https(&next)?;
                crossed_origin |= next.origin() != self.reference.origin.origin();
                url = next;
                continue;
            }
            if response.status() != StatusCode::OK {
                return Err(format!(
                    "Registry download refused (HTTP {})",
                    response.status().as_u16()
                ));
            }
            return Ok(response);
        }
        Err("Registry redirect/authentication limit exceeded".into())
    }
}

async fn body(mut response: Response, limit: u64) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|n| n > limit) {
        return Err("Registry response exceeds its byte budget".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Registry transfer was interrupted")?
    {
        if (bytes.len() as u64).saturating_add(chunk.len() as u64) > limit {
            return Err("Registry response exceeds its byte budget".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn challenge_url(challenge: &str, repository: &str) -> Result<Url, String> {
    // Bound and deliberately accept only the standard quoted Bearer attributes.
    // No hand-built URL query from an untrusted server and no broadening its scope.
    if challenge.len() > 4096 {
        return Err("Registry authentication challenge is too large".into());
    }
    let (scheme, attributes) = challenge
        .split_once(' ')
        .ok_or("Unsupported registry authentication challenge")?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err("Registry requires an explicit bearer token".into());
    }
    let mut fields = BTreeMap::new();
    for item in attributes.split(',') {
        let (name, value) = item
            .trim()
            .split_once('=')
            .ok_or("Invalid registry authentication challenge")?;
        let value = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or("Invalid registry authentication challenge")?;
        if !matches!(name, "realm" | "service" | "scope")
            || value.contains(['"', '\\'])
            || value.chars().any(char::is_control)
            || fields.insert(name, value).is_some()
        {
            return Err("Invalid registry authentication challenge".into());
        }
    }
    let mut url = Url::parse(
        fields
            .get("realm")
            .ok_or("Registry challenge has no realm")?,
    )
    .map_err(|_| "Invalid registry token realm")?;
    plain_https(&url)?;
    if url.query().is_some() {
        return Err("Registry token realm cannot contain query parameters".into());
    }
    let scope = format!("repository:{repository}:pull");
    if fields.get("scope").is_some_and(|s| *s != scope) {
        return Err("Registry requested a different repository or permissions".into());
    }
    let service = fields
        .get("service")
        .ok_or("Registry challenge has no service")?;
    if service.is_empty() || service.len() > 256 {
        return Err("Invalid registry token service".into());
    }
    url.query_pairs_mut()
        .append_pair("service", service)
        .append_pair("scope", &scope);
    Ok(url)
}

#[cfg(test)]
mod tests;
