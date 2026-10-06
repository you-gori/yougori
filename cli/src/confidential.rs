//! Client-held encryption and independently pinned attestation for Network inference.
//! Nothing in this module treats a website/provider assertion as hardware evidence.
use age::x25519;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const VERSION: u8 = 1;
pub mod command;
pub mod runner;
pub const MAX_CIPHERTEXT: usize = 1024 * 1024;
pub const EMPTY_POLICY: &str = include_str!("../../runtime/confidential/policy.json");
const POLICY_ERROR: &str =
    "No independently approved confidential hardware policy is installed. No prompt was sent.";
const PROOF_ERROR: &str = "Confidential attestation verification failed. No prompt was sent.";
const REPLY_ERROR: &str = "The confidential response failed authentication";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub version: u8,
    pub expires_at: u64,
    pub issuer: String,
    pub keys: Vec<VerifierKey>,
    pub images: Vec<Image>,
    pub revoked_kids: Vec<String>,
}
#[derive(Clone)]
pub struct VerifiedPolicy {
    policy: Policy,
    checked_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierKey {
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Image {
    pub model: String,
    pub revision: String,
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
    /// Independent verifier policy must enforce local CPU/GPU secure association
    /// and all attached GPUs in CC-On mode, in addition to our claim checks.
    pub appraisal_policy_id: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub node_id: String,
    pub model: String,
    pub revision: String,
    pub nonce: String,
    pub recipient: String,
    pub signing_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proof {
    pub descriptor: Descriptor,
    pub token: String,
}

fn random() -> Result<String, String> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Cannot generate confidential request randomness")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn hash(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}
fn decode(value: &str, limit: usize) -> Result<Vec<u8>, String> {
    if value.len() > limit * 4 / 3 + 4 {
        return Err(PROOF_ERROR.into());
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PROOF_ERROR.into())
}
fn fixed(value: &str, size: usize) -> bool {
    decode(value, size).is_ok_and(|v| v.len() == size)
}
fn measured(value: &str) -> bool {
    value.len() == 96 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
impl Policy {
    fn retain_published_keys(&mut self, catalog: &Value) -> Result<(), String> {
        let published = catalog["keys"].as_array().ok_or(PROOF_ERROR)?;
        self.keys.retain(|pin| {
            published.iter().any(|key| {
                key["kid"] == pin.kid
                    && key["kty"] == "RSA"
                    && key["use"] == "sig"
                    && key["alg"] == pin.alg
                    && key["n"] == pin.n
                    && key["e"] == pin.e
            })
        });
        if self.keys.is_empty() {
            return Err("No pinned verifier key is currently published by the independent vendor. No prompt was sent.".into());
        }
        Ok(())
    }
    async fn check_vendor_keys(
        mut self,
        client: &reqwest::Client,
    ) -> Result<VerifiedPolicy, String> {
        // Only these literal independent vendor origins are allowed by check().
        // Never follow a JWT's jku or a website/provider-supplied certificate URL.
        let mut response = client
            .get(format!("{}/certs", self.issuer))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|_| PROOF_ERROR)?;
        if !response.status().is_success() {
            return Err(PROOF_ERROR.into());
        }
        let mut bytes = Vec::new();
        while let Some(part) = response.chunk().await.map_err(|_| PROOF_ERROR)? {
            if bytes.len() + part.len() > 262144 {
                return Err(PROOF_ERROR.into());
            }
            bytes.extend_from_slice(&part);
        }
        let catalog: Value = serde_json::from_slice(&bytes).map_err(|_| PROOF_ERROR)?;
        self.retain_published_keys(&catalog)?;
        Ok(VerifiedPolicy {
            policy: self,
            checked_at: now(),
        })
    }
    pub fn load(path: Option<&str>, now: u64) -> Result<Self, String> {
        let bytes = match path {
            Some(path) => {
                let file = std::fs::File::open(path).map_err(|_| POLICY_ERROR)?;
                let mut data = Vec::new();
                file.take(262145)
                    .read_to_end(&mut data)
                    .map_err(|_| POLICY_ERROR)?;
                data
            }
            None => EMPTY_POLICY.as_bytes().to_vec(),
        };
        if bytes.len() > 262144 {
            return Err(POLICY_ERROR.into());
        }
        let policy: Self = serde_json::from_slice(&bytes).map_err(|_| POLICY_ERROR)?;
        policy.check(now)?;
        Ok(policy)
    }
    fn check(&self, now: u64) -> Result<(), String> {
        if self.version != VERSION
            || self.expires_at <= now
            || self.expires_at > now.saturating_add(7 * 86400)
            || self.keys.is_empty()
            || self.images.is_empty()
            || ![
                "https://portal.trustauthority.intel.com",
                "https://portal.eu.trustauthority.intel.com",
            ]
            .contains(&self.issuer.as_str())
            || self.images.iter().any(|p| {
                p.appraisal_policy_id.is_empty()
                    || p.revision.len() != 40
                    || !p.revision.bytes().all(|b| b.is_ascii_hexdigit())
                    || [&p.mrtd, &p.rtmr0, &p.rtmr1, &p.rtmr2, &p.rtmr3]
                        .iter()
                        .any(|v| !measured(v))
            })
        {
            return Err(POLICY_ERROR.into());
        }
        Ok(())
    }
}

/// Owns the fresh challenge and expected identity. Neither can be substituted by
/// a gateway response. Verifier keys/measurements are supplied only by local policy.
pub struct Challenge {
    nonce: String,
    node: String,
    model: String,
}
impl Challenge {
    pub fn new(node: String, model: String) -> Result<Self, String> {
        Ok(Self {
            nonce: random()?,
            node,
            model,
        })
    }
    pub fn request(&self) -> Value {
        json!({"nodeId":self.node,"nonce":self.nonce})
    }
    pub fn verify(
        self,
        proof: Proof,
        verified_policy: &VerifiedPolicy,
        now: u64,
    ) -> Result<VerifiedPeer, String> {
        if verified_policy.checked_at > now || now.saturating_sub(verified_policy.checked_at) > 60 {
            return Err(PROOF_ERROR.into());
        }
        let policy = &verified_policy.policy;
        policy.check(now)?;
        let d = &proof.descriptor;
        if d.version != VERSION
            || d.node_id != self.node
            || d.model != self.model
            || d.nonce != self.nonce
            || d.issued_at > now
            || now.saturating_sub(d.issued_at) > 60
            || d.expires_at <= now
            || d.expires_at > d.issued_at.saturating_add(60)
            || !fixed(&d.nonce, 32)
            || !fixed(&d.signing_key, 32)
            || d.recipient.parse::<x25519::Recipient>().is_err()
        {
            return Err(PROOF_ERROR.into());
        }
        let parts = proof.token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 || proof.token.len() > 262144 {
            return Err(PROOF_ERROR.into());
        }
        let header: Value =
            serde_json::from_slice(&decode(parts[0], 16384)?).map_err(|_| PROOF_ERROR)?;
        if header["typ"] != "JWT" || header.get("crit").is_some() || header.get("b64").is_some() {
            return Err(PROOF_ERROR.into());
        }
        let key = policy
            .keys
            .iter()
            .find(|k| {
                header["kid"] == k.kid
                    && header["alg"] == k.alg
                    && !policy.revoked_kids.contains(&k.kid)
            })
            .ok_or(PROOF_ERROR)?;
        let algorithm = match key.alg.as_str() {
            "PS384" => &signature::RSA_PSS_2048_8192_SHA384,
            "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
            _ => return Err(PROOF_ERROR.into()),
        };
        // Deliberately ignore JWT jku/jwk/x5u: no issuer-supplied network key discovery.
        let n = decode(&key.n, 1024)?;
        let e = decode(&key.e, 8)?;
        signature::RsaPublicKeyComponents { n: &n, e: &e }
            .verify(
                algorithm,
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &decode(parts[2], 1024)?,
            )
            .map_err(|_| PROOF_ERROR)?;
        let claims: Value =
            serde_json::from_slice(&decode(parts[1], 196608)?).map_err(|_| PROOF_ERROR)?;
        let iat = claims["iat"].as_u64().ok_or(PROOF_ERROR)?;
        let exp = claims["exp"].as_u64().ok_or(PROOF_ERROR)?;
        let nbf = claims["nbf"].as_u64().ok_or(PROOF_ERROR)?;
        if claims["iss"] != policy.issuer
            || claims["intuse"] != "generic"
            || iat > now
            || now.saturating_sub(iat) > 60
            || nbf > now
            || exp <= now
            || exp > iat.saturating_add(300)
            || claims["jti"].as_str().is_none_or(str::is_empty)
        {
            return Err(PROOF_ERROR.into());
        }
        let tdx = &claims["tdx"];
        if tdx["attester_type"] != "TDX"
            || tdx["attester_tcb_status"] != "UpToDate"
            || tdx["dbgstat"] != "disabled"
            || tdx["tdx_is_debuggable"] != false
            || tdx["tdx_is_migratable"] != false
            || tdx["tdx_td_attributes_debug"] != false
            || tdx["tdx_td_attributes_migratable"] != false
            || tdx["tdx_td_attributes_perfmon"] != false
            || tdx["attester_runtime_data"] != serde_json::to_value(d).map_err(|_| PROOF_ERROR)?
        {
            return Err(PROOF_ERROR.into());
        }
        let matched = claims["policy_ids_matched"].as_array().ok_or(PROOF_ERROR)?;
        if claims["policy_ids_unmatched"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
        {
            return Err(PROOF_ERROR.into());
        }
        let _image = policy
            .images
            .iter()
            .find(|p| {
                p.model == d.model
                    && p.revision == d.revision
                    && tdx["tdx_mrtd"] == p.mrtd
                    && tdx["tdx_rtmr0"] == p.rtmr0
                    && tdx["tdx_rtmr1"] == p.rtmr1
                    && tdx["tdx_rtmr2"] == p.rtmr2
                    && tdx["tdx_rtmr3"] == p.rtmr3
                    && matched.iter().any(|id| id == &p.appraisal_policy_id)
            })
            .ok_or(PROOF_ERROR)?;
        let gpu = &claims["nvgpu"];
        if gpu["attester_type"] != "NVGPU" || gpu["x-nvidia-overall-att-result"] != true {
            return Err(PROOF_ERROR.into());
        }
        let devices = gpu["claim_details"].as_object().ok_or(PROOF_ERROR)?;
        if devices.is_empty() || devices.len() > 64 {
            return Err(PROOF_ERROR.into());
        }
        for device in devices.values() {
            if device["iss"] != "https://nras.attestation.nvidia.com"
                || device["dbgstat"] != "disabled"
                || device["secboot"] != true
                || device["measres"] != "success"
                || device.get("x-nvidia-attestation-warning") != Some(&Value::Null)
            {
                return Err(PROOF_ERROR.into());
            }
            for flag in [
                "x-nvidia-gpu-attestation-report-signature-verified",
                "x-nvidia-gpu-attestation-report-nonce-match",
                "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
                "x-nvidia-gpu-driver-rim-signature-verified",
                "x-nvidia-gpu-driver-rim-version-match",
                "x-nvidia-gpu-vbios-rim-signature-verified",
                "x-nvidia-gpu-vbios-rim-version-match",
            ] {
                if device[flag] != true {
                    return Err(PROOF_ERROR.into());
                }
            }
            for chain in [
                "x-nvidia-gpu-attestation-report-cert-chain",
                "x-nvidia-gpu-driver-rim-cert-chain",
                "x-nvidia-gpu-vbios-rim-cert-chain",
            ] {
                if device[chain]["x-nvidia-cert-ocsp-status"] != "good"
                    || device[chain]["x-nvidia-cert-status"] != "valid"
                    || device[chain]["x-nvidia-cert-ocsp-response-valid"] != true
                    || device[chain]["x-nvidia-cert-ocsp-nonce-matches"] != true
                {
                    return Err(PROOF_ERROR.into());
                }
            }
        }
        Ok(VerifiedPeer {
            descriptor: proof.descriptor,
        })
    }
}

fn encrypt(recipient: &str, bytes: &[u8]) -> Result<String, String> {
    let key: x25519::Recipient = recipient
        .parse()
        .map_err(|_| "Invalid confidential recipient")?;
    let crypt = age::Encryptor::with_recipients(std::iter::once(&key as &dyn age::Recipient))
        .map_err(|_| "Cannot encrypt confidential request")?;
    let mut encrypted = Vec::new();
    let mut writer = crypt
        .wrap_output(&mut encrypted)
        .map_err(|_| "Cannot encrypt confidential request")?;
    writer
        .write_all(bytes)
        .map_err(|_| "Cannot encrypt confidential request")?;
    writer
        .finish()
        .map_err(|_| "Cannot encrypt confidential request")?;
    Ok(STANDARD.encode(encrypted))
}
fn decrypt(identity: &x25519::Identity, ciphertext: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if ciphertext.len() > MAX_CIPHERTEXT * 4 / 3 + 4 {
        return Err(REPLY_ERROR.into());
    }
    let bytes = STANDARD.decode(ciphertext).map_err(|_| REPLY_ERROR)?;
    let decryptor = age::Decryptor::new(&bytes[..]).map_err(|_| REPLY_ERROR)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| REPLY_ERROR)?;
    let mut output = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_CIPHERTEXT as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| REPLY_ERROR)?;
    if output.len() > MAX_CIPHERTEXT {
        return Err(REPLY_ERROR.into());
    }
    Ok(output)
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub node_id: String,
    pub model: String,
    pub request_id: String,
    pub reply_recipient: String,
    pub expires_at: u64,
    pub max_tokens: u64,
    pub ciphertext: String,
}
pub struct VerifiedPeer {
    descriptor: Descriptor,
}
pub struct PendingReply {
    identity: x25519::Identity,
    descriptor: Descriptor,
    request_id: String,
    request_hash: String,
    max_tokens: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub version: u8,
    pub node_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub ciphertext_hash: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedReply {
    pub ciphertext: String,
    pub receipt: Receipt,
    pub signature: String,
}
impl VerifiedPeer {
    pub fn prepare(self, request: Value, now: u64) -> Result<(Envelope, PendingReply), String> {
        if self.descriptor.expires_at <= now {
            return Err(PROOF_ERROR.into());
        }
        if request["model"] != self.descriptor.model || request["stream"].as_bool().unwrap_or(false)
        {
            return Err("Confidential requests require the attested repository ID and non-streaming text chat".into());
        }
        let identity = x25519::Identity::generate();
        let id = random()?;
        let max_tokens = request["max_tokens"].as_u64().unwrap_or(1024);
        if !(1..=4096).contains(&max_tokens) {
            return Err("max_tokens must be 1–4096".into());
        }
        let reply_recipient = identity.to_public().to_string();
        let expires_at = now.saturating_add(120);
        let data=Zeroizing::new(serde_json::to_vec(&json!({"version":VERSION,"nodeId":self.descriptor.node_id,"requestId":id,"replyRecipient":reply_recipient,"expiresAt":expires_at,"maxTokens":max_tokens,"request":request})).map_err(|_| "Cannot encode confidential request")?);
        if data.len() > 65536 {
            return Err("Confidential request exceeds 64 KiB".into());
        }
        let ciphertext = encrypt(&self.descriptor.recipient, &data)?;
        let pending = PendingReply {
            identity,
            descriptor: self.descriptor.clone(),
            request_id: id.clone(),
            request_hash: hash(ciphertext.as_bytes()),
            max_tokens,
        };
        Ok((
            Envelope {
                version: VERSION,
                node_id: self.descriptor.node_id,
                model: self.descriptor.model,
                request_id: id,
                reply_recipient,
                expires_at,
                max_tokens,
                ciphertext,
            },
            pending,
        ))
    }
}
impl PendingReply {
    pub fn finish(self, reply: EncryptedReply) -> Result<Value, String> {
        let r = &reply.receipt;
        if r.version != VERSION
            || r.node_id != self.descriptor.node_id
            || r.request_id != self.request_id
            || r.request_hash != self.request_hash
            || r.ciphertext_hash != hash(reply.ciphertext.as_bytes())
            || r.tokens_in > 65536
            || r.tokens_out > self.max_tokens
        {
            return Err(REPLY_ERROR.into());
        }
        let key = decode(&self.descriptor.signing_key, 32).map_err(|_| REPLY_ERROR)?;
        let signed = decode(&reply.signature, 64).map_err(|_| REPLY_ERROR)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, &key)
            .verify(&serde_json::to_vec(r).map_err(|_| REPLY_ERROR)?, &signed)
            .map_err(|_| REPLY_ERROR)?;
        let plain = decrypt(&self.identity, &reply.ciphertext)?;
        let value: Value = serde_json::from_slice(&plain).map_err(|_| REPLY_ERROR)?;
        if value["requestId"] != self.request_id {
            return Err(REPLY_ERROR.into());
        }
        Ok(value["response"].clone())
    }
}

/// The reference runner's keys are generated inside its process, never supplied
/// by the host and never serialized. These methods belong inside an attested VM.
pub struct RunnerKeys {
    identity: x25519::Identity,
    signing: signature::Ed25519KeyPair,
}
impl RunnerKeys {
    pub fn generate() -> Result<Self, String> {
        let pkcs = signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| "Cannot generate runner signing key")?;
        Ok(Self {
            identity: x25519::Identity::generate(),
            signing: signature::Ed25519KeyPair::from_pkcs8(pkcs.as_ref())
                .map_err(|_| "Cannot generate runner signing key")?,
        })
    }
    pub fn descriptor(
        &self,
        node: String,
        model: String,
        revision: String,
        nonce: String,
        now: u64,
    ) -> Descriptor {
        Descriptor {
            version: VERSION,
            node_id: node,
            model,
            revision,
            nonce,
            recipient: self.identity.to_public().to_string(),
            signing_key: URL_SAFE_NO_PAD.encode(self.signing.public_key().as_ref()),
            issued_at: now,
            expires_at: now.saturating_add(60),
        }
    }
    pub fn open(&self, envelope: &Envelope, now: u64) -> Result<Value, String> {
        if envelope.version != VERSION
            || !fixed(&envelope.request_id, 32)
            || envelope.expires_at <= now
            || envelope.expires_at > now.saturating_add(120)
        {
            return Err("Invalid confidential envelope".into());
        }
        let plain = decrypt(&self.identity, &envelope.ciphertext)?;
        let body: Value =
            serde_json::from_slice(&plain).map_err(|_| "Invalid confidential payload")?;
        if body["version"] != VERSION
            || body["nodeId"] != envelope.node_id
            || body["requestId"] != envelope.request_id
            || body["replyRecipient"] != envelope.reply_recipient
            || body["expiresAt"] != envelope.expires_at
            || body["maxTokens"] != envelope.max_tokens
            || body["request"]["model"] != envelope.model
        {
            return Err("Confidential envelope binding failed".into());
        }
        Ok(body["request"].clone())
    }
    pub fn reply(
        &self,
        envelope: &Envelope,
        response: Value,
        tokens_in: u64,
        tokens_out: u64,
    ) -> Result<EncryptedReply, String> {
        let plain = Zeroizing::new(
            serde_json::to_vec(&json!({"requestId":envelope.request_id,"response":response}))
                .map_err(|_| REPLY_ERROR)?,
        );
        let ciphertext = encrypt(&envelope.reply_recipient, &plain)?;
        let receipt = Receipt {
            version: VERSION,
            node_id: envelope.node_id.clone(),
            request_id: envelope.request_id.clone(),
            request_hash: hash(envelope.ciphertext.as_bytes()),
            ciphertext_hash: hash(ciphertext.as_bytes()),
            tokens_in,
            tokens_out,
        };
        let signed = self
            .signing
            .sign(&serde_json::to_vec(&receipt).map_err(|_| REPLY_ERROR)?);
        Ok(EncryptedReply {
            ciphertext,
            receipt,
            signature: URL_SAFE_NO_PAD.encode(signed.as_ref()),
        })
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
async fn post(
    client: &reqwest::Client,
    endpoint: &str,
    key: &str,
    path: &str,
    body: &Value,
) -> Result<Value, String> {
    let mut response = client
        .post(format!("{endpoint}{path}"))
        .bearer_auth(key)
        .json(body)
        .send()
        .await
        .map_err(|_| "Cannot reach confidential relay")?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Confidential relay response interrupted")?
    {
        if bytes.len() + chunk.len() > 2 * MAX_CIPHERTEXT {
            return Err("Confidential relay response exceeded its limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        return Err(format!("Confidential relay refused the request (HTTP {}). No plaintext fallback was attempted.",status.as_u16()));
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid confidential relay response".into())
}
pub async fn chat(
    endpoint: &str,
    key: &str,
    node: String,
    request: Value,
    policy_path: Option<&str>,
) -> Result<Value, String> {
    // Before networking or encryption, require independently provisioned trust.
    let policy = Policy::load(policy_path, now())?;
    let url = reqwest::Url::parse(endpoint).map_err(|_| "Invalid confidential endpoint")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Confidential relay must be an HTTPS URL without credentials or query".into());
    }
    let challenge = Challenge::new(
        node,
        request["model"]
            .as_str()
            .ok_or("Supply a model repository")?
            .into(),
    )?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(std::time::Duration::from_secs(330))
        .connect_timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Cannot initialize confidential client")?;
    let policy = policy.check_vendor_keys(&client).await?;
    let endpoint = endpoint.trim_end_matches('/');
    let proof: Proof = serde_json::from_value(
        post(
            &client,
            endpoint,
            key,
            "/confidential/attestation",
            &challenge.request(),
        )
        .await?,
    )
    .map_err(|_| PROOF_ERROR)?;
    let peer = challenge.verify(proof, &policy, now())?;
    let (envelope, pending) = peer.prepare(request, now())?;
    let answer = post(
        &client,
        endpoint,
        key,
        "/confidential/chat/completions",
        &serde_json::to_value(envelope).map_err(|_| "Cannot encode encrypted envelope")?,
    )
    .await?;
    pending.finish(serde_json::from_value(answer).map_err(|_| REPLY_ERROR)?)
}

#[cfg(test)]
mod tests;
