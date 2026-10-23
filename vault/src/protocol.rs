use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemInput {
    pub label: String,
    pub kind: String,
    pub resource: String,
    pub value: String,
}
impl Drop for ItemInput {
    fn drop(&mut self) { zeroize::Zeroize::zeroize(&mut self.value); }
}
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 256 * 1024;
pub const VERSION: u32 = 1;
pub fn negotiate(version: Option<&str>) -> &'static str {
    match version {
        Some("2024-11-05") => "2024-11-05",
        Some("2025-03-26") => "2025-03-26",
        Some("2025-06-18") => "2025-06-18",
        _ => "2025-11-25",
    }
}

// Desktop-only decisions and item entry are authenticated by the broker.
// Remote MCP requests cannot invoke them. Unknown fields are rejected.
#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {},
    Manage {},
    AddItems { items: Vec<ItemInput> },
    Approve { request: String },
    Browse {},
    HttpSetup {},
    HttpEndpoint {},
    HttpOrigin { origin: Option<String> },
    HttpCredentials {},
    Lock {},
    Remote {},
    RemoteOff {},
    Revoke { client: String },
    Remove { item: String },
    /// Deletes every item, client, grant and key, after its own approval in Desktop. Finished,
    /// it answers `{"destroyed":true}`, with `leftBehind` naming anything small that stayed.
    /// Its errors begin with [`DESTROY_NOT_STARTED`] when nothing was deleted, and with
    /// [`DESTROY_UNFINISHED`] when deleting began and stopped part way.
    Destroy {},
    Deny { request: String },
    Mcp { message: Value },
}

/// The answer of a request whose broker worker stopped before answering: its outcome is unknown.
pub const SERVICE_STOPPED: &str = "Protected approval service stopped";

/// How a destroy's error begins when nothing was deleted. The rest says why and what to do.
pub const DESTROY_NOT_STARTED: &str = "Nothing was deleted.";
/// How a destroy's error begins when deleting began and stopped part way. The rest names every
/// secret file left and whether they can still be read.
pub const DESTROY_UNFINISHED: &str = "Personal Vault was only partly deleted.";

/// Frames can carry credentials; the buffer is wiped when dropped.
pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "Vault connection closed")? as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("Invalid vault frame size".into());
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "Incomplete vault frame")?;
    Ok(bytes)
}
pub async fn write<W: AsyncWrite + Unpin>(stream: &mut W, value: &Value) -> Result<(), String> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| "Invalid vault response")?);
    if bytes.len() > MAX_FRAME {
        return Err("Vault response exceeds size limit".into());
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| "Vault connection closed")?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "Vault connection closed")?;
    stream
        .flush()
        .await
        .map_err(|_| "Vault connection closed".into())
}

/// Overwrites every string in a message before it is dropped. serde_json does
/// not wipe its buffers, so values that carried credentials are cleared here.
pub fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => zeroize::Zeroize::zeroize(text),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(fields) => fields.values_mut().for_each(wipe),
        _ => (),
    }
}

pub fn tool_catalog() -> Value {
    serde_json::json!({"tools":[
        {"name":"list_vault_items", "description":"Request an approved list of vault item names, IDs, types, and personal-information field names. No values are returned. The user must approve this inventory inside Yougori Desktop; connection approval alone is insufficient. Use the returned IDs for later requests, especially for duplicate names. Do not automatically retry a denial.", "inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"read_all_credentials", "description":"Request all credential values in the vault in one operation. Yougori Desktop displays the count and every item name before the user decides whether to share all of them with this agent and its provider. No value is returned without this explicit one-time approval. This may include passwords, API keys, tokens, private keys, and Cloudflare tokens. Use only when the user specifically asks to share all credentials; a connection approval or chat statement alone is insufficient. Do not automatically retry a denial.", "inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"read_credential", "description":"Request the complete value of one credential item by exact name or UUID, for example OpenSourceName. Use list_vault_items first if the user has not given the exact item name. This tool asks the user to approve inside Yougori Desktop. Only a fresh explicit Share credential once decision allows disclosure into this agent context. A connection approval or approval stated in chat is not enough. If denied, explain the error and do not automatically retry.", "inputSchema":{"type":"object","properties":{"item":{"type":"string","minLength":1,"maxLength":100,"description":"Exact credential item name or UUID; duplicate names require its copied UUID."}},"required":["item"],"additionalProperties":false}},
        {"name":"personal_info", "description":"Request selected fields from a Personal information item using its exact name or UUID. Use exact field names supplied by the user (for example openSourceName). Yougori asks for one-time disclosure approval. For a credential item, use read_credential to request separate disclosure approval. Explain isError messages; never automatically retry a denial.", "inputSchema":{"type":"object","properties":{"item":{"type":"string","description":"Exact personal-information item name or UUID copied from Yougori; duplicate names require the UUID."},"fields":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":16}},"required":["item","fields"],"additionalProperties":false}},
        {"name":"cloudflare_create_dns_record", "description":"Request one DNS record in a vault account's fixed Cloudflare zone. Requires one-time approval inside Yougori Desktop. The API token is used internally and never returned.", "inputSchema":{"type":"object","properties":{"item":{"type":"string"},"name":{"type":"string"},"type":{"type":"string","enum":["A","AAAA","CNAME","TXT"]},"content":{"type":"string"},"ttl":{"type":"integer","minimum":60,"maximum":86400},"proxied":{"type":"boolean"}},"required":["item","name","type","content","ttl","proxied"],"additionalProperties":false}}
    ]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_rejects_arbitrary_commands_and_approval_flags() {
        for method in [
            "approve_once",
            "unlock",
            "put",
            "read_secret",
            "execute",
            "http",
        ] {
            assert!(
                serde_json::from_value::<Request>(serde_json::json!({"method":method})).is_err()
            );
        }
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"method":"manage","approved":true})
        )
        .is_err());
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"method":"approve","request":"request-id","approved":true})
        ).is_err());
    }
    #[test]
    fn wipe_clears_nested_strings_in_place() {
        let mut value = serde_json::json!({"value":"secret","list":["token"],"nested":{"key":"private"},"count":2});
        wipe(&mut value);
        assert_eq!(value, serde_json::json!({"value":"","list":[""],"nested":{"key":""},"count":2}));
    }
    #[tokio::test]
    async fn framing_limits_and_truncation_fail_closed() {
        use tokio::io::AsyncWriteExt;
        for size in [0, MAX_FRAME as u32 + 1] {
            let (mut w, mut r) = tokio::io::duplex(16);
            w.write_u32(size).await.unwrap();
            assert!(read(&mut r).await.is_err());
        }
        let (mut w, mut r) = tokio::io::duplex(16);
        w.write_u32(8).await.unwrap();
        w.write_all(b"abc").await.unwrap();
        drop(w);
        assert!(read(&mut r).await.is_err());
    }
}
