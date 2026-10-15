//! Closed Neo Grid: a company's private model grid on its own network.
//!
//! One computer runs the hub, administered by the company. Other company computers join it with
//! the company password. The admin decides which models run, on what share of the computers,
//! in which hours and after how long without keyboard or mouse input. Each member runs the model
//! it is assigned and, while allowed, asks the hub for work over pinned TLS, runs it locally and
//! streams the reply back. Company apps use the hub's OpenAI-compatible API with keys the admin
//! creates. Members open no ports, nothing passes through yougori.com and prompts are never
//! recorded.
pub mod activity;
pub mod hub;
pub mod member;
pub mod net;
pub mod password;
pub mod policy;
pub mod schedule;
#[cfg(test)]
mod end_to_end;

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A 256-bit random secret as 64 hex characters.
pub(crate) fn token() -> String {
    format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple())
}

/// Secrets are kept only as salted hashes.
pub(crate) fn digest(purpose: &str, value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("yougori-grid:{purpose}:{value}").as_bytes()))
}

pub(crate) fn is_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

/// The name a model is listed under: a Hugging Face repository without its host.
pub fn model_name(raw: &str) -> String {
    let raw = raw.trim();
    ["https://huggingface.co/", "http://huggingface.co/", "huggingface.co/", "hf.co/"]
        .iter()
        .find_map(|prefix| raw.strip_prefix(prefix))
        .unwrap_or(raw)
        .trim_matches('/')
        .to_owned()
}

/// Model names match without regard to case, as Hugging Face repositories do.
pub fn model_key(raw: &str) -> String {
    model_name(raw).to_ascii_lowercase()
}

/// A display name from a person: printable, single line, at most 64 characters.
pub(crate) fn label(value: &str, what: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 64 || value.chars().any(char::is_control) {
        return Err(format!("{what} must be 1–64 printable characters"));
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn model_names_drop_the_host_and_match_without_case() {
        assert_eq!(model_name("hf.co/Qwen/Qwen3-8B"), "Qwen/Qwen3-8B");
        assert_eq!(model_name("https://huggingface.co/Qwen/Qwen3-8B/"), "Qwen/Qwen3-8B");
        assert_eq!(model_key("Qwen/QWEN3-8b"), model_key("hf.co/qwen/Qwen3-8B"));
        assert_eq!(model_name("yg/alice/model"), "yg/alice/model");
    }
    #[test]
    fn tokens_are_random_hex_and_labels_are_single_lines() {
        let (a, b) = (token(), token());
        assert!(is_token(&a) && a != b);
        assert!(!is_token("short") && !is_token(&"g".repeat(64)));
        assert_eq!(label("  Build server ", "Name").unwrap(), "Build server");
        assert!(label("", "Name").is_err() && label("a\nb", "Name").is_err() && label(&"x".repeat(65), "Name").is_err());
    }
}
