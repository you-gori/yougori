//! Explicit owner-file credentials and public pins for an existing SSH profile.
//! No private key is read, copied, returned or represented as a vault grant.
use std::fs;
use std::io::Read;

use super::wire::{algorithm_for_key_type, base64_decode, check_blob, openssh_sha256};
use super::{
    check_identity_file, IdentityFile, SshFilePath, MANAGEMENT_KEY_DOMAIN, MAX_PUBLIC_KEY_BYTES,
};
use crate::foundation::ids::DigestBuilder;
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::remote::HostKey;

pub struct OwnerPublicKey {
    pub key: HostKey,
    pub blob: Vec<u8>,
    pub openssh_fingerprint: String,
    pub credential: CredentialRef,
}

/// One bare public-key line, optionally with an owner's comment. Authorized-key
/// options, a second line, unknown algorithms and malformed blobs are refused.
pub fn parse_owner_public_key(bytes: &[u8]) -> Result<OwnerPublicKey, String> {
    if bytes.len() > MAX_PUBLIC_KEY_BYTES {
        return Err("The public key exceeds its size bound.".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "The public key is not UTF-8.")?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    let body = body.strip_suffix('\r').unwrap_or(body);
    if body.chars().any(|c| c.is_control() && c != '\t') {
        return Err("A single public-key line is required.".into());
    }
    let mut fields = body.split_whitespace();
    let algorithm = fields
        .next()
        .and_then(algorithm_for_key_type)
        .ok_or("Unsupported public-key algorithm or authorized-key options.")?;
    let blob = fields
        .next()
        .and_then(base64_decode)
        .ok_or("Invalid public-key encoding.")?;
    check_blob(algorithm, &blob).map_err(|e| e.to_string())?;
    Ok(OwnerPublicKey {
        blob: blob.clone(),
        openssh_fingerprint: openssh_sha256(&blob),
        credential: CredentialRef::from_digest(
            DigestBuilder::new(MANAGEMENT_KEY_DOMAIN)
                .bytes(&blob)
                .finish(),
        ),
        key: HostKey::new(algorithm, blob).map_err(|e| e.to_string())?,
    })
}

/// The `.pub` companion is owner-declared public metadata, not proof that a vault
/// grant exists. The SSH server still authenticates the actual private-key holder.
pub fn owner_identity_file(path: SshFilePath) -> Result<IdentityFile, String> {
    check_identity_file(&path).map_err(|e| e.to_string())?;
    let public = std::path::PathBuf::from(format!("{}.pub", path.as_str()));
    if !fs::symlink_metadata(&public)
        .map_err(|_| "The selected key needs its .pub companion.")?
        .is_file()
    {
        return Err("The public-key companion must be a regular file, not a link.".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(public)
        .map_err(|_| "Cannot open the public-key companion.")?
        .take(MAX_PUBLIC_KEY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read the public-key companion.")?;
    let public = parse_owner_public_key(&bytes)?;
    Ok(IdentityFile::new(public.credential, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::remote_ssh::fakes::ed25519_blob;
    use crate::sandbox_contract::remote_ssh::wire::base64_encode;

    #[test]
    fn owner_comments_do_not_change_identity_but_options_or_extra_keys_are_refused() {
        let line = format!("ssh-ed25519 {}", base64_encode(&ed25519_blob(7)));
        let bare = parse_owner_public_key(line.as_bytes()).unwrap();
        let commented =
            parse_owner_public_key(format!("{line} owner's key from this PC\r\n").as_bytes())
                .unwrap();
        assert_eq!(bare.credential, commented.credential);
        assert_eq!(bare.openssh_fingerprint, commented.openssh_fingerprint);
        assert!(parse_owner_public_key(format!("command=anything {line}").as_bytes()).is_err());
        assert!(parse_owner_public_key(format!("{line}\n{line}\n").as_bytes()).is_err());
        assert!(parse_owner_public_key(
            format!("ssh-rsa {}", base64_encode(&ed25519_blob(7))).as_bytes()
        )
        .is_err());
        assert!(parse_owner_public_key(&vec![b'A'; MAX_PUBLIC_KEY_BYTES + 1]).is_err());
    }
}
