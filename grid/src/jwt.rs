//! Signed tokens from the company's identity provider (OpenID Connect ID tokens): checked against
//! the provider's published keys with RS256 or ES256, nothing else. The claims are returned for
//! the caller to judge (issuer, audience, expiry, nonce); only the signature is settled here.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// No published key matches the token's key id: the provider may have rotated its keys.
    UnknownKey(String),
    Invalid(String),
}

/// The token's header and claims without any check, to pick a key or a message.
pub fn peek(token: &str) -> Option<(Value, Value)> {
    let mut parts = token.split('.');
    let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts.next()?).ok()?).ok()?;
    Some((header, claims))
}

/// The claims of `token`, once its signature checks out against one of `keys` (a JWK set).
pub fn verify(token: &str, keys: &Value) -> Result<Value, Reject> {
    let token = token.trim();
    if token.len() > 16 * 1024 || token.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Reject::Invalid("The token is malformed".into()));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Reject::Invalid("The token is not a signed JWT".into()));
    }
    let (header, claims) = peek(token).ok_or_else(|| Reject::Invalid("The token is malformed".into()))?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| Reject::Invalid("The token's signature is malformed".into()))?;
    let message = format!("{}.{}", parts[0], parts[1]);
    let alg = header["alg"].as_str().unwrap_or_default();
    let kid = header["kid"].as_str();
    let candidates: Vec<&Value> = keys["keys"].as_array().into_iter().flatten().filter(|key| kid.is_none_or(|kid| key["kid"] == kid) && key["use"].as_str().is_none_or(|purpose| purpose == "sig")).collect();
    if candidates.is_empty() {
        return Err(Reject::UnknownKey(kid.unwrap_or("(no key id)").to_owned()));
    }
    let verified = candidates.iter().any(|key| check(alg, key, message.as_bytes(), &signature));
    if !verified {
        return Err(Reject::Invalid(format!("The token's {} signature does not match the provider's keys", if alg.is_empty() { "missing" } else { alg })));
    }
    Ok(claims)
}

fn check(alg: &str, key: &Value, message: &[u8], signature: &[u8]) -> bool {
    let part = |name: &str| key[name].as_str().and_then(|text| URL_SAFE_NO_PAD.decode(text).ok());
    match (alg, key["kty"].as_str()) {
        ("RS256", Some("RSA")) => {
            let (Some(n), Some(e)) = (part("n"), part("e")) else { return false };
            ring::signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, message, signature).is_ok()
        }
        ("ES256", Some("EC")) if key["crv"] == "P-256" => {
            let (Some(x), Some(y)) = (part("x"), part("y")) else { return false };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let mut point = vec![4u8];
            point.extend(x);
            point.extend(y);
            ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &point).verify(message, signature).is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// A token signed once with a throwaway RSA key (made and discarded outside the repository);
    /// only its public half is here.
    const RS256_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci50ZXN0IiwiYXVkIjoiY2xpZW50LTEiLCJzdWIiOiJhZGEiLCJlbWFpbCI6IkFkYUBBY21lLmV4YW1wbGUiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwMDAwMDAwMCwibm9uY2UiOiJub25jZS0xIn0.F7T42CdIu8WDxN0TFu2tP35WSuqUog6Ivn_kEohuEZbs9UoidyIGo54uyCWbmQ0ontUh5WE3S9vaFii8tNsuFsrZBlSy6NmcORCfk4OnTbDFZiU9thIc0UwhZQLC851-km93nI_8ZHL5uNWKJUMtjL3h73Kvb36KHwKpiFlL80-bMsq9aAgCSEkD3uEqAM0MvkdpJkowhVr6wBb9ekSLRrkUCrEwRdSd_3RwfXTBEceK2Vuf6UHM_9Ti84fzBXNjTjL3JwUw7VmB4FM3aMSN5yEub9hcKHwW99XhYijHNf312bmvQLqCs9eq0ZMh0oaM12pyTK8mEs2W-hv_gtvfFg";
    const RS256_N: &str = "9R3hkn7gXeGOoT4WgW-EoWRJbfCeIxPjq9jThLEGp-CaC32KdqKRwogMEmM0RVOrOisY1zcBPsD8n2VvWjKTs54852KTxHqA7uTzzxLRUJ4xPyLxhKhgZ6KWV2q2BK8UcFI0ZbDIk2wSLHOYxQuudnGdkJMM-Wv3z9Bg103F3lePHbLUQUtGX4IjJrhR8Jvg7zeLQhPrbvfz8YASJXJBhoxtB3VPlfnJoz9Am6olQwq2Kfko9PUYa9iBQ2wnXboMWXQHASrfYhwr_L97S3sWomm6H7pIhKYuxehcEe3iIciK8WmEp7uSCZ7Fk7wCF6lyCuR2AFSKhUKo_Okpfzjyvw";

    /// A signer like an identity provider's, for tests: a fresh P-256 key, its JWK, and tokens.
    pub struct Issuer {
        key: ring::signature::EcdsaKeyPair,
        pub kid: String,
    }
    impl Issuer {
        pub fn new(kid: &str) -> Issuer {
            let pair = rcgen::KeyPair::generate().expect("a P-256 key");
            let der = pair.serialize_der();
            let key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &ring::rand::SystemRandom::new()).expect("ring reads rcgen's key");
            Issuer { key, kid: kid.into() }
        }
        pub fn jwks(&self) -> Value {
            use ring::signature::KeyPair;
            let point = self.key.public_key().as_ref();
            json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])}]})
        }
        pub fn token(&self, claims: &Value) -> String {
            let header = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"}).to_string());
            let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
            let message = format!("{header}.{payload}");
            let signature = self.key.sign(&ring::rand::SystemRandom::new(), message.as_bytes()).expect("signing");
            format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }
    }

    #[test]
    fn rs256_tokens_check_out_against_the_published_key_only() {
        let keys = json!({"keys": [{"kty": "RSA", "kid": "fixture", "use": "sig", "n": RS256_N, "e": "AQAB"}]});
        let claims = verify(RS256_TOKEN, &keys).unwrap();
        assert_eq!((claims["iss"].as_str(), claims["email"].as_str(), claims["nonce"].as_str()), (Some("https://issuer.test"), Some("Ada@Acme.example"), Some("nonce-1")));
        let other = json!({"keys": [{"kty": "RSA", "kid": "other", "n": RS256_N, "e": "AQAB"}]});
        assert_eq!(verify(RS256_TOKEN, &other), Err(Reject::UnknownKey("fixture".into())));
        let mut tampered = RS256_TOKEN.to_owned();
        tampered.replace_range(RS256_TOKEN.len() - 4.., "AAAA");
        assert!(matches!(verify(&tampered, &keys), Err(Reject::Invalid(_))));
        let forged_claims = format!("{}.{}.{}", RS256_TOKEN.split('.').next().unwrap(), URL_SAFE_NO_PAD.encode(r#"{"email":"eve@acme.example"}"#), RS256_TOKEN.split('.').nth(2).unwrap());
        assert!(matches!(verify(&forged_claims, &keys), Err(Reject::Invalid(_))));
        assert!(matches!(verify("not.a.token", &keys), Err(Reject::Invalid(_))));
        let none = format!("{}.{}.", URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"fixture"}"#), RS256_TOKEN.split('.').nth(1).unwrap());
        assert!(matches!(verify(&none, &keys), Err(Reject::Invalid(_))), "alg none is never accepted");
    }

    #[test]
    fn es256_tokens_from_a_fresh_issuer_check_out() {
        let issuer = Issuer::new("k1");
        let token = issuer.token(&json!({"iss": "https://issuer.test", "aud": "client-1", "email": "ada@acme.example", "exp": 4102444800i64}));
        assert_eq!(verify(&token, &issuer.jwks()).unwrap()["email"], "ada@acme.example");
        assert!(matches!(verify(&token, &Issuer::new("k1").jwks()), Err(Reject::Invalid(_))), "another issuer's key with the same id does not do");
        assert_eq!(verify(&token, &json!({"keys": []})), Err(Reject::UnknownKey("k1".into())));
    }
}
