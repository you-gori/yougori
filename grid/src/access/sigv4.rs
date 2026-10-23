//! AWS Signature Version 4, so the hub can sign a request with a company's AWS key without the
//! agent ever holding it, and the few STS calls that turn that key into temporary credentials.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// An AWS key, long-lived or temporary (with its session token).
#[derive(Clone)]
pub struct Keys {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

fn hmac(key: &[u8], message: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Percent-encodes all but unreserved characters, as SigV4 wants: `%XX` upper case, and `/`
/// kept only when `slash` says so.
fn uri_encode(bytes: &[u8], slash: bool) -> String {
    bytes.iter().map(|&byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || (slash && byte == b'/') { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[index + 1..index + 3]).ok().and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// The path as SigV4 reads it: S3 takes the path as sent; every other service has each segment
/// encoded once more.
fn canonical_uri(path: &str, service: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if service == "s3" {
        return path.to_owned();
    }
    path.split('/').map(|segment| uri_encode(segment.as_bytes(), false)).collect::<Vec<_>>().join("/")
}

fn canonical_query(query: Option<&str>) -> String {
    let mut pairs: Vec<(String, String)> = query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (uri_encode(&percent_decode(name), false), uri_encode(&percent_decode(value), false))
        })
        .collect();
    pairs.sort();
    pairs.into_iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join("&")
}

/// The service and region a host names: `s3.eu-west-1.amazonaws.com` is `s3` in `eu-west-1`,
/// `abc.execute-api.us-east-1.amazonaws.com` is `execute-api`, `sts.amazonaws.com` is `sts`.
pub fn service_of(host: &str) -> Option<String> {
    let name = host.strip_suffix(".amazonaws.com").or_else(|| host.strip_suffix(".amazonaws.com.cn"))?;
    let labels: Vec<&str> = name.split('.').collect();
    let region_like = |label: &str| label.contains('-') && label.bytes().any(|c| c.is_ascii_digit());
    match labels.as_slice() {
        [] => None,
        [.., service, region] if region_like(region) => Some((*service).to_owned()),
        [.., service] => Some((*service).to_owned()),
    }
}

/// `YYYYMMDDTHHMMSSZ` now.
pub fn amz_date() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// The headers that sign one request: `x-amz-date`, `x-amz-content-sha256` (when `content_hash`),
/// `x-amz-security-token` for temporary keys, and `authorization`. `path` and `query` are as sent.
#[allow(clippy::too_many_arguments)]
pub fn sign(method: &str, host: &str, path: &str, query: Option<&str>, payload: &[u8], keys: &Keys, region: &str, service: &str, amz_date: &str, content_hash: bool) -> Vec<(String, String)> {
    let date = &amz_date[..8.min(amz_date.len())];
    let payload_hash = hex::encode(Sha256::digest(payload));
    let mut headers = vec![("host".to_owned(), host.to_owned()), ("x-amz-date".to_owned(), amz_date.to_owned())];
    if content_hash {
        headers.push(("x-amz-content-sha256".into(), payload_hash.clone()));
    }
    if let Some(token) = &keys.session_token {
        headers.push(("x-amz-security-token".into(), token.clone()));
    }
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(name, value)| format!("{name}:{}\n", value.trim())).collect();
    let signed = headers.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(";");
    let request = [method, &canonical_uri(path, service), &canonical_query(query), &canonical_headers, &signed, &payload_hash].join("\n");
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex::encode(Sha256::digest(request.as_bytes())));
    let key = ["aws4_request"].iter().fold(hmac(&hmac(&hmac(format!("AWS4{}", keys.secret_key).as_bytes(), date), region), service), |key, part| hmac(&key, part));
    let signature = hex::encode(hmac(&key, &to_sign));
    let mut out: Vec<(String, String)> = headers.into_iter().filter(|(name, _)| name != "host").collect();
    out.push(("authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", keys.access_key)));
    out
}

/// One element's text in an STS XML answer.
pub fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim().replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'"))
}

/// Temporary keys and when they lapse (seconds since the epoch), from an STS answer.
pub fn credentials(xml: &str) -> Option<(Keys, i64)> {
    // Keys and tokens never contain whitespace; an answer may wrap them.
    let field = |tag: &str| xml_text(xml, tag).map(|text| text.split_whitespace().collect::<String>()).filter(|text| !text.is_empty());
    let keys = Keys { access_key: field("AccessKeyId")?, secret_key: field("SecretAccessKey")?, session_token: Some(field("SessionToken")?) };
    let expires = chrono::DateTime::parse_from_rfc3339(&xml_text(xml, "Expiration")?).ok()?.timestamp();
    Some((keys, expires))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Keys {
        Keys { access_key: "AKIDEXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(), session_token: None }
    }

    #[test]
    fn signatures_match_the_published_sigv4_test_suite() {
        // AWS SigV4 test suite: get-vanilla and get-vanilla-query-order-key-case.
        let signed = sign("GET", "example.amazonaws.com", "/", None, b"", &example(), "us-east-1", "service", "20150830T123600Z", false);
        let authorization = &signed.iter().find(|(name, _)| name == "authorization").unwrap().1;
        assert_eq!(authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
        let signed = sign("GET", "example.amazonaws.com", "/", Some("Param2=value2&Param1=value1"), b"", &example(), "us-east-1", "service", "20150830T123600Z", false);
        assert!(signed.iter().any(|(name, value)| name == "authorization" && value.ends_with("Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")), "{signed:?}");
        assert!(signed.iter().any(|(name, value)| name == "x-amz-date" && value == "20150830T123600Z"));
    }

    #[test]
    fn temporary_keys_and_payloads_are_signed_too() {
        let keys = Keys { session_token: Some("session-token".into()), ..example() };
        let signed = sign("POST", "s3.eu-west-1.amazonaws.com", "/bucket/a%20b.txt", None, b"hello", &keys, "eu-west-1", "s3", "20260101T000000Z", true);
        let names: Vec<&str> = signed.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["x-amz-content-sha256", "x-amz-date", "x-amz-security-token", "authorization"]);
        assert!(signed[3].1.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"));
        assert_eq!(canonical_uri("/a%20b/c", "s3"), "/a%20b/c");
        assert_eq!(canonical_uri("/a%20b/c", "execute-api"), "/a%2520b/c");
        assert_eq!(canonical_query(Some("b=2&a=x%2Fy&a=1")), "a=1&a=x%2Fy&b=2");
    }

    #[test]
    fn hosts_name_their_service_and_sts_answers_parse() {
        assert_eq!(service_of("s3.eu-west-1.amazonaws.com").as_deref(), Some("s3"));
        assert_eq!(service_of("abc123.execute-api.us-east-1.amazonaws.com").as_deref(), Some("execute-api"));
        assert_eq!(service_of("sts.amazonaws.com").as_deref(), Some("sts"));
        assert_eq!(service_of("bucket.s3.amazonaws.com").as_deref(), Some("s3"));
        assert_eq!(service_of("api.example.com"), None);
        let answer = "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>temp/secret</SecretAccessKey><SessionToken>token&amp;more</SessionToken><Expiration>2026-10-18T12:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>";
        let (keys, expires) = credentials(answer).unwrap();
        assert_eq!((keys.access_key.as_str(), keys.session_token.as_deref(), expires), ("ASIATEMP", Some("token&more"), 1_792_324_800));
        assert!(credentials("<Error><Message>denied</Message></Error>").is_none());
        let wrapped = answer.replace("token&amp;more", "token\n  &amp;more ");
        assert_eq!(credentials(&wrapped).unwrap().0.session_token.as_deref(), Some("token&more"), "whitespace inside a token is dropped");
    }
}
