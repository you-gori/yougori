//! Protected stream delivery keeps raw byte cursors while masking before JSON.
//! Look behind and ahead so a caller cannot expose a secret by choosing a cursor
//! in its middle. Partial tail prefixes wait for more bytes or are masked at EOF.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::future::Future;

fn prefixes(pattern: &[u8]) -> Vec<usize> {
    let mut prefix = vec![0; pattern.len()];
    for i in 1..pattern.len() {
        let mut q = prefix[i - 1];
        while q > 0 && pattern[q] != pattern[i] {
            q = prefix[q - 1];
        }
        if pattern[q] == pattern[i] {
            q += 1;
        }
        prefix[i] = q;
    }
    prefix
}
fn suffix_match(pattern: &[u8], text: &[u8]) -> usize {
    if pattern.is_empty() {
        return 0;
    }
    let prefix = prefixes(pattern);
    let mut q = 0;
    for &b in text {
        if q == pattern.len() {
            q = prefix[q - 1];
        }
        while q > 0 && pattern[q] != b {
            q = prefix[q - 1];
        }
        if pattern[q] == b {
            q += 1;
        }
    }
    q
}
fn masked(data: &[u8], secrets: &[String], leading_cut: bool, finished: bool) -> (Vec<u8>, usize) {
    let mut ranges = vec![0_i32; data.len() + 1];
    let mut pending_start = data.len();
    for value in secrets {
        let secret = value.as_bytes();
        if secret.is_empty() {
            continue;
        }
        let prefix = prefixes(secret);
        let mut q = 0;
        for (i, &b) in data.iter().enumerate() {
            while q > 0 && secret[q] != b {
                q = prefix[q - 1];
            }
            if secret[q] == b {
                q += 1;
            }
            if q == secret.len() {
                ranges[i + 1 - q] += 1;
                ranges[i + 1] -= 1;
                q = prefix[q - 1];
            }
        }
        if q > 0 {
            if finished {
                ranges[data.len() - q] += 1;
                ranges[data.len()] -= 1;
            } else {
                pending_start = pending_start.min(data.len() - q);
            }
        }
        if leading_cut && secret.len() > 1 {
            let n = suffix_match(&data[..data.len().min(secret.len() - 1)], secret);
            if n > 0 {
                ranges[0] += 1;
                ranges[n] -= 1;
            }
        }
    }
    let mut masked = data.to_vec();
    let mut depth = 0;
    let mut stable = data.len();
    for (i, b) in masked.iter_mut().enumerate() {
        depth += ranges[i];
        if depth > 0 {
            *b = b'*';
        } else if i >= pending_start && stable == data.len() {
            stable = i;
        }
    }
    (masked, stable)
}
pub(super) fn mask_text(text: &str, secrets: &[String], withhold_partial: bool) -> String {
    let (mut bytes, stable) = masked(text.as_bytes(), secrets, false, !withhold_partial);
    bytes.truncate(stable);
    String::from_utf8_lossy(&bytes).into_owned()
}
#[derive(Default)]
struct Stream {
    bytes: Vec<u8>,
    base: u64,
    cursor: u64,
    total: u64,
    goal: Option<u64>,
    requested: u64,
}
impl Stream {
    fn new(requested: u64, overlap: u64) -> Self {
        Self {
            requested,
            cursor: requested.saturating_sub(overlap),
            ..Self::default()
        }
    }
    fn append(&mut self, value: &Value, name: &str, limit: u64) -> Result<(), String> {
        let encoded = value[format!("{name}Base64")]
            .as_str()
            .ok_or("The guest agent needs updating for protected execution output")?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| "Invalid guest output encoding")?;
        if bytes.len() > 65536 {
            return Err("Guest output exceeds its bounded window".into());
        }
        let next = value[format!("{name}Cursor")]
            .as_u64()
            .ok_or("Invalid guest output cursor")?;
        let start = next
            .checked_sub(bytes.len() as u64)
            .ok_or("Invalid guest output length")?;
        self.total = value[format!("{name}Bytes")]
            .as_u64()
            .ok_or("Invalid guest output total")?;
        if self.requested > self.total {
            return Err("Output cursor exceeds available bytes".into());
        }
        if self.bytes.is_empty() || start != self.cursor {
            self.bytes.clear();
            self.base = start;
            self.goal = Some(self.requested.max(start).saturating_add(limit));
        }
        self.bytes.extend_from_slice(&bytes);
        self.cursor = next;
        Ok(())
    }
    fn ready(&self, overlap: u64) -> bool {
        self.cursor
            >= self
                .goal
                .unwrap_or(self.requested)
                .saturating_add(overlap)
                .min(self.total)
    }
    fn deliver(&self, secrets: &[String], finished: bool) -> (String, u64, bool) {
        let (masked, stable) = masked(&self.bytes, secrets, self.base > 0, finished);
        let start = self.requested.max(self.base);
        let end = self
            .goal
            .unwrap_or(start)
            .min(self.base + stable as u64)
            .max(start);
        let left = (start - self.base) as usize;
        let mut right = (end - self.base) as usize;
        // A window can end inside a multi-byte character; leave it whole for the next read.
        if !(finished && end == self.total) {
            let tail = incomplete_utf8_tail(masked.get(left..right).unwrap_or_default());
            if right - tail > left {
                right -= tail;
            }
        }
        let text =
            String::from_utf8_lossy(masked.get(left..right).unwrap_or_default()).into_owned();
        (text, self.base + right as u64, self.base > self.requested)
    }
}

/// Bytes of a character that starts in `bytes` but continues past its end.
fn incomplete_utf8_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if byte & 0xC0 != 0x80 {
            let width = match byte {
                0xF0.. => 4,
                0xE0.. => 3,
                0xC0.. => 2,
                _ => 1,
            };
            return if width > back { back } else { 0 };
        }
    }
    0
}

pub(super) async fn read_with<F, Fut>(
    stdout_cursor: u64,
    stderr_cursor: u64,
    limit: u64,
    secrets: &[String],
    mut fetch: F,
) -> Result<Value, String>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if !(1..=65536).contains(&limit) {
        return Err("Output limit must be 1–65536 bytes per stream".into());
    }
    if secrets.len() > 512 || secrets.iter().map(String::len).sum::<usize>() > 1024 * 1024 {
        return Err(
            "Protected output bindings exceed the bounded redaction budget; output withheld".into(),
        );
    }
    let overlap = secrets
        .iter()
        .map(String::len)
        .max()
        .unwrap_or(1)
        .saturating_sub(1)
        .min(65535) as u64;
    let mut stdout = Stream::new(stdout_cursor, overlap);
    let mut stderr = Stream::new(stderr_cursor, overlap);
    let mut result = json!({});
    for _ in 0..4 {
        result = fetch(stdout.cursor, stderr.cursor).await?;
        stdout.append(&result, "stdout", limit)?;
        stderr.append(&result, "stderr", limit)?;
        if stdout.ready(overlap) && stderr.ready(overlap) {
            break;
        }
    }
    let finished = result["done"] == true;
    let (text, out, truncated) = stdout.deliver(secrets, finished);
    result["stdout"] = text.into();
    result["stdoutCursor"] = out.into();
    result["stdoutTruncated"] = truncated.into();
    let (text, err, truncated) = stderr.deliver(secrets, finished);
    result["stderr"] = text.into();
    result["stderrCursor"] = err.into();
    result["stderrTruncated"] = truncated.into();
    if let Some(object) = result.as_object_mut() {
        object.remove("stdoutBase64");
        object.remove("stderrBase64");
    }
    result["protectedOutput"] = json!(true);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_overlapping_unicode_and_partial_secrets_keep_byte_offsets() {
        let secrets = vec!["ababa".into(), "🦉key".into()];
        let raw = "abababa 🦉key aba".as_bytes();
        let (value, stable) = masked(raw, &secrets, false, false);
        assert_eq!(String::from_utf8(value).unwrap(), "******* ******* aba");
        assert_eq!(stable, raw.len() - 3);
        let (value, stable) = masked(raw, &secrets, false, true);
        assert_eq!(String::from_utf8(value).unwrap(), "******* ******* ***");
        assert_eq!(stable, raw.len());
        let (value, _) = masked(b"baba okay", &secrets, true, true);
        assert_eq!(value, b"**** okay");
        let (value, stable) = masked(b"aaaa", &["aaaa".into()], false, false);
        assert_eq!(value, b"****");
        assert_eq!(stable, 4);
    }
    #[tokio::test]
    async fn arbitrary_cursor_and_tiny_pages_cannot_reveal_secret_fragments() {
        let data = b"public TOP-SECRET finish";
        let secrets = vec!["TOP-SECRET".into()];
        for cursor in 0..data.len() as u64 {
            let result=read_with(cursor,0,2,&secrets,|out,_|async move{let end=(out+65536).min(data.len() as u64);Ok(json!({"stdoutBase64":STANDARD.encode(&data[out as usize..end as usize]),"stdoutCursor":end,"stdoutBytes":data.len(),"stderrBase64":"","stderrCursor":0,"stderrBytes":0,"done":true}))}).await.unwrap();
            let text = result["stdout"].as_str().unwrap();
            if (7..17).contains(&(cursor as usize)) {
                assert!(
                    !text.contains(|c: char| c.is_ascii_uppercase() || c == '-'),
                    "cursor {cursor}: {text}"
                );
            }
            assert!(result.get("stdoutBase64").is_none());
            assert!(result["stdoutCursor"].as_u64().unwrap() > cursor);
        }
    }
    #[tokio::test]
    async fn unfinished_tail_waits_and_completed_tail_is_masked() {
        let data = b"ready SEC";
        let secrets = vec!["SECRET".into()];
        for done in [false, true] {
            let result=read_with(0,0,65536,&secrets,|out,_|async move{Ok(json!({"stdoutBase64":STANDARD.encode(&data[out as usize..]),"stdoutCursor":data.len(),"stdoutBytes":data.len(),"stderrBase64":"","stderrCursor":0,"stderrBytes":0,"done":done}))}).await.unwrap();
            assert_eq!(result["stdout"], if done { "ready ***" } else { "ready " });
            assert_eq!(result["stdoutCursor"], if done { 9 } else { 6 });
        }
    }
    #[tokio::test]
    async fn characters_split_across_pages_arrive_whole() {
        let mut data = vec![b'a'; 65535];
        data.extend_from_slice("é🦉 done".as_bytes());
        let total = data.len() as u64;
        let data = &data;
        let mut cursor = 0;
        let mut text = String::new();
        while cursor < total {
            let result=read_with(cursor,0,65536,&[],|out,_|async move{let end=(out+65536).min(total);Ok(json!({"stdoutBase64":STANDARD.encode(&data[out as usize..end as usize]),"stdoutCursor":end,"stdoutBytes":total,"stderrBase64":"","stderrCursor":0,"stderrBytes":0,"done":true}))}).await.unwrap();
            let next = result["stdoutCursor"].as_u64().unwrap();
            assert!(next > cursor);
            text.push_str(result["stdout"].as_str().unwrap());
            cursor = next;
        }
        assert!(!text.contains('\u{FFFD}'));
        assert!(text.ends_with("aé🦉 done"));
        // A window smaller than one character still makes progress.
        let owl = "🦉".as_bytes();
        let result=read_with(0,0,1,&[],|out,_|async move{Ok(json!({"stdoutBase64":STANDARD.encode(&owl[out as usize..]),"stdoutCursor":owl.len(),"stdoutBytes":owl.len(),"stderrBase64":"","stderrCursor":0,"stderrBytes":0,"done":false}))}).await.unwrap();
        assert!(result["stdoutCursor"].as_u64().unwrap() > 0);
        assert_eq!(incomplete_utf8_tail("a🦉".as_bytes()), 0);
        assert_eq!(incomplete_utf8_tail(&"a🦉".as_bytes()[..3]), 2);
        assert_eq!(incomplete_utf8_tail(&"é".as_bytes()[..1]), 1);
    }
}
