//! Small helpers shared by the engine's parts: ids, text cutting, dates, canonical JSON.
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// A short unique id for events: `m-1a2b3c4d5e6f`.
pub fn new_id(prefix: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", &id[..12])
}

/// Nine letters and digits: a tool-call id every server accepts (some insist on exactly this).
pub fn call_id() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    uuid::Uuid::new_v4().as_bytes()[..9].iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/// A random factor between 0.8 and 1.2, to spread retries.
pub fn jitter() -> f64 {
    let n = uuid::Uuid::new_v4().as_u128() % 10_000;
    0.8 + (n as f64 / 10_000.0) * 0.4
}

/// The longest prefix of `text` within `max` bytes that ends on a character boundary.
pub fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The longest suffix of `text` within `max` bytes that starts on a character boundary.
pub fn cut_tail(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// Text on one line with runs of whitespace collapsed, cut to `max` characters with an ellipsis.
pub fn one_line(text: &str, max: usize) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max {
        return joined;
    }
    let mut out: String = joined.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// JSON with object keys sorted, so equal values compare equal as text.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", Value::String(key.clone()), canonical(&map[key])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(canonical).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date for a count of days since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

/// `YYYY-MM-DD` (UTC) for seconds since 1970.
pub fn date(unix: u64) -> String {
    let (year, month, day) = civil_from_days((unix / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DD HH:MM` (UTC) for seconds since 1970.
pub fn date_time(unix: u64) -> String {
    let rest = unix % 86_400;
    format!("{} {:02}:{:02}", date(unix), rest / 3600, (rest % 3600) / 60)
}

/// Seconds since 1970 for an HTTP date such as `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(value: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day: u32 = parts[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(parts[2]))? as u32 + 1;
    let year: i64 = parts[3].parse().ok()?;
    let mut clock = parts[4].split(':').map(|p| p.parse::<u64>().ok());
    let (hours, minutes, seconds) = (clock.next()??, clock.next()??, clock.next()??);
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hours * 3600 + minutes * 60 + seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(days_from_civil(2026, 11, 12)), (2026, 11, 12));
        assert_eq!(civil_from_days(days_from_civil(2000, 2, 29)), (2000, 2, 29));
        assert_eq!(date(784_111_777), "1994-11-06");
        assert_eq!(http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(http_date("soon"), None);
        assert_eq!(date_time(784_111_777), "1994-11-06 08:49");
    }

    #[test]
    fn cutting_respects_characters() {
        assert_eq!(cut("h\u{e9}llo", 2), "h");
        assert_eq!(cut_tail("h\u{e9}llo", 5), "\u{e9}llo");
        assert_eq!(cut_tail("h\u{e9}llo", 4), "llo");
        assert_eq!(one_line("a\n  b\tc", 10), "a b c");
        assert_eq!(one_line("abcdefghijk", 5), "abcd\u{2026}");
    }

    #[test]
    fn canonical_json_sorts_keys() {
        assert_eq!(canonical(&json!({"b": 1, "a": [{"d": 2, "c": "x"}]})), r#"{"a":[{"c":"x","d":2}],"b":1}"#);
        let id = call_id();
        assert_eq!(id.len(), 9);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
        let j = jitter();
        assert!((0.8..=1.2).contains(&j));
    }
}
