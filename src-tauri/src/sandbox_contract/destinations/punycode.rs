//! Punycode (RFC 3492), used only to check that an A-label is well formed and canonical
//! (VM §4.2 step 2: ambiguous encodings are rejected). Full IDNA2008 validation of the
//! decoded U-label needs Unicode tables this crate does not have, so it is not claimed.

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

fn decode_digit(byte: u8) -> Option<u32> {
    match byte {
        b'a'..=b'z' => Some(u32::from(byte - b'a')),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 26),
        _ => None,
    }
}

fn encode_digit(digit: u32) -> Option<char> {
    match digit {
        0..=25 => char::from_u32(u32::from(b'a') + digit),
        26..=35 => char::from_u32(u32::from(b'0') + digit - 26),
        _ => None,
    }
}

/// Decodes the part of an A-label after `xn--` into code points; `None` when the input
/// is not valid lowercase Punycode or overflows.
pub(crate) fn decode(input: &str) -> Option<Vec<u32>> {
    let (basic, extended) = match input.rfind('-') {
        Some(index) => (&input[..index], &input[index + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() {
        return None;
    }
    let mut output: Vec<u32> = basic.bytes().map(u32::from).collect();
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut bytes = extended.bytes().peekable();
    while bytes.peek().is_some() {
        let old_i = i;
        let mut weight: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = decode_digit(bytes.next()?)?;
            i = i.checked_add(digit.checked_mul(weight)?)?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            weight = weight.checked_mul(BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        let length = u32::try_from(output.len()).ok()?.checked_add(1)?;
        bias = adapt(i - old_i, length, old_i == 0);
        n = n.checked_add(i / length)?;
        i %= length;
        let position = usize::try_from(i).ok()?;
        output.insert(position, n);
        i += 1;
    }
    Some(output)
}

/// Encodes code points as Punycode (without the `xn--` prefix); `None` on overflow.
pub(crate) fn encode(input: &[u32]) -> Option<String> {
    let mut output: String = input
        .iter()
        .filter(|&&point| point < 0x80)
        .filter_map(|&point| char::from_u32(point))
        .collect();
    let basic = u32::try_from(output.len()).ok()?;
    let total = u32::try_from(input.len()).ok()?;
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while handled < total {
        let next = input.iter().copied().filter(|&point| point >= n).min()?;
        delta = delta.checked_add((next - n).checked_mul(handled + 1)?)?;
        n = next;
        for &point in input {
            if point < n {
                delta = delta.checked_add(1)?;
            }
            if point == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + (q - t) % (BASE - t))?);
                    q = (q - t) / (BASE - t);
                    k = k.checked_add(BASE)?;
                }
                output.push(encode_digit(q)?);
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn points(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    #[test]
    fn known_vectors_decode_and_encode() {
        assert_eq!(decode("bcher-kva"), Some(points("bücher")));
        assert_eq!(encode(&points("bücher")).as_deref(), Some("bcher-kva"));
        assert_eq!(decode("mnchen-3ya"), Some(points("münchen")));
        // RFC 3492 section 7.1, sample (B): simplified Chinese.
        let chinese = points("他们为什么不说中文");
        assert_eq!(
            encode(&chinese).as_deref(),
            Some("ihqwcrb4cv8a8dqg056pqjye")
        );
        assert_eq!(decode("ihqwcrb4cv8a8dqg056pqjye"), Some(chinese));
    }

    #[test]
    fn malformed_input_is_refused() {
        assert_eq!(decode("bcher-kv!"), None);
        assert_eq!(decode("b\u{fc}cher-kva"), None);
        // Digit 35 never ends a number, so the weight overflows.
        assert_eq!(decode("9999999999999999"), None);
        // A truncated digit sequence ends mid-number.
        assert_eq!(decode("bcher-k9"), None);
    }
}
