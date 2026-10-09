//! Terminal decoration only. Wire JSON, guest output and stored data never use
//! this module. SSH clients sometimes decode UTF-8 as a legacy code page.
use std::{borrow::Cow, sync::OnceLock};

pub fn stdout_color() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
        && std::env::var("NO_COLOR").ok().is_none_or(|value| value.is_empty())
        && !matches!(std::env::var("TERM").ok().as_deref(), Some("dumb" | "xterm-mono"))
}

pub fn ascii() -> bool {
    static ASCII: OnceLock<bool> = OnceLock::new();
    *ASCII.get_or_init(|| {
        let get = |key: &str| std::env::var(key).unwrap_or_default();
        let locale = [get("LC_ALL"), get("LC_CTYPE"), get("LANG")]
            .into_iter().find(|v| !v.is_empty()).unwrap_or_default();
        choose_ascii(&get("YOUGORI_ASCII"),
            !get("SSH_CONNECTION").is_empty() || !get("SSH_TTY").is_empty(),
            &locale, cfg!(windows))
    })
}

fn choose_ascii(setting: &str, ssh: bool, locale: &str, windows: bool) -> bool {
    match setting.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => true,
        "0" | "false" | "no" => false,
        _ => {
            let locale = locale.to_ascii_lowercase();
            ssh || (!windows && !locale.contains("utf-8") && !locale.contains("utf8"))
        }
    }
}

pub fn text(s: &str) -> Cow<'_, str> { text_mode(s, ascii()) }

pub fn text_mode(s: &str, ascii: bool) -> Cow<'_, str> {
    if !ascii { return Cow::Borrowed(s); }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        // Preserve ANSI and OSC payloads, including URLs, byte for byte.
        if c == '\x1b' {
            out.push(c);
            match chars.next() {
                Some('[') => {
                    out.push('[');
                    for c in chars.by_ref() {
                        out.push(c);
                        if ('\u{40}'..='\u{7e}').contains(&c) { break; }
                    }
                }
                Some(']') => {
                    out.push(']');
                    while let Some(c) = chars.next() {
                        out.push(c);
                        if c == '\x07' { break; }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            out.push(chars.next().unwrap()); break;
                        }
                    }
                }
                Some(c) => out.push(c),
                None => (),
            }
            continue;
        }
        let replacement = match c {
            '─' | '━' | '—' | '–' => "-",
            '│' | '┃' => "|",
            '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => "+",
            '●' | '•' | '·' | '◆' | '◇' => "*",
            '○' => "o", '■' | '█' | '▀' | '▄' => "#",
            '░' | '▒' | '▓' => ".",
            '▲' | '△' | '⚠' => "!", '✓' | '✔' => "+", '✕' | '✖' | '×' => "x",
            '→' => "->", '←' => "<-", '↑' => "^", '↓' => "v", '↔' => "<->",
            '…' => "...",
            '⠋' | '⠙' | '⠹' | '⠸' | '⠼' | '⠴' | '⠦' | '⠧' | '⠇' | '⠏' => "*",
            '▁' | '▂' => "_", '▃' | '▅' | '▆' | '▇' | '▉' | '▊' | '▋' | '▌' | '▍' | '▎' | '▏' => "#",
            '▸' | '▶' | '▹' => ">",
            _ => { out.push(c); continue; }
        };
        out.push_str(replacement);
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_policy_respects_override_ssh_and_locale() {
        assert!(!choose_ascii("0", true, "C", false));
        assert!(choose_ascii("1", false, "en_US.UTF-8", true));
        assert!(choose_ascii("", true, "en_US.UTF-8", false));
        assert!(choose_ascii("", false, "C", false));
        assert!(!choose_ascii("", false, "C.UTF-8", false));
        assert!(!choose_ascii("", false, "en_US.utf8", false));
        assert!(!choose_ascii("", false, "", true));
    }

    #[test]
    fn fallback_preserves_user_names_ansi_and_hyperlink_targets() {
        let line = "\x1b[32m◇ café 日本 → ready…\x1b[0m";
        assert_eq!(text_mode(line, true), "\x1b[32m* café 日本 -> ready...\x1b[0m");
        assert_eq!(text_mode(line, false), line);
        let url = "\x1b]8;;https://example.com/a→b\x1b\\Open →\x1b]8;;\x1b\\";
        assert_eq!(text_mode(url, true), "\x1b]8;;https://example.com/a→b\x1b\\Open ->\x1b]8;;\x1b\\");
    }
}
