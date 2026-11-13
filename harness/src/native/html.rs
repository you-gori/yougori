//! HTML as readable text for webfetch: headings, paragraphs, lists, links, code and tables in
//! plain text; scripts, styles and page navigation left out. Tolerant of broken markup.

/// Tags whose content is never text for a reader.
const SKIP: &[&str] = &["script", "style", "noscript", "template", "svg", "iframe", "object", "canvas", "nav", "footer", "head"];

struct Writer {
    out: String,
    pre: usize,
    lists: Vec<(bool, usize)>,
    links: Vec<(usize, Option<String>)>,
    cells: usize,
    base: Option<reqwest::Url>,
}

impl Writer {
    fn ends_with_newlines(&self) -> usize {
        self.out.chars().rev().take_while(|c| *c == '\n').count()
    }

    /// Ensures the text so far ends with `count` line breaks (none at the very start).
    fn block(&mut self, count: usize) {
        let trimmed = self.out.trim_end_matches([' ', '\t']).len();
        self.out.truncate(trimmed);
        if self.out.is_empty() {
            return;
        }
        let have = self.ends_with_newlines();
        for _ in have..count {
            self.out.push('\n');
        }
    }

    fn text(&mut self, text: &str) {
        if self.pre > 0 {
            self.out.push_str(text);
            return;
        }
        for (index, word) in text.split_whitespace().enumerate() {
            let starts_word = index > 0 || text.starts_with(char::is_whitespace);
            let at_line_start = self.out.is_empty() || self.out.ends_with('\n');
            if starts_word && !at_line_start && !self.out.ends_with(' ') {
                self.out.push(' ');
            }
            self.out.push_str(word);
        }
        if text.ends_with(char::is_whitespace) && !text.trim().is_empty() && !self.out.ends_with('\n') {
            self.out.push(' ');
        }
    }

    fn link_target(&self, href: &str) -> Option<String> {
        let href = href.trim();
        if href.is_empty() || href.starts_with('#') || href.starts_with("javascript:") || href.starts_with("mailto:") {
            return None;
        }
        let url = match &self.base {
            Some(base) => base.join(href).ok()?,
            None => reqwest::Url::parse(href).ok()?,
        };
        matches!(url.scheme(), "http" | "https").then(|| url.to_string())
    }
}

fn attribute(attributes: &str, name: &str) -> Option<String> {
    let lower = attributes.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find(name) {
        let at = from + found;
        from = at + name.len();
        let before_ok = at == 0 || lower.as_bytes()[at - 1].is_ascii_whitespace();
        let rest = attributes[at + name.len()..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let rest = rest[1..].trim_start();
        let value = match rest.chars().next() {
            Some(quote @ ('"' | '\'')) => rest[1..].split(quote).next().unwrap_or(""),
            _ => rest.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or(""),
        };
        return Some(decode(value));
    }
    None
}

/// The page's text; `base` resolves relative links.
pub fn to_text(html: &str, base: Option<&reqwest::Url>) -> String {
    let mut w = Writer { out: String::new(), pre: 0, lists: Vec::new(), links: Vec::new(), cells: 0, base: base.cloned() };
    let mut title: Option<String> = None;
    let mut skipping: Option<String> = None;
    let mut i = 0;
    let bytes = html.as_bytes();
    while i < html.len() {
        if bytes[i] != b'<' {
            let end = html[i..].find('<').map(|n| i + n).unwrap_or(html.len());
            if skipping.is_none() {
                w.text(&decode(&html[i..end]));
            }
            i = end;
            continue;
        }
        if html[i..].starts_with("<!--") {
            i = html[i..].find("-->").map(|n| i + n + 3).unwrap_or(html.len());
            continue;
        }
        // A `<` that cannot start a tag is text.
        if !bytes.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, b'/' | b'!' | b'?')) {
            if skipping.is_none() {
                w.text("<");
            }
            i += 1;
            continue;
        }
        // The tag runs to the next `>` outside quotes.
        let mut end = i + 1;
        let mut quote: Option<u8> = None;
        while end < bytes.len() {
            match (quote, bytes[end]) {
                (None, b'"' | b'\'') => quote = Some(bytes[end]),
                (Some(q), c) if c == q => quote = None,
                (None, b'>') => break,
                _ => {}
            }
            end += 1;
        }
        let inside = &html[i + 1..end.min(html.len())];
        i = (end + 1).min(html.len());
        if inside.starts_with('!') || inside.starts_with('?') {
            continue;
        }
        let closing = inside.starts_with('/');
        let body = inside.trim_start_matches('/');
        let name: String = body.chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let attributes = &body[name.len()..];
        if name == "title" && !closing && title.is_none() {
            let mut end = (i + 4096).min(html.len());
            while !html.is_char_boundary(end) {
                end -= 1;
            }
            let close = html[i..end].to_ascii_lowercase().find("</title").map(|n| i + n).unwrap_or(i);
            let text = decode(&html[i..close]).split_whitespace().collect::<Vec<_>>().join(" ");
            if !text.is_empty() {
                title = Some(text);
            }
            i = close;
            continue;
        }
        if let Some(skipped) = &skipping {
            // A page that never closes its head still has a body.
            if (closing && name == *skipped) || (skipped == "head" && !closing && name == "body") {
                skipping = None;
            }
            continue;
        }
        if SKIP.contains(&name.as_str()) {
            if !closing && !inside.ends_with('/') {
                skipping = Some(name);
            }
            continue;
        }
        match (name.as_str(), closing) {
            ("h1" | "h2" | "h3" | "h4" | "h5" | "h6", false) => {
                w.block(2);
                let level = name[1..].parse::<usize>().unwrap_or(1);
                w.out.push_str(&"#".repeat(level));
                w.out.push(' ');
            }
            ("h1" | "h2" | "h3" | "h4" | "h5" | "h6", true) | ("p", _) | ("table", _) | ("blockquote", _) => w.block(2),
            ("div" | "section" | "article" | "main" | "header" | "aside" | "figure" | "figcaption" | "dl" | "dd" | "dt" | "form" | "details" | "summary" | "address", _) => {
                w.block(1)
            }
            ("br", _) => {
                let trimmed = w.out.trim_end_matches(' ').len();
                w.out.truncate(trimmed);
                w.out.push('\n');
            }
            ("hr", _) => {
                w.block(2);
                w.out.push_str("---");
                w.block(2);
            }
            ("ul", false) => {
                w.block(1);
                w.lists.push((false, 0));
            }
            ("ol", false) => {
                w.block(1);
                w.lists.push((true, 0));
            }
            ("ul" | "ol", true) => {
                w.lists.pop();
                w.block(1);
            }
            ("li", false) => {
                w.block(1);
                let depth = w.lists.len().max(1);
                w.out.push_str(&"  ".repeat(depth - 1));
                let marker = match w.lists.last_mut() {
                    Some((true, count)) => {
                        *count += 1;
                        format!("{count}. ")
                    }
                    _ => "- ".to_owned(),
                };
                w.out.push_str(&marker);
            }
            ("li", true) => w.block(1),
            ("pre", false) => {
                w.block(2);
                w.out.push_str("```\n");
                w.pre += 1;
            }
            ("pre", true) => {
                w.pre = w.pre.saturating_sub(1);
                if !w.out.ends_with('\n') {
                    w.out.push('\n');
                }
                w.out.push_str("```");
                w.block(2);
            }
            ("code", _) if w.pre == 0 => w.out.push('`'),
            ("a", false) => {
                let href = attribute(attributes, "href").and_then(|h| w.link_target(&h));
                w.links.push((w.out.len(), href));
            }
            ("a", true) => {
                if let Some((start, Some(href))) = w.links.pop() {
                    let text = w.out.get(start..).unwrap_or("").trim().to_owned();
                    if !text.is_empty() && text != href && !href.ends_with(&text) {
                        w.out.push_str(&format!(" ({href})"));
                    }
                }
            }
            ("img", _) => {
                if let Some(alt) = attribute(attributes, "alt").filter(|a| !a.trim().is_empty()) {
                    w.text(&format!(" [image: {}] ", alt.trim()));
                }
            }
            ("tr", false) => {
                w.block(1);
                w.cells = 0;
            }
            ("td" | "th", false) => {
                if w.cells > 0 {
                    w.out.push_str(" | ");
                }
                w.cells += 1;
            }
            _ => {}
        }
    }
    let mut text = String::new();
    if let Some(title) = title {
        text.push_str(&format!("Title: {title}\n\n"));
    }
    text.push_str(&w.out);
    tidy(&text)
}

/// Trailing spaces off every line, at most one blank line in a row.
fn tidy(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut blank = 0;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_owned()
}

/// Character references: named common ones and numeric ones.
pub fn decode(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..].find(|c: char| c == ';' || c.is_whitespace() || c == '&').map(|n| n + 1);
        let decoded = match end {
            Some(end) if rest.as_bytes().get(end) == Some(&b';') && end <= 12 => {
                let name = &rest[1..end];
                let value = match name {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "nbsp" => Some(' '),
                    "mdash" => Some('\u{2014}'),
                    "ndash" => Some('\u{2013}'),
                    "hellip" => Some('\u{2026}'),
                    "copy" => Some('\u{a9}'),
                    "reg" => Some('\u{ae}'),
                    "trade" => Some('\u{2122}'),
                    "laquo" => Some('\u{ab}'),
                    "raquo" => Some('\u{bb}'),
                    "ldquo" => Some('\u{201c}'),
                    "rdquo" => Some('\u{201d}'),
                    "lsquo" => Some('\u{2018}'),
                    "rsquo" => Some('\u{2019}'),
                    "middot" => Some('\u{b7}'),
                    "bull" => Some('\u{2022}'),
                    "times" => Some('\u{d7}'),
                    _ => {
                        let number = name.strip_prefix('#').and_then(|n| match n.strip_prefix(['x', 'X']) {
                            Some(hex) => u32::from_str_radix(hex, 16).ok(),
                            None => n.parse::<u32>().ok(),
                        });
                        number.and_then(char::from_u32)
                    }
                };
                value.map(|c| (c, end + 1))
            }
            _ => None,
        };
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &rest[used..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_become_readable_text() {
        let html = r#"<!DOCTYPE html><html><head><title>Guide &amp; Notes</title><style>p{color:red}</style>
            <script>var x = "<p>no</p>";</script></head><body><nav><a href="/">Home</a></nav>
            <h1>Install</h1><p>Run   the <code>setup</code> script.<br>Then restart.</p>
            <ul><li>One</li><li>Two <a href="/docs/two">details</a></li></ul>
            <ol><li>First</li><li>Second</li></ol>
            <pre>let x = 1;
    let y = 2;</pre>
            <table><tr><th>Name</th><th>Size</th></tr><tr><td>a</td><td>1 KB</td></tr></table>
            <p>Caf&eacute; &#233; &#x263A; &lt;tag&gt;</p><!-- hidden --><footer>Copyright</footer></body></html>"#;
        let base = reqwest::Url::parse("https://example.com/start/").unwrap();
        let text = to_text(html, Some(&base));
        assert!(text.starts_with("Title: Guide & Notes\n\n# Install\n\nRun the `setup` script.\nThen restart."), "{text}");
        assert!(text.contains("- One\n- Two details (https://example.com/docs/two)"), "{text}");
        assert!(text.contains("1. First\n2. Second"), "{text}");
        assert!(text.contains("```\nlet x = 1;\n    let y = 2;\n```"), "{text}");
        assert!(text.contains("Name | Size\na | 1 KB"), "{text}");
        assert!(text.contains("Caf&eacute; \u{e9} \u{263a} <tag>"), "{text}");
        assert!(!text.contains("color") && !text.contains("no</p>") && !text.contains("Home") && !text.contains("Copyright"), "{text}");
    }

    #[test]
    fn broken_markup_does_not_break_the_text() {
        assert_eq!(to_text("a < b and <unclosed", None), "a < b and");
        assert_eq!(to_text("<p>x</p><p>y", None), "x\n\ny");
        assert_eq!(to_text("<html><head><title>T</title><body><p>Shown</p>", None), "Title: T\n\nShown");
        assert_eq!(decode("&amp;&bogus;&#65;&"), "&&bogus;A&");
    }
}
