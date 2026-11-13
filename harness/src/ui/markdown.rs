//! A model's markdown drawn as terminal lines: headings, paragraphs, lists, block quotes, fenced
//! code (highlighted), simple tables, rules, emphasis, inline code, and links as text.
use super::highlight::Code;
use super::text::{self, span, spans_width, wrap, wrap_hard};
use super::theme::Theme;
use pulldown_cmark::{Alignment, CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

/// Rendering state kept with a message between frames: its code blocks' highlighting.
#[derive(Default)]
pub struct Markdown {
    codes: Vec<Code>,
}

impl Markdown {
    pub fn new() -> Markdown {
        Markdown::default()
    }

    /// The text as lines at most `width` columns wide.
    pub fn render(&mut self, source: &str, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        let mut r = Renderer::new(theme, width.max(8), &mut self.codes);
        let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        for event in Parser::new_ext(source, options) {
            r.event(event);
        }
        r.finish()
    }
}

struct List {
    next: Option<u64>,
    /// Columns the current item's marker takes ("• " is 2, "12. " is 4).
    indent: usize,
    /// The marker not drawn yet: the item's first line takes it.
    marker: Option<String>,
}

#[derive(Default)]
struct Table {
    alignments: Vec<Alignment>,
    rows: Vec<Vec<Vec<Span<'static>>>>,
    header: bool,
    row: Vec<Vec<Span<'static>>>,
}

struct Renderer<'a> {
    theme: &'a Theme,
    width: usize,
    codes: &'a mut Vec<Code>,
    code_index: usize,
    lines: Vec<Line<'static>>,
    inline: Vec<Span<'static>>,
    styles: Vec<Style>,
    links: Vec<(String, usize)>,
    quotes: usize,
    lists: Vec<List>,
    code: Option<(String, String)>,
    heading: Option<HeadingLevel>,
    table: Option<Table>,
    cell: Option<Vec<Span<'static>>>,
    /// A blank line goes before the next block.
    gap: bool,
}

impl<'a> Renderer<'a> {
    fn new(theme: &'a Theme, width: usize, codes: &'a mut Vec<Code>) -> Renderer<'a> {
        Renderer {
            theme,
            width,
            codes,
            code_index: 0,
            lines: Vec::new(),
            inline: Vec::new(),
            styles: Vec::new(),
            links: Vec::new(),
            quotes: 0,
            lists: Vec::new(),
            code: None,
            heading: None,
            table: None,
            cell: None,
            gap: false,
        }
    }

    fn style(&self) -> Style {
        self.styles.iter().fold(Style::default(), |acc, s| acc.patch(*s))
    }

    fn rails(&self) -> Vec<Span<'static>> {
        (0..self.quotes).map(|_| span("│ ", self.theme.muted())).collect()
    }

    /// Prefixes for a block's first line and the lines after it.
    fn prefixes(&mut self) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        let mut first = self.rails();
        let mut rest = self.rails();
        let count = self.lists.len();
        for (i, list) in self.lists.iter_mut().enumerate() {
            if i + 1 == count {
                match list.marker.take() {
                    Some(marker) => first.push(span(marker, self.theme.muted())),
                    None => first.push(text::pad(list.indent)),
                }
            } else {
                first.push(text::pad(list.indent));
            }
            rest.push(text::pad(list.indent));
        }
        (first, rest)
    }

    fn blank(&mut self) {
        if self.lines.is_empty() {
            return;
        }
        let rails = self.rails();
        self.lines.push(Line::from(rails));
    }

    /// Puts the pending blank line before a new block (never inside list items).
    fn open_block(&mut self) {
        self.flush();
        if self.gap && self.lists.is_empty() {
            self.blank();
        }
        self.gap = false;
    }

    fn flush(&mut self) {
        if self.inline.is_empty() {
            return;
        }
        let spans = std::mem::take(&mut self.inline);
        let (first, rest) = self.prefixes();
        if spans.iter().all(|s| s.content.trim().is_empty()) && first.iter().all(|s| s.content.trim().is_empty()) {
            return;
        }
        self.lines.extend(wrap(&spans, self.width, &first, &rest));
    }

    fn push_text(&mut self, text: &str, style: Style) {
        if text.is_empty() {
            return;
        }
        let target = match self.cell.as_mut() {
            Some(cell) => cell,
            None => &mut self.inline,
        };
        match target.last_mut() {
            Some(last) if last.style == style => last.content.to_mut().push_str(text),
            _ => target.push(Span::styled(text.to_owned(), style)),
        }
    }

    fn event(&mut self, event: Event<'_>) {
        if let Some((_, code)) = self.code.as_mut() {
            match event {
                Event::Text(t) => {
                    code.push_str(&t);
                    return;
                }
                Event::End(TagEnd::CodeBlock) => {}
                _ => return,
            }
        }
        match event {
            Event::Start(tag) => self.start(tag),
            Event::End(tag) => self.end(tag),
            Event::Text(t) => {
                let style = self.style();
                self.push_text(&t, style);
            }
            Event::Code(t) | Event::InlineMath(t) => {
                let style = self.style().patch(self.theme.code());
                self.push_text(&t, style);
            }
            Event::DisplayMath(t) => {
                self.open_block();
                let (first, rest) = self.prefixes();
                let code = self.theme.code();
                for (i, line) in t.trim_matches('\n').split('\n').enumerate() {
                    let prefix = if i == 0 { &first } else { &rest };
                    let spans = text::expand_tabs(&[span(line, code)]);
                    self.lines.extend(wrap_hard(&spans, self.width, prefix, &rest));
                }
                self.gap = true;
            }
            Event::Html(t) | Event::InlineHtml(t) => {
                let style = self.theme.muted();
                self.push_text(t.trim_end_matches('\n'), style);
            }
            Event::FootnoteReference(name) => {
                let style = self.theme.muted();
                self.push_text(&format!("[{name}]"), style);
            }
            Event::SoftBreak => {
                let style = self.style();
                self.push_text(" ", style);
            }
            Event::HardBreak => {
                if self.cell.is_some() {
                    let style = self.style();
                    self.push_text(" ", style);
                } else {
                    self.flush();
                }
            }
            Event::Rule => {
                self.open_block();
                let (first, _) = self.prefixes();
                let room = self.width.saturating_sub(spans_width(&first)).max(1);
                let mut spans = first;
                spans.push(span("─".repeat(room), self.theme.muted()));
                self.lines.push(Line::from(spans));
                self.gap = true;
            }
            Event::TaskListMarker(done) => {
                let style = if done { self.theme.good() } else { self.theme.muted() };
                self.push_text(if done { "[x] " } else { "[ ] " }, style);
            }
        }
    }

    fn start(&mut self, tag: Tag<'_>) {
        match tag {
            Tag::Paragraph => self.open_block(),
            Tag::Heading { level, .. } => {
                self.open_block();
                self.heading = Some(level);
                let style = match level {
                    HeadingLevel::H1 | HeadingLevel::H2 => self.theme.accent().add_modifier(Modifier::BOLD),
                    _ => self.theme.bold(),
                };
                self.styles.push(style);
            }
            Tag::BlockQuote(_) => {
                self.open_block();
                self.quotes += 1;
                self.styles.push(Style::new().add_modifier(Modifier::ITALIC));
            }
            Tag::CodeBlock(kind) => {
                self.open_block();
                let language = match kind {
                    CodeBlockKind::Fenced(info) => info.to_string(),
                    CodeBlockKind::Indented => String::new(),
                };
                self.code = Some((language, String::new()));
            }
            Tag::HtmlBlock => self.open_block(),
            Tag::List(start) => {
                if self.lists.is_empty() {
                    self.open_block();
                } else {
                    self.flush();
                }
                self.lists.push(List { next: start, indent: 2, marker: None });
            }
            Tag::Item => {
                self.flush();
                if let Some(list) = self.lists.last_mut() {
                    let marker = match list.next.as_mut() {
                        Some(n) => {
                            let marker = format!("{n}. ");
                            *n += 1;
                            marker
                        }
                        None => "• ".to_owned(),
                    };
                    list.indent = text::width(&marker);
                    list.marker = Some(marker);
                }
            }
            Tag::Table(alignments) => {
                self.open_block();
                self.table = Some(Table { alignments, ..Table::default() });
            }
            Tag::TableHead => {
                if let Some(table) = self.table.as_mut() {
                    table.header = true;
                    table.row.clear();
                }
            }
            Tag::TableRow => {
                if let Some(table) = self.table.as_mut() {
                    table.row.clear();
                }
            }
            Tag::TableCell => self.cell = Some(Vec::new()),
            Tag::Emphasis => self.styles.push(Style::new().add_modifier(Modifier::ITALIC)),
            Tag::Strong => self.styles.push(Style::new().add_modifier(Modifier::BOLD)),
            Tag::Strikethrough => self.styles.push(Style::new().add_modifier(Modifier::CROSSED_OUT)),
            Tag::Superscript | Tag::Subscript => self.styles.push(Style::new()),
            Tag::Link { dest_url, .. } => {
                let at = self.text_len();
                self.links.push((dest_url.to_string(), at));
                self.styles.push(self.theme.accent().add_modifier(Modifier::UNDERLINED));
            }
            Tag::Image { dest_url, .. } => {
                let at = self.text_len();
                self.links.push((dest_url.to_string(), at));
                let style = self.theme.muted();
                self.push_text("[image: ", style);
                self.styles.push(self.theme.muted());
            }
            Tag::FootnoteDefinition(name) => {
                self.open_block();
                let style = self.theme.muted();
                self.push_text(&format!("[{name}] "), style);
            }
            Tag::DefinitionList | Tag::DefinitionListTitle | Tag::DefinitionListDefinition => self.open_block(),
            Tag::MetadataBlock(_) => self.open_block(),
        }
    }

    /// The text written so far into the current inline run, to tell a link's text from its URL.
    fn text_len(&self) -> usize {
        let target = self.cell.as_ref().unwrap_or(&self.inline);
        target.iter().map(|s| s.content.len()).sum()
    }

    fn text_since(&self, at: usize) -> String {
        let target = self.cell.as_ref().unwrap_or(&self.inline);
        let all: String = target.iter().map(|s| s.content.as_ref()).collect();
        all.get(at..).unwrap_or("").to_owned()
    }

    fn end(&mut self, tag: TagEnd) {
        match tag {
            TagEnd::Paragraph => {
                self.flush();
                self.gap = true;
            }
            TagEnd::Heading(_) => {
                self.flush();
                self.styles.pop();
                self.heading = None;
                self.gap = true;
            }
            TagEnd::BlockQuote(_) => {
                self.flush();
                self.quotes = self.quotes.saturating_sub(1);
                self.styles.pop();
                self.gap = true;
            }
            TagEnd::CodeBlock => {
                if let Some((language, mut code)) = self.code.take() {
                    if code.ends_with('\n') {
                        code.pop();
                    }
                    self.code_block(&language, &code);
                }
                self.gap = true;
            }
            TagEnd::HtmlBlock => {
                self.flush();
                self.gap = true;
            }
            TagEnd::List(_) => {
                self.flush();
                self.lists.pop();
                if self.lists.is_empty() {
                    self.gap = true;
                }
            }
            TagEnd::Item => self.flush(),
            TagEnd::Table => {
                if let Some(table) = self.table.take() {
                    self.draw_table(table);
                }
                self.gap = true;
            }
            TagEnd::TableHead => {
                if let Some(table) = self.table.as_mut() {
                    let row = std::mem::take(&mut table.row);
                    table.rows.push(row);
                }
            }
            TagEnd::TableRow => {
                if let Some(table) = self.table.as_mut() {
                    let row = std::mem::take(&mut table.row);
                    table.rows.push(row);
                }
            }
            TagEnd::TableCell => {
                let cell = self.cell.take().unwrap_or_default();
                if let Some(table) = self.table.as_mut() {
                    table.row.push(cell);
                }
            }
            TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough | TagEnd::Superscript | TagEnd::Subscript => {
                self.styles.pop();
            }
            TagEnd::Link => {
                self.styles.pop();
                if let Some((url, at)) = self.links.pop() {
                    let label = self.text_since(at);
                    let shown = url.trim_start_matches("mailto:");
                    if !url.is_empty() && !url.starts_with('#') && label.trim() != shown && label.trim() != url {
                        let style = self.theme.muted();
                        self.push_text(&format!(" ({url})"), style);
                    }
                }
            }
            TagEnd::Image => {
                self.styles.pop();
                self.links.pop();
                let style = self.theme.muted();
                self.push_text("]", style);
            }
            TagEnd::FootnoteDefinition => {
                self.flush();
                self.gap = true;
            }
            TagEnd::DefinitionList | TagEnd::DefinitionListTitle | TagEnd::DefinitionListDefinition => {
                self.flush();
                self.gap = true;
            }
            TagEnd::MetadataBlock(_) => {
                self.inline.clear();
                self.gap = true;
            }
        }
    }

    fn code_block(&mut self, language: &str, code: &str) {
        let index = self.code_index;
        self.code_index += 1;
        if self.codes.len() <= index {
            self.codes.push(Code::new(language));
        } else if self.codes[index].language() != language {
            self.codes[index] = Code::new(language);
        }
        let highlighted = self.codes[index].lines(code, self.theme);
        let (mut first, mut rest) = self.prefixes();
        first.push(text::pad(2));
        rest.push(text::pad(2));
        let continued = {
            let mut c = rest.clone();
            c.push(text::pad(2));
            c
        };
        for (i, spans) in highlighted.iter().enumerate() {
            let prefix = if i == 0 { &first } else { &rest };
            // Highlighted as written (a Makefile's recipe lines start with a tab), drawn with
            // the tabs as spaces.
            self.lines.extend(wrap_hard(&text::expand_tabs(spans), self.width, prefix, &continued));
        }
    }

    fn draw_table(&mut self, table: Table) {
        let columns = table.rows.iter().map(Vec::len).max().unwrap_or(0);
        if columns == 0 {
            return;
        }
        let (first, rest) = self.prefixes();
        let room = self.width.saturating_sub(spans_width(&rest));
        let gaps = 2 * (columns - 1);
        let mut widths = vec![1usize; columns];
        for row in &table.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(spans_width(cell));
            }
        }
        let available = room.saturating_sub(gaps).max(columns * 3);
        while widths.iter().sum::<usize>() > available {
            let (widest, _) = widths.iter().enumerate().max_by_key(|(_, w)| **w).unwrap_or((0, &0));
            if widths[widest] <= 3 {
                break;
            }
            widths[widest] -= 1;
        }
        let muted = self.theme.muted();
        let bold = self.theme.bold();
        let mut out: Vec<Line<'static>> = Vec::new();
        for (r, row) in table.rows.iter().enumerate() {
            let header = table.header && r == 0;
            let cells: Vec<Vec<Line<'static>>> = (0..columns)
                .map(|i| {
                    let mut spans = row.get(i).cloned().unwrap_or_default();
                    if header {
                        spans = spans.into_iter().map(|s| Span::styled(s.content, s.style.patch(bold))).collect();
                    }
                    wrap(&spans, widths[i], &[], &[])
                })
                .collect();
            let height = cells.iter().map(Vec::len).max().unwrap_or(1);
            for l in 0..height {
                let mut spans: Vec<Span<'static>> = Vec::new();
                for (i, cell) in cells.iter().enumerate() {
                    let line = cell.get(l).cloned().unwrap_or_default();
                    let used = text::line_width(&line);
                    let free = widths[i].saturating_sub(used);
                    let (before, after) = match table.alignments.get(i) {
                        Some(Alignment::Right) => (free, 0),
                        Some(Alignment::Center) => (free / 2, free - free / 2),
                        _ => (0, free),
                    };
                    if before > 0 {
                        spans.push(text::pad(before));
                    }
                    spans.extend(line.spans);
                    if i + 1 < columns {
                        spans.push(text::pad(after + 2));
                    }
                }
                out.push(Line::from(spans));
            }
            if header {
                let rule: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
                out.push(Line::from(span(rule.join("  "), muted)));
            }
        }
        for (i, line) in out.into_iter().enumerate() {
            let mut spans = if i == 0 { first.clone() } else { rest.clone() };
            spans.extend(line.spans);
            self.lines.push(Line::from(spans));
        }
    }

    fn finish(mut self) -> Vec<Line<'static>> {
        self.flush();
        if let Some((language, code)) = self.code.take() {
            self.code_block(&language, &code);
        }
        while self.lines.last().is_some_and(|l| l.spans.iter().all(|s| s.content.trim().is_empty())) {
            self.lines.pop();
        }
        self.lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::Depth;

    fn render(source: &str, width: usize) -> Vec<String> {
        let theme = Theme::new(Depth::True);
        Markdown::new()
            .render(source, width, &theme)
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>().trim_end().to_owned())
            .collect()
    }

    #[test]
    fn paragraphs_headings_lists_and_quotes() {
        let lines = render("# Title\n\nSome *text* here.\n\n- one\n- two\n  1. nested\n\n> quoted\n\n---", 40);
        assert_eq!(
            lines,
            [
                "Title",
                "",
                "Some text here.",
                "",
                "• one",
                "• two",
                "  1. nested",
                "",
                "│ quoted",
                "",
                "────────────────────────────────────────"
            ]
        );
    }

    #[test]
    fn code_blocks_are_indented_and_highlighted() {
        let theme = Theme::new(Depth::True);
        let lines = Markdown::new().render("Run:\n\n```rust\nfn main() {}\n```\n", 40, &theme);
        let texts: Vec<String> = lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect();
        assert_eq!(texts, ["Run:", "", "  fn main() {}"]);
        assert!(lines[2].spans.iter().any(|s| s.content == "fn" && s.style.fg.is_some()));
    }

    #[test]
    fn tables_links_and_inline_code() {
        let lines = render("| Name | Size |\n|---|--:|\n| a.rs | 12 |\n| long name | 3 |\n\nSee [docs](https://example.com) and `cargo test`.", 40);
        assert_eq!(lines[0], "Name       Size");
        assert_eq!(lines[1], "─────────  ────");
        assert_eq!(lines[2], "a.rs         12");
        assert_eq!(lines[3], "long name     3");
        assert_eq!(lines[5], "See docs (https://example.com) and cargo");
        assert_eq!(lines[6], "test.");
    }

    #[test]
    fn code_indented_with_tabs_keeps_its_indentation() {
        let lines = render("```go\nfunc main() {\n\tif ok {\n\t\tfmt.Println(1)\n\t}\n}\n```\n", 60);
        assert_eq!(lines, ["  func main() {", "      if ok {", "          fmt.Println(1)", "      }", "  }"]);
        let lines = render("```\nall:\n\tcc -o app main.c\n```\n", 60);
        assert_eq!(lines, ["  all:", "      cc -o app main.c"]);
    }

    #[test]
    fn an_unclosed_fence_still_renders_while_streaming() {
        let lines = render("```python\nprint(1)\nprint(2", 40);
        assert_eq!(lines, ["  print(1)", "  print(2"]);
    }
}
