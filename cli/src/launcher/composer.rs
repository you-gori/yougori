//! The line a person types a message on in the terminal chats: a cursor, Up/Down for the
//! messages sent before, and wrapping for long messages.
use crate::cli_ui as ui;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The message being typed, with a cursor and the messages sent this session.
#[derive(Default)]
pub struct Editor {
    pub text: String,
    cursor: usize,
    sent: Vec<String>,
    recall: Option<usize>,
}

pub enum Input {
    Send(String),
    Leave,
    None,
}

impl Editor {
    pub fn key(&mut self, key: &KeyEvent) -> Input {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c' | 'd') if ctrl => return Input::Leave,
            KeyCode::Char('u') if ctrl => self.set(String::new()),
            KeyCode::Enter => {
                let text = self.text.trim().to_owned();
                if !text.is_empty() {
                    self.sent.push(text.clone());
                    self.recall = None;
                    self.set(String::new());
                    return Input::Send(text);
                }
            }
            KeyCode::Esc => self.set(String::new()),
            KeyCode::Backspace => {
                if let Some(c) = self.text[..self.cursor].chars().next_back() {
                    self.cursor -= c.len_utf8();
                    self.text.remove(self.cursor);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.text.len() {
                    self.text.remove(self.cursor);
                }
            }
            KeyCode::Left => {
                if let Some(c) = self.text[..self.cursor].chars().next_back() {
                    self.cursor -= c.len_utf8();
                }
            }
            KeyCode::Right => {
                if let Some(c) = self.text[self.cursor..].chars().next() {
                    self.cursor += c.len_utf8();
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Up if !self.sent.is_empty() => {
                let at = self.recall.map_or(self.sent.len() - 1, |i| i.saturating_sub(1));
                self.recall = Some(at);
                self.set(self.sent[at].clone());
            }
            KeyCode::Down => match self.recall {
                Some(i) if i + 1 < self.sent.len() => {
                    self.recall = Some(i + 1);
                    self.set(self.sent[i + 1].clone());
                }
                _ => {
                    self.recall = None;
                    self.set(String::new());
                }
            },
            KeyCode::Tab => self.insert(' '),
            KeyCode::Char(c) if !ctrl && !c.is_control() && self.text.len() < 30_000 => {
                self.insert(c)
            }
            _ => {}
        }
        Input::None
    }

    pub fn set(&mut self, text: String) {
        self.cursor = text.len();
        self.text = text;
    }

    pub fn insert(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Pasted text, joined onto one line.
    pub fn paste(&mut self, text: &str) {
        for c in text.chars() {
            if self.text.len() >= 30_000 {
                break;
            }
            self.insert(if c.is_control() { ' ' } else { c });
        }
    }

    /// The message wrapped to the terminal behind a `›` prompt, with the cursor shown as a
    /// highlighted cell. Empty, it shows `placeholder`.
    pub fn lines(&self, placeholder: &str, columns: usize) -> Vec<String> {
        let prompt = ui::paint("›", ui::SKY);
        self.rows(placeholder, columns.saturating_sub(2))
            .into_iter()
            .enumerate()
            .map(|(i, row)| format!("{} {row}", if i == 0 { prompt.clone() } else { " ".into() }))
            .collect()
    }

    /// The message's rows of at most `columns`, without a prompt; see [`Editor::lines`].
    pub fn rows(&self, placeholder: &str, columns: usize) -> Vec<String> {
        let caret = |c: &str| {
            if ui::color() {
                format!("\x1b[7m{c}\x1b[27m")
            } else {
                format!("[{c}]")
            }
        };
        if self.text.is_empty() {
            return vec![format!("{}{}", caret(" "), ui::muted(placeholder))];
        }
        let mut rows = Vec::new();
        let mut start = 0;
        for (row, used) in ui::wrap(&format!("{} ", self.text), columns.saturating_sub(2)) {
            let end = start + row.len();
            let shown = if (start..end).contains(&self.cursor) {
                let at = self.cursor - start;
                let c = row[at..].chars().next().map_or(" ".into(), String::from);
                format!("{}{}{}", &row[..at], caret(&c), &row[at + c.len()..])
            } else if self.cursor >= end && self.cursor < start + used {
                format!("{row}{}", caret(" "))
            } else {
                row
            };
            rows.push(shown);
            start += used;
        }
        // Long messages show their end, where the typing is.
        let keep = rows.len().saturating_sub(8);
        rows.split_off(keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(editor: &mut Editor, code: KeyCode) -> Option<String> {
        match editor.key(&KeyEvent::new(code, KeyModifiers::NONE)) {
            Input::Send(text) => Some(text),
            _ => None,
        }
    }

    #[test]
    fn the_editor_moves_recalls_and_sends() {
        let mut editor = Editor::default();
        for c in "helo".chars() {
            press(&mut editor, KeyCode::Char(c));
        }
        press(&mut editor, KeyCode::Left);
        press(&mut editor, KeyCode::Char('l'));
        assert_eq!(editor.text, "hello");
        press(&mut editor, KeyCode::Home);
        press(&mut editor, KeyCode::Delete);
        press(&mut editor, KeyCode::Char('H'));
        assert_eq!(press(&mut editor, KeyCode::Enter).as_deref(), Some("Hello"));
        assert_eq!(press(&mut editor, KeyCode::Enter), None, "empty messages are not sent");
        press(&mut editor, KeyCode::Up);
        assert_eq!(editor.text, "Hello");
        press(&mut editor, KeyCode::Down);
        assert_eq!(editor.text, "");
        for c in "é日".chars() {
            press(&mut editor, KeyCode::Char(c));
        }
        press(&mut editor, KeyCode::Backspace);
        assert_eq!(editor.text, "é");
        let lines = editor.lines("Message Model", 40);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains('é'));
        assert!(editor.lines("Message Model", 12).len() == 1);
        editor.set("word ".repeat(30));
        assert!(editor.lines("Message Model", 30).len() > 1, "long messages wrap");
        assert!(editor.rows("", 30).iter().all(|row| ui::width(row) <= 30));
        editor.set(String::new());
        assert!(editor.rows("Your prompt here", 30)[0].contains("Your prompt here"));
        editor.paste("two\nlines");
        assert_eq!(editor.text, "two lines");
    }
}
