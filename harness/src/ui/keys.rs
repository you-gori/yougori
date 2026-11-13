//! Keys on the conversation screen.
//!
//! Order: Ctrl+C, then the screen's own panel (palette, pickers, confirmations), a stopped
//! engine's keys, the engine's dialog, the slash-command list, and last the prompt box.
use super::dialog;
use super::overlay::Overlay;
use super::state::{App, Effect, Phase, Scroll, QUIT_WINDOW};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::time::Instant;

impl App {
    pub fn key(&mut self, key: KeyEvent, now: Instant) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        self.dirty = true;
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        if control && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            self.ctrl_c(now);
            return;
        }
        // Any other key means the person went on: a Ctrl+C before it no longer counts towards
        // quitting.
        self.quit_armed = None;
        if matches!(self.phase, Phase::Quitting { .. }) {
            return;
        }
        if let Some(overlay) = self.overlay.as_mut() {
            let outcome = overlay.key(key);
            self.outcome(outcome, now);
            if self.overlay.is_none() {
                // A dialog it covered shows again.
                self.front_shown(now);
            }
            return;
        }
        // Keys that work everywhere else.
        match key.code {
            KeyCode::Char('p') if control => {
                self.overlay = Some(Overlay::palette(self.palette()));
                return;
            }
            KeyCode::Char('o') if control => {
                self.details = !self.details;
                return;
            }
            KeyCode::Char('l') if control => {
                self.effects.push(Effect::Redraw);
                return;
            }
            KeyCode::PageUp => {
                self.scroll_by(-(self.page() as isize));
                return;
            }
            KeyCode::PageDown => {
                self.scroll_by(self.page() as isize);
                return;
            }
            KeyCode::End if control => {
                self.scroll = Scroll::Follow;
                return;
            }
            KeyCode::Home if control => {
                self.scroll_to_top();
                return;
            }
            KeyCode::End if self.scroll != Scroll::Follow && key.modifiers.is_empty() => {
                self.scroll = Scroll::Follow;
                return;
            }
            _ => {}
        }
        if self.stopped() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => self.quit(),
                KeyCode::Enter if self.owns_engine => self.effects.push(Effect::Start),
                _ => {}
            }
            return;
        }
        if let Some(dialog) = self.dialogs.front_mut() {
            if let Some(answer) = dialog.key(key, now) {
                self.dialogs.pop_front();
                self.send(answer);
                // The next request takes this one's place: it gets its own settle time.
                self.front_shown(now);
            }
            return;
        }
        let completions = self.completions().len();
        if completions > 0 {
            self.completion = self.completion.min(completions - 1);
            match key.code {
                KeyCode::Up | KeyCode::BackTab => {
                    self.completion = (self.completion + completions - 1) % completions;
                    return;
                }
                KeyCode::Down | KeyCode::Tab => {
                    self.completion = (self.completion + 1) % completions;
                    return;
                }
                KeyCode::Esc => {
                    self.completion_closed = Some(self.input.text().to_owned());
                    return;
                }
                KeyCode::Enter if key.modifiers.is_empty() => {
                    let (name, takes_text) = {
                        let chosen = self.completions()[self.completion];
                        (chosen.name.clone(), chosen.hint.is_some())
                    };
                    let full = format!("/{name}");
                    if self.input.text() == full || !takes_text {
                        self.input.set(&full);
                        self.submit(now);
                    } else {
                        self.input.set(&format!("{full} "));
                    }
                    self.completion = 0;
                    return;
                }
                _ => {}
            }
        }
        match key.code {
            KeyCode::Esc if matches!(self.phase, Phase::Changing { .. }) => self.effects.push(Effect::CancelSwitch),
            KeyCode::Esc => {
                if !self.cancel() && self.scroll != Scroll::Follow {
                    self.scroll = Scroll::Follow;
                }
            }
            KeyCode::Enter if shift || alt || control => self.input.newline(),
            KeyCode::Char('j') if control => self.input.newline(),
            KeyCode::Enter => self.submit(now),
            KeyCode::Tab if self.input.is_empty() => self.cycle_mode(false),
            KeyCode::BackTab if self.input.is_empty() => self.cycle_mode(true),
            KeyCode::Up if !alt && !control => {
                if self.input.on_first_row(self.input_width) {
                    if let Some(text) = self.history.older(self.input.text()) {
                        self.input.set(&text);
                    }
                } else {
                    self.input.up(self.input_width);
                }
            }
            KeyCode::Down if !alt && !control => {
                if self.input.on_last_row(self.input_width) {
                    if let Some(text) = self.history.newer(self.input.text()) {
                        self.input.set(&text);
                    }
                } else {
                    self.input.down(self.input_width);
                }
            }
            KeyCode::Char('d') if control => self.input.delete(),
            _ => {
                // Editing a recalled prompt keeps the place in the history: Down still returns
                // to the draft, and the change stays with that prompt until one is sent.
                let before = self.input.text().len();
                dialog::edit(&mut self.input, key);
                if self.input.text().len() != before {
                    self.completion = 0;
                    self.completion_closed = None;
                }
            }
        }
    }

    /// Text pasted into the terminal.
    pub fn paste(&mut self, text: &str) {
        self.dirty = true;
        self.quit_armed = None;
        if let Some(overlay) = self.overlay.as_mut() {
            overlay.paste(text);
            return;
        }
        if self.stopped() {
            return;
        }
        if let Some(dialog) = self.dialogs.front_mut() {
            dialog.paste(text);
            return;
        }
        self.input.insert(text);
        self.completion_closed = None;
    }

    /// Ctrl+C closes the panel, dismisses the request, or clears the box, whichever shows; only
    /// when there was none of these does it stop the turn and count towards quitting, so a second
    /// press meant to clear new text never quits.
    fn ctrl_c(&mut self, now: Instant) {
        if self.stopped() {
            self.quit();
            return;
        }
        if matches!(self.phase, Phase::Quitting { .. }) {
            return;
        }
        let again = self.quit_armed.is_some_and(|t| now.saturating_duration_since(t) < QUIT_WINDOW);
        if again {
            self.quit_armed = None;
            self.request_quit();
            return;
        }
        if self.overlay.take().is_some() {
            self.front_shown(now);
            return;
        }
        if let Some(dialog) = self.dialogs.pop_front() {
            self.send(dialog.dismissed());
            self.front_shown(now);
            return;
        }
        if !self.input.is_empty() {
            self.input.clear();
            self.history.reset();
            return;
        }
        self.quit_armed = Some(now);
        self.cancel();
    }

    fn page(&self) -> usize {
        self.view.height.saturating_sub(2).max(1)
    }

    pub fn scroll_by(&mut self, delta: isize) {
        let view = &self.view;
        let max_top = view.total.saturating_sub(view.height);
        let top = (view.top as isize + delta).clamp(0, max_top as isize) as usize;
        self.scroll = if top >= max_top { Scroll::Follow } else { self.anchor(top) };
    }

    fn scroll_to_top(&mut self) {
        self.scroll = if self.view.total <= self.view.height { Scroll::Follow } else { self.anchor(0) };
    }

    /// The anchor that keeps line `top` at the top of the view.
    fn anchor(&self, top: usize) -> Scroll {
        for &(key, start, height) in &self.view.blocks {
            if top >= start && top < start + height {
                return Scroll::At { key, offset: top - start };
            }
        }
        Scroll::At { key: None, offset: 0 }
    }
}
