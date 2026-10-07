//! Keep control characters in ConPTY replies: they can have virtual key code 0.
use super::{detach_key, key_bytes, InputBatch, KeyCode, KeyEvent, KeyModifiers};
use std::io;
use windows_sys::Win32::System::Console::*;

#[derive(Default)]
pub(super) struct InputReader {
    surrogate: Option<u16>,
}

impl InputReader {
    pub(super) fn read_batch(&mut self) -> Result<InputBatch, String> {
        let mut batch = InputBatch::default();
        // This session owns stdin in raw mode. Peek before reading so an idle
        // keyboard never blocks output or cancellation; no input thread survives.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut records = [unsafe { std::mem::zeroed::<INPUT_RECORD>() }; 128];
        let mut total = 0;
        loop {
            let mut available = 0;
            if unsafe {
                PeekConsoleInputW(
                    handle,
                    records.as_mut_ptr(),
                    records.len() as u32,
                    &mut available,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            if available == 0 {
                break;
            }
            let mut count = 0;
            if unsafe { ReadConsoleInputW(handle, records.as_mut_ptr(), available, &mut count) }
                == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            for record in &records[..count as usize] {
                match record.EventType as u32 {
                    KEY_EVENT => self.key(unsafe { record.Event.KeyEvent }, &mut batch),
                    WINDOW_BUFFER_SIZE_EVENT => {
                        let size = unsafe { record.Event.WindowBufferSizeEvent.dwSize };
                        if size.X > 0 && size.Y > 0 {
                            batch.resize = Some((size.X as u16, size.Y as u16));
                        }
                    }
                    _ => {}
                }
            }
            total += count;
            if batch.detached || batch.bytes.len() >= 64 * 1024 || total >= 8192 {
                break;
            }
        }
        Ok(batch)
    }

    fn key(&mut self, record: KEY_EVENT_RECORD, batch: &mut InputBatch) {
        if record.bKeyDown == 0 {
            return;
        }
        let mut modifiers = KeyModifiers::empty();
        if record.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0 {
            modifiers |= KeyModifiers::CONTROL;
        }
        if record.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0 {
            modifiers |= KeyModifiers::ALT;
        }
        if record.dwControlKeyState & SHIFT_PRESSED != 0 {
            modifiers |= KeyModifiers::SHIFT;
        }
        let character = unsafe { record.uChar.UnicodeChar };
        if character == 0x1d {
            batch.detached = true;
            return;
        }
        let special = match record.wVirtualKeyCode {
            0x08 => Some(KeyCode::Backspace),
            0x09 if modifiers.contains(KeyModifiers::SHIFT) => Some(KeyCode::BackTab),
            0x09 => Some(KeyCode::Tab),
            0x0d => Some(KeyCode::Enter),
            0x1b => Some(KeyCode::Esc),
            0x21 => Some(KeyCode::PageUp),
            0x22 => Some(KeyCode::PageDown),
            0x23 => Some(KeyCode::End),
            0x24 => Some(KeyCode::Home),
            0x25 => Some(KeyCode::Left),
            0x26 => Some(KeyCode::Up),
            0x27 => Some(KeyCode::Right),
            0x28 => Some(KeyCode::Down),
            0x2e => Some(KeyCode::Delete),
            _ => None,
        };
        let bytes = if let Some(code) = special {
            self.surrogate = None;
            key_bytes(KeyEvent::new(code, modifiers))
        } else if (0xd800..=0xdbff).contains(&character) {
            self.surrogate = Some(character);
            return;
        } else {
            let value = if (0xdc00..=0xdfff).contains(&character) {
                self.surrogate
                    .take()
                    .and_then(|high| char::decode_utf16([high, character]).next()?.ok())
            } else {
                self.surrogate = None;
                char::from_u32(character as u32)
            };
            let Some(value) = value else {
                return;
            };
            if character == 0
                && !(record.wVirtualKeyCode == 0x20 && modifiers.contains(KeyModifiers::CONTROL))
            {
                return;
            }
            // AltGr produces a printable Unicode character, not an Alt command.
            if !value.is_control()
                && record.dwControlKeyState & RIGHT_ALT_PRESSED != 0
                && modifiers.contains(KeyModifiers::CONTROL)
            {
                modifiers.remove(KeyModifiers::ALT | KeyModifiers::CONTROL);
            }
            let key = KeyEvent::new(KeyCode::Char(value), modifiers);
            if detach_key(key) {
                batch.detached = true;
                return;
            }
            key_bytes(key)
        };
        for _ in 0..record.wRepeatCount.max(1) {
            batch.bytes.extend(&bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(character: u16) -> KEY_EVENT_RECORD {
        KEY_EVENT_RECORD {
            bKeyDown: 1,
            wRepeatCount: 1,
            wVirtualKeyCode: 0,
            wVirtualScanCode: 0,
            uChar: KEY_EVENT_RECORD_0 {
                UnicodeChar: character,
            },
            dwControlKeyState: 0,
        }
    }
    #[test]
    fn terminal_reports_keep_their_escape_prefix_in_one_batch() {
        let mut reader = InputReader::default();
        let mut batch = InputBatch::default();
        let reply = "\x1b[4;1R\x1b[61;6;7c";
        for character in reply.encode_utf16() {
            reader.key(record(character), &mut batch);
        }
        assert_eq!(batch.bytes, reply.as_bytes());
        assert!(!batch.detached);
    }
    #[test]
    fn unicode_interrupts_and_detach_survive_console_records() {
        let mut reader = InputReader::default();
        let mut batch = InputBatch::default();
        for character in "é🦊\x03".encode_utf16() {
            reader.key(record(character), &mut batch);
        }
        assert_eq!(batch.bytes, "é🦊\x03".as_bytes());
        reader.key(record(0x1d), &mut batch);
        assert!(batch.detached);
    }
}
