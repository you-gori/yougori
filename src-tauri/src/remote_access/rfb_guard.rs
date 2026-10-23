//! Restricted desk protocol: pixels, keyboard, pointer and inbound text only.
//! Parse complete RFB messages, including fragmented WebSocket frames. Never forward unknown
//! extensions or server clipboard messages. The upstream is forced to raw framebuffer encoding.
const MAX: usize = 64 * 1024 * 1024;
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    ServerVersion,
    ClientVersion,
    Security,
    Choice,
    Challenge,
    Answer,
    Result,
    Init,
    ServerInit,
    Normal,
}
pub(super) struct Guard {
    phase: Phase,
    client: Vec<u8>,
    server: Vec<u8>,
    offered: Vec<u8>,
    rectangles: u16,
    pixel_bytes: usize,
}
impl Default for Guard {
    fn default() -> Self {
        Self {
            phase: Phase::ServerVersion,
            client: Vec::new(),
            server: Vec::new(),
            offered: Vec::new(),
            rectangles: 0,
            pixel_bytes: 4,
        }
    }
}
fn u16be(b: &[u8]) -> usize {
    u16::from_be_bytes([b[0], b[1]]) as usize
}
fn u32be(b: &[u8]) -> usize {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
}
impl Guard {
    /// Return (upstream bytes, recipient bytes). Only parsed/allowed messages leave this guard.
    pub(super) fn feed(
        &mut self,
        from_client: bool,
        data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let buffer = if from_client {
            &mut self.client
        } else {
            &mut self.server
        };
        if buffer.len() + data.len() > MAX {
            return Err("Restricted display buffer limit exceeded".into());
        }
        buffer.extend_from_slice(data);
        let (mut up, mut down) = (Vec::new(), Vec::new());
        loop {
            let (client, needed, next) = match self.phase {
                Phase::ServerVersion => (false, 12, Phase::ClientVersion),
                Phase::ClientVersion => (true, 12, Phase::Security),
                Phase::Security => {
                    if self.server.is_empty() {
                        break;
                    }
                    let n = self.server[0] as usize;
                    if n == 0 || n > 32 {
                        return Err("Unsupported desktop authentication".into());
                    }
                    (false, 1 + n, Phase::Choice)
                }
                Phase::Choice => (true, 1, Phase::Result),
                Phase::Challenge => (false, 16, Phase::Answer),
                Phase::Answer => (true, 16, Phase::Result),
                Phase::Result => (false, 4, Phase::Init),
                Phase::Init => (true, 1, Phase::ServerInit),
                Phase::ServerInit => {
                    if self.server.len() < 24 {
                        break;
                    }
                    let n = u32be(&self.server[20..24]);
                    if n > 16384 {
                        return Err("Invalid desktop name".into());
                    }
                    (false, 24 + n, Phase::Normal)
                }
                Phase::Normal => {
                    let a = self.client_message(&mut up)?;
                    let b = self.server_message(&mut down)?;
                    if !a && !b {
                        break;
                    }
                    continue;
                }
            };
            let buffer = if client {
                &mut self.client
            } else {
                &mut self.server
            };
            if buffer.len() < needed {
                break;
            }
            let bytes: Vec<u8> = buffer.drain(..needed).collect();
            let mut next = next;
            match self.phase {
                Phase::ServerVersion | Phase::ClientVersion => {
                    if bytes != b"RFB 003.008\n" {
                        return Err("Restricted desktops require RFB 3.8".into());
                    }
                }
                Phase::Security => {
                    self.offered = bytes[1..].to_vec();
                    if !self.offered.iter().any(|v| matches!(v, 1 | 2)) {
                        return Err("Unsupported desktop authentication".into());
                    }
                }
                Phase::Choice => {
                    if !self.offered.contains(&bytes[0]) || !matches!(bytes[0], 1 | 2) {
                        return Err("Unsupported desktop authentication".into());
                    }
                    if bytes[0] == 2 {
                        next = Phase::Challenge
                    }
                }
                Phase::Result => {
                    if bytes != [0, 0, 0, 0] {
                        return Err("Desktop authentication failed".into());
                    }
                }
                Phase::ServerInit => {
                    self.pixel_bytes = bytes[4] as usize / 8;
                    if !matches!(self.pixel_bytes, 1 | 2 | 4) {
                        return Err("Unsupported desktop pixel format".into());
                    }
                }
                _ => {}
            }
            if client {
                up.extend(bytes)
            } else {
                down.extend(bytes)
            }
            self.phase = next;
        }
        Ok((up, down))
    }
    fn client_message(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        if self.client.is_empty() {
            return Ok(false);
        }
        let b = &self.client;
        let size = match b[0] {
            0 => 20,
            2 => {
                if b.len() < 4 {
                    return Ok(false);
                }
                let count = u16be(&b[2..]);
                if count > 256 {
                    return Err("Too many display encodings".into());
                }
                4 + count * 4
            }
            3 => 10,
            4 => 8,
            5 => 6,
            6 => {
                if b.len() < 8 {
                    return Ok(false);
                }
                let count = u32be(&b[4..]);
                if count > 65536 {
                    return Err("Inbound clipboard exceeds 64 KiB".into());
                }
                8 + count
            }
            _ => return Err("This desktop extension is disabled by the workspace policy".into()),
        };
        if b.len() < size {
            return Ok(false);
        }
        let bytes: Vec<u8> = self.client.drain(..size).collect();
        if bytes[0] == 2 {
            // Raw pixels + desktop-size notifications. No clipboard, files, audio, or other channels.
            output.extend_from_slice(&[2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33]);
        } else {
            if bytes[0] == 0 {
                if bytes[4] as usize != self.pixel_bytes * 8 || bytes[7] != 1 {
                    return Err("Only true-color desktop pixels are supported".into());
                }
            }
            output.extend(bytes);
        }
        Ok(true)
    }
    fn server_message(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
        let b = &self.server;
        if b.is_empty() {
            return Ok(false);
        }
        if self.rectangles > 0 {
            if b.len() < 12 {
                return Ok(false);
            }
            let encoding = i32::from_be_bytes(b[8..12].try_into().unwrap());
            let size = match encoding {
                0 => 12 + u16be(&b[4..]) * u16be(&b[6..]) * self.pixel_bytes,
                -223 => 12,
                _ => return Err("The desktop sent a disabled encoding".into()),
            };
            if size > MAX {
                return Err("Desktop rectangle is too large".into());
            }
            if b.len() < size {
                return Ok(false);
            }
            output.extend(self.server.drain(..size));
            self.rectangles -= 1;
            return Ok(true);
        }
        match b[0] {
            0 => {
                if b.len() < 4 {
                    return Ok(false);
                }
                self.rectangles = u16be(&b[2..]) as u16;
                output.extend(self.server.drain(..4));
            }
            2 => {
                output.push(2);
                self.server.remove(0);
            }
            3 => {
                if b.len() < 8 {
                    return Ok(false);
                }
                let count = u32be(&b[4..]);
                if count > 1024 * 1024 {
                    return Err("Outbound clipboard was blocked".into());
                }
                if b.len() < 8 + count {
                    return Ok(false);
                }
                self.server.drain(..8 + count);
            }
            _ => return Err("The desktop sent a disabled data channel".into()),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> Guard {
        Guard {
            phase: Phase::Normal,
            ..Guard::default()
        }
    }
    #[test]
    fn outbound_clipboard_is_dropped_across_fragmented_frames() {
        let mut g = ready();
        let payload = b"\x03\0\0\0\0\0\0\x06secret\x02";
        let mut visible = Vec::new();
        for b in payload {
            let (_, out) = g.feed(false, &[*b]).unwrap();
            visible.extend(out)
        }
        assert_eq!(visible, vec![2]);
    }
    #[test]
    fn clipboard_extensions_and_file_channels_cannot_be_negotiated() {
        let mut g = ready();
        let (up, _) = g.feed(true, &[2, 0, 0, 1, 255, 255, 255, 196]).unwrap();
        assert_eq!(up, [2, 0, 0, 2, 0, 0, 0, 0, 255, 255, 255, 33]);
        assert!(g.feed(true, &[7, 0, 0, 0]).is_err());
    }
    #[test]
    fn pixels_and_keyboard_are_preserved() {
        let mut g = ready();
        let key = [4, 1, 0, 0, 0, 0, 0, 65];
        assert_eq!(g.feed(true, &key).unwrap().0, key);
        let frame = [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(g.feed(false, &frame).unwrap().1, frame);
    }
    #[test]
    fn incoming_clipboard_is_allowed_but_extended_clipboard_is_not() {
        let mut g = ready();
        let text = b"\x06\0\0\0\0\0\0\x03abc";
        assert_eq!(g.feed(true, text).unwrap().0, text);
        assert!(g.feed(true, &[6, 0, 0, 0, 255, 255, 255, 255]).is_err());
    }
    #[test]
    fn fragmented_handshake_negotiates_authentication_before_pixel_traffic() {
        for security in [1u8, 2] {
            let mut guard = Guard::default();
            let mut exchange = |client: bool, bytes: &[u8]| {
                let mut forwarded = Vec::new();
                for byte in bytes {
                    let (up, down) = guard.feed(client, &[*byte]).unwrap();
                    forwarded.extend(if client { up } else { down });
                }
                assert_eq!(forwarded, bytes);
            };
            exchange(false, b"RFB 003.008\n");
            exchange(true, b"RFB 003.008\n");
            exchange(false, &[1, security]);
            exchange(true, &[security]);
            if security == 2 {
                exchange(false, &[0x17; 16]);
                exchange(true, &[0x42; 16]);
            }
            exchange(false, &[0; 4]);
            exchange(true, &[1]);
            let mut init = vec![0u8; 24];
            init[..4].copy_from_slice(&[4, 0, 3, 0]);
            init[4] = 32;
            init[5] = 24;
            init[7] = 1;
            init[23] = 4;
            init.extend_from_slice(b"Desk");
            exchange(false, &init);
            assert!(guard.phase == Phase::Normal);
            assert_eq!(
                guard.feed(true, &[4, 1, 0, 0, 0, 0, 0, 65]).unwrap().0,
                [4, 1, 0, 0, 0, 0, 0, 65]
            );
        }
    }
    #[test]
    fn malformed_or_unnegotiated_channels_close_the_connection() {
        let mut guard = Guard::default();
        assert!(guard.feed(false, b"RFB 003.003\n").is_err());
        let mut guard = ready();
        assert!(guard.feed(false, &[1, 0, 0, 0, 0, 0]).is_err());
        let mut guard = ready();
        let extended = [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 255, 255, 255, 196];
        assert!(guard.feed(false, &extended).is_err());
    }
}
