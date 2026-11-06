//! Bounded HTTP/1 response framing for the existing guest/SSH byte stream.
const HEADER_LIMIT: usize = 16 * 1024;
const INVALID: &str = "Invalid model HTTP response";

#[derive(Default)]
pub(super) struct Response {
    json: bool,
    buffer: Vec<u8>,
    status: Option<u16>,
    framing: Option<Framing>,
    done: bool,
    version: Option<String>,
    features: Option<String>,
}

enum Framing {
    Close,
    Length(usize),
    Chunked(Chunk),
}

enum Chunk {
    Size,
    Data(usize),
    Delimiter,
    Trailers(usize),
}

fn header(line: &str) -> Result<(String, &str), String> {
    let (name, value) = line.split_once(':').ok_or(INVALID)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || value.bytes().any(|b| b < 32 && b != b'\t' || b == 127)
    {
        return Err(INVALID.into());
    }
    Ok((name.to_ascii_lowercase(), value.trim()))
}

impl Response {
    pub(super) fn json() -> Self {
        Self {
            json: true,
            ..Self::default()
        }
    }
    pub(super) fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub(super) fn features(&self) -> Option<&str> {
        self.features.as_deref()
    }
    pub(super) fn status(&self) -> Option<u16> {
        self.status
    }
    pub(super) fn done(&self) -> bool {
        self.done
    }
    pub(super) fn close_delimited(&self) -> bool {
        matches!(self.framing, Some(Framing::Close))
    }

    fn headers(&mut self, bytes: &[u8]) -> Result<(), String> {
        let text = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
        let mut lines = text.split("\r\n");
        let mut status = lines.next().ok_or(INVALID)?.splitn(3, ' ');
        if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(INVALID.into());
        }
        let code = status.next().ok_or(INVALID)?;
        if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(INVALID.into());
        }
        let code: u16 = code.parse().map_err(|_| INVALID)?;
        if !(200..600).contains(&code) {
            return Err(INVALID.into());
        }
        let (mut length, mut transfer, mut content_type, mut encoding) = (None, None, None, None);
        let (mut version, mut features) = (None, None);
        for line in lines {
            let (name, value) = header(line)?;
            let slot = match name.as_str() {
                "content-length" => &mut length,
                "transfer-encoding" => &mut transfer,
                "content-type" => &mut content_type,
                "content-encoding" => &mut encoding,
                super::negotiation::VERSION_HEADER => &mut version,
                super::negotiation::FEATURES_HEADER => &mut features,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(INVALID.into());
            }
        }
        if encoding.is_some_and(|s| !s.eq_ignore_ascii_case("identity")) {
            return Err("Unsupported model HTTP content encoding".into());
        }
        if code == 200
            && !content_type.is_some_and(|s| {
                s.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case(if self.json {
                        "application/json"
                    } else {
                        "text/event-stream"
                    })
            })
        {
            return Err(if self.json {
                "Expected a JSON model reply"
            } else {
                "Run this model again to enable streaming replies"
            }
            .into());
        }
        let framing = match (transfer, length) {
            (Some(te), None) if te.eq_ignore_ascii_case("chunked") => Framing::Chunked(Chunk::Size),
            (Some(_), _) => return Err("Unsupported or ambiguous model HTTP framing".into()),
            (None, Some(value)) => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(INVALID.into());
                }
                let count: usize = value.parse().map_err(|_| INVALID)?;
                if count > super::MAX_RESPONSE {
                    return Err("Model response exceeded 8 MiB".into());
                }
                Framing::Length(count)
            }
            (None, None) => Framing::Close,
        };
        self.status = Some(code);
        self.version = version.map(str::to_owned);
        self.features = features.map(str::to_owned);
        self.framing = Some(framing);
        Ok(())
    }

    pub(super) fn push(&mut self, bytes: &[u8], eof: bool) -> Result<Vec<u8>, String> {
        self.buffer.extend_from_slice(bytes);
        if self.status.is_none() {
            let Some(end) = self.buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                if eof || self.buffer.len() > HEADER_LIMIT {
                    return Err(INVALID.into());
                }
                return Ok(Vec::new());
            };
            if end + 4 > HEADER_LIMIT {
                return Err(INVALID.into());
            }
            let headers = self.buffer[..end].to_vec();
            self.headers(&headers)?;
            self.buffer.drain(..end + 4);
        }
        let mut output = Vec::new();
        loop {
            if self.done {
                if !self.buffer.is_empty() {
                    return Err(INVALID.into());
                }
                break;
            }
            match self.framing.as_mut().unwrap() {
                Framing::Close => {
                    output.append(&mut self.buffer);
                    self.done = eof;
                    break;
                }
                Framing::Length(left) => {
                    if self.buffer.len() > *left {
                        return Err(INVALID.into());
                    }
                    *left -= self.buffer.len();
                    output.append(&mut self.buffer);
                    self.done = *left == 0;
                    break;
                }
                Framing::Chunked(state) => match state {
                    Chunk::Size => {
                        let Some(end) = self.buffer.windows(2).position(|w| w == b"\r\n") else {
                            if self.buffer.len() > 128 {
                                return Err(INVALID.into());
                            }
                            break;
                        };
                        if end > 128 {
                            return Err(INVALID.into());
                        }
                        let line = std::str::from_utf8(&self.buffer[..end]).map_err(|_| INVALID)?;
                        if !line.bytes().all(|b| (32..127).contains(&b)) {
                            return Err(INVALID.into());
                        }
                        let size = line.split(';').next().unwrap_or("");
                        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(INVALID.into());
                        }
                        let count = usize::from_str_radix(size, 16).map_err(|_| INVALID)?;
                        if count > super::MAX_RESPONSE {
                            return Err("Model response exceeded 8 MiB".into());
                        }
                        self.buffer.drain(..end + 2);
                        *state = if count == 0 {
                            Chunk::Trailers(0)
                        } else {
                            Chunk::Data(count)
                        };
                    }
                    Chunk::Data(left) => {
                        let count = (*left).min(self.buffer.len());
                        output.extend(self.buffer.drain(..count));
                        *left -= count;
                        if *left > 0 {
                            break;
                        }
                        *state = Chunk::Delimiter;
                    }
                    Chunk::Delimiter => {
                        if self.buffer.len() < 2 {
                            break;
                        }
                        if &self.buffer[..2] != b"\r\n" {
                            return Err(INVALID.into());
                        }
                        self.buffer.drain(..2);
                        *state = Chunk::Size;
                    }
                    Chunk::Trailers(total) => {
                        let Some(end) = self.buffer.windows(2).position(|w| w == b"\r\n") else {
                            if *total + self.buffer.len() > HEADER_LIMIT {
                                return Err(INVALID.into());
                            }
                            break;
                        };
                        *total += end + 2;
                        if *total > HEADER_LIMIT {
                            return Err(INVALID.into());
                        }
                        if end == 0 {
                            self.done = true;
                        } else {
                            let (name, _) = header(
                                std::str::from_utf8(&self.buffer[..end]).map_err(|_| INVALID)?,
                            )?;
                            if matches!(
                                name.as_str(),
                                "content-length"
                                    | "transfer-encoding"
                                    | "content-type"
                                    | "content-encoding"
                                    | super::negotiation::VERSION_HEADER
                                    | super::negotiation::FEATURES_HEADER
                            ) {
                                return Err(INVALID.into());
                            }
                        }
                        self.buffer.drain(..end + 2);
                    }
                },
            }
        }
        if eof && !self.done {
            return Err("The model closed an incomplete HTTP response".into());
        }
        Ok(output)
    }
}
