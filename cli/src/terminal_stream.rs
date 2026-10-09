//! Version-one bounded terminal frames, shared by the CLI and engine.
//! Input is never replayed after an uncertain connection failure.
use crate::wire;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinHandle,
};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 64 * 1024 + 9;
pub const QUEUE: usize = 16;
pub const UNSUPPORTED: &str = "YOUGORI_TERMINAL_STREAM_UNSUPPORTED";

#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    Input(Vec<u8>),
    Resize(u16, u16),
    Output { offset: u64, bytes: Vec<u8> },
    Done,
    Error(String),
}
impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        match self {
            Self::Input(bytes) if !bytes.is_empty() && bytes.len() <= 16 * 1024 => {
                out.push(1);
                out.extend(bytes);
            }
            Self::Resize(cols, rows) if *cols > 0 && *rows > 0 => {
                out.push(2);
                out.extend(cols.to_be_bytes());
                out.extend(rows.to_be_bytes());
            }
            Self::Output { offset, bytes }
                if !bytes.is_empty()
                    && bytes.len() <= 64 * 1024
                    && *offset >= bytes.len() as u64 =>
            {
                out.push(3);
                out.extend(offset.to_be_bytes());
                out.extend(bytes);
            }
            Self::Done => out.push(4),
            Self::Error(error) if !error.is_empty() && error.len() <= 4096 => {
                out.push(5);
                out.extend(error.as_bytes());
            }
            _ => return Err("Invalid terminal stream frame".into()),
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let frame = match bytes.first() {
            Some(1) => Self::Input(bytes[1..].to_vec()),
            Some(2) if bytes.len() == 5 => Self::Resize(
                u16::from_be_bytes([bytes[1], bytes[2]]),
                u16::from_be_bytes([bytes[3], bytes[4]]),
            ),
            Some(3) if bytes.len() >= 10 => Self::Output {
                offset: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
                bytes: bytes[9..].to_vec(),
            },
            Some(4) if bytes.len() == 1 => Self::Done,
            Some(5) => Self::Error(
                std::str::from_utf8(&bytes[1..])
                    .map_err(|_| "Invalid terminal error")?
                    .into(),
            ),
            _ => return Err("Invalid terminal stream frame".into()),
        };
        frame.encode()?;
        Ok(frame)
    }
}

pub struct Channel {
    pub tx: mpsc::Sender<Frame>,
    pub rx: mpsc::Receiver<Result<Frame, String>>,
    pub tasks: Vec<JoinHandle<()>>,
}
impl Drop for Channel {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The reader owns its entire frame future. Selecting another event must never
/// discard a partially read length prefix or payload.
pub fn from_io(stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Channel {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut outgoing) = mpsc::channel::<Frame>(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    let errors = incoming.clone();
    let read = tokio::spawn(async move {
        loop {
            let result = match wire::read_frame(&mut reader, MAX_FRAME).await {
                Ok(bytes) => Frame::decode(&bytes),
                Err(_) => Err("Terminal connection ended. Input was not resent.".into()),
            };
            let done = result.is_err();
            if incoming.send(result).await.is_err() || done {
                break;
            }
        }
    });
    let write = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            let result = match frame.encode() {
                Ok(bytes) => tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    wire::write_frame(&mut writer, &bytes, MAX_FRAME),
                )
                .await
                .map_err(|_| "Terminal connection stalled")
                .and_then(|v| v.map_err(|_| "Terminal write ended; input was not resent")),
                Err(_) => Err("Invalid terminal frame"),
            };
            if let Err(error) = result {
                let _ = errors.send(Err(error.into())).await;
                break;
            }
        }
    });
    Channel {
        tx,
        rx,
        tasks: vec![read, write],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[test]
    fn strict_bounded_frames_preserve_terminal_bytes() {
        for frame in [
            Frame::Input(b"\x1b[200~hi\0\x03".to_vec()),
            Frame::Resize(123, 42),
            Frame::Output {
                offset: 20,
                bytes: vec![0xff, 0, 27],
            },
            Frame::Done,
            Frame::Error("closed".into()),
        ] {
            assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
        }
        for bytes in [
            vec![],
            vec![4, 0],
            vec![1],
            vec![2, 0, 0, 0, 1],
            vec![3; MAX_FRAME + 1],
            vec![5, 255],
        ] {
            assert!(Frame::decode(&bytes).is_err());
        }
    }
    #[tokio::test]
    async fn input_does_not_wait_for_partial_output_frame() {
        let (client, server) = tokio::io::duplex(4096);
        let mut channel = from_io(client);
        let (mut read, mut write) = tokio::io::split(server);
        write.write_all(&[0, 0]).await.unwrap();
        channel.tx.send(Frame::Input(b"x".to_vec())).await.unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            wire::read_frame(&mut read, MAX_FRAME),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Frame::decode(&received).unwrap(),
            Frame::Input(b"x".to_vec())
        );
        write.write_all(&[0, 1, 4]).await.unwrap();
        assert_eq!(channel.rx.recv().await.unwrap().unwrap(), Frame::Done);
    }
}
