use super::*;
use crate::terminal_stream::{Channel, Frame, QUEUE};
use tokio::sync::mpsc;

pub(super) async fn open(id: &str, session: &str, offset: u64) -> Result<Channel, String> {
    if let Some(channel) = crate::client::open_terminal_stream(id, session, offset).await? {
        return Ok(channel);
    }
    // Old engines keep working. Independent read/write tasks remove the
    // input-behind-output delay even without remote WebSocket support.
    let (tx, mut outgoing) = mpsc::channel::<Frame>(QUEUE);
    let (incoming, rx) = mpsc::channel(QUEUE);
    let id = id.to_owned();
    let session = session.to_owned();
    let read_id = id.clone();
    let read_session = session.clone();
    let errors = incoming.clone();
    let read = tokio::spawn(async move {
        let mut offset = offset;
        loop {
            let result = call("terminal_action",json!({"environmentId":read_id,"sessionId":read_session,"action":"read","offset":offset})).await;
            let value = match result {
                Ok(value) => value,
                Err(error) => {
                    let _ = errors.send(Err(error)).await;
                    break;
                }
            };
            let data = match B64.decode(value["data"].as_str().unwrap_or("")) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let _ = errors.send(Err("Invalid terminal output".into())).await;
                    break;
                }
            };
            let next = value["offset"].as_u64().unwrap_or(offset);
            if !data.is_empty()
                && errors
                    .send(Ok(Frame::Output {
                        offset: next,
                        bytes: data,
                    }))
                    .await
                    .is_err()
            {
                break;
            }
            offset = next;
            if value["done"] == true {
                let _ = errors.send(Ok(Frame::Done)).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let write = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            let params = match frame {
                Frame::Input(bytes) => {
                    json!({"environmentId":id,"sessionId":session,"action":"write","data":B64.encode(bytes)})
                }
                Frame::Resize(cols, rows) => {
                    json!({"environmentId":id,"sessionId":session,"action":"resize","cols":cols,"rows":rows})
                }
                _ => {
                    let _ = incoming
                        .send(Err("Invalid terminal input frame".into()))
                        .await;
                    break;
                }
            };
            if let Err(error) = call("terminal_action", params).await {
                let _ = incoming.send(Err(error)).await;
                break;
            }
        }
    });
    Ok(Channel {
        tx,
        rx,
        tasks: vec![read, write],
    })
}
