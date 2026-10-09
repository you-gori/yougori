use super::*;

#[tokio::test]
async fn terminal_stream_pipe_and_websocket_preserve_output_offsets_and_exit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let mut offset = 0;
        for _ in 0..3 {
            let Message::Binary(bytes) = socket.next().await.unwrap().unwrap() else {
                panic!("binary input required")
            };
            let Frame::Input(bytes) = Frame::decode(&bytes).unwrap() else {
                panic!("input required")
            };
            offset += bytes.len() as u64;
            socket
                .send(Message::Binary(
                    Frame::Output { offset, bytes }.encode().unwrap().into(),
                ))
                .await
                .unwrap();
        }
        socket
            .send(Message::Binary(Frame::Done.encode().unwrap().into()))
            .await
            .unwrap();
        // Keep the socket alive until the receiving side consumes Done.
        while socket.next().await.is_some() {}
    });
    let (socket, _) = tokio_tungstenite::connect_async_with_config(
        format!("ws://{address}"),
        Some(websocket_config()),
        true,
    )
    .await
    .unwrap();
    let back = from_websocket(socket);
    let (client, engine) = tokio::io::duplex(4096);
    let forwarding = tokio::spawn(relay(yougori_cli::terminal_stream::from_io(engine), back));
    let mut client = yougori_cli::terminal_stream::from_io(client);
    for bytes in [
        vec![27, 91, 50, 48, 48, 126],
        vec![0xff, 0, 3],
        "é中文".as_bytes().to_vec(),
    ] {
        client.tx.send(Frame::Input(bytes)).await.unwrap();
    }
    let mut offset = 0;
    for expected in [
        vec![27, 91, 50, 48, 48, 126],
        vec![0xff, 0, 3],
        "é中文".as_bytes().to_vec(),
    ] {
        let frame = tokio::time::timeout(Duration::from_secs(2), client.rx.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        offset += expected.len() as u64;
        assert_eq!(
            frame,
            Frame::Output {
                offset,
                bytes: expected
            }
        );
    }
    assert_eq!(client.rx.recv().await.unwrap().unwrap(), Frame::Done);
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), forwarding)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), peer)
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_stream_backpressure_on_input_does_not_block_output() {
    let (client, engine) = tokio::io::duplex(65536);
    let mut client = yougori_cli::terminal_stream::from_io(client);
    let (back_tx, _blocked_input) = mpsc::channel(1);
    let (output, back_rx) = mpsc::channel(16);
    let back = Channel {
        tx: back_tx,
        rx: back_rx,
        tasks: vec![],
    };
    let forwarding = tokio::spawn(relay(yougori_cli::terminal_stream::from_io(engine), back));
    for _ in 0..8 {
        client
            .tx
            .send(Frame::Input(b"input".to_vec()))
            .await
            .unwrap();
    }
    output
        .send(Ok(Frame::Output {
            offset: 5,
            bytes: b"hello".to_vec(),
        }))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(300), client.rx.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Frame::Output {
            offset: 5,
            bytes: b"hello".to_vec()
        }
    );
    forwarding.abort();
}

#[tokio::test]
async fn terminal_stream_delivers_failure_before_disconnecting() {
    let (client, engine) = tokio::io::duplex(4096);
    let mut client = yougori_cli::terminal_stream::from_io(client);
    let (back_tx, _input) = mpsc::channel(1);
    let (output, back_rx) = mpsc::channel(1);
    let forwarding = tokio::spawn(relay(
        yougori_cli::terminal_stream::from_io(engine),
        Channel {
            tx: back_tx,
            rx: back_rx,
            tasks: vec![],
        },
    ));
    output
        .send(Err("terminal output cursor expired".into()))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), client.rx.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Frame::Error("terminal output cursor expired".into())
    );
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(1), forwarding)
        .await
        .unwrap();
}
