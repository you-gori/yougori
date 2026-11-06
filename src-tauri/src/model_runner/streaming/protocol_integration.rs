//! Real Rust HTTP reader and real Python relay/admission, with synthetic inference.
use super::*;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
use tokio::{io::AsyncWriteExt, net::TcpStream};

struct Fixture {
    child: Child,
    root: tempfile::TempDir,
    port: u16,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fixture {
    async fn start() -> Self {
        let scratch = Path::new("D:/YougoriBuildCache/scratch");
        let root = if scratch.is_dir() {
            tempfile::tempdir_in(scratch)
        } else {
            tempfile::tempdir()
        }
        .unwrap();
        let mut command = Command::new("python");
        command.env_clear();
        for (name, value) in std::env::vars_os() {
            if [
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "SYSTEMDRIVE",
            ]
            .contains(&name.to_string_lossy().to_ascii_uppercase().as_str())
            {
                command.env(name, value);
            }
        }
        for name in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TMP",
            "TEMP",
            "TMPDIR",
        ] {
            command.env(name, root.path());
        }
        let child = command
            .args(["-I", "-B", "-u"])
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("src/model_runner/streaming/protocol_fixture.py"),
            )
            .arg(root.path().join("ready.json"))
            .arg(root.path().join("cache"))
            .env("HF_HUB_OFFLINE", "1")
            .env("TRANSFORMERS_OFFLINE", "1")
            .env("CUDA_VISIBLE_DEVICES", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(root.path().join("errors.txt")).unwrap(),
            ))
            .spawn()
            .expect("Python required for the offline protocol integration gate");
        let mut fixture = Self {
            child,
            root,
            port: 0,
        };
        fixture.port = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read(fixture.root.path().join("ready.json")) {
                    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                        if let Some(port) = value["port"]
                            .as_u64()
                            .and_then(|p| u16::try_from(p).ok())
                            .filter(|p| *p > 0)
                        {
                            return port;
                        }
                    }
                }
                assert!(
                    fixture.child.try_wait().unwrap().is_none(),
                    "fixture exited"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture readiness deadline");
        fixture
    }

    async fn request(
        &self,
        body: &Value,
        override_headers: Option<&str>,
    ) -> (Result<Value, String>, Vec<Value>) {
        let profile = profile(body).unwrap();
        let mut pieces = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut socket = TcpStream::connect(("127.0.0.1",self.port)).await.unwrap();
            let bytes = body.to_string();
            let headers = override_headers.map(str::to_owned).unwrap_or_else(||profile.headers());
            socket.write_all(format!("POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer fixture-model-token\r\n{headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{bytes}",bytes.len()).as_bytes()).await.unwrap();
            if body["stream"] == true {
                read(socket, &tokio::sync::Notify::new(), &profile, |piece| { pieces.push(piece.clone()); Ok(()) }).await
            } else { read_buffered(socket, &profile).await }
        }).await.expect("chat transport deadline");
        (result, pieces)
    }
}

#[tokio::test]
async fn actual_relay_agrees_with_host_then_streams_text_and_validated_tools() {
    let fixture = Fixture::start().await;
    let request = super::tests::request();
    for headers in [None, Some("")] {
        let (result, pieces) = fixture.request(&request, headers).await;
        let result = result.unwrap();
        assert_eq!(
            result["servingProtocol"],
            json!({"version":1,"mode":"negotiated","features":["stream"]})
        );
        assert_eq!(result["finishReason"], "stop");
        assert_eq!(
            pieces,
            vec![
                json!({"role":"assistant","content":""}),
                json!({"content":"fixture output"})
            ]
        );
    }
    let tools = super::tests::tools_request();
    let (result, pieces) = fixture.request(&tools, None).await;
    let result = result.unwrap();
    assert_eq!(
        result["servingProtocol"]["features"],
        json!(["stream", "tools"])
    );
    assert_eq!(result["finishReason"], "tool_calls");
    assert_eq!(
        pieces,
        vec![
            json!({"role":"assistant","content":""}),
            json!({"tool_calls":[super::tests::call(0,"fixture-call","{\"id\":1}")]})
        ]
    );
    for headers in [
        "X-Yougori-Serving-Protocol: 2\r\nX-Yougori-Serving-Features: stream\r\n",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream\r\n",
    ] {
        let (result, pieces) = fixture.request(&tools, Some(headers)).await;
        assert!(result.is_err());
        assert!(pieces.is_empty());
    }
}

#[tokio::test]
async fn actual_relay_negotiates_and_validates_buffered_text_tools_and_truncation() {
    let fixture = Fixture::start().await;
    let mut plain = super::tests::request();
    plain["stream"] = json!(false);
    let (result, pieces) = fixture.request(&plain, None).await;
    let result = result.unwrap();
    assert!(pieces.is_empty());
    assert_eq!(result["servingProtocol"]["features"], json!(["json"]));
    assert_eq!(result["choices"][0]["message"]["content"], "fixture output");
    let mut tools = super::tests::tools_request();
    tools["stream"] = json!(false);
    let (result, _) = fixture.request(&tools, None).await;
    let result = result.unwrap();
    assert_eq!(
        result["servingProtocol"]["features"],
        json!(["json", "tools"])
    );
    assert_eq!(
        result["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"],
        "{\"id\":1}"
    );
    tools["messages"][0]["content"] = json!("fixture-truncated");
    let (result, _) = fixture.request(&tools, None).await;
    let result = result.unwrap();
    assert_eq!(result["choices"][0]["finish_reason"], "length");
    assert!(result["choices"][0]["message"].get("tool_calls").is_none());
    tools["messages"][0]["content"] = json!("fixture-invalid");
    assert!(fixture.request(&tools, None).await.0.is_err());
    let (result, _) = fixture
        .request(
            &plain,
            Some("X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream\r\n"),
        )
        .await;
    assert!(result.is_err());
}
