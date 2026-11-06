use super::*;
use tokio::io::AsyncWriteExt;

fn request(tools: bool) -> Value {
    let mut value = if tools {
        super::super::tests::tools_request()
    } else {
        super::super::tests::request()
    };
    value["stream"] = json!(false);
    value
}
fn reply(tools: bool) -> Value {
    let mut value = json!({"id":"fixture","object":"chat.completion","choices":[{"index":0,
        "message":{"role":"assistant","content":"hello","reasoning_content":"fixture reasoning"},"finish_reason":"stop"}],
        "usage":{"completion_tokens":2,"context_window":2048}});
    if tools {
        let mut call = super::super::tests::call(0, "a", r#"{"id":1}"#);
        call.as_object_mut().unwrap().remove("index");
        value["choices"][0]["message"]["tool_calls"] = json!([call]);
        value["choices"][0]["finish_reason"] = json!("tool_calls");
    }
    value
}
fn wire(value: &Value, request: &Value, framed: bool, ack: bool) -> Vec<u8> {
    let body = value.to_string();
    let agreement = if ack {
        profile(request).unwrap().headers()
    } else {
        String::new()
    };
    let length = if framed {
        format!("Content-Length: {}\r\n", body.len())
    } else {
        String::new()
    };
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n{agreement}{length}\r\n{body}").into_bytes()
}
async fn run(value: &Value, request: &Value) -> Result<Value, String> {
    read(
        wire(value, request, true, true).as_slice(),
        &profile(request)?,
    )
    .await
}

#[tokio::test]
async fn buffered_text_preserves_shape_reasoning_usage_and_agreement() {
    let value = reply(false);
    let result = run(&value, &request(false)).await.unwrap();
    assert_eq!(result["choices"], value["choices"]);
    assert_eq!(result["usage"], value["usage"]);
    assert_eq!(
        result["servingProtocol"],
        json!({"version":1,"mode":"negotiated","features":["json"]})
    );
}

#[tokio::test]
async fn complete_calls_validate_schema_choice_parallel_policy_and_every_argument() {
    let value = reply(true);
    let result = run(&value, &request(true)).await.unwrap();
    assert_eq!(result["choices"], value["choices"]);
    let mut extended = value.clone();
    extended["choices"][0]["message"]["tool_calls"][0]["unvalidated"] = json!("ignored");
    extended["choices"][0]["message"]["tool_calls"][0]["function"]["unvalidated"] =
        json!("ignored");
    assert_eq!(
        run(&extended, &request(true)).await.unwrap()["choices"],
        value["choices"]
    );
    extended["choices"][0]["message"]["tool_calls"][0]
        .as_object_mut()
        .unwrap()
        .remove("type");
    assert!(run(&extended, &request(true)).await.is_err());
    assert_eq!(
        result["servingProtocol"]["features"],
        json!(["json", "tools"])
    );
    for args in [
        r#"{"id":"wrong"}"#,
        r#"{"id":1,"extra":true}"#,
        r#"{"id":"#,
        r#"{"id":1}{}"#,
    ] {
        let mut invalid = value.clone();
        invalid["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json!(args);
        assert!(run(&invalid, &request(true)).await.is_err());
    }
    assert!(run(&value, &request(false)).await.is_err());
    let mut disabled = request(true);
    disabled["tool_choice"] = json!("none");
    assert!(run(&value, &disabled).await.is_err());
    let mut forced = request(true);
    forced["tool_choice"] = json!({"type":"function","function":{"name":"lookup"}});
    let mut stopped = value.clone();
    stopped["choices"][0]["finish_reason"] = json!("stop");
    assert!(run(&stopped, &forced).await.is_ok());
    assert!(run(&stopped, &request(true)).await.is_err());
    let mut parallel = value.clone();
    let mut call = parallel["choices"][0]["message"]["tool_calls"][0].clone();
    call["id"] = json!("b");
    parallel["choices"][0]["message"]["tool_calls"]
        .as_array_mut()
        .unwrap()
        .push(call);
    let mut serial = request(true);
    serial["parallel_tool_calls"] = json!(false);
    assert!(run(&parallel, &serial).await.is_err());
    assert!(run(&parallel, &request(true)).await.is_ok());
    parallel["choices"][0]["message"]["tool_calls"][1]["function"]["arguments"] = json!("{}");
    assert!(run(&parallel, &request(true)).await.is_err());
}

#[tokio::test]
async fn refusal_and_truncation_preserve_display_but_never_calls() {
    for reason in ["length", "content_filter"] {
        let mut value = reply(true);
        value["choices"][0]["finish_reason"] = json!(reason);
        let result = run(&value, &request(true)).await.unwrap();
        assert!(result["choices"][0]["message"].get("tool_calls").is_none());
        assert_eq!(result["choices"][0]["finish_reason"], reason);
        assert_eq!(result["usage"], value["usage"]);
    }
    let mut value = reply(true);
    value["choices"][0]["message"]["refusal"] = json!("cannot comply");
    let result = run(&value, &request(true)).await.unwrap();
    assert!(result["choices"][0]["message"].get("tool_calls").is_none());
    assert_eq!(result["choices"][0]["message"]["refusal"], "cannot comply");
}

#[tokio::test]
async fn malformed_terminal_shapes_and_calls_never_return_a_completion() {
    for (pointer, value) in [
        ("/choices", json!([])),
        ("/choices", json!([{}, {}])),
        ("/choices/0/index", json!(1)),
        ("/choices/0/message/role", json!("user")),
        ("/choices/0/message/content", json!({"x":1})),
        ("/choices/0/finish_reason", Value::Null),
        ("/choices/0/finish_reason", json!("unknown")),
        ("/choices/0/message/tool_calls/0/id", Value::Null),
        ("/choices/0/message/tool_calls/0/type", json!("code")),
        (
            "/choices/0/message/tool_calls/0/function/name",
            json!("not_declared"),
        ),
    ] {
        let mut bad = reply(true);
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(run(&bad, &request(true)).await.is_err(), "{pointer}");
    }
    let mut bad = reply(false);
    bad["choices"][0]["message"]["function_call"] = json!({"name":"lookup","arguments":"{}"});
    assert!(run(&bad, &request(false)).await.is_err());
    let mut bad = reply(true);
    bad["choices"][0]["message"]["tool_calls"][0]["index"] = json!(1);
    assert!(run(&bad, &request(true)).await.is_err());
}

#[tokio::test]
async fn legacy_text_is_explicit_and_missing_or_mismatched_tool_agreement_refuses() {
    let plain = request(false);
    let old = wire(&reply(false), &plain, true, false);
    assert_eq!(
        read(old.as_slice(), &profile(&plain).unwrap())
            .await
            .unwrap()["servingProtocol"]["mode"],
        "legacy"
    );
    let tools = request(true);
    assert!(read(
        wire(&reply(true), &tools, true, false).as_slice(),
        &profile(&tools).unwrap()
    )
    .await
    .unwrap_err()
    .contains("Restart"));
    let wrong = String::from_utf8(wire(&reply(true), &tools, true, true))
        .unwrap()
        .replace("json,tools", "stream,tools");
    assert!(read(wrong.as_bytes(), &profile(&tools).unwrap())
        .await
        .is_err());
    let mut history = plain.clone();
    history["messages"] = json!([
        {"role":"assistant","content":null,"tool_calls":[{"id":"a","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
        {"role":"tool","tool_call_id":"a","content":"fixture"}]);
    assert!(read(old.as_slice(), &profile(&history).unwrap())
        .await
        .is_err());
}

#[tokio::test]
async fn chunked_and_byte_fragmented_json_keep_utf8_and_require_complete_http() {
    let req = request(false);
    let mut value = reply(false);
    value["choices"][0]["message"]["content"] = json!("hello 🌍");
    let body = value.to_string();
    let chunked = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",profile(&req).unwrap().headers(),body.len(),body);
    let (mut writer, reader) = tokio::io::duplex(1);
    let bytes = chunked.clone().into_bytes();
    let task = tokio::spawn(async move {
        for byte in bytes {
            if writer.write_all(&[byte]).await.is_err() {
                break;
            }
        }
    });
    assert_eq!(
        read(reader, &profile(&req).unwrap()).await.unwrap()["choices"],
        value["choices"]
    );
    task.await.unwrap();
    for bytes in [
        chunked[..chunked.len() - 2].as_bytes().to_vec(),
        chunked
            .replace(
                "Transfer-Encoding: chunked",
                "Content-Length: 3\r\nTransfer-Encoding: chunked",
            )
            .into_bytes(),
        chunked
            .replace("application/json", "text/event-stream")
            .into_bytes(),
        chunked
            .replace("0\r\n\r\n", "0\r\nX-Yougori-Serving-Protocol: 1\r\n\r\n")
            .into_bytes(),
    ] {
        assert!(read(bytes.as_slice(), &profile(&req).unwrap())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn errors_are_bounded_redacted_and_never_become_chat_messages() {
    for status in [400, 401, 429, 503] {
        let bytes = format!("HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\n\r\n{{\"error\":{{\"message\":\"private-secret\"}}}}");
        let error = read(bytes.as_bytes(), &profile(&request(false)).unwrap())
            .await
            .unwrap_err();
        assert!(!error.contains("private-secret"));
    }
    let oversized = format!("HTTP/1.1 500 Error\r\n\r\n{}", "x".repeat(MAX_ERROR + 1));
    assert!(
        read(oversized.as_bytes(), &profile(&request(false)).unwrap())
            .await
            .unwrap_err()
            .contains("64 KiB")
    );
    let mut large = reply(false);
    large["choices"][0]["message"]["content"] = json!("x".repeat(LIMIT));
    assert!(run(&large, &request(false))
        .await
        .unwrap_err()
        .contains("2 MiB"));
}

#[tokio::test]
async fn whole_response_deadline_and_drop_cover_stalled_headers_and_body() {
    for prefix in [
        b"".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{",
    ] {
        let (mut writer, reader) = tokio::io::duplex(512);
        writer.write_all(prefix).await.unwrap();
        let result = read_with_deadline(
            reader,
            &profile(&request(false)).unwrap(),
            Duration::from_millis(10),
        )
        .await;
        assert!(result.unwrap_err().contains("timed out"));
        assert!(writer.write_all(b"x").await.is_err());
    }
}
