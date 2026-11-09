use super::*;
use tokio::io::AsyncWriteExt;

pub(super) fn request() -> Value {
    json!({"messages":[{"role":"user","content":"synthetic"}],"stream":true})
}
pub(super) fn tools_request() -> Value {
    let mut body = request();
    body["tools"] = json!([{"type":"function","function":{"name":"lookup","parameters":{
        "type":"object","properties":{"id":{"type":"integer"}},"required":["id"],"additionalProperties":false
    }}}]);
    body
}
fn event(piece: Value, finish: Option<&str>) -> String {
    format!(
        "data: {}\n\n",
        json!({"choices":[{"index":0,"delta":piece,"finish_reason":finish}]})
    )
}
fn terminal(reason: &str) -> String {
    event(json!({}), Some(reason)) + "data: [DONE]\n\n"
}
pub(super) fn call(index: u32, id: &str, args: &str) -> Value {
    json!({"index":index,"id":id,"type":"function","function":{"name":"lookup","arguments":args}})
}
fn response(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n\r\n{body}")
        .into_bytes()
}
fn acknowledge(bytes: &[u8], request: &Value) -> Vec<u8> {
    let headers = profile(request).unwrap().headers();
    let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return bytes.to_vec();
    };
    let mut result = bytes[..end + 2].to_vec();
    result.extend(headers.as_bytes());
    result.extend(&bytes[end + 2..]);
    result
}
async fn run(bytes: &[u8], request: &Value) -> (Result<Value, String>, Vec<Value>) {
    let mut deltas = Vec::new();
    let bytes = acknowledge(bytes, request);
    let result = read(
        bytes.as_slice(),
        &tokio::sync::Notify::new(),
        &profile(request).unwrap(),
        |d| {
            deltas.push(d.clone());
            Ok(())
        },
    )
    .await;
    (result, deltas)
}

#[tokio::test]
async fn actual_http_reader_streams_text_and_preserves_usage_extensions() {
    let body = event(
        json!({"role":"assistant","content":"hello","reasoning_content":"thinking"}),
        None,
    ) + &event(json!({}), Some("stop"))
        + "data: {\"choices\":[],\"usage\":{\"completion_tokens\":1,\"context_window\":2048}}\n\n"
        + "data: [DONE]\n\n";
    let (result, deltas) = run(&response(&body), &request()).await;
    assert_eq!(
        result.unwrap(),
        json!({"finishReason":"stop","usage":{"completion_tokens":1,"context_window":2048},"servingProtocol":{"version":1,"mode":"negotiated","features":["stream"]}})
    );
    assert_eq!(
        deltas,
        vec![json!({"role":"assistant","content":"hello","reasoning_content":"thinking"})]
    );
}

#[tokio::test]
async fn real_duplex_stream_handles_every_byte_boundary_and_crlf() {
    let body = "\u{feff}: keepalive\r\n\r\n".to_owned()
        + &event(json!({"content":"\u{1f30d}\u{0142}"}), None).replace('\n', "\r\n")
        + &terminal("stop").replace('\n', "\r\n");
    let bytes = response(&body);
    let (mut writer, reader) = tokio::io::duplex(1);
    let sent = tokio::spawn(async move {
        for b in bytes {
            if writer.write_all(&[b]).await.is_err() {
                break;
            }
        }
    });
    let mut text = String::new();
    let result = read(
        reader,
        &tokio::sync::Notify::new(),
        &profile(&request()).unwrap(),
        |d| {
            text.push_str(d["content"].as_str().unwrap_or(""));
            Ok(())
        },
    )
    .await;
    sent.await.unwrap();
    assert_eq!(result.unwrap()["finishReason"], "stop");
    assert_eq!(text, "\u{1f30d}\u{0142}");
}

#[tokio::test]
async fn interleaved_parallel_calls_are_released_once_as_complete_arguments() {
    let body = event(
        json!({"tool_calls":[call(0,"a","{\"id\":"), call(1,"b","{")]}),
        None,
    ) + &event(
        json!({"tool_calls":[{"index":1,"function":{"arguments":"\"id\":2}"}},
            {"index":0,"function":{"arguments":"1}"}}]}),
        None,
    ) + &terminal("tool_calls");
    let (result, deltas) = run(&response(&body), &tools_request()).await;
    assert_eq!(result.unwrap()["finishReason"], "tool_calls");
    assert_eq!(
        deltas,
        vec![json!({"tool_calls":[call(0,"a","{\"id\":1}"),call(1,"b","{\"id\":2}") ]})]
    );
}

#[tokio::test]
async fn tool_policy_and_all_arguments_are_validated_before_any_call_is_delivered() {
    let mut no_parallel = tools_request();
    no_parallel["parallel_tool_calls"] = json!(false);
    let mut disabled = tools_request();
    disabled["tool_choice"] = json!("none");
    let mut required = tools_request();
    required["tool_choice"] = json!("required");
    let cases = [
        (
            tools_request(),
            vec![
                call(0, "a", "{\"id\":1}"),
                call(1, "b", "{\"id\":\"wrong\"}"),
            ],
            "tool_calls",
        ),
        (
            tools_request(),
            vec![call(0, "a", "{\"id\":")],
            "tool_calls",
        ),
        (tools_request(), vec![call(0, "a", "[]")], "tool_calls"),
        (request(), vec![call(0, "a", "{\"id\":1}")], "tool_calls"),
        (
            no_parallel,
            vec![call(0, "a", "{\"id\":1}"), call(1, "b", "{\"id\":2}")],
            "tool_calls",
        ),
        (disabled, vec![call(0, "a", "{\"id\":1}")], "tool_calls"),
        (required, vec![], "stop"),
        (tools_request(), vec![call(0, "a", "{\"id\":1}")], "stop"),
    ];
    for (request, calls, reason) in cases {
        let body = event(json!({"tool_calls":calls}), None) + &terminal(reason);
        let (result, deltas) = run(&response(&body), &request).await;
        assert!(result.is_err(), "{result:?}");
        assert!(deltas.is_empty(), "{deltas:?}");
    }
}

#[tokio::test]
async fn forced_named_tool_accepts_stop_but_truncation_never_releases_calls() {
    let mut req = tools_request();
    req["tool_choice"] = json!({"type":"function","function":{"name":"lookup"}});
    for reason in ["stop", "length", "content_filter"] {
        let body =
            event(json!({"tool_calls":[call(0,"a","{\"id\":1}")]}), None) + &terminal(reason);
        let (result, deltas) = run(&response(&body), &req).await;
        assert_eq!(result.unwrap()["finishReason"], reason);
        assert_eq!(deltas.len(), usize::from(reason == "stop"));
    }
}

#[tokio::test]
async fn malformed_or_unfinished_streams_never_succeed_or_release_calls() {
    let start = event(json!({"tool_calls":[call(0,"a","{\"id\":1}")]}), None);
    for tail in [
        "data: [DONE]\n\n".to_owned(),
        String::new(),
        event(json!({}), Some("tool_calls")),
        terminal("unknown"),
        terminal("tool_calls") + "data: [DONE]\n\n",
        terminal("tool_calls") + "data: incomplete",
        "data: invalid-json\n\n".into(),
        event(json!({}), Some("tool_calls")) + &terminal("tool_calls"),
        "data: {\"choices\":[{\"index\":1,\"delta\":{}}]}\n\n".into(),
        event(
            json!({"function_call":{"name":"legacy","arguments":"{}"}}),
            None,
        ),
    ] {
        let (result, deltas) = run(&response(&(start.clone() + &tail)), &tools_request()).await;
        assert!(result.is_err(), "tail {tail:?}: {result:?}");
        assert!(deltas.is_empty());
    }
}

#[tokio::test]
async fn the_model_servers_typed_refusals_are_rendered_from_their_numbers_not_their_text() {
    // The runner's own integers name the window and what overflowed it; its message text is
    // never copied, so a tokenizer echo could not reach the user through this path.
    let cases: [(u16, Value, &str); 6] = [
        (400, json!({"code":"yougori_context_window","message":"sensitive-synthetic-value","context":9728,"promptTokens":10294,"maxTokens":256,"grantContext":9728}),
            "This conversation needs 10294 prompt tokens plus up to 256 reply tokens, more than the model's 9728-token context window (the GPU grant covers that many tokens). Shorten the conversation or lower max_tokens."),
        (400, json!({"code":"yougori_context_window","message":"sensitive-synthetic-value","context":32768,"promptTokens":40000,"maxTokens":256}),
            "This conversation needs 40000 prompt tokens plus up to 256 reply tokens, more than the model's 32768-token context window. Shorten the conversation or lower max_tokens."),
        (400, json!({"code":"yougori_context_window","message":"sensitive-synthetic-value","context":4096,"maxTokens":4096}),
            "max_tokens 4096 is not below the model's 4096-token context window. Lower max_tokens."),
        (400, json!({"code":"yougori_context_window","message":"sensitive-synthetic-value","context":4096,"grantContext":9728}),
            "This conversation exceeds the model's 4096-token context window. Shorten it or lower max_tokens."),
        (507, json!({"code":"yougori_gpu_memory","message":"sensitive-synthetic-value"}), GPU_MEMORY_REFUSED),
        // A JSON reply format the runner cannot enforce: the reason reaches the person, in the engine's words.
        (400, json!({"code":"yougori_structured_output","message":"sensitive-synthetic-value"}), STRUCTURED_OUTPUT_REFUSED),
    ];
    for (status, error, expected) in cases {
        let value = json!({"error": error});
        let bytes = format!(
            "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\n\r\n{value}",
            value.to_string().len()
        );
        let (result, _) = run(bytes.as_bytes(), &request()).await;
        assert_eq!(result.unwrap_err(), expected);
        assert_eq!(typed_refusal(&value).as_deref(), Some(expected));
    }
    // The GPU-memory refusal inside a stream (headers already sent) is rendered the same way.
    let frame = json!({"error":{"code":"yougori_gpu_memory","message":"sensitive-synthetic-value"}});
    let (result, _) = run(&response(&format!("data: {frame}\n\n")), &request()).await;
    assert_eq!(result.unwrap_err(), GPU_MEMORY_REFUSED);
    // A context refusal without its window is not a typed refusal: the classifier's words stay.
    let value = json!({"error":{"code":"yougori_context_window","message":"sensitive-synthetic-value"}});
    assert!(typed_refusal(&value).is_none());
    let bytes = format!("HTTP/1.1 400 Error\r\nContent-Length: {}\r\n\r\n{value}", value.to_string().len());
    let (result, _) = run(bytes.as_bytes(), &request()).await;
    let error = result.unwrap_err();
    assert!(error.starts_with("Model service") && !error.contains("sensitive"), "{error}");
}

#[tokio::test]
async fn service_errors_are_classified_without_echoing_payloads() {
    for (status, code, expected) in [
        (429, "insufficient_quota", "quota exceeded"),
        (400, "context_length_exceeded", "context overflow"),
        (429, "rate_limit_exceeded", "busy"),
        (401, "invalid_api_key", "authentication failed"),
    ] {
        let value = json!({"error":{"code":code,"message":"sensitive-synthetic-value"}});
        let bytes = format!(
            "HTTP/1.1 {status} Error\r\nContent-Length: {}\r\n\r\n{value}",
            value.to_string().len()
        );
        let (result, _) = run(bytes.as_bytes(), &request()).await;
        let error = result.unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("sensitive"));
        let (result, _) = run(&response(&format!("data: {value}\n\n")), &request()).await;
        assert!(!result.unwrap_err().contains("sensitive"));
    }
}

#[tokio::test]
async fn cancellation_and_idle_timeout_cover_headers_and_error_bodies() {
    for prefix in [
        b"".as_slice(),
        b"HTTP/1.1 429 Busy\r\nContent-Length: 100\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
    ] {
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(prefix).await.unwrap();
        let result = read_with_idle(
            reader,
            &tokio::sync::Notify::new(),
            &profile(&request()).unwrap(),
            |_| Ok(()),
            Duration::from_millis(10),
        )
        .await;
        assert!(result.unwrap_err().contains("stopped responding"));
        let (mut writer, reader) = tokio::io::duplex(1024);
        writer.write_all(prefix).await.unwrap();
        let cancel = tokio::sync::Notify::new();
        let notify = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.notify_one();
        };
        let profile = profile(&request()).unwrap();
        let (result, ()) = tokio::join!(read(reader, &cancel, &profile, |_| Ok(())), notify);
        assert_eq!(result.unwrap()["finishReason"], "cancelled");
    }
}

#[tokio::test]
async fn consumer_failure_and_invalid_utf8_stop_without_calls() {
    let bytes = response(&(event(json!({"content":"hello"}), None) + &terminal("stop")));
    assert_eq!(
        read(
            bytes.as_slice(),
            &tokio::sync::Notify::new(),
            &profile(&request()).unwrap(),
            |_| Err("consumer closed".into())
        )
        .await
        .unwrap_err(),
        "consumer closed"
    );
    for tail in [vec![0xff], vec![0xf0, 0x9f]] {
        let mut bytes = response("data: ");
        bytes.extend(tail);
        assert!(run(&bytes, &request()).await.0.is_err());
    }
}

#[tokio::test]
async fn chunked_http_and_content_length_are_checked_through_the_end() {
    let body =
        event(json!({"tool_calls":[call(0,"a","{\"id\":1}")]}), None) + &terminal("tool_calls");
    let mut bytes =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    for piece in body.as_bytes().chunks(3) {
        bytes.extend(format!("{:x};test=yes\r\n", piece.len()).as_bytes());
        bytes.extend(piece);
        bytes.extend(b"\r\n");
    }
    let unfinished = bytes.clone();
    bytes.extend(b"0\r\nX-Synthetic: yes\r\n\r\n");
    assert!(run(&bytes, &tools_request()).await.0.is_ok());
    let (result, deltas) = run(&unfinished, &tools_request()).await;
    assert!(result.is_err());
    assert!(deltas.is_empty());
    for difference in [0, 1, -1] {
        let bytes = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",body.len() as i64 + difference);
        let (result, deltas) = run(bytes.as_bytes(), &tools_request()).await;
        assert_eq!(result.is_ok(), difference == 0);
        assert_eq!(deltas.len(), usize::from(difference == 0));
    }
}

#[test]
fn http_framing_is_independent_of_read_boundaries() {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
    for split in 0..=wire.len() {
        let mut http = transport::Response::default();
        let mut body = http.push(&wire[..split], false).unwrap();
        body.extend(http.push(&wire[split..], true).unwrap());
        assert_eq!(body, b"abcde");
        assert!(http.done());
    }
}

#[tokio::test]
async fn ambiguous_oversized_or_encoded_http_is_rejected() {
    for headers in [
        "Content-Length: 1\r\nContent-Length: 1".into(),
        "Content-Length: 1\r\nTransfer-Encoding: chunked".into(),
        "Transfer-Encoding: gzip, chunked".into(),
        "Content-Encoding: gzip".into(),
        "Content-Length: -1".into(),
        "Content-Length: 999999999".into(),
        "Content-Type: application/json".into(),
        " Content-Length: 1".into(),
        format!("X-Large: {}", "x".repeat(16 * 1024)),
    ] {
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{headers}\r\n\r\n{}",
            terminal("stop")
        );
        assert!(
            run(wire.as_bytes(), &request()).await.0.is_err(),
            "{headers}"
        );
    }
    let wire = format!("HTTP/1.1 400 Error\r\n\r\n{}", "x".repeat(MAX_ERROR + 1));
    assert!(run(wire.as_bytes(), &request())
        .await
        .0
        .unwrap_err()
        .contains("64 KiB"));
    let wire = response(&"x".repeat(MAX_RESPONSE));
    assert!(run(&wire, &request())
        .await
        .0
        .unwrap_err()
        .contains("8 MiB"));
}

#[test]
fn bad_requests_are_rejected_before_opening_a_connection() {
    assert!(profile(&request()).is_ok());
    assert!(profile(&json!({"messages":"wrong"})).is_err());
    let mut body = tools_request();
    body["tools"][0]["type"] = json!("web_search");
    assert!(profile(&body).is_err());
}

#[tokio::test]
async fn cancellation_during_display_drops_even_completed_calls() {
    let body = event(
        json!({"content":"hello","tool_calls":[call(0,"a","{\"id\":1}")]}),
        None,
    ) + &terminal("tool_calls");
    let wire = acknowledge(&response(&body), &tools_request());
    let cancel = tokio::sync::Notify::new();
    let mut tools = 0;
    let result = read(
        wire.as_slice(),
        &cancel,
        &profile(&tools_request()).unwrap(),
        |d| {
            if d.get("tool_calls").is_some() {
                tools += 1;
            }
            if d.get("content").is_some() {
                cancel.notify_one();
            }
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(result["finishReason"], "cancelled");
    assert_eq!(tools, 0);
}

#[tokio::test]
async fn unfinished_tool_call_is_discarded_on_cancel() {
    let body = event(json!({"tool_calls":[call(0,"a","{\"id\":")]}), None);
    let wire = acknowledge(&response(&body), &tools_request());
    let (mut writer, reader) = tokio::io::duplex(4096);
    writer.write_all(&wire).await.unwrap();
    let cancel = tokio::sync::Notify::new();
    let request = profile(&tools_request()).unwrap();
    let mut tools = 0;
    let notify = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.notify_one();
    };
    let (result, ()) = tokio::join!(
        read(reader, &cancel, &request, |_| {
            tools += 1;
            Ok(())
        }),
        notify
    );
    assert_eq!(result.unwrap()["finishReason"], "cancelled");
    assert_eq!(tools, 0);
}

#[tokio::test]
async fn tool_count_and_argument_limits_are_enforced() {
    let calls: Vec<_> = (0..33)
        .map(|i| call(i, &format!("id-{i}"), "{\"id\":1}"))
        .collect();
    for calls in [calls, vec![call(0, "a", &" ".repeat(65537))]] {
        let body = event(json!({"tool_calls":calls}), None) + &terminal("tool_calls");
        let (result, deltas) = run(&response(&body), &tools_request()).await;
        assert!(result.unwrap_err().contains("LimitExceeded"));
        assert!(deltas.is_empty());
    }
}

#[tokio::test]
async fn multiline_and_cr_only_events_use_shared_sse_rules() {
    let body = "data: {\"choices\":[\rdata: {\"index\":0,\"delta\":{\"content\":\"text\"}}]}\r\r"
        .to_owned()
        + &terminal("stop").replace('\n', "\r");
    let (result, deltas) = run(&response(&body), &request()).await;
    assert!(result.is_ok());
    assert_eq!(deltas, vec![json!({"content":"text"})]);
}

#[tokio::test]
async fn refused_turn_drops_calls_and_preserves_finish() {
    let body = event(
        json!({"refusal":"Cannot comply","tool_calls":[call(0,"a","{\"id\":1}")]}),
        None,
    ) + &terminal("tool_calls");
    let (result, deltas) = run(&response(&body), &tools_request()).await;
    assert_eq!(result.unwrap()["finishReason"], "tool_calls");
    assert_eq!(deltas, vec![json!({"refusal":"Cannot comply"})]);
}

#[test]
fn malformed_chunk_framing_cannot_finish_a_response() {
    for body in [
        "z\r\n",
        "-1\r\n",
        "100000000000000000000\r\n",
        "1\r\naXX",
        "0\r\nContent-Length: 3\r\n\r\n",
        "0\r\n\r\nextra",
        "1\r\na\r\n",
    ] {
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{body}");
        let mut http = transport::Response::default();
        assert!(http.push(wire.as_bytes(), true).is_err(), "{body}");
    }
}

#[tokio::test]
async fn legacy_text_is_explicit_but_legacy_tools_are_not_released() {
    let wire = response(&(event(json!({"content":"legacy"}), None) + &terminal("stop")));
    let result = read(
        wire.as_slice(),
        &tokio::sync::Notify::new(),
        &profile(&request()).unwrap(),
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(
        result["servingProtocol"],
        json!({"version":null,"mode":"legacy","features":[]})
    );
    let wire = response(
        &(event(json!({"tool_calls":[call(0,"a","{\"id\":1}")]}), None) + &terminal("tool_calls")),
    );
    let mut pieces = 0;
    let error = read(
        wire.as_slice(),
        &tokio::sync::Notify::new(),
        &profile(&tools_request()).unwrap(),
        |_| {
            pieces += 1;
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert!(error.contains("Restart"));
    assert_eq!(pieces, 0);
}

#[tokio::test]
async fn malformed_duplicate_unknown_or_mismatched_agreements_do_not_downgrade() {
    for headers in [
        "X-Yougori-Serving-Protocol: 2\r\nX-Yougori-Serving-Features: stream",
        "X-Yougori-Serving-Protocol: 01\r\nX-Yougori-Serving-Features: stream",
        "X-Yougori-Serving-Protocol: 1",
        "X-Yougori-Serving-Features: stream",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream,tools",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream,unknown",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream\r\nX-Yougori-Serving-Protocol: 1",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: stream\r\nX-Yougori-Serving-Features: stream",
        "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features:",
    ] {
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{headers}\r\n\r\n{}", terminal("stop"));
        let mut delivered = false;
        let result = read(wire.as_bytes(), &tokio::sync::Notify::new(), &profile(&request()).unwrap(), |_| {delivered=true;Ok(())}).await;
        assert!(result.is_err(), "{headers}"); assert!(!delivered);
    }
}

#[test]
fn continuation_and_disabled_tool_choices_still_require_tool_aware_input() {
    let mut body = request();
    assert!(profile(&body)
        .unwrap()
        .headers()
        .contains("Features: stream\r\n"));
    body["messages"] = json!([{"role":"assistant","content":null,"tool_calls":[{"id":"a"}]}, {"role":"tool","tool_call_id":"a","content":"result"}]);
    assert!(profile(&body)
        .unwrap()
        .headers()
        .contains("Features: stream,tools\r\n"));
    let mut body = tools_request();
    body["tool_choice"] = json!("none");
    assert!(profile(&body)
        .unwrap()
        .headers()
        .contains("Features: stream,tools\r\n"));
}

#[tokio::test]
async fn compatibility_refusals_are_actionable_without_echoing_backend_text() {
    for code in [
        "yougori_serving_version",
        "yougori_serving_features",
        "yougori_serving_request",
    ] {
        let body = json!({"error":{"code":code,"message":"sensitive-fixture"}});
        let wire = format!(
            "HTTP/1.1 412 Precondition Failed\r\nContent-Length: {}\r\n\r\n{body}",
            body.to_string().len()
        );
        let error = run(wire.as_bytes(), &request()).await.0.unwrap_err();
        assert!(!error.contains("sensitive-fixture"));
        assert!(!error.contains("unrecognized"));
    }
}

#[test]
fn a_trailer_cannot_change_the_negotiated_contract() {
    for field in [
        "X-Yougori-Serving-Protocol: 2",
        "X-Yougori-Serving-Features: stream,tools",
    ] {
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{field}\r\n\r\n");
        assert!(transport::Response::default()
            .push(wire.as_bytes(), true)
            .is_err());
    }
}
