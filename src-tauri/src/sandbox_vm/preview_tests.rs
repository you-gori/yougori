//! Tests of the preview adapter: the head checks and rewriting as pure functions, the policy
//! headers against the contract's own record, the token verifier, and one request end to end
//! over a real loopback connection with a scripted gate.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, MonotonicTime, SandboxBootGeneration};
use crate::sandbox::vm_service::SessionsPumped;
use crate::sandbox_contract::connections::{GatePublicationId, ProofBinding};
use crate::sandbox_contract::destinations::{
    Audience, DestinationPort, IngressTable, NetworkMode, PublicationRequest, ServiceIdentity,
};
use crate::sandbox_contract::untrusted::{
    FrameAncestors, HostApplicationOrigin, PreviewDomain, PreviewPolicy, SuffixListing,
};

const GET: &[u8] = b"GET /echo?x=1 HTTP/1.1\r\nHost: 127.0.0.1:4000\r\nAuthorization: Bearer secret\r\nCookie: host-session=1\r\nProxy-Authorization: Basic x\r\nConnection: keep-alive\r\nUpgrade: websocket\r\nAccept: text/html\r\n\r\n";

#[test]
fn explicitly_hosted_applications_keep_only_their_own_origin_sessions() {
    let request = parse_request(GET).unwrap();
    let application = String::from_utf8(forwarded_head_mode(&request, 3000, true)).unwrap();
    assert!(application.contains("Host: 127.0.0.1:4000\r\n"));
    assert!(application.contains("Cookie: host-session=1\r\n"));
    assert!(application.contains("Authorization: Bearer secret\r\n"));
    assert!(!application.contains("Proxy-Authorization"));
    let preview = String::from_utf8(forwarded_head(&request, 3000)).unwrap();
    assert!(!preview.contains("host-session"));
    let response = b"HTTP/1.0 200 OK\r\nSet-Cookie: app=own; Path=/; HttpOnly; SameSite=Strict\r\nSet-Cookie: poison=x; Domain=.localhost; Path=/\r\nContent-Length: 0\r\n\r\n";
    let application = String::from_utf8(rewritten_response_mode(response, true).unwrap()).unwrap();
    assert!(application.contains("Set-Cookie: app=own"));
    assert!(!application.contains("poison"));
    assert!(!application.contains("sandbox allow-scripts"));
    assert!(application.contains("frame-ancestors 'none'"));
    let preview = String::from_utf8(rewritten_response(response).unwrap()).unwrap();
    assert!(!preview.contains("Set-Cookie"));
    assert!(preview.contains("sandbox allow-scripts"));
}

/// PROVES a plain request head is taken and every unsafe form refused: a folded header, two
/// hosts, two lengths, a chunked body, an absolute or authority target, another version, a
/// body past the bound, bytes that are not ASCII.
#[test]
fn a_request_head_is_taken_only_in_its_plain_form() {
    let request = parse_request(GET).unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/echo?x=1");
    assert_eq!(request.content_length(), Ok(0));
    let refused = |head: &str| parse_request(head.as_bytes()).unwrap_err();
    assert_eq!(refused("GET / HTTP/1.1\r\nHost: a:1\r\nX: 1\r\n folded\r\n\r\n"), HeadRefusal::Malformed("folded header"));
    assert_eq!(refused("GET / HTTP/1.1\r\nHost: a:1\r\nHost: b:1\r\n\r\n"), HeadRefusal::Malformed("host"));
    assert_eq!(refused("POST / HTTP/1.1\r\nHost: a:1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"), HeadRefusal::Malformed("content-length"));
    assert_eq!(refused("POST / HTTP/1.1\r\nHost: a:1\r\nTransfer-Encoding: chunked\r\n\r\n"), HeadRefusal::ChunkedBody);
    assert_eq!(refused("GET http://evil.example/ HTTP/1.1\r\nHost: a:1\r\n\r\n"), HeadRefusal::Malformed("target"));
    assert_eq!(refused("CONNECT evil.example:443 HTTP/1.1\r\nHost: a:1\r\n\r\n"), HeadRefusal::Malformed("target"));
    assert_eq!(refused("GET / HTTP/2.0\r\nHost: a:1\r\n\r\n"), HeadRefusal::Malformed("version"));
    assert_eq!(refused("POST / HTTP/1.1\r\nHost: a:1\r\nContent-Length: 99999999999\r\n\r\n"), HeadRefusal::BodyTooLarge);
    assert!(parse_request("GET / HTTP/1.1\r\nHost: a:1\r\nX: \u{e9}\r\n\r\n".as_bytes()).is_err());
    assert_eq!(refused("GET / HTTP/1.1\r\nHost: a:1\r\nBad Name: 1\r\n\r\n"), HeadRefusal::Malformed("header name"));
}

/// PROVES only this listener's loopback names on its port are taken, and a token label is
/// read from a `<token>.localhost` host; another site's name (a DNS rebinding), another
/// port, a deeper name or a label with other characters is refused.
#[test]
fn only_this_listeners_loopback_names_are_taken() {
    assert_eq!(check_host("127.0.0.1:4000", 4000), Ok(None));
    assert_eq!(check_host("localhost:4000", 4000), Ok(None));
    assert_eq!(check_host("[::1]:4000", 4000), Ok(None));
    assert_eq!(check_host("Yabc123.LOCALHOST:4000", 4000), Ok(Some("yabc123".to_owned())));
    for wrong in [
        "evil.example:4000",
        "127.0.0.1:4001",
        "127.0.0.1",
        "a.b.localhost:4000",
        "a_b.localhost:4000",
        "localhost.evil.example:4000",
        ".localhost:4000",
    ] {
        assert_eq!(check_host(wrong, 4000), Err(HeadRefusal::WrongHost), "{wrong}");
    }
}

/// PROVES the forwarded head carries none of the caller's credentials or hop-by-hop fields,
/// names the guest's own host and asks for the connection's close; the caller's other
/// fields pass as they were.
#[test]
fn the_forwarded_head_carries_no_credential_of_the_caller() {
    let request = parse_request(GET).unwrap();
    let forwarded = String::from_utf8(forwarded_head(&request, 8080)).unwrap();
    assert!(forwarded.starts_with("GET /echo?x=1 HTTP/1.1\r\nHost: localhost:8080\r\n"), "{forwarded}");
    for gone in ["secret", "host-session", "Proxy-Authorization", "keep-alive", "websocket", "127.0.0.1"] {
        assert!(!forwarded.contains(gone), "{gone} in {forwarded}");
    }
    assert!(forwarded.contains("Accept: text/html\r\n"));
    assert!(forwarded.ends_with("Connection: close\r\n\r\n"));
}

/// PROVES the guest's answer reaches the caller without its cookies, hop-by-hop fields or
/// own policy headers, under the preview policy's; a status line that is not HTTP is refused.
#[test]
fn the_answer_carries_the_policy_and_no_cookie_of_the_guest() {
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: guest=1; Path=/\r\nContent-Security-Policy: default-src *\r\nX-Frame-Options: ALLOWALL\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\n";
    let answer = String::from_utf8(rewritten_response(head).unwrap()).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"), "{answer}");
    assert!(!answer.contains("guest=1") && !answer.contains("default-src *") && !answer.contains("keep-alive"));
    assert!(answer.contains("Content-Length: 2\r\n"));
    for (name, value) in policy_headers() {
        assert!(answer.contains(&format!("{name}: {value}\r\n")), "{name} missing:\n{answer}");
    }
    assert!(answer.ends_with("Connection: close\r\n\r\n"));
    assert!(rewritten_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
}

/// PROVES the adapter's headers are exactly the response headers of the contract's preview
/// policy for a publication, denying framing (VM-CP-28, VM-P03, VM-P35).
#[test]
fn the_policy_headers_are_the_contracts() {
    let sandbox = ExecutionId::new("exe-preview").unwrap();
    let mut table = IngressTable::new(sandbox, NetworkMode::DeclaredTransport, Duration::from_secs(3600));
    let now = MonotonicTime::from_nanos(1_000_000_000);
    let id = table
        .publish(
            PublicationRequest {
                service: ServiceIdentity::new("web").unwrap(),
                port: DestinationPort::new(8080).unwrap(),
                audience: Audience::Public,
                authentication: crate::sandbox_contract::destinations::AuthenticationMode::None,
                expires_at: now.saturating_add(Duration::from_secs(60)),
            },
            now,
        )
        .unwrap();
    let policy = PreviewPolicy::for_publication(
        table.publication(id).unwrap(),
        SandboxBootGeneration::FIRST,
        &PreviewDomain::new("localhost", SuffixListing::NotListed).unwrap(),
        &HostApplicationOrigin::parse("http://tauri.localhost").unwrap(),
        FrameAncestors::None,
    );
    let contract: Vec<(String, String)> = policy
        .response_headers
        .iter()
        .map(|line| (line.name.clone(), line.value.clone()))
        .collect();
    let ours: Vec<(String, String)> = policy_headers()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
    assert_eq!(ours, contract);
}

fn binding(publication: u64) -> ProofBinding {
    ProofBinding {
        sandbox: ExecutionId::new("exe-preview").unwrap(),
        epoch: AuthorizationEpoch::new(1),
        publication: gate_id(publication),
    }
}

fn gate_id(number: u64) -> GatePublicationId {
    GatePublicationId::for_tests(number)
}

/// PROVES a token proves the owner only for the publication, sandbox and epoch it was
/// issued for and only until the publication's expiry; another token is invalid.
#[test]
fn a_token_proves_the_owner_for_its_own_publication_only() {
    let verifier = TokenVerifier::default();
    let until = MonotonicTime::from_nanos(10_000_000_000);
    let token = verifier.issue(binding(1), until);
    assert!(token.starts_with('y') && token.len() == 33);
    let now = MonotonicTime::from_nanos(1_000_000_000);
    let proof = |text: &str| AuthenticationProof::new(AuthenticationMode::BearerToken, text.as_bytes().to_vec());
    let verified = verifier.verify(&binding(1), &proof(&token), now).unwrap();
    assert_eq!(verified.principal.as_str(), OWNER_PRINCIPAL);
    assert_eq!(verified.valid_until, until);
    assert_eq!(verifier.verify(&binding(1), &proof("ywrong"), now), Err(ProofRefusal::Invalid));
    assert_eq!(verifier.verify(&binding(2), &proof(&token), now), Err(ProofRefusal::WrongPublication));
    let mut later_epoch = binding(1);
    later_epoch.epoch = AuthorizationEpoch::new(2);
    assert_eq!(verifier.verify(&later_epoch, &proof(&token), now), Err(ProofRefusal::WrongPublication));
    assert_eq!(verifier.verify(&binding(1), &proof(&token), until), Err(ProofRefusal::Expired));
    verifier.forget(&ExecutionId::new("exe-preview").unwrap(), 1);
    assert_eq!(verifier.verify(&binding(1), &proof(&token), now), Err(ProofRefusal::WrongPublication));
}

/// A gate standing in for the VM service: it admits a caller whose proof the verifier
/// takes (any caller of a public publication), records what reached the guest and answers
/// the request once its head arrived, with a cookie and a policy of its own.
struct ScriptedHost {
    sessions: Mutex<Vec<(Box<dyn SessionStream>, Vec<u8>, bool)>>,
    received: Arc<Mutex<Vec<u8>>>,
    binding: ProofBinding,
}

impl PreviewHost for ScriptedHost {
    fn admit(
        &self,
        _sandbox: &SandboxId,
        _service: &str,
        proof: Option<AuthenticationProof>,
        verifier: &dyn ProofVerifier,
        mut outside: Box<dyn SessionStream>,
        _caller_room: crate::sandbox::vm_service::CallerRoom,
    ) -> Result<(u64, crate::sandbox::vm_service::GuestIngressWatch), GateRefusal> {
        let admitted = match &proof {
            Some(proof) => verifier
                .verify(&self.binding, proof, MonotonicTime::from_nanos(1))
                .map(|_| ())
                .map_err(GateRefusal::Proof),
            None => Err(GateRefusal::Ingress(IngressError::NotAuthenticated)),
        };
        if let Err(refusal) = admitted {
            outside.close();
            return Err(refusal);
        }
        self.sessions.lock().unwrap().push((outside, Vec::new(), false));
        Ok((1, crate::sandbox::vm_service::GuestIngressWatch::unbounded_for_tests()))
    }

    fn pump(&self) -> SessionsPumped {
        let mut sessions = self.sessions.lock().unwrap();
        for (outside, request, answered) in sessions.iter_mut() {
            let mut buffer = [0u8; 4096];
            while let Ok(StreamRead::Bytes(read)) = outside.read(&mut buffer) {
                request.extend_from_slice(&buffer[..read]);
            }
            if !*answered && head_end(request).is_some() {
                *answered = true;
                self.received.lock().unwrap().extend_from_slice(request);
                let _ = outside.write(b"HTTP/1.1 200 OK\r\nSet-Cookie: guest=1\r\nContent-Security-Policy: default-src *\r\nContent-Length: 5\r\n\r\nhello");
                outside.close();
            }
        }
        SessionsPumped::default()
    }

    fn publication_state(&self, _sandbox: &SandboxId, _publication: u64) -> Option<&'static str> {
        Some("active")
    }
}

fn exchange(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}

/// PROVES one request end to end over a real loopback connection: a caller without the
/// token is told 401 and nothing reaches the guest; a caller at the token's address gets
/// the guest's answer under the policy's headers and without its cookie, and the guest got
/// the request without the caller's cookie or authorization; another site's host is refused.
#[test]
fn a_preview_serves_its_owner_through_a_real_loopback_connection() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let previews = Arc::new(Previews::new());
    let host: Arc<ScriptedHost> = Arc::new(ScriptedHost {
        sessions: Mutex::new(Vec::new()),
        received: Arc::clone(&received),
        binding: binding(7),
    });
    let weak: Weak<dyn PreviewHost> = Arc::downgrade(&(Arc::clone(&host) as Arc<dyn PreviewHost>));
    let sandbox = SandboxId::new(ExecutionId::new("exe-preview").unwrap());
    let opened = previews
        .open(
            weak.clone(),
            &sandbox,
            7,
            "web",
            8080,
            PublicationAudience::Owner,
            binding(7),
            MonotonicTime::from_nanos(60_000_000_000),
        )
        .unwrap();
    previews.start_pump(weak);
    let token = opened
        .url
        .strip_prefix("http://")
        .and_then(|rest| rest.split_once(".localhost:"))
        .map(|(token, _)| token.to_owned())
        .unwrap();
    let port = opened.port;
    // No token.
    let answer = exchange(port, &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"));
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
    // Another site's name.
    let answer = exchange(port, &format!("GET / HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n"));
    assert!(answer.starts_with("HTTP/1.1 421"), "{answer}");
    assert!(received.lock().unwrap().is_empty(), "a refused caller reached the guest");
    // The owner at the token's address.
    let answer = exchange(
        port,
        &format!("GET /page HTTP/1.1\r\nHost: {token}.localhost:{port}\r\nCookie: host=1\r\nAuthorization: Basic eA==\r\n\r\n"),
    );
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("\r\n\r\nhello"), "{answer}");
    assert!(!answer.contains("guest=1") && !answer.contains("default-src *"), "{answer}");
    assert!(answer.contains("Content-Security-Policy: sandbox allow-scripts allow-forms; frame-ancestors 'none'\r\n"));
    let reached = String::from_utf8(received.lock().unwrap().clone()).unwrap();
    assert!(reached.starts_with("GET /page HTTP/1.1\r\nHost: localhost:8080\r\n"), "{reached}");
    assert!(!reached.contains("host=1") && !reached.contains("Basic") && !reached.contains(&token), "{reached}");
    assert_eq!(previews.view(&sandbox)[0].connections_served, 3);
    assert!(previews.view(&sandbox)[0].address.contains("<token>"), "status never shows the token");
    // Closed: the listener is gone.
    assert!(previews.close(&sandbox, 7));
    std::thread::sleep(Duration::from_millis(300));
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "the listener stayed open");
    assert!(previews.view(&sandbox).is_empty());
}
