//! VM §4.3, VM-P10 and VM-P30: inspected HTTP over a typed request model.

use super::*;

fn authorized() -> Authority {
    Authority::parse("api.example.com", DestinationPort::HTTPS).unwrap()
}

fn h1(method: &str, target: &str, headers: &[(&str, &str)]) -> InspectedRequest {
    InspectedRequest {
        version: HttpVersion::Http11,
        method: method.to_owned(),
        target: target.to_owned(),
        authority: None,
        scheme: None,
        protocol: None,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn h2(method: &str, target: &str, headers: &[(&str, &str)]) -> InspectedRequest {
    InspectedRequest {
        version: HttpVersion::Http2,
        method: method.to_owned(),
        target: target.to_owned(),
        authority: Some("api.example.com".to_owned()),
        scheme: Some("https".to_owned()),
        protocol: None,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn sni() -> TlsFacts {
    TlsFacts {
        sni: Some("api.example.com".to_owned()),
    }
}

fn bind_on(
    route: &OperationRoute,
    request: &InspectedRequest,
) -> Result<BoundRequest, RequestRefusal> {
    bind_request(
        &route_id("provider-api"),
        route,
        &authorized(),
        request,
        &sni(),
    )
}

fn bind(request: &InspectedRequest) -> Result<BoundRequest, RequestRefusal> {
    bind_on(&operation_route(RedirectPolicy::Disabled, true), request)
}

const HOST: (&str, &str) = ("Host", "api.example.com");

#[test]
fn a_valid_http11_request_binds_authority_operation_path_and_query() {
    let bound = bind(&h1(
        "GET",
        "/v1/models?limit=10&after=m-2",
        &[HOST, ("Accept", "application/json")],
    ))
    .unwrap();
    assert_eq!(bound.operation, OperationName::new("list-models").unwrap());
    assert_eq!(bound.method, HttpMethod::Get);
    assert_eq!(bound.authority, authorized());
    assert_eq!(bound.path_text(), "/v1/models");
    assert_eq!(bound.query.get("limit").map(String::as_str), Some("10"));
    assert_eq!(bound.body, BodyFraming::None);
    assert_eq!(bound.effect, EffectClass::ReadOnly);
}

#[test]
fn a_valid_http2_request_binds_the_same_operation() {
    let bound = bind(&h2(
        "GET",
        "/v1/models?limit=10",
        &[("accept", "application/json")],
    ))
    .unwrap();
    let same = bind(&h1("GET", "/v1/models?limit=10", &[HOST])).unwrap();
    assert_eq!(bound.digest(), same.digest());
}

#[test]
fn canonical_equivalents_bind_identically_and_any_bound_change_differs() {
    let base = bind(&h1("GET", "/v1/models?limit=10&after=m-2", &[HOST])).unwrap();
    let reordered = bind(&h1("GET", "/v1/models?after=m-2&limit=10", &[HOST])).unwrap();
    let encoded = bind(&h1("GET", "/v1/%6Dodels?limit=1%30&after=m%2D2", &[HOST])).unwrap();
    let port_spelled = bind(&h1(
        "GET",
        "/v1/models?limit=10&after=m-2",
        &[("Host", "API.example.com:443")],
    ))
    .unwrap();
    assert_eq!(base.digest(), reordered.digest());
    assert_eq!(base.digest(), encoded.digest());
    assert_eq!(base.digest(), port_spelled.digest());
    let changed = bind(&h1("GET", "/v1/models?limit=11&after=m-2", &[HOST])).unwrap();
    assert_ne!(base.digest(), changed.digest());
    // Reserved characters stay encoded with uppercase hex, distinct from their raw form.
    let a = bind(&h1("GET", "/v1/models/a%3fb", &[HOST])).unwrap();
    let b = bind(&h1("GET", "/v1/models/a%3Fb", &[HOST])).unwrap();
    assert_eq!(a.path, vec!["v1", "models", "a%3Fb"]);
    assert_eq!(a.digest(), b.digest());
}

#[test]
fn the_outbound_target_is_encoded_from_the_bound_form_and_binds_identically() {
    let bound = bind(&h1("GET", "/v1/%6Dodels?limit=1%30&after=m%2D2", &[HOST])).unwrap();
    assert_eq!(bound.outbound_target(), "/v1/models?after=m-2&limit=10");
    let again = bind(&h1("GET", &bound.outbound_target(), &[HOST])).unwrap();
    assert_eq!(again.digest(), bound.digest());
    let reserved = bind(&h1("GET", "/v1/models/a%3fb", &[HOST])).unwrap();
    assert_eq!(reserved.outbound_target(), "/v1/models/a%3Fb");
    assert_eq!(
        bind(&h1("GET", &reserved.outbound_target(), &[HOST]))
            .unwrap()
            .digest(),
        reserved.digest()
    );
    // A retried request binds to the same operation identity.
    assert_eq!(
        bind(&h1("GET", "/v1/models?limit=10&after=m-2", &[HOST]))
            .unwrap()
            .digest(),
        bound.digest()
    );
}

#[test]
fn ambiguous_duplicate_headers_are_refused() {
    assert_eq!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Host", "evil.example.net")]
        )),
        Err(RequestRefusal::DuplicateHeader {
            name: "host".to_owned()
        })
    );
    assert_eq!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("X-Trace", "1"), ("x-trace", "2")]
        )),
        Err(RequestRefusal::DuplicateHeader {
            name: "x-trace".to_owned()
        })
    );
    assert_eq!(
        bind(&h1(
            "POST",
            "/v1/jobs",
            &[HOST, ("Content-Length", "2"), ("Content-Length", "2")]
        )),
        Err(RequestRefusal::DuplicateHeader {
            name: "content-length".to_owned()
        })
    );
}

#[test]
fn conflicting_or_ambiguous_framing_is_refused() {
    assert_eq!(
        bind(&h1(
            "POST",
            "/v1/jobs",
            &[
                HOST,
                ("Content-Length", "5"),
                ("Transfer-Encoding", "chunked")
            ]
        )),
        Err(RequestRefusal::ConflictingFraming)
    );
    for encoding in ["gzip, chunked", "chunked, chunked", "identity", " chunked"] {
        assert!(
            bind(&h1(
                "POST",
                "/v1/jobs",
                &[HOST, ("Transfer-Encoding", encoding)]
            ))
            .is_err(),
            "{encoding}"
        );
    }
    for length in ["05", "1,1", "-1", "+5", "", "1e3", "18446744073709551616"] {
        assert!(
            matches!(
                bind(&h1("POST", "/v1/jobs", &[HOST, ("Content-Length", length)])),
                Err(RequestRefusal::InvalidContentLength { .. }
                    | RequestRefusal::InvalidHeaderValue { .. })
            ),
            "{length:?}"
        );
    }
    assert_eq!(
        bind(&h2("POST", "/v1/jobs", &[("transfer-encoding", "chunked")])),
        Err(RequestRefusal::HopByHop {
            header: "transfer-encoding".to_owned()
        })
    );
    assert_eq!(
        bind(&h1("GET", "/v1/models", &[HOST, ("Content-Length", "4")])),
        Err(RequestRefusal::BodyNotAllowed {
            method: HttpMethod::Get
        })
    );
    assert!(bind(&h1("GET", "/v1/models", &[HOST, ("Content-Length", "0")])).is_ok());
}

#[test]
fn streaming_and_sized_bodies_are_framed_explicitly() {
    let chunked = bind(&h1(
        "POST",
        "/v1/jobs",
        &[HOST, ("Transfer-Encoding", "chunked")],
    ))
    .unwrap();
    assert_eq!(chunked.body, BodyFraming::Chunked);
    assert_eq!(chunked.effect, EffectClass::External);
    let sized = bind(&h2("POST", "/v1/jobs", &[("content-length", "42")])).unwrap();
    assert_eq!(sized.body, BodyFraming::ContentLength(42));
}

#[test]
fn upgrade_and_tunnelling_forms_are_refused() {
    assert_eq!(
        bind(&h1("CONNECT", "api.example.com:443", &[HOST])),
        Err(RequestRefusal::Tunneling)
    );
    let mut extended = h2("CONNECT", "/chat", &[]);
    extended.protocol = Some("websocket".to_owned());
    assert_eq!(bind(&extended), Err(RequestRefusal::Tunneling));
    let mut extended_get = h2("GET", "/v1/models", &[]);
    extended_get.protocol = Some("websocket".to_owned());
    assert_eq!(bind(&extended_get), Err(RequestRefusal::Tunneling));
    // WebSocket over HTTP/1.1.
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Connection", "Upgrade"), ("Upgrade", "websocket")]
        )),
        Err(RequestRefusal::Upgrade { .. })
    ));
    // h2c upgrade.
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[
                HOST,
                ("Upgrade", "h2c"),
                ("HTTP2-Settings", "AAMAAABkAAQAAP__")
            ]
        )),
        Err(RequestRefusal::Upgrade { .. })
    ));
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("HTTP2-Settings", "AAMAAABkAAQAAP__")]
        )),
        Err(RequestRefusal::Upgrade { .. })
    ));
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Connection", "keep-alive, Upgrade")]
        )),
        Err(RequestRefusal::Upgrade { .. })
    ));
}

#[test]
fn hop_by_hop_tricks_and_method_overrides_are_refused() {
    // Nominating Authorization as hop-by-hop would let a proxy strip or keep it inconsistently.
    assert_eq!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Connection", "close, Authorization")]
        )),
        Err(RequestRefusal::HopByHop {
            header: "authorization".to_owned()
        })
    );
    assert!(bind(&h1("GET", "/v1/models", &[HOST, ("Connection", "close")])).is_ok());
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Keep-Alive", "timeout=5")]
        )),
        Err(RequestRefusal::HopByHop { .. })
    ));
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("Proxy-Connection", "keep-alive")]
        )),
        Err(RequestRefusal::HopByHop { .. })
    ));
    assert!(matches!(
        bind(&h1("GET", "/v1/models", &[HOST, ("TE", "gzip")])),
        Err(RequestRefusal::HopByHop { .. })
    ));
    assert!(bind(&h2("GET", "/v1/models", &[("te", "trailers")])).is_ok());
    assert!(matches!(
        bind(&h2("GET", "/v1/models", &[("connection", "close")])),
        Err(RequestRefusal::HopByHop { .. })
    ));
    for header in METHOD_OVERRIDE_HEADERS {
        assert_eq!(
            bind(&h1("POST", "/v1/jobs", &[HOST, (header, "DELETE")])),
            Err(RequestRefusal::MethodOverride {
                header: header.to_owned()
            })
        );
    }
}

#[test]
fn methods_must_be_exact_and_permitted() {
    assert_eq!(
        bind(&h1("get", "/v1/models", &[HOST])),
        Err(RequestRefusal::UnknownMethod {
            method: "get".to_owned()
        })
    );
    assert_eq!(
        bind(&h1("TRACE", "/v1/models", &[HOST])),
        Err(RequestRefusal::UnknownMethod {
            method: "TRACE".to_owned()
        })
    );
    assert_eq!(
        bind(&h1("DELETE", "/v1/models/m-1", &[HOST])),
        Err(RequestRefusal::NoMatchingOperation)
    );
    assert_eq!(
        bind(&h1("GET", "/v1/secrets", &[HOST])),
        Err(RequestRefusal::NoMatchingOperation)
    );
}

#[test]
fn header_names_and_values_are_checked() {
    assert!(matches!(
        bind(&h1("GET", "/v1/models", &[HOST, ("Bad Header", "x")])),
        Err(RequestRefusal::InvalidHeaderName { .. })
    ));
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[HOST, ("X-A", "a\r\nInjected: 1")]
        )),
        Err(RequestRefusal::InvalidHeaderValue { .. })
    ));
    assert!(matches!(
        bind(&h1("GET", "/v1/models", &[HOST, ("X-A", " padded")])),
        Err(RequestRefusal::InvalidHeaderValue { .. })
    ));
    assert!(matches!(
        bind(&h1("GET", "/v1/models", &[HOST, ("X-A", "nul\0")])),
        Err(RequestRefusal::InvalidHeaderValue { .. })
    ));
    assert!(matches!(
        bind(&h2("GET", "/v1/models", &[("X-Upper", "1")])),
        Err(RequestRefusal::UppercaseHeaderNameInHttp2 { .. })
    ));
    assert!(matches!(
        bind(&h2("GET", "/v1/models", &[(":path", "/admin")])),
        Err(RequestRefusal::PseudoHeaderInFields { .. })
    ));
    let mut pseudo_in_h1 = h1("GET", "/v1/models", &[HOST]);
    pseudo_in_h1.authority = Some("api.example.com".to_owned());
    assert_eq!(
        bind(&pseudo_in_h1),
        Err(RequestRefusal::PseudoHeaderInHttp11)
    );
    let mut plain_scheme = h2("GET", "/v1/models", &[]);
    plain_scheme.scheme = Some("http".to_owned());
    assert_eq!(bind(&plain_scheme), Err(RequestRefusal::SchemeNotHttps));
}

#[test]
fn the_authority_must_be_present_consistent_and_the_authorized_one() {
    assert_eq!(
        bind(&h1("GET", "/v1/models", &[])),
        Err(RequestRefusal::MissingAuthority)
    );
    let mut no_authority = h2("GET", "/v1/models", &[]);
    no_authority.authority = None;
    assert_eq!(bind(&no_authority), Err(RequestRefusal::MissingAuthority));
    assert_eq!(
        bind(&h2("GET", "/v1/models", &[("host", "evil.example.net")])),
        Err(RequestRefusal::AuthorityConflict)
    );
    assert!(bind(&h2("GET", "/v1/models", &[("host", "api.example.com:443")])).is_ok());
    assert!(matches!(
        bind(&h1("GET", "/v1/models", &[("Host", "other.example.com")])),
        Err(RequestRefusal::AuthorityMismatch { .. })
    ));
    assert!(matches!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[("Host", "api.example.com:8443")]
        )),
        Err(RequestRefusal::AuthorityMismatch { .. })
    ));
    assert_eq!(
        bind(&h1(
            "GET",
            "/v1/models",
            &[("Host", "user@api.example.com")]
        )),
        Err(RequestRefusal::InvalidAuthority(NameError::Userinfo))
    );
    assert_eq!(
        bind(&h1("GET", "/v1/models", &[("Host", "api.example.com.")])),
        Err(RequestRefusal::InvalidAuthority(NameError::TrailingDot))
    );
}

#[test]
fn sni_must_name_the_authority_and_never_stands_in_for_it() {
    let route = operation_route(RedirectPolicy::Disabled, true);
    let request = h1("GET", "/v1/models", &[HOST]);
    // Domain fronting: an innocuous SNI with another Host.
    let fronted = TlsFacts {
        sni: Some("cdn-front.example.net".to_owned()),
    };
    assert_eq!(
        bind_request(
            &route_id("provider-api"),
            &route,
            &authorized(),
            &request,
            &fronted
        ),
        Err(RequestRefusal::SniAuthorityMismatch {
            sni: "cdn-front.example.net".to_owned(),
            authority: authorized()
        })
    );
    assert_eq!(
        bind_request(
            &route_id("provider-api"),
            &route,
            &authorized(),
            &request,
            &TlsFacts::default()
        ),
        Err(RequestRefusal::MissingSni)
    );
    assert!(matches!(
        bind_request(
            &route_id("provider-api"),
            &route,
            &authorized(),
            &request,
            &TlsFacts {
                sni: Some("api.example.com.".to_owned())
            }
        ),
        Err(RequestRefusal::InvalidSni(NameError::TrailingDot))
    ));
    let upper = TlsFacts {
        sni: Some("API.EXAMPLE.COM".to_owned()),
    };
    assert!(bind_request(
        &route_id("provider-api"),
        &route,
        &authorized(),
        &request,
        &upper
    )
    .is_ok());
    // A matching SNI does not rescue a different Host.
    let other_host = h1("GET", "/v1/models", &[("Host", "admin.example.com")]);
    assert!(matches!(
        bind_request(
            &route_id("provider-api"),
            &route,
            &authorized(),
            &other_host,
            &sni()
        ),
        Err(RequestRefusal::AuthorityMismatch { .. })
    ));
}

#[test]
fn credential_headers_are_reserved_on_credentialed_routes() {
    for header in ["Authorization", "Cookie", "Proxy-Authorization"] {
        assert_eq!(
            bind(&h1("GET", "/v1/models", &[HOST, (header, "secret")])),
            Err(RequestRefusal::ReservedHeader {
                name: header.to_ascii_lowercase()
            })
        );
    }
    let uncredentialed = operation_route(RedirectPolicy::Disabled, false);
    assert!(bind_on(
        &uncredentialed,
        &h1(
            "GET",
            "/v1/models",
            &[HOST, ("Authorization", "Bearer guest-scoped")]
        )
    )
    .is_ok());
}

#[test]
fn targets_must_be_origin_form_without_ambiguous_encodings() {
    let cases: &[(&str, RequestRefusal)] = &[
        (
            "https://api.example.com/v1/models",
            RequestRefusal::TargetNotOriginForm,
        ),
        ("*", RequestRefusal::TargetNotOriginForm),
        ("api.example.com:443", RequestRefusal::TargetNotOriginForm),
        ("/v1/models#top", RequestRefusal::Fragment),
        (
            "/v1%2Fmodels",
            RequestRefusal::AmbiguousEncodedCharacter {
                encoded: "%2F".to_owned(),
            },
        ),
        (
            "/v1/%2e%2e/admin",
            RequestRefusal::AmbiguousEncodedCharacter {
                encoded: "%2E".to_owned(),
            },
        ),
        (
            "/v1/models%5C..",
            RequestRefusal::AmbiguousEncodedCharacter {
                encoded: "%5C".to_owned(),
            },
        ),
        (
            "/v1/models/a%00",
            RequestRefusal::AmbiguousEncodedCharacter {
                encoded: "%00".to_owned(),
            },
        ),
        (
            "/v1/models/a%0d%0a",
            RequestRefusal::AmbiguousEncodedCharacter {
                encoded: "%0D".to_owned(),
            },
        ),
        ("/v1/models/%zz", RequestRefusal::InvalidPercentEncoding),
        ("/v1/models/%4", RequestRefusal::InvalidPercentEncoding),
        ("/v1/../admin", RequestRefusal::DotSegment),
        ("/v1/./models", RequestRefusal::DotSegment),
        ("//v1/models", RequestRefusal::EmptySegment),
        ("/v1//models", RequestRefusal::EmptySegment),
        ("/v1/models/", RequestRefusal::EmptySegment),
        ("/v1/models;jsessionid=1", RequestRefusal::PathParameter),
        (
            "/v1/models\\admin",
            RequestRefusal::InvalidPathCharacter { character: '\\' },
        ),
        (
            "/v1/mo dels",
            RequestRefusal::InvalidPathCharacter { character: ' ' },
        ),
        ("/v1/models?", RequestRefusal::EmptyQuery),
        (
            "/v1/models?limit=1&&after=2",
            RequestRefusal::EmptyQueryPair,
        ),
        ("/v1/models?=1", RequestRefusal::EmptyQueryPair),
        (
            "/v1/models?limit",
            RequestRefusal::QueryPairWithoutValue {
                key: "limit".to_owned(),
            },
        ),
        (
            "/v1/models?limit=1;after=2",
            RequestRefusal::AmbiguousQuerySeparator,
        ),
        ("/v1/models?after=a+b", RequestRefusal::PlusInQuery),
        (
            "/v1/models?limit=1&limit=2",
            RequestRefusal::DuplicateQueryKey {
                key: "limit".to_owned(),
            },
        ),
        (
            "/v1/models?lim%69t=1&limit=2",
            RequestRefusal::DuplicateQueryKey {
                key: "limit".to_owned(),
            },
        ),
        (
            "/v1/models?admin=true",
            RequestRefusal::QueryKeyNotPermitted {
                key: "admin".to_owned(),
            },
        ),
    ];
    for (target, expected) in cases {
        assert_eq!(
            &bind(&h1("GET", target, &[HOST])).unwrap_err(),
            expected,
            "{target}"
        );
    }
}

#[test]
fn redirect_targets_are_read_with_the_same_parser() {
    let current = authorized();
    let relative = redirect_target(&current, "/next").unwrap();
    assert_eq!(relative.authority, current);
    assert_eq!(relative.target, "/next");
    let absolute = redirect_target(&current, "HTTPS://Other.Example.com:8443/a?b=1").unwrap();
    assert_eq!(
        absolute.authority,
        Authority::parse("other.example.com:8443", DestinationPort::HTTPS).unwrap()
    );
    assert_eq!(absolute.target, "/a?b=1");
    assert_eq!(
        redirect_target(&current, "https://api.example.com")
            .unwrap()
            .target,
        "/"
    );
    assert_eq!(
        redirect_target(&current, "https://api.example.com?x=1")
            .unwrap()
            .target,
        "/?x=1"
    );
    assert_eq!(
        redirect_target(&current, "http://api.example.com/next"),
        Err(RequestRefusal::RedirectSchemeNotHttps)
    );
    assert_eq!(
        redirect_target(&current, "//evil.example.net/next"),
        Err(RequestRefusal::RedirectSchemeRelative)
    );
    assert_eq!(
        redirect_target(&current, "javascript:alert(1)"),
        Err(RequestRefusal::InvalidRedirect)
    );
    assert_eq!(
        redirect_target(&current, "next"),
        Err(RequestRefusal::InvalidRedirect)
    );
    assert_eq!(
        redirect_target(&current, "/next#frag"),
        Err(RequestRefusal::Fragment)
    );
    assert_eq!(
        redirect_target(&current, "https://user@evil.example.net/"),
        Err(RequestRefusal::InvalidAuthority(NameError::Userinfo))
    );
    assert_eq!(
        redirect_target(&current, "https://0x7f.1/"),
        Err(RequestRefusal::InvalidAuthority(NameError::IpLiteral {
            form: IpLiteralForm::HexIpv4
        }))
    );
    assert_eq!(
        redirect_target(&current, "/a/../b"),
        Err(RequestRefusal::DotSegment)
    );
}
