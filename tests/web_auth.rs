//! Integration tests for `zapret-rs web` HTTP/1.1 parser, HMAC session auth, and CLI routing.

/// Raw TCP HTTP request helper for end-to-end loopback tests without an HTTP client crate.
use std::io::{Cursor, Read, Write};
/// Loopback addresses and TCP client streams.
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
/// CLI subprocess execution verifying `zapret-rs web --help` and security refusal.
use std::process::Command;

/// Web HTTP/auth/CLI primitives under test.
use zapret_rs::tools::{
    HttpReadError, MAX_BODY_BYTES, MAX_HEADER_BYTES, MulticallApplet, SESSION_COOKIE_NAME,
    WebAuth, WebConfig, read_http_request, resolve_multicall, start_web_server,
};

/// Sends a raw HTTP/1.1 request over TCP and returns `(status_line, raw_response)`.
fn raw_http(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to web server");
    stream.write_all(request.as_bytes()).expect("write HTTP request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read HTTP response");
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("HTTP status code");
    (status, resp)
}

#[test]
fn web_auth_refuses_no_auth_on_non_loopback_and_signs_cookies() {
    let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8787);
    let err = WebAuth::new(lan, None, true).expect_err("non-loopback --no-auth must fail");
    assert!(err.contains("--no-auth"));

    let lo = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787);
    let (disabled, generated) = WebAuth::new(lo, None, true).expect("loopback no-auth succeeds");
    assert!(!disabled.is_required());
    assert!(generated.is_none());

    let (req_auth, gen_tok) = WebAuth::new(lan, None, false).expect("generated pairing token");
    let tok = gen_tok.expect("auto token");
    assert!(req_auth.verify_token(&tok));
    assert!(!req_auth.verify_token("wrong-token"));

    let cookie = req_auth.issue_session_cookie(1000).expect("issued cookie");
    assert!(req_auth.verify_session_value(&cookie, 1005));
    assert!(!req_auth.verify_session_value(&cookie, 1000 + 20 * 3600), "expired cookie rejected");
    let tampered = format!("{cookie}x");
    assert!(!req_auth.verify_session_value(&tampered, 1005));
}

#[test]
fn http_parser_enforces_header_and_body_bounds() {
    let mut big_hdr = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
    big_hdr.extend(vec![b'a'; MAX_HEADER_BYTES]);
    big_hdr.extend_from_slice(b"\r\n\r\n");
    let mut cur = Cursor::new(big_hdr);
    assert_eq!(read_http_request(&mut cur), Err(HttpReadError::HeadersTooLarge));

    let too_big_len = format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY_BYTES + 1
    );
    let mut cur_len = Cursor::new(too_big_len.into_bytes());
    assert_eq!(read_http_request(&mut cur_len), Err(HttpReadError::BodyTooLarge));
}

#[test]
fn web_server_enforces_cookie_login_csrf_and_logout_over_tcp() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let (auth, _) = WebAuth::new(bind, Some("secret-pass-42".to_owned()), false).expect("auth");
    let mut srv = start_web_server(WebConfig {
        bind,
        auth,
        control_socket: None,
        config: None,
        lua_dir: None,
    })
    .expect("start web server");
    let addr = srv.addr();

    // Unauthenticated health check works; protected check returns 401.
    let (status, _) = raw_http(addr, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 200);
    let (status, _) = raw_http(addr, "GET /api/auth/check HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(status, 401);

    // Form POST without JSON / X-Zapret-Action triggers 403 CSRF guard.
    let body_bad_ct = "token=secret-pass-42";
    let req_csrf = format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body_bad_ct}",
        body_bad_ct.len()
    );
    assert_eq!(raw_http(addr, &req_csrf).0, 403);

    // Wrong password -> 401.
    let wrong_json = "{\"token\":\"nope\"}";
    let req_wrong = format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{wrong_json}",
        wrong_json.len()
    );
    assert_eq!(raw_http(addr, &req_wrong).0, 401);

    // Valid JSON login -> 200 + HttpOnly SameSite=Strict session cookie.
    let ok_json = "{\"token\":\"secret-pass-42\"}";
    let req_ok = format!(
        "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{ok_json}",
        ok_json.len()
    );
    let (status, resp) = raw_http(addr, &req_ok);
    assert_eq!(status, 200);
    let set_cookie = resp
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .expect("Set-Cookie header");
    assert!(set_cookie.contains(SESSION_COOKIE_NAME));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie_pair = set_cookie
        .split_once(':')
        .expect(":")
        .1
        .split(';')
        .next()
        .expect("pair")
        .trim();

    // Authenticated request succeeds with session cookie or bearer header.
    let authed_req = format!(
        "GET /api/auth/check HTTP/1.1\r\nHost: localhost\r\nCookie: {cookie_pair}\r\n\r\n"
    );
    assert_eq!(raw_http(addr, &authed_req).0, 200);

    let bearer_req =
        "GET /api/auth/check HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret-pass-42\r\n\r\n";
    assert_eq!(raw_http(addr, bearer_req).0, 200);

    // Logout clears cookie.
    let logout_req = format!(
        "POST /api/logout HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nCookie: {cookie_pair}\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    let (status, out) = raw_http(addr, &logout_req);
    assert_eq!(status, 200);
    assert!(out.contains("Max-Age=0"));

    srv.shutdown();
}

#[test]
fn multicall_dispatches_web_subcommand_and_cli_help() {
    let (applet, args) = resolve_multicall(["zapret-rs", "web", "--bind", "127.0.0.1:8787"]);
    assert_eq!(applet, MulticallApplet::Web);
    assert_eq!(args.len(), 3);

    let bin = env!("CARGO_BIN_EXE_zapret-rs");
    let help = Command::new(bin).args(["web", "--help"]).output().expect("run web --help");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("--bind"));
    assert!(stdout.contains("--token"));

    let fail = Command::new(bin)
        .args(["web", "--bind", "0.0.0.0:8787", "--no-auth"])
        .output()
        .expect("run insecure web args");
    assert!(!fail.status.success());
}

#[test]
fn web_server_serves_self_contained_assets_without_external_cdn() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let (auth, _) = WebAuth::new(bind, Some("asset-pass".to_owned()), false).expect("auth");
    let mut srv = start_web_server(WebConfig {
        bind,
        auth,
        control_socket: None,
        config: None,
        lua_dir: None,
    })
    .expect("start web server");
    let addr = srv.addr();

    let (st_html, html) = raw_http(addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(st_html, 200);
    assert!(html.contains("X-Content-Type-Options: nosniff"));
    assert!(html.contains("text/html; charset=utf-8"));
    assert!(html.contains("Reload Lists") && html.contains("Confirm Stop"));
    assert!(!html.contains("http://") && !html.contains("https://"));

    let (st_css, css) = raw_http(addr, "GET /app.css HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(st_css, 200);
    assert!(css.contains("text/css") && css.contains("tabular-nums"));
    assert!(!css.contains("http://") && !css.contains("https://"));

    let (st_js, js) = raw_http(addr, "GET /app.js HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert_eq!(st_js, 200);
    assert!(js.contains("application/javascript") && js.contains("/api/events"));

    srv.shutdown();
}
