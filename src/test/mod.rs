//! An ACME server for tests, answering each request with a canned response

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

pub struct TestServer {
    pub dir_url: String,
    address: std::net::SocketAddr,
    stopped: Arc<AtomicBool>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        // Wakes the listener up, to see it's stopped
        TcpStream::connect(self.address).ok();
    }
}

/// A response: its status, headers and body
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn new(status: u16, content_type: &str, body: &str) -> Self {
        Response {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
        }
    }

    fn empty(status: u16) -> Self {
        Response {
            status,
            headers: vec![],
            body: String::new(),
        }
    }

    fn with_status_code(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    fn with_additional_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn write(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let mut head = format!("HTTP/1.1 {} X\r\n", self.status);
        for (name, value) in &self.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.body.len()
        ));
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())
    }
}

fn json_response(body: &str) -> Response {
    Response::new(200, "application/jose+json", body)
}

fn get_directory(url: &str) -> Response {
    let body = r#"{
    "keyChange": "<URL>/acme/key-change",
    "newAccount": "<URL>/acme/new-acct",
    "newNonce": "<URL>/acme/new-nonce",
    "newOrder": "<URL>/acme/new-order",
    "revokeCert": "<URL>/acme/revoke-cert",
    "meta": {
        "caaIdentities": [
        "testdir.org"
        ]
    }
    }"#;

    let body = body.replace("<URL>", url);

    json_response(&body)
}

fn head_new_nonce() -> Response {
    Response::empty(204).with_additional_header(
        "replay-nonce",
        "8_uBBV3N2DBRJczhoiB46ugJKUkUHxGzVe6xIMpjHFM",
    )
}

fn post_new_acct(url: &str) -> Response {
    let body = r#"{
    "id": 7728515,
    "key": {
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": "ttpobTRK2bw7ttGBESRO7Nb23mbIRfnRZwunL1W6wRI",
        "y": "h2Z00J37_2qRKH0-flrHEsH0xbit915Tyvd2v_CAOSk"
    },
    "contact": [
        "mailto:foo@bar.com"
    ],
    "initialIp": "90.171.37.12",
    "createdAt": "2018-12-31T17:15:40.399104457Z",
    "status": "valid"
    }"#;
    let location: String = "<URL>/acme/acct/7728515".replace("<URL>", url);

    json_response(body).with_additional_header("Location", location)
}

fn post_new_order(url: &str) -> Response {
    let body = r#"{
    "status": "pending",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324"
    }"#;

    let location: String = "<URL>/acme/order/YTqpYUthlVfwBncUufE8".replace("<URL>", url);
    let body = body.replace("<URL>", url);
    json_response(&body).with_additional_header("Location", location)
}

fn post_get_order(url: &str) -> Response {
    let body = r#"{
    "status": "<STATUS>",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324",
    "certificate": "<URL>/acme/cert/fae41c070f967713109028"
    }"#;

    let body = body.replace("<URL>", url);

    json_response(&body)
}

fn post_authz(url: &str) -> Response {
    let body = r#"{
        "identifier": {
            "type": "dns",
            "value": "acmetest.algesten.se"
        },
        "status": "pending",
        "expires": "2019-01-09T08:26:43Z",
        "challenges": [
        {
            "type": "http-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789597",
            "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
        },
        {
            "type": "tls-alpn-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789598",
            "token": "WCdRWkCy4THTD_j5IH4ISAzr59lFIg5wzYmKxuOJ1lU"
        },
        {
            "type": "dns-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789599",
            "token": "RRo2ZcXAEqxKvMH8RGcATjSK1KknLEUmauwfQ5i3gG8"
        }
        ]
    }"#;

    let body = body.replace("<URL>", url);

    json_response(&body).with_status_code(201)
}

fn post_finalize(_url: &str) -> Response {
    Response::empty(200)
}

fn post_certificate(_url: &str) -> Response {
    Response::new(200, "text/plain", "CERT HERE")
        .with_additional_header("Link", "link-to-chain-cert")
}

/// The method and path of a request, and its `Host` header. Its body is read and dropped.
fn read_request(stream: &TcpStream) -> std::io::Result<(String, String, String)> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let (mut host, mut length) = (String::new(), 0);
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').unwrap_or((header, ""));
        match name.to_ascii_lowercase().as_str() {
            "host" => host = value.trim().to_string(),
            "content-length" => length = value.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    reader.take(length).read_to_end(&mut vec![])?;
    Ok((method, path, host))
}

fn route_request(method: &str, path: &str, host: &str) -> Response {
    let base_url = &format!("http://{host}");

    match (method, path) {
        ("GET", "/directory") => get_directory(base_url),
        ("HEAD", "/acme/new-nonce") => head_new_nonce(),
        ("POST", "/acme/new-acct") => post_new_acct(base_url),
        ("POST", "/acme/new-order") => post_new_order(base_url),
        ("POST", "/acme/order/YTqpYUthlVfwBncUufE8") => post_get_order(base_url),
        ("POST", "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs") => post_authz(base_url),
        ("POST", "/acme/finalize/7738992/18234324") => post_finalize(base_url),
        ("POST", "/acme/cert/fae41c070f967713109028") => post_certificate(base_url),
        (_, _) => Response::empty(404),
    }
}

fn serve(mut stream: TcpStream) -> std::io::Result<()> {
    let (method, path, host) = read_request(&stream)?;
    route_request(&method, &path, &host).write(&mut stream)
}

pub fn with_directory_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));

    let stop = stopped.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(stream) = stream {
                thread::spawn(move || serve(stream));
            }
        }
    });

    TestServer {
        dir_url: format!("http://{address}/directory"),
        address,
        stopped,
    }
}

#[test]
pub fn test_make_directory() {
    let server = with_directory_server();
    let res = ureq::get(&server.dir_url).call();
    assert!(res.is_ok());
}
