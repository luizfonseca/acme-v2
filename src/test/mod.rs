use rouille::{Request, Response, Server};

use std::sync::mpsc::Sender;
use std::thread;

pub struct TestServer {
    pub dir_url: String,
    shutdown: Option<Sender<()>>,
    #[allow(dead_code)]
    handle: thread::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.take().unwrap().send(()).ok();
    }
}

fn json_response(body: &str) -> Response {
    Response::from_data("application/jose+json", body).with_status_code(200)
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
    Response::empty_204().with_additional_header(
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
    Response::empty_204().with_status_code(200)
}

fn post_certificate(_url: &str) -> Response {
    Response::text("CERT HERE")
        .with_status_code(200)
        .with_additional_header("Link", "link-to-chain-cert")
}

fn route_request(req: &Request) -> Response {
    println!("Called with {:?}", req);
    let base_url = &format!("http://{}", &req.header("Host").unwrap_or("default"));

    match (req.method(), req.url().as_str()) {
        ("GET", "/directory") => get_directory(base_url),
        ("HEAD", "/acme/new-nonce") => head_new_nonce(),
        ("POST", "/acme/new-acct") => post_new_acct(base_url),
        ("POST", "/acme/new-order") => post_new_order(base_url),
        ("POST", "/acme/order/YTqpYUthlVfwBncUufE8") => post_get_order(base_url),
        ("POST", "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs") => post_authz(base_url),
        ("POST", "/acme/finalize/7738992/18234324") => post_finalize(base_url),
        ("POST", "/acme/cert/fae41c070f967713109028") => post_certificate(base_url),
        (_, _) => Response::empty_404(),
    }
}

pub fn with_directory_server() -> TestServer {
    let server = Server::new("127.0.0.1:0", |request| route_request(request)).unwrap();

    let base_url = format!("http://127.0.0.1:{}", server.server_addr().port());
    let dir_url = format!("{}/directory", base_url);

    let (handle, sender) = server.stoppable();

    TestServer {
        dir_url,
        shutdown: Some(sender),
        handle,
    }
}

#[test]
pub fn test_make_directory() {
    let server = with_directory_server();
    let res = ureq::get(&server.dir_url).call();
    assert!(res.is_ok());
}
