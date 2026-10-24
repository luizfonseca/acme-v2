use std::sync::LazyLock;

use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) type Response = ureq::http::Response<ureq::Body>;

/// TLS with the system's OpenSSL and root certificates. Statuses come back as responses,
/// and become problems in `req_handle_error`.
static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT_DURATION))
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::NativeTls)
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into()
});

pub(crate) fn req_get(url: &str) -> Result<Response, ureq::Error> {
    let req = AGENT.get(url);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_head(url: &str) -> Result<Response, ureq::Error> {
    let req = AGENT.head(url);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_post(url: &str, body: &str) -> Result<Response, ureq::Error> {
    let req = AGENT
        .post(url)
        .header("content-type", "application/jose+json");
    trace!("{:?} {}", req, body);
    req.send(body)
}

pub(crate) fn req_handle_error(res: Result<Response, ureq::Error>) -> ReqResult<Response> {
    let res = match res {
        // ok responses pass through
        Ok(res) if res.status().as_u16() < 400 => return Ok(res),
        Ok(res) => res,
        Err(_) => {
            return Err(ApiProblem {
                _type: "httpReqError".into(),
                detail: Some("Transport error".into()),
                subproblems: None,
            });
        }
    };

    let problem = if req_content_type(&res) == "application/problem+json" {
        // if we were sent a problem+json, deserialize it
        let body = req_safe_read_body(res);
        serde_json::from_str(&body).unwrap_or_else(|e| ApiProblem {
            _type: "problemJsonFail".into(),
            detail: Some(format!(
                "Failed to deserialize application/problem+json ({}) body: {}",
                e, body
            )),
            subproblems: None,
        })
    } else {
        // some other problem
        let status = res.status().to_string();
        let body = req_safe_read_body(res);
        let detail = format!("{} body: {}", status, body);
        ApiProblem {
            _type: "httpReqError".into(),
            detail: Some(detail),
            subproblems: None,
        }
    };

    Err(problem)
}

/// Extract a header from a response.
pub(crate) fn req_expect_header(res: &Response, name: &str) -> ReqResult<String> {
    req_header(res, name)
        .map(|v| v.to_string())
        .ok_or_else(|| ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
}

/// A header of a response, if it's text
pub(crate) fn req_header<'a>(res: &'a Response, name: &str) -> Option<&'a str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

/// The media type of a response, without its parameters
fn req_content_type(res: &Response) -> &str {
    let content_type = req_header(res, "content-type").unwrap_or_default();
    content_type.split(';').next().unwrap_or_default().trim()
}

pub(crate) fn req_safe_read_body(res: Response) -> String {
    use std::io::Read;
    let mut res_body = String::new();
    let mut read = res.into_body().into_reader();
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    read.read_to_string(&mut res_body).ok();
    res_body
}
