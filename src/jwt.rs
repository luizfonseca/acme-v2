use serde::{Deserialize, Serialize};

use openssl::ec::EcKeyRef;
use openssl::pkey::Private;
use openssl::sha::sha256;

use crate::Result;
use crate::cert::p256;
use crate::util::base64url;

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JwsProtected {
    alg: String,
    url: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl JwsProtected {
    pub(crate) fn new_jwk(jwk: Jwk, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }
    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            kid: Some(kid.into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Jwk {
    alg: String,
    crv: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl Jwk {
    /// The public part of an account key
    pub(crate) fn of(key: &EcKeyRef<Private>) -> Result<Jwk> {
        let mut ctx = openssl::bn::BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        let group = p256()?;
        key.public_key()
            .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        Ok(Jwk {
            alg: "ES256".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            _use: "sig".into(),
            x: base64url(&x.to_vec()),
            y: base64url(&y.to_vec()),
        })
    }

    /// Its thumbprint (RFC 7638), which challenges' proofs end with
    pub(crate) fn thumbprint(&self) -> Result<String> {
        let json = serde_json::to_string(&JwkThumb::from(self))?;
        Ok(base64url(&sha256(json.as_bytes())))
    }
}

impl From<&Jwk> for JwkThumb {
    fn from(a: &Jwk) -> Self {
        JwkThumb {
            crv: a.crv.clone(),
            kty: a.kty.clone(),
            x: a.x.clone(),
            y: a.y.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
    pub(crate) fn new(protected: String, payload: String, signature: String) -> Self {
        Jws {
            protected,
            payload,
            signature,
        }
    }
}
