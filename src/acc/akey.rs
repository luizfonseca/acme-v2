use openssl::ec::EcKey;
use openssl::pkey;

use crate::Result;
use crate::cert::p256;
use crate::jwt::Jwk;

#[derive(Clone, Debug)]
pub(crate) struct AcmeKey {
    private_key: EcKey<pkey::Private>,
    /// set once we contacted the ACME API to figure out the key id
    key_id: Option<String>,
    /// The public key, as sent to the ACME API
    jwk: Jwk,
    /// The thumbprint of `jwk`
    thumbprint: String,
}

impl AcmeKey {
    pub(crate) fn new() -> Result<AcmeKey> {
        let group = p256()?;
        Self::from_key(EcKey::generate(&group)?)
    }

    pub(crate) fn from_pem(pem: &[u8]) -> Result<AcmeKey> {
        let pri_key =
            EcKey::private_key_from_pem(pem).map_err(|e| format!("Failed to read PEM: {}", e))?;
        Self::from_key(pri_key)
    }

    fn from_key(private_key: EcKey<pkey::Private>) -> Result<AcmeKey> {
        let jwk = Jwk::of(&private_key)?;
        let thumbprint = jwk.thumbprint()?;
        Ok(AcmeKey {
            private_key,
            key_id: None,
            jwk,
            thumbprint,
        })
    }

    pub(crate) fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.private_key.private_key_to_pem()?)
    }

    pub(crate) fn private_key(&self) -> &EcKey<pkey::Private> {
        &self.private_key
    }

    pub(crate) fn jwk(&self) -> &Jwk {
        &self.jwk
    }

    pub(crate) fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    pub(crate) fn key_id(&self) -> Result<&str> {
        self.key_id
            .as_deref()
            .ok_or_else(|| "the account's key id isn't known yet".into())
    }

    pub(crate) fn set_key_id(&mut self, kid: String) {
        self.key_id = Some(kid)
    }
}
