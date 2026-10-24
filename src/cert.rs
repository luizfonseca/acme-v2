use openssl::asn1::Asn1Time;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509, X509Req, X509ReqBuilder};

use crate::Result;

fn ec_group(nid: Nid) -> Result<EcGroup> {
    let mut g = EcGroup::from_curve_name(nid)?;
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    Ok(g)
}

/// The P-256 curve, of account keys
pub(crate) fn p256() -> Result<EcGroup> {
    ec_group(Nid::X9_62_PRIME256V1)
}

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> Result<PKey<pkey::Private>> {
    Ok(PKey::from_rsa(Rsa::generate(bits)?)?)
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> Result<PKey<pkey::Private>> {
    let group = p256()?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> Result<PKey<pkey::Private>> {
    let group = ec_group(Nid::SECP384R1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new()?;

    // set private/public key in builder
    req_bld.set_pubkey(pkey)?;

    // set all domains as alt names
    let mut stack = Stack::new()?;
    let ctx = req_bld.x509v3_context(None);
    let mut an = SubjectAlternativeName::new();
    for d in domains {
        an.dns(d);
    }

    let ext = an.build(&ctx)?;
    stack.push(ext)?;
    req_bld.add_extensions(&stack)?;

    // sign it
    req_bld.sign(pkey, MessageDigest::sha256())?;

    // the csr
    Ok(req_bld.build())
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
    chain: Vec<String>,
}

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String, chain: Vec<String>) -> Self {
        Certificate {
            private_key,
            certificate,
            chain,
        }
    }

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes())?;
        Ok(pkey.private_key_to_der()?)
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    pub fn chain(&self) -> &Vec<String> {
        &self.chain
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Result<Vec<u8>> {
        let x509 = X509::from_pem(self.certificate.as_bytes())?;
        Ok(x509.to_der()?)
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate, and an error for a
    /// certificate that can't be read.
    pub fn valid_days_left(&self) -> Result<i64> {
        let x509 = X509::from_pem(self.certificate.as_bytes())?;
        let left = Asn1Time::days_from_now(0)?.diff(x509.not_after())?;
        Ok(i64::from(left.days))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// A self-signed certificate, valid until `not_after`
    pub(crate) fn certificate_until(not_after: &Asn1Time) -> String {
        let key = create_p256_key().unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "acmetest.example.com")
            .unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(0).unwrap())
            .unwrap();
        builder.set_not_after(not_after).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    }

    fn certificate(pem: &str) -> Certificate {
        Certificate::new(String::new(), pem.to_string(), vec![])
    }

    #[test]
    fn test_days_left_are_whole_days() {
        let in_90_days = certificate_until(&Asn1Time::days_from_now(90).unwrap());
        // 89 and some, once a second has passed
        assert!((89..=90).contains(&certificate(&in_90_days).valid_days_left().unwrap()));
    }

    #[test]
    fn test_expired_certificates_have_negative_days_left() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let two_days_ago = certificate_until(&Asn1Time::from_unix(now - 2 * 86_400).unwrap());
        assert!((-2..=-1).contains(&certificate(&two_days_ago).valid_days_left().unwrap()));
    }

    #[test]
    fn test_unreadable_certificates_are_errors() {
        assert!(certificate("CERT HERE").valid_days_left().is_err());
    }
}
