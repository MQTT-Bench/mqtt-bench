use anyhow::{Context, Error};
use log::{debug, info};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::Private;
use openssl::pkey::{PKey, PKeyRef};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509};
use std::path::Path;
use std::{fs, fs::File, io::Read};

use crate::cli::{TlsConfig, TlsType};

const CA_KEY_NAME: &str = "CA.key";
const CA_CERT_NAME: &str = "CA.crt";

fn read_pem(path: &Path) -> Result<Vec<u8>, Error> {
    let mut f = File::open(path).context("Failed to read CA key file")?;
    let metadata = fs::metadata(path).context("Failed to read metadata of CA key file")?;
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).context("buffer overflow")?;
    Ok(buffer)
}

pub fn load_ca_pkey(key_path: &Path) -> Result<PKey<Private>, Error> {
    let buffer = read_pem(key_path)?;
    let rsa = Rsa::private_key_from_pem(&buffer[..]).context("Failed to read RSA private key")?;
    let pkey = PKey::from_rsa(rsa).context("Failed tp wrap RSA to Private Key")?;
    Ok(pkey)
}

pub fn load_ca_cert(cert_path: &Path) -> Result<X509, Error> {
    let buffer = read_pem(cert_path)?;
    let cert = X509::from_pem(&buffer).context("Failed to read X509 certificate")?;
    Ok(cert)
}

pub fn load_cert_stack(cert_path: &Path) -> Result<Vec<X509>, Error> {
    let buffer = read_pem(cert_path)?;
    let stack = X509::stack_from_pem(&buffer).context("Failed to parse cert stack")?;
    Ok(stack)
}

/// Make a CA certificate and private key
pub fn mk_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some CA organization")?;
    x509_name.append_entry_by_text("CN", "ca test")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

/// Make a X509 request with the given private key
pub fn mk_request(key_pair: &PKey<Private>, common_name: &str) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some organization")?;
    x509_name.append_entry_by_text("CN", common_name)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

/// Make a certificate and private key signed by the given CA cert and private key
pub fn mk_ca_signed_cert(
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    common_name: &str,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let req = mk_request(&key_pair, common_name)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns("*.example.com")
        .dns("hello.com")
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

pub fn parse_ca(config: &TlsConfig) -> Result<Option<(PKey<Private>, X509)>, anyhow::Error> {
    match config.tls_type {
        TlsType::None => {
            debug!("TLS is disabled");
            return Ok(None);
        }
        TlsType::TLS => {
            debug!("TLS");
            return Ok(None);
        }
        TlsType::MTLS => {
            info!("mTLS");
        }
        TlsType::BYOC => {
            info!("BYOC");
        }
    }
    let path = config
        .tls_path
        .as_ref()
        .ok_or(anyhow::anyhow!("TLS config path required"))?;

    let entries = std::fs::read_dir(path).context("Failed to list directory {path}")?;

    let mut ca_key = None;
    let mut ca_cert = None;

    for entry in entries {
        let entry = entry.context("Failed to visit directory entry")?;
        let file_type = entry.file_type().context("Failed to acquire file type")?;
        if !file_type.is_file() {
            continue;
        }

        if let Some(file_name) = entry.file_name().to_str() {
            if file_name == CA_KEY_NAME {
                let ca_key_path = entry.path();
                ca_key = Some(load_ca_pkey(&ca_key_path)?);
            }

            if file_name == CA_CERT_NAME {
                let ca_cert_path = entry.path();
                ca_cert = Some(load_ca_cert(&ca_cert_path)?);
            }
        }

        if ca_cert.is_some() && ca_key.is_some() {
            break;
        }
    }
    Ok(ca_key.zip(ca_cert))
}

#[cfg(test)]
mod tests {
    use crate::cert::{load_ca_cert, load_ca_pkey, mk_ca_signed_cert};
    use anyhow::Error;
    use log::info;
    use openssl::nid::Nid;
    use openssl::ssl::{NameType, SniError, SslConnector, SslMethod, SslVerifyMode};
    use std::net::TcpStream;
    use std::path::PathBuf;

    #[test]
    fn test_load_ca_pkey() -> Result<(), Error> {
        let mut ca_key_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_key_path_buf.push("assets");
        ca_key_path_buf.push("CA.key");
        let ca_key = load_ca_pkey(&ca_key_path_buf)?;
        assert_eq!(2048, ca_key.bits());
        Ok(())
    }

    #[test]
    fn test_load_ca_cert() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut ca_cert_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_cert_path_buf.push("assets");
        ca_cert_path_buf.push("CA.crt");
        let ca_cert = load_ca_cert(&ca_cert_path_buf)?;
        for entry in ca_cert.subject_name().entries() {
            info!("{:?}", entry);
        }
        Ok(())
    }

    #[test]
    fn test_mk_ca_signed_cert() -> Result<(), Error> {
        let mut ca_key_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_key_path_buf.push("assets");
        ca_key_path_buf.push("CA.key");
        let ca_key = load_ca_pkey(&ca_key_path_buf)?;

        let mut ca_cert_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_cert_path_buf.push("assets");
        ca_cert_path_buf.push("CA.crt");
        let ca_cert = load_ca_cert(&ca_cert_path_buf)?;

        let (cert, _key) = mk_ca_signed_cert(&ca_cert, &ca_key, "abc.com")?;

        for entry in cert.subject_name().entries() {
            let asn1_object = entry.object();
            if Nid::COMMONNAME == asn1_object.nid() {
                let value = entry.data().as_slice();
                assert_eq!("abc.com", String::from_utf8_lossy(value));
            }
        }

        Ok(())
    }

    #[test]
    fn test_tls_connect() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut ca_key_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_key_path_buf.push("assets");
        ca_key_path_buf.push("CA.key");
        let ca_key = load_ca_pkey(&ca_key_path_buf)?;

        let mut ca_cert_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_cert_path_buf.push("assets");
        ca_cert_path_buf.push("CA.crt");
        let ca_cert = load_ca_cert(&ca_cert_path_buf)?;

        let (cert, key) = mk_ca_signed_cert(&ca_cert, &ca_key, "abc.com")?;

        let tcp_stream = TcpStream::connect("www.baidu.com:443")?;
        let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls_client())?;
        ssl_connector_builder.set_certificate(&cert)?;
        ssl_connector_builder.set_private_key(&key)?;
        ssl_connector_builder.set_verify(SslVerifyMode::NONE);
        ssl_connector_builder.set_servername_callback(
            |ssl_ref, _ssl_alert| -> Result<(), SniError> {
                if let Some(hostname) = ssl_ref.servername(NameType::HOST_NAME) {
                    info!("Server Hostname: {}", hostname);
                }
                Ok(())
            },
        );
        let ssl_connector = ssl_connector_builder.build();
        let _ssl_stream = ssl_connector.connect("www.baidu.com", tcp_stream)?;
        info!("SSL connected");
        Ok(())
    }
}

#[cfg(test)]
mod async_tests {
    use crate::cert::{load_ca_cert, load_ca_pkey, mk_ca_signed_cert};
    use anyhow::Error;
    use log::info;
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
    use std::path::PathBuf;
    use std::pin::pin;
    use tokio::net::TcpStream;
    use tokio_openssl::SslStream;
    #[tokio::test]
    async fn test_tokio() -> Result<(), Error> {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut ca_key_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_key_path_buf.push("assets");
        ca_key_path_buf.push("CA.key");
        let ca_key = load_ca_pkey(&ca_key_path_buf)?;

        let mut ca_cert_path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ca_cert_path_buf.push("assets");
        ca_cert_path_buf.push("CA.crt");
        let ca_cert = load_ca_cert(&ca_cert_path_buf)?;

        let (cert, key) = mk_ca_signed_cert(&ca_cert, &ca_key, "abc.com")?;

        let mut ssl_context_builder = SslContext::builder(SslMethod::tls_client())?;
        ssl_context_builder.set_certificate(&cert)?;
        ssl_context_builder.set_private_key(&key)?;
        ssl_context_builder.set_verify(SslVerifyMode::NONE);
        let ssl_context = ssl_context_builder.build();
        let ssl = Ssl::new(&ssl_context)?;

        let tcp_stream = TcpStream::connect("www.baidu.com:443").await?;
        let ssl_stream = SslStream::new(ssl, tcp_stream)?;
        let ssl_stream = pin!(ssl_stream);
        ssl_stream.connect().await?;
        info!("Tokio SSL connected");
        Ok(())
    }
}
