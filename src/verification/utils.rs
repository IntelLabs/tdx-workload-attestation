use crate::error::{Error, Result};
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn get_x509_pubkey(cert: &X509) -> Result<PKey<Public>> {
    cert.public_key().map_err(|e| Error::Signing(e.to_string()))
}

pub fn x509_from_der_bytes(der_bytes: &[u8]) -> Result<X509> {
    X509::from_der(&der_bytes).map_err(|e| Error::Signing(e.to_string()))
}

pub fn load_x509_der(path: &Path) -> Result<X509> {
    // throw an error if the cert is a symlink
    if path.exists() && path.is_symlink() {
        return Err(Error::NotSupported(format!(
            "Path {} is a symlink",
            path.display()
        )));
    }

    let mut cert_file = File::open(path)?;
    let mut cert_bytes = Vec::new();
    cert_file.read_to_end(&mut cert_bytes)?;

    x509_from_der_bytes(&cert_bytes)
}
