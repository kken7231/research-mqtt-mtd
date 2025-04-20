use std::io;

use rustls::{pki_types::InvalidDnsNameError, server::VerifierBuilderError};
use tokio::time;

#[derive(Debug)]
pub enum SocketError {
    IoError(io::Error),
    ElapsedError(),
    InvalidTimeoutError(time::Duration),
    InvalidDnsNameError(InvalidDnsNameError),
}

impl std::error::Error for SocketError {}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::IoError(e) => write!(f, "io::Error found: {}", e),
            SocketError::ElapsedError() => {
                write!(f, "timed out")
            }
            SocketError::InvalidTimeoutError(d) => {
                write!(f, "invalid timeout of : {:?}", d)
            }
            SocketError::InvalidDnsNameError(e) => {
                write!(f, "invalid dns name: {}", e)
            }
        }
    }
}

impl PartialEq for SocketError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            SocketError::IoError(e) => match other {
                SocketError::IoError(other_e) => e.kind() == other_e.kind(),
                _ => false,
            },
            SocketError::ElapsedError() => match other {
                SocketError::ElapsedError() => true,
                _ => false,
            },
            SocketError::InvalidTimeoutError(d) => match other {
                SocketError::InvalidTimeoutError(other_d) => d.eq(other_d),
                _ => false,
            },
            SocketError::InvalidDnsNameError(e) => match other {
                SocketError::InvalidDnsNameError(other_e) => e.to_string() == other_e.to_string(),
                _ => false,
            },
        }
    }
}

impl From<io::Error> for SocketError {
    fn from(error: io::Error) -> Self {
        SocketError::IoError(error)
    }
}

impl From<InvalidDnsNameError> for SocketError {
    fn from(error: InvalidDnsNameError) -> Self {
        SocketError::InvalidDnsNameError(error)
    }
}

#[derive(Debug)]
pub enum LoadTLSConfigError {
    IoError(io::Error),
    PemError(rustls::pki_types::pem::Error),
    RustlsError(rustls::Error),
    VerifierBuilderError(VerifierBuilderError),
}

impl std::error::Error for LoadTLSConfigError {}

impl std::fmt::Display for LoadTLSConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadTLSConfigError::IoError(e) => write!(f, "io::Error found: {}", e),
            LoadTLSConfigError::PemError(e) => {
                write!(f, "pem error: {}", e)
            }
            LoadTLSConfigError::RustlsError(e) => {
                write!(f, "rustls error: {}", e)
            }
            LoadTLSConfigError::VerifierBuilderError(e) => {
                write!(f, "VerifierBuilderError error: {}", e)
            }
        }
    }
}

impl PartialEq for LoadTLSConfigError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            LoadTLSConfigError::IoError(e) => match other {
                LoadTLSConfigError::IoError(other_e) => e.kind() == other_e.kind(),
                _ => false,
            },
            LoadTLSConfigError::PemError(e) => match other {
                LoadTLSConfigError::PemError(other_e) => e.to_string() == other_e.to_string(),
                _ => false,
            },
            LoadTLSConfigError::RustlsError(e) => match other {
                LoadTLSConfigError::RustlsError(other_e) => e.eq(other_e),
                _ => false,
            },
            LoadTLSConfigError::VerifierBuilderError(e) => match other {
                LoadTLSConfigError::VerifierBuilderError(other_e) => {
                    e.to_string() == other_e.to_string()
                }
                _ => false,
            },
        }
    }
}

impl From<io::Error> for LoadTLSConfigError {
    fn from(error: io::Error) -> Self {
        LoadTLSConfigError::IoError(error)
    }
}

impl From<rustls::pki_types::pem::Error> for LoadTLSConfigError {
    fn from(error: rustls::pki_types::pem::Error) -> Self {
        LoadTLSConfigError::PemError(error)
    }
}

impl From<rustls::Error> for LoadTLSConfigError {
    fn from(error: rustls::Error) -> Self {
        LoadTLSConfigError::RustlsError(error)
    }
}

impl From<VerifierBuilderError> for LoadTLSConfigError {
    fn from(error: VerifierBuilderError) -> Self {
        LoadTLSConfigError::VerifierBuilderError(error)
    }
}
