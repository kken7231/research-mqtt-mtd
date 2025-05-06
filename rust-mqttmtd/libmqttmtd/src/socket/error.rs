//! Defines errors in the module.

use std::io;

use rustls::{pki_types::InvalidDnsNameError, server::VerifierBuilderError};

/// Error for socket server & clients
///
/// Wraps two errors:
/// - [std::io::Error]
/// - [rustls::pki_types::InvalidDnsNameError]
///
/// Indicates unique errors:
/// - timed out
/// - invalid timeout
#[derive(Debug)]
pub enum SocketError {
    /// Wraps [std::io::Error] error on server bind
    BindError(std::io::Error),

    /// Wraps [std::io::Error] error on client connect
    ConnectError(std::io::Error),

    /// Indicates a process was timed out.
    ElapsedError(),

    /// Indicates a given timeout duration was invalid (e.g. negative).
    InvalidTimeoutError(std::time::Duration),

    /// Wraps [rustls::pki_types::InvalidDnsNameError].
    InvalidDnsNameError(InvalidDnsNameError),
}

impl std::error::Error for SocketError {}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::BindError(e) => write!(f, "socket failed on server bind: {}", e),
            SocketError::ConnectError(e) => {
                write!(f, "socket failed on client connect: {}", e)
            }
            SocketError::ElapsedError() => {
                write!(f, "operation timed out")
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

impl From<InvalidDnsNameError> for SocketError {
    fn from(error: InvalidDnsNameError) -> Self {
        SocketError::InvalidDnsNameError(error)
    }
}

/// Error for TLS config generation
///
/// Wraps four errors:
/// - [std::io::Error]
/// - [rustls::pki_types::pem::Error]
/// - [rustls::Error]
/// - [rustls::server::VerifierBuilderError]
#[derive(Debug)]
pub enum LoadTLSConfigError {
    /// Wraps [std::io::Error].
    IoError(io::Error),

    /// Wraps [rustls::pki_types::pem::Error].
    PemError(rustls::pki_types::pem::Error),

    /// Wraps [rustls::Error].
    RustlsError(rustls::Error),

    /// Wraps [rustls::server::VerifierBuilderError].
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
