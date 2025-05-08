use libmqttmtd;
use libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError;
use std::fmt::Formatter;

/// Errors regarding tokenset
#[derive(Debug)]
pub enum TokenSetError {
    RandomLenMismatchError(usize),
    NonceLenMismatchError(usize),
    EncKeyMismatchError(usize),
    PathNotHavingFilenameError,

    InvalidCurIdxInFilenameError(Option<u16>),
    InvalidNumTokensError(u8),
    UnsupportedAlgorithmError(AeadAlgorithmNotSupportedError),
    FileWriteError(std::io::Error),
    FileReadError(std::io::Error),
    FileCreateError(std::io::Error),
    FileOpenError(std::io::Error),
    FileRenameError(std::io::Error),
}

impl std::error::Error for TokenSetError {}

impl std::fmt::Display for TokenSetError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSetError::RandomLenMismatchError(n) => {
                write!(f, "Random length mismatch: length={} not expected", n)
            }
            TokenSetError::NonceLenMismatchError(n) => {
                write!(f, "Nonce length mismatch: length={} not expected", n)
            }
            TokenSetError::EncKeyMismatchError(n) => {
                write!(f, "EncKey mismatch: length={} not expected", n)
            }
            TokenSetError::PathNotHavingFilenameError => write!(f, "Path not having file name"),
            TokenSetError::InvalidCurIdxInFilenameError(Some(idx)) => {
                write!(f, "Invalid curidx ({}) in filename", idx)
            }
            TokenSetError::InvalidCurIdxInFilenameError(_) => {
                write!(f, "Invalid curidx in filename")
            }
            TokenSetError::InvalidNumTokensError(n) => write!(f, "Invalid number of tokens: {}", n),
            TokenSetError::UnsupportedAlgorithmError(e) => {
                write!(f, "Unsupported AEAD Algorithm: {}", e)
            }
            TokenSetError::FileWriteError(e) => write!(f, "File write failure: {}", e),
            TokenSetError::FileReadError(e) => write!(f, "File read failure: {}", e),
            TokenSetError::FileCreateError(e) => write!(f, "File create failure: {}", e),
            TokenSetError::FileOpenError(e) => write!(f, "File open failure: {}", e),
            TokenSetError::FileRenameError(e) => write!(f, "File rename failure: {}", e),
        }
    }
}

/// Errors on fetching tokens
#[derive(Debug)]
pub enum TokenFetchError {
    IssuerConnectError(libmqttmtd::socket::error::SocketError),
    SocketWriteError(libmqttmtd::auth_serv::error::AuthServerParserError),
    SocketReadError(libmqttmtd::auth_serv::error::AuthServerParserError),
    ErrorResponseFromIssuer,
}

impl std::error::Error for TokenFetchError {}
impl std::fmt::Display for TokenFetchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenFetchError::IssuerConnectError(e) => {
                write!(f, "Connect to the Issuer failed: {}", e)
            }
            TokenFetchError::SocketWriteError(e) => {
                write!(f, "Write to a socket connected with Issuer failed: {}", e)
            }
            TokenFetchError::SocketReadError(e) => {
                write!(f, "Read from a socket connected with Issuer failed: {}", e)
            }
            TokenFetchError::ErrorResponseFromIssuer => {
                write!(f, "Error response from Issuer")
            }
        }
    }
}
