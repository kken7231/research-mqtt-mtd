/// Error for issuer/verifier request/response parsing
///
/// Wraps three errors:
/// - [std::io::Error]
/// - [std::str::Utf8Error]
/// - [crate::aead::algo::AeadAlgorithmNotSupportedError]
///
/// Indicates unique errors:
/// - buffer is too small
/// - topic is too long
#[derive(Debug)]
pub enum AuthServerParserError {
    /// Indicates a buffer byte array (slice) is shorter than expected.
    BufferTooSmallError(),

    /// Indicates topic is longer than expected.
    TopicTooLongError(),

    /// Wraps [std::io::Error]
    IoError(std::io::Error),

    /// Wraps [std::str::Utf8Error]
    Utf8Error(std::str::Utf8Error),

    /// Wraps [crate::aead::algo::AeadAlgorithmNotSupportedError]
    AeadAlgorithmNotSupportedError(crate::aead::algo::AeadAlgorithmNotSupportedError),
}

impl std::error::Error for AuthServerParserError {}

impl std::fmt::Display for AuthServerParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthServerParserError::BufferTooSmallError() => {
                write!(f, "index out of bounds")
            }
            AuthServerParserError::TopicTooLongError() => {
                write!(f, "token is too long")
            }
            AuthServerParserError::IoError(e) => {
                write!(f, "io error: {}", e)
            }
            AuthServerParserError::Utf8Error(e) => {
                write!(f, "utf8 error: {}", e)
            }
            AuthServerParserError::AeadAlgorithmNotSupportedError(e) => {
                write!(f, "aead algo not supported error: {}", e)
            }
        }
    }
}

impl PartialEq for AuthServerParserError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            AuthServerParserError::BufferTooSmallError() => match other {
                AuthServerParserError::BufferTooSmallError() => true,
                _ => false,
            },
            AuthServerParserError::TopicTooLongError() => match other {
                AuthServerParserError::TopicTooLongError() => true,
                _ => false,
            },
            AuthServerParserError::IoError(e) => match other {
                AuthServerParserError::IoError(other_e) => e.kind() == other_e.kind(),
                _ => false,
            },
            AuthServerParserError::Utf8Error(e) => match other {
                AuthServerParserError::Utf8Error(other_e) => e.eq(other_e),
                _ => false,
            },
            AuthServerParserError::AeadAlgorithmNotSupportedError(_) => match other {
                AuthServerParserError::AeadAlgorithmNotSupportedError(_) => true,
                _ => false,
            },
        }
    }
}

impl From<std::io::Error> for AuthServerParserError {
    fn from(value: std::io::Error) -> Self {
        AuthServerParserError::IoError(value)
    }
}

impl From<std::str::Utf8Error> for AuthServerParserError {
    fn from(value: std::str::Utf8Error) -> Self {
        AuthServerParserError::Utf8Error(value)
    }
}

impl From<crate::aead::algo::AeadAlgorithmNotSupportedError> for AuthServerParserError {
    fn from(value: crate::aead::algo::AeadAlgorithmNotSupportedError) -> Self {
        AuthServerParserError::AeadAlgorithmNotSupportedError(value)
    }
}
