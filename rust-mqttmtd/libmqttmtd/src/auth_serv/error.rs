/// Error for issuer/verifier request/response parsing
///
/// Wraps three errors:
/// - [std::io::Error]: Read/write failed
/// - [std::str::Utf8Error]: UTF8 conversion failed
/// - [crate::aead::algo::AeadAlgorithmNotSupportedError]: AEAD algorithm is not
///   supported
///
/// Indicates unique errors:
/// - buffer is too small
/// - topic is too long
#[derive(Debug)]
pub enum AuthServerParserError {
    /// Indicates header in the packet is invalid.
    InvalidHeaderError(u32),

    /// Indicates a buffer byte array (slice) is shorter than expected.
    BufferTooSmallError,

    /// Indicates topic is longer than expected.
    TopicTooLongError,

    /// Wraps [std::io::Error] error in reading a socket
    SocketReadError(std::io::Error),

    /// Wraps [std::io::Error] error in writing to a socket
    SocketWriteError(std::io::Error),

    /// Wraps [std::string::FromUtf8Error]
    Utf8Error(std::string::FromUtf8Error),

    /// Wraps [crate::aead::algo::AeadAlgorithmNotSupportedError]
    AlgoNotSupportedError(crate::aead::algo::AeadAlgorithmNotSupportedError),

    /// Wraps [IssuerRequestValidationError] on issuer request creation
    InvalidIssuerRequestError(IssuerRequestValidationError),
}

impl std::error::Error for AuthServerParserError {}

impl std::fmt::Display for AuthServerParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthServerParserError::InvalidHeaderError(u) => {
                write!(f, "magic number invalid: {:x}", u)
            }
            AuthServerParserError::BufferTooSmallError => {
                write!(f, "buffer too small, index out of bounds")
            }
            AuthServerParserError::TopicTooLongError => {
                write!(f, "token is too long")
            }
            AuthServerParserError::SocketReadError(e) => {
                write!(f, "reading a socket failed: {}", e)
            }
            AuthServerParserError::SocketWriteError(e) => {
                write!(f, "writing to a socket failed: {}", e)
            }
            AuthServerParserError::Utf8Error(e) => {
                write!(f, "utf8 conversion error: {}", e)
            }
            AuthServerParserError::AlgoNotSupportedError(e) => {
                write!(f, "AEAD algo not supported error: {}", e)
            }
            AuthServerParserError::InvalidIssuerRequestError(e) => {
                write!(f, "invalid issuer request detected: {}", e)
            }
        }
    }
}
impl From<std::string::FromUtf8Error> for AuthServerParserError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        AuthServerParserError::Utf8Error(value)
    }
}

impl From<crate::aead::algo::AeadAlgorithmNotSupportedError> for AuthServerParserError {
    fn from(value: crate::aead::algo::AeadAlgorithmNotSupportedError) -> Self {
        AuthServerParserError::AlgoNotSupportedError(value)
    }
}

impl From<IssuerRequestValidationError> for AuthServerParserError {
    fn from(value: IssuerRequestValidationError) -> Self {
        AuthServerParserError::InvalidIssuerRequestError(value)
    }
}

/// Errors on validation of issuer's request.
#[derive(Debug)]
pub enum IssuerRequestValidationError {
    NumTokensDiv4OutOfRangeError(u8),
    EmptyTopicError,
}

impl std::error::Error for IssuerRequestValidationError {}

impl std::fmt::Display for IssuerRequestValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerRequestValidationError::NumTokensDiv4OutOfRangeError(num) => {
                write!(f, "number of tokens out of range: {}", num)
            }
            IssuerRequestValidationError::EmptyTopicError => {
                write!(f, "empty topic")
            }
        }
    }
}
