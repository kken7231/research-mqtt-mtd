/// Error for issuer request/response parsing
///
/// Wraps two errors:
/// - [std::io::Error]
/// - [std::str::Utf8Error]
///
/// Indicates unique errors:
/// - buffer is too small
/// - topic is too long
#[derive(Debug)]
pub enum IssuerParserError {
    /// Indicates a buffer byte array (slice) is shorter than expected.
    BufferTooSmallError(),

    /// Indicates topic is longer than expected.
    TopicTooLongError(),

    /// Wraps [std::io::Error]
    IoError(std::io::Error),

    /// Wraps [std::str::Utf8Error]
    Utf8Error(std::str::Utf8Error),

    /// Wraps [libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError]
    AeadAlgorithmNotSupportedError(libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError),
}

impl std::error::Error for IssuerParserError {}

impl std::fmt::Display for IssuerParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerParserError::BufferTooSmallError() => {
                write!(f, "index out of bounds")
            }
            IssuerParserError::TopicTooLongError() => {
                write!(f, "token is too long")
            }
            IssuerParserError::IoError(e) => {
                write!(f, "io error: {}", e)
            }
            IssuerParserError::Utf8Error(e) => {
                write!(f, "utf8 error: {}", e)
            }
            IssuerParserError::AeadAlgorithmNotSupportedError(e) => {
                write!(f, "aead algo not supported error: {}", e)
            }
        }
    }
}

impl PartialEq for IssuerParserError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            IssuerParserError::BufferTooSmallError() => match other {
                IssuerParserError::BufferTooSmallError() => true,
                _ => false,
            },
            IssuerParserError::TopicTooLongError() => match other {
                IssuerParserError::TopicTooLongError() => true,
                _ => false,
            },
            IssuerParserError::IoError(e) => match other {
                IssuerParserError::IoError(other_e) => e.kind() == other_e.kind(),
                _ => false,
            },
            IssuerParserError::Utf8Error(e) => match other {
                IssuerParserError::Utf8Error(other_e) => e.eq(other_e),
                _ => false,
            },
            IssuerParserError::AeadAlgorithmNotSupportedError(_) => match other {
                IssuerParserError::AeadAlgorithmNotSupportedError(_) => true,
                _ => false,
            },
        }
    }
}

impl From<std::io::Error> for IssuerParserError {
    fn from(value: std::io::Error) -> Self {
        IssuerParserError::IoError(value)
    }
}

impl From<std::str::Utf8Error> for IssuerParserError {
    fn from(value: std::str::Utf8Error) -> Self {
        IssuerParserError::Utf8Error(value)
    }
}

impl From<libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError> for IssuerParserError {
    fn from(value: libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError) -> Self {
        IssuerParserError::AeadAlgorithmNotSupportedError(value)
    }
}

/// Error for ATL process.
///
/// Wraps an error:
/// - [std::time::SystemTimeError]
/// - [tokio::sync::TryLockError]
/// - [std::num::TryFromIntError]
/// - [ring::error::Unspecified]
#[derive(Debug)]
pub enum ATLError {
    /// Indicates two maps in an ATL is not consistent
    TwoMapsNotConsistentError(),

    /// Indicates token index is out of bound
    TokenIdxOutOfBoundError(usize),

    /// Indicates too long valid duration
    ValidDurationTooLongError(std::time::Duration),

    /// Wraps [std::time::SystemTimeError]
    SystemTimeError(std::time::SystemTimeError),

    /// Wraps [tokio::sync::TryLockError]
    TryLockError(tokio::sync::TryLockError),

    /// Wraps [std::num::TryFromIntError]
    TryFromIntError(std::num::TryFromIntError),

    /// Wraps [ring::error::Unspecified]
    RingUnspecifiedError(ring::error::Unspecified),
}

impl std::error::Error for ATLError {}

impl std::fmt::Display for ATLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ATLError::TwoMapsNotConsistentError() => {
                write!(f, "entry is not in either of sorted_map or lookup_map")
            }
            ATLError::TokenIdxOutOfBoundError(i) => {
                write!(f, "token index is out of bound: {}", i)
            }
            ATLError::ValidDurationTooLongError(d) => {
                write!(f, "valid duration is too long: {} secs", d.as_secs())
            }
            ATLError::SystemTimeError(e) => {
                write!(f, "system time error: {}", e)
            }
            ATLError::TryLockError(e) => {
                write!(f, "try lock error: {}", e)
            }
            ATLError::TryFromIntError(e) => {
                write!(f, "try from int (conversion) error: {}", e)
            }
            ATLError::RingUnspecifiedError(e) => {
                write!(f, "unspecified error from ring: {}", e)
            }
        }
    }
}

impl PartialEq for ATLError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            ATLError::TwoMapsNotConsistentError() => match other {
                ATLError::TwoMapsNotConsistentError() => true,
                _ => false,
            },
            ATLError::TokenIdxOutOfBoundError(i) => match other {
                ATLError::TokenIdxOutOfBoundError(other_i) => i == other_i,
                _ => false,
            },
            ATLError::ValidDurationTooLongError(d) => match other {
                ATLError::ValidDurationTooLongError(other_d) => d == other_d,
                _ => false,
            },
            ATLError::SystemTimeError(_) => match other {
                ATLError::SystemTimeError(_) => true,
                _ => false,
            },
            ATLError::TryLockError(_) => match other {
                ATLError::TryLockError(_) => true,
                _ => false,
            },
            ATLError::TryFromIntError(e) => match other {
                ATLError::TryFromIntError(other_e) => e.eq(other_e),
                _ => false,
            },
            ATLError::RingUnspecifiedError(e) => match other {
                ATLError::RingUnspecifiedError(other_e) => e.eq(other_e),
                _ => false,
            },
        }
    }
}

impl From<std::time::SystemTimeError> for ATLError {
    fn from(value: std::time::SystemTimeError) -> Self {
        ATLError::SystemTimeError(value)
    }
}

impl From<tokio::sync::TryLockError> for ATLError {
    fn from(value: tokio::sync::TryLockError) -> Self {
        ATLError::TryLockError(value)
    }
}

impl From<std::num::TryFromIntError> for ATLError {
    fn from(value: std::num::TryFromIntError) -> Self {
        ATLError::TryFromIntError(value)
    }
}

impl From<ring::error::Unspecified> for ATLError {
    fn from(value: ring::error::Unspecified) -> Self {
        ATLError::RingUnspecifiedError(value)
    }
}
