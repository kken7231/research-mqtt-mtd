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
    TokenIdxOutOfBoundError(u16),

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

/// Error for ACL process.
///
/// Wraps two errors:
/// - [std::io::Error]
/// - [serde_yaml::Error]
#[derive(Debug)]
pub enum ACLError {
    /// Wraps [std::io::Error]
    IoError(std::io::Error),

    /// Wraps [serde_yaml::Error]
    SerdeYamlError(serde_yaml::Error),
}

impl std::error::Error for ACLError {}

impl std::fmt::Display for ACLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ACLError::IoError(e) => {
                write!(f, "io error: {}", e)
            }
            ACLError::SerdeYamlError(e) => {
                write!(f, "serde yaml error: {}", e)
            }
        }
    }
}

impl PartialEq for ACLError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            ACLError::IoError(e) => match other {
                ACLError::IoError(other_e) => e.kind() == other_e.kind(),
                _ => false,
            },
            ACLError::SerdeYamlError(e) => match other {
                ACLError::SerdeYamlError(other_e) => e.to_string() == other_e.to_string(),
                _ => false,
            },
        }
    }
}

impl From<std::io::Error> for ACLError {
    fn from(value: std::io::Error) -> Self {
        ACLError::IoError(value)
    }
}

impl From<serde_yaml::Error> for ACLError {
    fn from(value: serde_yaml::Error) -> Self {
        ACLError::SerdeYamlError(value)
    }
}
