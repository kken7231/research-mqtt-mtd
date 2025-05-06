/// Error for ATL process.
///
/// Wraps an error:
/// - [std::time::SystemTimeError]: in random generation
/// - [ring::error::Unspecified]: in time difference calculation
///
/// Indicates unique situations:
/// - Two inner maps are not consistent
/// - Token index out of bound
/// - Too long valid duration
#[derive(Debug)]
pub enum ATLError {
    /// Wraps [ring::error::Unspecified] error in generating random bytes
    RandGenError(ring::error::Unspecified),

    /// Wraps [std::time::SystemTimeError] error in calculating time difference
    NegativeTimeDifferenceError(std::time::SystemTimeError),

    /// Indicates two maps in an ATL are not consistent
    TwoMapsNotConsistentError(),

    /// Indicates token index is out of bound
    TokenIdxOutOfBoundError(u16),

    /// Indicates too long valid duration
    ValidDurationTooLongError(std::time::Duration),
}

impl std::error::Error for ATLError {}

impl std::fmt::Display for ATLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ATLError::RandGenError(e) => {
                write!(f, "generating random bytes ended up a failure: {}", e)
            }
            ATLError::NegativeTimeDifferenceError(e) => {
                write!(f, "negative time difference observed: {}", e)
            }
            ATLError::TwoMapsNotConsistentError() => {
                write!(f, "entry is not in either of sorted_map or lookup_map")
            }
            ATLError::TokenIdxOutOfBoundError(i) => {
                write!(f, "token index is out of bound: {}", i)
            }
            ATLError::ValidDurationTooLongError(d) => {
                write!(f, "valid duration is too long: {} secs", d.as_secs())
            }
        }
    }
}

/// Error for ACL process.
///
/// Wraps two errors:
/// - [std::io::Error]
/// - [serde_yaml::Error]
#[derive(Debug)]
pub enum ACLError {
    /// Wraps [std::io::Error] error in opening a yaml file
    OpenYamlFailedError(std::io::Error),

    /// Wraps [serde_yaml::Error] error in parsing a yaml file
    ParseYamlFailedError(serde_yaml::Error),
}

impl std::error::Error for ACLError {}

impl std::fmt::Display for ACLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ACLError::OpenYamlFailedError(e) => {
                write!(f, "opening an acl yaml file failed: {}", e)
            }
            ACLError::ParseYamlFailedError(e) => {
                write!(f, "parsing an acl yaml file failed: {}", e)
            }
        }
    }
}
