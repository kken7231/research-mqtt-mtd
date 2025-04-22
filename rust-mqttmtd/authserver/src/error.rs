use std::io;

/// Error for issuer request/response parsing
///
/// Wraps two errors:
/// - [std::io::Error]
/// - [rustls::pki_types::InvalidDnsNameError]
///
/// Indicates unique errors:
/// - timed out
/// - invalid timeout
#[derive(Debug)]
pub enum IssuerParserError {
    /// Indicates a buffer byte array (slice) is shorter than expected.
    BufferTooSmallError(),

    /// Indicates parameter is bigger/longer than expected.
    ParameterTooBigError(),

    /// Indicates a byte array (slice) failed to be converted to utf8.
    UTF8ConversionError(),
}

impl std::error::Error for IssuerParserError {}

impl std::fmt::Display for IssuerParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerParserError::BufferTooSmallError() => {
                write!(f, "index out of bounds")
            }
            IssuerParserError::ParameterTooBigError() => {
                write!(f, "parameter is too big/long")
            }
            IssuerParserError::UTF8ConversionError() => {
                write!(f, "failed to convert bytes to utf8")
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
            IssuerParserError::ParameterTooBigError() => match other {
                IssuerParserError::ParameterTooBigError() => true,
                _ => false,
            },
            IssuerParserError::UTF8ConversionError() => match other {
                IssuerParserError::UTF8ConversionError() => true,
                _ => false,
            },
        }
    }
}
