use libmqttmtd;

/// Error on fetching a token set
#[derive(Debug)]
pub enum TokenSetFetchError {
    /// TLS connect() failed
    TlsConnectFailedError(libmqttmtd::socket::error::SocketError),

    /// Sending request/response failed
    SocketReadWriteError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Error response from issuer
    ErrorResponseFromIssuer,
}

impl std::error::Error for TokenSetFetchError {}

impl std::fmt::Display for TokenSetFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSetFetchError::TlsConnectFailedError(e) => {
                write!(f, "tls connect() failed: {}", e)
            }
            TokenSetFetchError::SocketReadWriteError(e) => {
                write!(f, "socket read/write failed: {}", e)
            }
            TokenSetFetchError::ErrorResponseFromIssuer => {
                write!(f, "error response from issuer")
            }
        }
    }
}

impl From<libmqttmtd::socket::error::SocketError> for TokenSetFetchError {
    fn from(error: libmqttmtd::socket::error::SocketError) -> Self {
        TokenSetFetchError::TlsConnectFailedError(error)
    }
}

impl From<libmqttmtd::auth_serv::error::AuthServerParserError> for TokenSetFetchError {
    fn from(error: libmqttmtd::auth_serv::error::AuthServerParserError) -> Self {
        TokenSetFetchError::SocketReadWriteError(error)
    }
}
