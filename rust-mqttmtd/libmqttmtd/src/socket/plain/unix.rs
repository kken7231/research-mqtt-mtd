//! Defines plain Unix socket operations.

use std::{path::PathBuf, time::Duration};

/// Plain Unix socket server
///
/// Plain socket connection from clients can be accepted through an instance
pub struct UnixServer {
    pub(super) addr: PathBuf,
    pub(super) listen_timeout: Option<Duration>,
}
impl UnixServer {
    /// Creates a new instance that will try connecting to an address with
    /// `addr` until `connect_timeout` comes.
    pub fn new(pathname: &str, listen_timeout: impl Into<Option<Duration>>) -> Self {
        Self {
            addr: PathBuf::from(pathname),
            listen_timeout: listen_timeout.into(),
        }
    }
}

/// Plain Unix socket client
///
/// Client can make a connection to an already-listening plain Unix socket
/// server.
pub struct UnixClient {
    pub(super) addr: PathBuf,
    pub(super) connect_timeout: Option<Duration>,
}

impl UnixClient {
    pub fn new(pathname: &str, connect_timeout: impl Into<Option<Duration>>) -> Self {
        UnixClient {
            addr: PathBuf::from(pathname),
            connect_timeout: connect_timeout.into(),
        }
    }
}
