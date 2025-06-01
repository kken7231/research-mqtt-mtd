//! Defines TCP plain socket operations.

use crate::socket::error::SocketError;
use std::{
    net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs},
    time::Duration,
};
use tokio::{net::ToSocketAddrs, time::timeout};

pub enum TcpServerType {
    LOCAL,
    GLOBAL,
}

/// Plain TCP socket server
///
/// Plain socket connection from clients can be accepted through an instance.
pub struct TcpServer {
    pub(super) addr: SocketAddr,
    pub(super) listen_timeout: Option<Duration>,
}

impl TcpServer {
    /// Creates a new instance that will try connecting to an address with
    /// `addr` and `server_type` until `connect_timeout` comes.
    pub(super) fn new(
        port: u16,
        listen_timeout: impl Into<Option<Duration>>,
        server_type: TcpServerType,
    ) -> Result<Self, SocketError> {
        let addr_str = match server_type {
            TcpServerType::LOCAL => format!("localhost:{}", port),
            TcpServerType::GLOBAL => format!("0.0.0.0:{}", port),
        };
        let mut socket_addrs = addr_str
            .to_socket_addrs()
            .map_err(|_| SocketError::InvalidAddressError(addr_str.to_owned()))?;
        let actual_addr = socket_addrs
            .next()
            .ok_or_else(|| SocketError::InvalidAddressError(addr_str.to_owned()))?;
        Ok(Self {
            addr: actual_addr,
            listen_timeout: listen_timeout.into(),
        })
    }
}

/// Plain TCP socket client
///
/// Client can make a connection to an already-listening plain TCP socket
/// server.
pub struct TcpClient {
    pub(super) addr: SocketAddr,
    pub(super) connect_timeout: Option<Duration>,
}

impl TcpClient {
    /// Creates a new instance that will try to connect to `addr` until
    /// `connect_timeout` comes.
    pub(super) fn new(
        addr: &str,
        connect_timeout: impl Into<Option<Duration>>,
    ) -> Result<Self, SocketError> {
        let mut socket_addrs = addr
            .to_socket_addrs()
            .map_err(|_| SocketError::InvalidAddressError(addr.to_owned()))?;
        let actual_addr = socket_addrs
            .next()
            .ok_or_else(|| SocketError::InvalidAddressError(addr.to_owned()))?;
        Ok(Self {
            addr: actual_addr,
            connect_timeout: connect_timeout.into(),
        })
    }
}
