#[cfg(unix)]
use crate::socket::plain::unix::UnixClient;
use crate::socket::{
    error::SocketError,
    plain::{stream::PlainStream, tcp::TcpClient},
};
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{net::TcpStream, time::timeout};

macro_rules! cli_println {
    ($type:ident, $($arg:tt)*) => {
        println!("[{}_client] {}", $type, format!($($arg)*));
    };
}

/// Enum that can hold either [TcpClient] or [UnixClient]
/// Implements connect()
pub enum PlainClient {
    Tcp(TcpClient),

    #[cfg(unix)]
    Unix(UnixClient),
}

impl PlainClient {
    /// Creates a new TCP socket client.
    pub fn new_tcp(
        addr: &str,
        connect_timeout: impl Into<Option<Duration>>,
    ) -> Result<Self, SocketError> {
        Ok(Self::Tcp(TcpClient::new(addr, connect_timeout)?))
    }

    /// Creates a new Unix domain socket client
    #[cfg(unix)]
    pub fn new_unix(addr: &str, connect_timeout: impl Into<Option<Duration>>) -> Self {
        Self::Unix(UnixClient::new(addr, connect_timeout))
    }

    /// Gets `connect_timeout`.
    pub fn connect_timeout(&self) -> Option<Duration> {
        match self {
            PlainClient::Tcp(tcp_cli) => tcp_cli.connect_timeout,
            #[cfg(unix)]
            PlainClient::Unix(unix_cli) => unix_cli.connect_timeout,
        }
    }

    /// Connects to a server at `self.addr` with `self.timeout`
    pub async fn connect(self) -> Result<PlainStream, SocketError> {
        // Get the type_name and listen_timeout
        let (type_name, connect_timeout) = match &self {
            PlainClient::Tcp(tcp_cli) => ("tcp", tcp_cli.connect_timeout),
            #[cfg(unix)]
            PlainClient::Unix(unix_cli) => ("unix", unix_cli.connect_timeout),
        };
        cli_println!(type_name, "Connecting to server...");

        // Try to connect
        let connect_result = match connect_timeout {
            Some(duration) if duration <= Duration::ZERO => {
                return Err(SocketError::InvalidTimeoutError(duration));
            }
            Some(duration) => match self {
                PlainClient::Tcp(tcp_cli) => timeout(duration, TcpStream::connect(tcp_cli.addr))
                    .await
                    .map(|res| res.map(PlainStream::Tcp)),
                #[cfg(unix)]
                PlainClient::Unix(unix_cli) => {
                    timeout(duration, UnixStream::connect(unix_cli.addr))
                        .await
                        .map(|res| res.map(PlainStream::Unix))
                }
            },
            None => Ok(match self {
                PlainClient::Tcp(tcp_cli) => {
                    TcpStream::connect(tcp_cli.addr).await.map(PlainStream::Tcp)
                }
                #[cfg(unix)]
                PlainClient::Unix(unix_cli) => UnixStream::connect(unix_cli.addr)
                    .await
                    .map(PlainStream::Unix),
            }),
        };

        match connect_result {
            Ok(Ok(socket)) => {
                cli_println!(type_name, "Socket connected!");
                Ok(socket)
            }
            Ok(Err(e)) => {
                cli_println!(type_name, "Connect error: {}", e);
                Err(SocketError::ConnectError(e))
            }
            Err(_elapsed) => {
                cli_println!(type_name, "Connect timed out after {:?}", connect_timeout);
                Err(SocketError::ElapsedError)
            }
        }
    }
}
