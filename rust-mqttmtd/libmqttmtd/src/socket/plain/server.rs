use crate::socket::error::SocketError;
use crate::socket::plain::stream::{PlainStream, PlainStreamAddress};
use crate::socket::plain::tcp::{TcpServer, TcpServerType};
#[cfg(unix)]
use crate::socket::plain::unix::UnixServer;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;

macro_rules! srv_println {
    ($type:ident, $($arg:tt)*) => {
        println!("[{}_server] {}", $type, format!($($arg)*));
    };
}

/// Enum that can hold either [TcpListener] or [UnixListener]
/// Implements accept()
pub enum PlainListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl PlainListener {
    async fn accept(&self) -> tokio::io::Result<(PlainStream, PlainStreamAddress)> {
        match self {
            PlainListener::Tcp(tcp_listener) => tcp_listener
                .accept()
                .await
                .map(|(stream, addr)| (PlainStream::Tcp(stream), PlainStreamAddress::Tcp(addr))),
            #[cfg(unix)]
            PlainListener::Unix(unix_listener) => {
                unix_listener.accept().await.map(|(stream, addr)| {
                    (
                        PlainStream::Unix(stream),
                        PlainStreamAddress::Unix(addr.into()),
                    )
                })
            }
        }
    }
}

/// Enum that can hold either [TcpServer] or [UnixServer]
/// Implements spawn()
pub enum PlainServer {
    Tcp(TcpServer),
    #[cfg(unix)]
    Unix(UnixServer),
}

impl PlainServer {
    /// Creates a new TCP socket server.
    pub fn new_tcp(
        port: u16,
        listen_timeout: impl Into<Option<Duration>>,
        server_type: TcpServerType,
    ) -> Result<Self, SocketError> {
        Ok(Self::Tcp(TcpServer::new(
            port,
            listen_timeout,
            server_type,
        )?))
    }

    /// Creates a new Unix domain socket server.
    #[cfg(unix)]
    pub fn new_unix(pathname: &str, listen_timeout: impl Into<Option<Duration>>) -> Self {
        Self::Unix(UnixServer::new(pathname, listen_timeout))
    }

    /// Spawns a server that can handle multiple connections.
    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(PlainStream, PlainStreamAddress) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // Get the type_name and listen_timeout
        let (type_name, listen_timeout) = match &self {
            PlainServer::Tcp(tcp_srv) => ("tcp", tcp_srv.listen_timeout),
            #[cfg(unix)]
            PlainServer::Unix(unix_srv) => ("unix", unix_srv.listen_timeout),
        };
        srv_println!(type_name, "Spawning socket server...");

        // Spawn the handler
        tokio::spawn(async move {
            let listener = match &self {
                PlainServer::Tcp(tcp_srv) => PlainListener::Tcp(
                    TcpListener::bind(tcp_srv.addr)
                        .await
                        .map_err(|e| SocketError::BindError(e))?,
                ),
                #[cfg(unix)]
                PlainServer::Unix(unix_srv) => PlainListener::Unix(
                    UnixListener::bind(unix_srv.addr.as_path())
                        .map_err(|e| SocketError::BindError(e))?,
                ),
            };

            let handler = Arc::new(handler);

            loop {
                let accept_result = match listen_timeout {
                    Some(duration) if duration <= Duration::ZERO => {
                        return Err(SocketError::InvalidTimeoutError(duration));
                    }
                    Some(duration) => timeout(duration, listener.accept()).await,
                    None => Ok(listener.accept().await),
                };

                match accept_result {
                    Ok(Ok((stream, addr))) => {
                        srv_println!(type_name, "Accepted connection from {}", addr.to_string());
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move { handler(stream, addr.into()).await });
                    }
                    Ok(Err(e)) => {
                        srv_println!(type_name, "Accept error: {}", e);
                    }
                    Err(_elapsed) => {
                        srv_println!(type_name, "Accept timeout expired, closing...");
                        return Ok(());
                    }
                };
            }
        })
    }
}
