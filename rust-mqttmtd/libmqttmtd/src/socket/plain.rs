//! Defines plain socket operations.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use super::error::SocketError;
use crate::{sock_cli_println, sock_serv_println};
use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    task::JoinHandle,
    time::timeout,
};

/// Plain TCP socket server
///
/// Plain socket connection from clients can be accepted through an instance.
pub struct PlainServer {
    port: u16,
    listen_timeout: Option<Duration>,
}

impl PlainServer {
    /// Creates a new instance that will bind at localhost:`port` until `listen_timeout` comes.
    pub fn new(port: u16, listen_timeout: impl Into<Option<Duration>>) -> Self {
        PlainServer {
            port,
            listen_timeout: listen_timeout.into(),
        }
    }

    /// Spawns a [tokio::task::JoinHandle] task that will serve as a socket server.
    /// Runs `handler` for each client.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use crate::libmqttmtd::socket::error::SocketError;
    /// use crate::libmqttmtd::socket::plain::PlainServer;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), SocketError> {
    ///     let server_task = PlainServer::new(3000, Duration::from_secs(1)).spawn(|_, _| async {}).await;
    ///
    ///     match server_task {
    ///         Ok(_) => println!("new server task: {:?}", server_task),
    ///         Err(e) => println!("couldn't get client: {:?}", e),
    ///     }
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        sock_serv_println!("spawning socket server...");
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port))
                .await
                .map_err(|e| SocketError::BindError(e))?;
            let handler = Arc::new(handler);

            loop {
                let accept_result = match self.listen_timeout {
                    Some(duration) if duration <= Duration::ZERO => {
                        return Err(SocketError::InvalidTimeoutError(duration));
                    }
                    Some(duration) => timeout(duration, listener.accept()).await,
                    None => Ok(listener.accept().await),
                };

                match accept_result {
                    Ok(Ok((stream, addr))) => {
                        sock_serv_println!("Accepted connection from {}", addr);
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move { handler(stream, addr).await });
                    }
                    Ok(Err(e)) => {
                        sock_serv_println!("Accept error: {}", e);
                    }
                    Err(_elapsed) => {
                        sock_serv_println!("Accept timeout expired, closing...");
                        return Ok(());
                    }
                };
            }
        })
    }
}

/// Plain TCP socket client
///
/// Client can make a connection to an already-listening plain TCP socket server.
pub struct PlainClient<A: ToSocketAddrs> {
    pub(super) addr: A,
    pub(super) connect_timeout: Option<Duration>,
}

impl<A: ToSocketAddrs> PlainClient<A> {
    /// Creates a new instance that will try connecting to an address `addr` until `connect_timeout` comes.
    pub fn new(addr: A, connect_timeout: impl Into<Option<Duration>>) -> Self {
        PlainClient {
            addr,
            connect_timeout: connect_timeout.into(),
        }
    }

    /// Tries to connect to an address specified on instance creation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tokio::net::TcpStream;
    /// use tokio::io::AsyncWriteExt;
    /// use std::error::Error;
    /// use crate::libmqttmtd::socket::plain::PlainClient;
    /// use std::time::Duration;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn Error>> {
    ///     // Connect to a peer
    ///     let mut cli_sock = PlainClient::new("localhost:3000", Duration::from_secs(1)).connect().await?;
    ///
    ///     // Write some data.
    ///     cli_sock.write_all(b"hello world!").await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn connect(self) -> Result<TcpStream, SocketError> {
        sock_cli_println!("connecting to server...");

        let connect_result = match self.connect_timeout {
            Some(duration) if duration <= Duration::ZERO => {
                return Err(SocketError::InvalidTimeoutError(duration));
            }
            Some(duration) => timeout(duration, TcpStream::connect(self.addr)).await,
            None => Ok(TcpStream::connect(self.addr).await),
        };

        match connect_result {
            Ok(Ok(socket)) => {
                sock_cli_println!("Socket connected!");
                Ok(socket)
            }
            Ok(Err(e)) => {
                sock_cli_println!("Connect error: {}", e);
                Err(SocketError::ConnectError(e))
            }
            Err(_elapsed) => {
                sock_cli_println!("Connect timed out after {:?}", self.connect_timeout);
                Err(SocketError::ElapsedError())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn spawn_serv_cli_pass() {
        const PORT: u16 = 3000;
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Spawn server
        let _ = PlainServer::new(PORT, TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = PlainClient::new(format!("localhost:{}", PORT), TO_CLIENT)
            .connect()
            .await;
        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn spawn_serv_zero_duration() {
        const PORT: u16 = 3001;
        const TO_SERVER: Duration = Duration::ZERO;

        assert!(match timeout(
            Duration::from_secs(1),
            PlainServer::new(PORT, TO_SERVER).spawn(|_, _| async {}),
        )
        .await
        {
            Ok(Ok(Err(SocketError::InvalidTimeoutError(e)))) => e == TO_SERVER,
            _ => false,
        });
    }

    #[tokio::test]
    async fn spawn_cli_none_duration() {
        const PORT: u16 = 3002;
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;

        // Spawn server
        let _ = PlainServer::new(PORT, TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        assert!(match timeout(
            Duration::from_secs(1),
            PlainClient::new(format!("localhost:{}", PORT), TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Ok(_)) => true,
            _ => false,
        });
    }

    #[tokio::test]
    async fn listen_conn_not_listening() {
        const PORT: u16 = 3003;
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Try connecting
        assert!(match timeout(
            Duration::from_secs(2),
            PlainClient::new(format!("localhost:{}", PORT), TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Err(SocketError::ConnectError(e))) => e.kind() == ErrorKind::ConnectionRefused,
            _ => false,
        });
    }

    #[tokio::test]
    async fn listen_conn_after_deadline() {
        const PORT: u16 = 3004;
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Spawn server
        let _ = PlainServer::new(PORT, TO_SERVER).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_millis(100)).await;

        // Spawn client and connect
        assert!(
            match PlainClient::new(format!("localhost:{}", PORT), TO_CLIENT)
                .connect()
                .await
            {
                Err(SocketError::ConnectError(e)) => e.kind() == ErrorKind::ConnectionRefused,
                _ => false,
            }
        );
    }
}
