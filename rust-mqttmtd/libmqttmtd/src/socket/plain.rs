use std::sync::Arc;

use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    task::JoinHandle,
    time::{Duration, timeout},
};

use super::err::SocketError;

macro_rules! server_println {
    ($($arg:tt)*) => {
        println!("server| {}", format!($($arg)*));
    };
}

macro_rules! client_println {
    ($($arg:tt)*) => {
        println!("client| {}", format!($($arg)*));
    };
}

// pub async fn read_with_timeout(
//     mut socket: TcpStream,
//     mut buf: &mut [u8],
//     read_timeout: impl Into<Option<Duration>>,
// ) -> Result<usize, SocketError> {
//     let read_timeout = read_timeout.into();
//     let read_result = match read_timeout {
//         Some(duration) if duration <= Duration::ZERO => {
//             return Err(SocketError::InvalidTimeoutError(duration));
//         }
//         Some(duration) => timeout(duration, socket.read(&mut buf)).await,
//         None => Ok(socket.read(&mut buf).await),
//     };

//     match read_result {
//         Ok(Ok(n)) if n == 0 => {
//             eprintln!("Connection closed by client");
//             Ok(n)
//         }
//         Ok(Ok(n)) => {
//             // println!("Received: {} bytes", n);
//             Ok(n)
//         }
//         Ok(Err(e)) => {
//             eprintln!("Read error: {}", e);
//             Err(SocketError::IoError(e))
//         }
//         Err(_elapsed) => {
//             eprintln!("Read timed out after {:?}", read_timeout);
//             Err(SocketError::ElapsedError())
//         }
//     }
// }

// pub async fn write_with_timeout(
//     mut socket: TcpStream,
//     buf: &[u8],
//     write_timeout: impl Into<Option<Duration>>,
// ) -> Result<usize, SocketError> {
//     let write_timeout = write_timeout.into();
//     let read_result = match write_timeout {
//         Some(duration) if duration <= Duration::ZERO => {
//             return Err(SocketError::InvalidTimeoutError(duration));
//         }
//         Some(duration) => timeout(duration, socket.write(buf)).await,
//         None => Ok(socket.write(buf).await),
//     };

//     match read_result {
//         Ok(Ok(n)) => {
//             // println!("Wrote: {} bytes", n);
//             Ok(n)
//         }
//         Ok(Err(e)) => {
//             println!("Write error: {}", e);
//             Err(SocketError::IoError(e))
//         }
//         Err(_e) => {
//             println!("Write timed out after {:?}", write_timeout);
//             Err(SocketError::ElapsedError())
//         }
//     }
// }

///////////////////////////////////////////////////////////
///
/// Plain TCP Socket Server
///
///////////////////////////////////////////////////////////
pub struct PlainServer<A: ToSocketAddrs + Send + 'static> {
    addr: A,
    listen_timeout: Option<Duration>,
}

impl<A: ToSocketAddrs + Send + 'static> PlainServer<A> {
    pub fn new(addr: A, listen_timeout: impl Into<Option<Duration>>) -> Self {
        PlainServer {
            addr,
            listen_timeout: listen_timeout.into(),
        }
    }

    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        server_println!("spawning socket server...");
        tokio::spawn(async move {
            let listener = TcpListener::bind(self.addr).await?;
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
                        server_println!("Accepted connection from {}", addr);
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move { handler(stream).await });
                    }
                    Ok(Err(e)) => {
                        server_println!("Accept error: {}", e);
                    }
                    Err(_elapsed) => {
                        server_println!("Accept timeout expired, closing...");
                        return Ok(());
                    }
                };
            }
        })
    }
}

///////////////////////////////////////////////////////////
///
/// Plain TCP Socket Client
///
///////////////////////////////////////////////////////////
pub struct PlainClient<A: ToSocketAddrs> {
    pub(super) addr: A,
    pub(super) connect_timeout: Option<Duration>,
}

impl<A: ToSocketAddrs> PlainClient<A> {
    pub fn new(addr: A, connect_timeout: impl Into<Option<Duration>>) -> Self {
        PlainClient {
            addr,
            connect_timeout: connect_timeout.into(),
        }
    }

    pub async fn connect(self) -> Result<TcpStream, SocketError> {
        client_println!("connecting to server...");

        let connect_result = match self.connect_timeout {
            Some(duration) if duration <= Duration::ZERO => {
                return Err(SocketError::InvalidTimeoutError(duration));
            }
            Some(duration) => timeout(duration, TcpStream::connect(self.addr)).await,
            None => Ok(TcpStream::connect(self.addr).await),
        };

        match connect_result {
            Ok(Ok(socket)) => {
                client_println!("Socket connected!");
                Ok(socket)
            }
            Ok(Err(e)) => {
                client_println!("Connect error: {}", e);
                return Err(SocketError::IoError(e));
            }
            Err(_elapsed) => {
                client_println!("Connect timed out after {:?}", self.connect_timeout);
                return Err(SocketError::ElapsedError());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::time::Duration;

    use super::*;

    #[tokio::test]
    async fn spawn_serv_cli_pass() {
        const ADDR: &str = "localhost:3000";
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Spawn server
        let _ = PlainServer::new(ADDR, TO_SERVER).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = PlainClient::new(ADDR, TO_CLIENT).connect().await;
        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn spawn_serv_zero_duration() {
        const ADDR: &str = "localhost:3001";
        const TO_SERVER: Duration = Duration::ZERO;

        match timeout(
            Duration::from_secs(1),
            PlainServer::new(ADDR, TO_SERVER).spawn(async |_| {}),
        )
        .await
        {
            Ok(Ok(Err(e))) => assert!(e.eq(&SocketError::InvalidTimeoutError(TO_SERVER))),
            _ => assert!(false),
        };
    }

    #[tokio::test]
    async fn spawn_cli_none_duration() {
        const ADDR: &str = "localhost:3002";
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;

        // Spawn server
        let _ = PlainServer::new(ADDR, TO_SERVER).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        match timeout(
            Duration::from_secs(1),
            PlainClient::new(ADDR, TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Ok(_)) => assert!(true),
            _ => assert!(false),
        };
    }

    #[tokio::test]
    async fn listen_conn_not_listening() {
        const ADDR: &str = "localhost:3003";
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Try connecting
        match timeout(
            Duration::from_secs(2),
            PlainClient::new(ADDR, TO_CLIENT).connect(),
        )
        .await
        {
            Ok(Err(e)) => assert!(e.eq(&SocketError::IoError(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                ""
            )))),
            _ => assert!(false),
        };
    }

    #[tokio::test]
    async fn listen_conn_after_deadline() {
        const ADDR: &str = "localhost:3004";
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);

        // Spawn server
        let _ = PlainServer::new(ADDR, TO_SERVER).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_millis(100)).await;

        // Spawn client and connect
        match PlainClient::new(ADDR, TO_CLIENT).connect().await {
            Err(e) => assert!(e.eq(&SocketError::IoError(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                ""
            )))),
            _ => assert!(false),
        }
    }
}
