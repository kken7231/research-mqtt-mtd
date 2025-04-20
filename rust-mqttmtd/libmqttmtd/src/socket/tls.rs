use std::sync::Arc;

use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};

use tokio::{
    net::{TcpStream, ToSocketAddrs},
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

use super::{
    err::SocketError,
    plain::{PlainClient, PlainServer},
};

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

///////////////////////////////////////////////////////////
///
/// TLS-enabled TCP Socket Server
///
///////////////////////////////////////////////////////////
pub struct TlsServer<A: ToSocketAddrs + Send + 'static> {
    plain_server: PlainServer<A>,
    acceptor: Arc<TlsAcceptor>,
}

impl<A: ToSocketAddrs + Send + 'static> TlsServer<A> {
    pub fn new(
        addr: A,
        listen_timeout: impl Into<Option<Duration>>,
        config: Arc<ServerConfig>,
    ) -> Self {
        TlsServer {
            plain_server: PlainServer::new(addr, listen_timeout),
            acceptor: Arc::new(TlsAcceptor::from(config)),
        }
    }

    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(server::TlsStream<TcpStream>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let acceptor = self.acceptor.clone();
        let handler = Arc::new(handler);

        self.plain_server.spawn(move |socket| {
            server_println!("doing tls...");
            let acceptor = acceptor.clone();
            let handler = handler.clone();

            async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        server_println!("TLS accepted!");
                        handler(tls_stream).await
                    }
                    Err(e) => {
                        server_println!("TLS accept error: {}", e);
                    }
                }
            }
        })
    }
}

///////////////////////////////////////////////////////////
///
/// TLS-enabled TCP Socket Client
///
///////////////////////////////////////////////////////////
pub struct TlsClient<A: ToSocketAddrs + Send + 'static> {
    plain_client: PlainClient<A>,
    connector: TlsConnector,
}

impl<A: ToSocketAddrs + Send + 'static> TlsClient<A> {
    pub fn new(
        addr: A,
        connect_timeout: impl Into<Option<Duration>>,
        config: Arc<ClientConfig>,
    ) -> Self {
        TlsClient {
            plain_client: PlainClient::new(addr, connect_timeout),
            connector: TlsConnector::from(config),
        }
    }

    pub async fn connect(
        self,
        domain: &'static str,
    ) -> Result<client::TlsStream<TcpStream>, SocketError> {
        client_println!("connecting to tls server...");

        let connect_result = match self.plain_client.connect_timeout {
            Some(duration) if duration <= Duration::ZERO => {
                return Err(SocketError::InvalidTimeoutError(duration));
            }
            Some(duration) => timeout(duration, TcpStream::connect(self.plain_client.addr)).await,
            None => Ok(TcpStream::connect(self.plain_client.addr).await),
        };

        match connect_result {
            Ok(Ok(socket)) => {
                client_println!("Socket connected!");
                let domain = ServerName::try_from(domain)?;
                return Ok(self.connector.connect(domain, socket).await?);
            }
            Ok(Err(e)) => {
                client_println!("Connect error: {}", e);
                return Err(SocketError::IoError(e));
            }
            Err(_elapsed) => {
                client_println!(
                    "Connect timed out after {:?}",
                    self.plain_client.connect_timeout
                );
                return Err(SocketError::ElapsedError());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{File, create_dir_all},
        io::{self, Write},
        path::Path,
        sync::Once,
    };

    use rcgen::CertifiedKey;
    use tempfile::tempdir;
    use tokio::time::Duration;

    use crate::socket::tls_config::{load_client_config, load_server_config};

    use super::*;

    const DOMAIN_CA: &str = "localhost-ca";
    const DOMAIN_SERV: &str = "localhost";
    const DOMAIN_CLI: &str = "localhost-cli";

    static DEFAULT_PROVIDER_INSTALLED: Once = Once::new();
    fn install_provider() {
        DEFAULT_PROVIDER_INSTALLED.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("failed to install default provider");
        });
    }

    fn create_cert_key_file<'a, 'b, 'c>(
        file_dir: impl AsRef<Path>,
        domain: impl Into<String>,
        ca_info: impl Into<Option<(&'b rcgen::Certificate, &'c rcgen::KeyPair)>>,
    ) -> CertifiedKey {
        if !file_dir.as_ref().exists() {
            create_dir_all(&file_dir).expect("failed to create a parent directory");
        }

        // Paths
        let cert_path = file_dir.as_ref().join("cert.crt");
        let key_path = file_dir.as_ref().join("key.pem");

        // Generate cert
        let key_pair = rcgen::KeyPair::generate().expect("failed to generate a key pair");
        let ca_info = ca_info.into();
        let cert = if ca_info.is_some() {
            let ca_info = ca_info.unwrap();
            rcgen::CertificateParams::new(vec![domain.into()])
                .expect("failed to initialize certificate params")
                .signed_by(&key_pair, ca_info.0, ca_info.1)
                .expect("failed to generate a cert")
        } else {
            rcgen::CertificateParams::new(vec![domain.into()])
                .expect("failed to initialize certificate params")
                .self_signed(&key_pair)
                .expect("failed to generate a cert")
        };

        // Save files
        let mut cert_file = File::create(&cert_path).expect("failed to create a cert file");
        cert_file
            .write_all(cert.pem().as_bytes())
            .expect("failed to write a cert file");
        let mut key_file = File::create(&key_path).expect("failed to create a key file");
        key_file
            .write_all(key_pair.serialize_pem().as_bytes())
            .expect("failed to write a key file");

        CertifiedKey { cert, key_pair }
    }

    fn create_load_sample_configs(
        no_client_auth: bool,
        ca_domain: impl Into<String>,
        serv_domain: impl Into<String>,
        cli_domain: impl Into<String>,
    ) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        install_provider();

        let temp_dir = tempdir().expect("failed to create temp dir");
        let ca_dir = temp_dir.as_ref().join("ca");
        let server_dir = temp_dir.as_ref().join("server");
        let clients_dir = temp_dir.as_ref().join("clients");

        let CertifiedKey {
            cert: ca_cert,
            key_pair: ca_key,
        } = create_cert_key_file(&ca_dir, ca_domain, None);
        let CertifiedKey {
            cert: _serv_cert,
            key_pair: _serv_key,
        } = create_cert_key_file(&server_dir, serv_domain, (&ca_cert, &ca_key));
        let CertifiedKey {
            cert: _cli_cert,
            key_pair: _cli_key,
        } = create_cert_key_file(&clients_dir, cli_domain, None);

        let conf_serv = load_server_config(
            &server_dir.join("cert.crt"),
            &server_dir.join("key.pem"),
            &clients_dir,
            no_client_auth,
        );
        assert!(conf_serv.is_ok());

        let conf_cli = load_client_config(
            &clients_dir.join("cert.crt"),
            &clients_dir.join("key.pem"),
            &ca_dir,
            no_client_auth,
        );
        assert!(conf_cli.is_ok());

        (conf_serv.unwrap(), conf_cli.unwrap())
    }

    #[tokio::test]
    async fn spawn_serv_cli_pass() {
        const ADDR: &str = "localhost:3000";
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(ADDR, TO_SERVER, conf_server).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = TlsClient::new(ADDR, TO_CLIENT, conf_client)
            .connect(DOMAIN_SERV)
            .await;

        // Wait a while enough to flush output from server
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn spawn_serv_zero_duration() {
        const ADDR: &str = "localhost:3001";
        const TO_SERVER: Duration = Duration::ZERO;
        let (conf_server, _) = create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        match timeout(
            Duration::from_secs(1),
            TlsServer::new(ADDR, TO_SERVER, conf_server).spawn(async |_| {}),
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
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(ADDR, TO_SERVER, conf_server).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        match timeout(
            Duration::from_secs(1),
            TlsClient::new(ADDR, TO_CLIENT, conf_client).connect(DOMAIN_SERV),
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
        let (_, conf_client) = create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Try connecting
        match timeout(
            Duration::from_secs(2),
            TlsClient::new(ADDR, TO_CLIENT, conf_client).connect(DOMAIN_SERV),
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
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(ADDR, TO_SERVER, conf_server).spawn(async |_| {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_millis(100)).await;

        // Spawn client and connect
        match TlsClient::new(ADDR, TO_CLIENT, conf_client)
            .connect(DOMAIN_SERV)
            .await
        {
            Err(e) => assert!(e.eq(&SocketError::IoError(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                ""
            )))),
            _ => assert!(false),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use std::thread::{self, sleep};

//     use super::*;

//     #[test]
//     fn listen_conn_pass() {
//         const ADDR: &str = "localhost:3000";
//         let _ = thread::spawn(|| listen(ADDR, Some(Duration::from_secs(1)), |_| {}));
//         sleep(Duration::from_millis(100));
//         let stream = connect(ADDR);
//         assert!(stream.is_ok());
//     }

//     #[test]
//     fn listen_conn_zero_duration() {
//         const ADDR: &str = "localhost:3001";

//         // Try listening
//         assert!(listen(ADDR, Some(Duration::from_secs(0)), |_| {}).is_err());
//     }

//     #[test]
//     fn listen_conn_none_duration() {
//         const ADDR: &str = "localhost:3002";
//         let _ = thread::spawn(|| listen(ADDR, None, |_| {}));
//         sleep(Duration::from_millis(100));

//         // Try connecting
//         assert!(connect(ADDR).is_ok());
//     }

//     #[test]
//     fn listen_conn_not_listening() {
//         const ADDR: &str = "localhost:3003";

//         // Try connecting
//         assert!(connect(ADDR).is_err());
//     }

//     #[test]
//     fn listen_conn_after_deadline() {
//         const ADDR: &str = "localhost:3004";

//         // Socket server
//         let _ = thread::spawn(|| listen(ADDR, Some(Duration::from_secs(1)), |_| {}));

//         // Wait for the listener to set up and get timed out
//         sleep(Duration::from_millis(1100));

//         // Try connecting
//         assert!(connect(ADDR).is_err());
//     }

//     #[test]
//     fn send_recv_pass() {
//         const ADDR: &str = "localhost:3005";
//         const MESSAGE: &str = "hello, socket!";

//         // Message sender (socket server)
//         let _ = thread::spawn(|| {
//             listen(ADDR, Some(Duration::from_secs(1)), |s| {
//                 assert!(write(s, MESSAGE.as_bytes(), Some(Duration::from_millis(500)),).is_ok());
//             })
//         });

//         // Wait for the listener to set up
//         sleep(Duration::from_millis(100));

//         // Message receiver (socket client)
//         let stream = connect(ADDR).unwrap(); // already checked above
//         let mut buf: [u8; 1024] = [0; 1024];
//         assert!(read(stream, &mut buf[..], Some(Duration::from_millis(500))).is_ok());

//         // Check message
//         assert_eq!(
//             std::str::from_utf8(&buf[..MESSAGE.as_bytes().len()]).unwrap(),
//             MESSAGE
//         );
//         assert_eq!(buf[MESSAGE.as_bytes().len()], 0);
//     }

//     #[test]
//     fn send_recv_send_timeout() {
//         const ADDR: &str = "localhost:3006";
//         const MESSAGE: &str = "hello, socket!";

//         // Message sender (socket server)
//         let _ = listen(ADDR, Some(Duration::from_secs(1)), |s| {
//             let res = write(s, MESSAGE.as_bytes(), Some(Duration::from_nanos(1)));
//             assert!(res.is_err());
//             let res = res.err().unwrap().kind();
//             assert!((res == io::ErrorKind::WouldBlock) || (res == io::ErrorKind::InvalidInput));
//         });
//     }

//     #[test]
//     fn send_recv_recv_timeout() {
//         const ADDR: &str = "localhost:3007";
//         const MESSAGE: &str = "hello, socket!";

//         // Message sender (socket server)
//         let _ = thread::spawn(|| {
//             listen(ADDR, Some(Duration::from_secs(1)), |s| {
//                 assert!(write(s, MESSAGE.as_bytes(), Some(Duration::from_millis(500)),).is_ok());
//             })
//         });

//         // Wait for the listener to set up
//         sleep(Duration::from_millis(100));

//         // Message receiver (socket client)
//         let stream = connect(ADDR).unwrap(); // already checked above
//         let mut buf: [u8; 1024] = [0; 1024];

//         let res = read(stream, &mut buf[..], Some(Duration::from_nanos(1)));
//         assert!(res.is_err());
//         let res = res.err().unwrap().kind();
//         assert!((res == io::ErrorKind::WouldBlock) || (res == io::ErrorKind::InvalidInput));
//     }
// }
