//! Defines TLS socket operations.

use std::{net::SocketAddr, sync::Arc};

use super::error::SocketError;
use crate::socket::plain::{
    client::PlainClient,
    server::PlainServer,
    stream::{PlainStream, PlainStreamAddress},
    tcp::TcpServerType,
};
use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};
use tokio::{net::TcpStream, task::JoinHandle, time::Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

macro_rules! srv_println {
    ($($arg:tt)*) => {
        println!("[tls_server] {}", format!($($arg)*));
    };
}

macro_rules! cli_println {
    ($($arg:tt)*) => {
        println!("[tls_client] {}", format!($($arg)*));
    };
}

/// TLS-enabled TCP Socket Server
pub struct TlsServer {
    plain_server: PlainServer,
    acceptor: Arc<TlsAcceptor>,
}

impl TlsServer {
    /// Creates a new [TlsServer] instance.
    pub fn new(
        port: u16,
        listen_timeout: impl Into<Option<Duration>>,
        server_type: TcpServerType,
        config: Arc<ServerConfig>,
    ) -> Result<Self, SocketError> {
        Ok(Self {
            plain_server: PlainServer::new_tcp(port, listen_timeout, server_type)?,
            acceptor: Arc::new(TlsAcceptor::from(config)),
        })
    }

    /// Spawns a server that can handle multiple connections.
    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(server::TlsStream<TcpStream>, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let acceptor = self.acceptor.clone();
        let handler = Arc::new(handler);

        self.plain_server.spawn(move |socket, addr| {
            let socket = match socket {
                PlainStream::Tcp(tcp) => Some(tcp),
                PlainStream::Unix(_) => None,
            };
            let addr = match addr {
                PlainStreamAddress::Tcp(tcp) => Some(tcp),
                PlainStreamAddress::Unix(_) => None,
            };
            srv_println!("doing tls...");
            let acceptor = acceptor.clone();
            let handler = handler.clone();

            async move {
                if socket.is_none() || addr.is_none() {
                    srv_println!("TLS on unix socket is not yet supported");
                    return;
                }
                let socket = socket.unwrap();
                let addr = addr.unwrap();
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        srv_println!("TLS accepted at addr {}", addr.to_string());
                        handler(tls_stream, addr).await
                    }
                    Err(e) => {
                        srv_println!("TLS accept error at addr {}: {}", addr, e);
                    }
                }
            }
        })
    }
}

///////////////////////////////////////////////////////////
///
/// TLS-enabled TCP Socket Client
///////////////////////////////////////////////////////////
pub struct TlsClient {
    plain_client: PlainClient,
    connector: TlsConnector,
}

impl TlsClient {
    /// Creates a new [TlsClient] instance.
    pub fn new(
        addr: &str,
        connect_timeout: impl Into<Option<Duration>>,
        config: Arc<ClientConfig>,
    ) -> Result<Self, SocketError> {
        Ok(Self {
            plain_client: PlainClient::new_tcp(addr, connect_timeout)?,
            connector: TlsConnector::from(config),
        })
    }

    pub async fn connect(
        self,
        domain: &'static str,
    ) -> Result<client::TlsStream<TcpStream>, SocketError> {
        cli_println!("connecting to tls server...");
        let domain = ServerName::try_from(domain)?;

        let socket = self.plain_client.connect().await?;

        let s = match socket {
            PlainStream::Tcp(tcp) => tcp,
            PlainStream::Unix(_) => {
                // This is unexpected
                return Err(SocketError::ConnectError(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TLS on unix socket is not yet supported",
                )));
            }
        };
        self.connector
            .connect(domain, s)
            .await
            .map_err(|e| SocketError::ConnectError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        localhost_v4,
        socket::{plain::tcp::TcpServerType::LOCAL, tls_config::TlsConfigLoader},
    };
    use rcgen::CertifiedKey;
    use std::{
        fs::{File, create_dir_all},
        io::{ErrorKind, Write},
        path::Path,
        sync::{LazyLock, Once},
        time::Duration,
    };
    use tempfile::tempdir;
    use tokio::{sync::RwLock, time::timeout};

    static UNUSED_PORT: LazyLock<RwLock<u16>> = LazyLock::new(|| RwLock::new(3100));

    async fn get_port() -> u16 {
        let mut port = UNUSED_PORT.write().await;
        let cur_port = *port;
        *port += 1;
        cur_port
    }

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
        enable_client_auth: bool,
        enable_key_log: bool,
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

        let conf_serv = TlsConfigLoader::load_server_config(
            &server_dir.join("cert.crt"),
            &server_dir.join("key.pem"),
            &ca_dir,
            enable_client_auth,
            enable_key_log,
        );
        assert!(conf_serv.is_ok());

        let conf_cli = TlsConfigLoader::load_client_config(
            &clients_dir.join("cert.crt"),
            &clients_dir.join("key.pem"),
            &ca_dir,
            enable_client_auth,
        );
        assert!(conf_cli.is_ok());

        (conf_serv.unwrap(), conf_cli.unwrap())
    }

    #[tokio::test]
    async fn spawn_serv_cli_pass() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);
        let (conf_server, conf_client) =
            create_load_sample_configs(true, false, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        let port = get_port().await;

        // Spawn server
        let _ = TlsServer::new(port, TO_SERVER, LOCAL, conf_server)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = TlsClient::new(localhost_v4!(port).as_str(), TO_CLIENT, conf_client)
            .unwrap()
            .connect(DOMAIN_SERV)
            .await;

        // Wait a while enough to flush output from server
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn spawn_serv_zero_duration() {
        const TO_SERVER: Duration = Duration::ZERO;

        let port = get_port().await;

        let (conf_server, _) =
            create_load_sample_configs(true, false, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        match timeout(
            Duration::from_secs(1),
            TlsServer::new(port, TO_SERVER, LOCAL, conf_server)
                .unwrap()
                .spawn(|_, _| async {}),
        )
        .await
        {
            Ok(Ok(Err(SocketError::InvalidTimeoutError(d)))) => assert_eq!(d, TO_SERVER),
            _ => panic!(),
        };
    }

    #[tokio::test]
    async fn spawn_cli_none_duration() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;

        let port = get_port().await;

        let (conf_server, conf_client) =
            create_load_sample_configs(true, false, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(port, TO_SERVER, LOCAL, conf_server)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        match timeout(
            Duration::from_secs(1),
            TlsClient::new(localhost_v4!(port).as_str(), TO_CLIENT, conf_client)
                .unwrap()
                .connect(DOMAIN_SERV),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => panic!(),
        };
    }

    #[tokio::test]
    async fn listen_conn_not_listening() {
        const TO_CLIENT: Duration = Duration::from_secs(1);

        let port = get_port().await;

        let (_, conf_client) =
            create_load_sample_configs(true, false, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Try connecting
        assert!(match timeout(
            Duration::from_secs(2),
            TlsClient::new(localhost_v4!(port).as_str(), TO_CLIENT, conf_client)
                .unwrap()
                .connect(DOMAIN_SERV),
        )
        .await
        {
            Ok(Err(SocketError::ConnectError(e))) => {
                e.kind() == ErrorKind::ConnectionRefused
            }
            _ => false,
        });
    }

    #[tokio::test]
    async fn listen_conn_after_deadline() {
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);
        let (conf_server, conf_client) =
            create_load_sample_configs(true, false, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        let port = get_port().await;

        // Spawn server
        let _ = TlsServer::new(port, TO_SERVER, LOCAL, conf_server)
            .unwrap()
            .spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_secs(1)).await;

        // Spawn client and connect
        assert!(
            match TlsClient::new(localhost_v4!(port).as_str(), TO_CLIENT, conf_client)
                .unwrap()
                .connect(DOMAIN_SERV)
                .await
            {
                Err(SocketError::ConnectError(e)) => e.kind() == ErrorKind::ConnectionRefused,
                _ => false,
            }
        );
    }
}
