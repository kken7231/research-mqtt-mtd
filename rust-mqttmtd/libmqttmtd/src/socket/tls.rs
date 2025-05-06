//! Defines TLS socket operations.

use std::{net::SocketAddr, sync::Arc};

use rustls::{pki_types::ServerName, ClientConfig, ServerConfig};

use tokio::{
    net::{TcpStream, ToSocketAddrs},
    task::JoinHandle,
    time::{timeout, Duration},
};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

use crate::{sock_cli_println, sock_serv_println};

use super::{
    error::SocketError,
    plain::{PlainClient, PlainServer},
};

///////////////////////////////////////////////////////////
///
/// TLS-enabled TCP Socket Server
///
///////////////////////////////////////////////////////////
pub struct TlsServer {
    plain_server: PlainServer,
    acceptor: Arc<TlsAcceptor>,
}

impl TlsServer {
    pub fn new(
        port: u16,
        listen_timeout: impl Into<Option<Duration>>,
        config: Arc<ServerConfig>,
    ) -> Self {
        TlsServer {
            plain_server: PlainServer::new(port, listen_timeout),
            acceptor: Arc::new(TlsAcceptor::from(config)),
        }
    }

    pub fn spawn<F, Fut>(self, handler: F) -> JoinHandle<Result<(), SocketError>>
    where
        F: Fn(server::TlsStream<TcpStream>, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output=()> + Send + 'static,
    {
        let acceptor = self.acceptor.clone();
        let handler = Arc::new(handler);

        self.plain_server.spawn(move |socket, addr| {
            sock_serv_println!("doing tls...");
            let acceptor = acceptor.clone();
            let handler = handler.clone();

            async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        sock_serv_println!("TLS accepted at addr {}", addr);
                        handler(tls_stream, addr).await
                    }
                    Err(e) => {
                        sock_serv_println!("TLS accept error at addr {}: {}", addr, e);
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
        sock_cli_println!("connecting to tls server...");

        let connect_result = match self.plain_client.connect_timeout {
            Some(duration) if duration <= Duration::ZERO => {
                return Err(SocketError::InvalidTimeoutError(duration));
            }
            Some(duration) => timeout(duration, TcpStream::connect(self.plain_client.addr)).await,
            None => Ok(TcpStream::connect(self.plain_client.addr).await),
        };

        match connect_result {
            Ok(Ok(socket)) => {
                sock_cli_println!("Socket connected!");
                let domain = ServerName::try_from(domain)?;
                Ok(self
                    .connector
                    .connect(domain, socket)
                    .await
                    .map_err(|e| SocketError::ConnectError(e))?)
            }
            Ok(Err(e)) => {
                sock_cli_println!("Connect error: {}", e);
                Err(SocketError::ConnectError(e))
            }
            Err(_elapsed) => {
                sock_cli_println!(
                    "Connect timed out after {:?}",
                    self.plain_client.connect_timeout
                );
                Err(SocketError::ElapsedError())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::CertifiedKey;
    use std::io::ErrorKind;
    use std::{
        fs::{create_dir_all, File},
        io::Write,
        path::Path,
        sync::Once,
        time::Duration,
    };
    use tempfile::tempdir;

    use crate::socket::tls_config::TlsConfigLoader;

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

        let conf_serv = TlsConfigLoader::load_server_config(
            &server_dir.join("cert.crt"),
            &server_dir.join("key.pem"),
            &clients_dir,
            no_client_auth,
        );
        assert!(conf_serv.is_ok());

        let conf_cli = TlsConfigLoader::load_client_config(
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
        const PORT: u16 = 3000;
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Duration = Duration::from_secs(1);
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(PORT, TO_SERVER, conf_server).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client and connect
        let cli_sock = TlsClient::new(format!("localhost:{}", PORT), TO_CLIENT, conf_client)
            .connect(DOMAIN_SERV)
            .await;

        // Wait a while enough to flush output from server
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cli_sock.is_ok());
    }

    #[tokio::test]
    async fn spawn_serv_zero_duration() {
        const PORT: u16 = 3001;
        const TO_SERVER: Duration = Duration::ZERO;
        let (conf_server, _) = create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        assert!(match timeout(
            Duration::from_secs(1),
            TlsServer::new(PORT, TO_SERVER, conf_server).spawn(|_, _| async {}),
        )
            .await
        {
            Ok(Ok(Err(SocketError::InvalidTimeoutError(d)))) => d == TO_SERVER,
            _ => false,
        });
    }

    #[tokio::test]
    async fn spawn_cli_none_duration() {
        const PORT: u16 = 3002;
        const TO_SERVER: Duration = Duration::from_secs(1);
        const TO_CLIENT: Option<Duration> = None;
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(PORT, TO_SERVER, conf_server).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Spawn client
        assert!(match timeout(
            Duration::from_secs(1),
            TlsClient::new(format!("localhost:{}", PORT), TO_CLIENT, conf_client)
                .connect(DOMAIN_SERV),
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
        let (_, conf_client) = create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Try connecting
        assert!(match timeout(
            Duration::from_secs(2),
            TlsClient::new(format!("localhost:{}", PORT), TO_CLIENT, conf_client)
                .connect(DOMAIN_SERV),
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
        let (conf_server, conf_client) =
            create_load_sample_configs(true, DOMAIN_CA, DOMAIN_SERV, DOMAIN_CLI);

        // Spawn server
        let _ = TlsServer::new(PORT, TO_SERVER, conf_server).spawn(|_, _| async {});

        // Wait a while
        tokio::time::sleep(TO_SERVER + Duration::from_millis(100)).await;

        // Spawn client and connect
        assert!(
            match TlsClient::new(format!("localhost:{}", PORT), TO_CLIENT, conf_client)
                .connect(DOMAIN_SERV)
                .await
            {
                Err(SocketError::ConnectError(e)) => e.kind() == ErrorKind::ConnectionRefused,
                _ => false,
            }
        );
    }
}
