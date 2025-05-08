use clap::Parser;
use config::{Config, ConfigError, File};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::auth_serv::issuer;
use libmqttmtd::config_helper::display_config;
use libmqttmtd::socket::tls_config::TlsConfigLoader;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::fmt::Formatter;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokenmgr::fetch_tokens;

#[derive(Parser)]
#[command(ignore_errors(true))]
struct IntegrationTestsArgs {
    /// Issuer address. Default: "server:3000". Overrides config file.
    #[arg(short, long)]
    issuer_addr: Option<String>,

    /// MQTT Interface address. Default: "server:11883". Overrides config file.
    #[arg(short, long)]
    mqtt_interface_addr: Option<String>,

    /// Client cert file. Overrides config file.
    #[arg(long)]
    cli_cert: Option<String>,

    /// Client key file. Overrides config file.
    #[arg(long)]
    cli_key: Option<String>,

    /// Directory containing CA certificates for authentication. Overrides config file.
    #[arg(long)]
    ca_certs_dir: Option<String>,

    /// Whether client authentication is disabled. Overrides config file.
    #[arg(long)]
    client_auth_disabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IntegrationTestsConfig {
    issuer_addr: String,
    mqtt_interface_addr: String,
    cli_cert: PathBuf,
    cli_key: PathBuf,
    ca_certs_dir: PathBuf,
    client_auth_disabled: bool,
}

fn load_config(args: IntegrationTestsArgs) -> Result<IntegrationTestsConfig, ConfigError> {
    let mut builder = Config::builder()
        .set_default("issuer_addr", "server:3000")?
        .set_default("mqtt_interface_addr", "server:11883")?
        .set_default("cli_cert", "../../tests/certs/clients/client1.crt")?
        .set_default("cli_key", "../../tests/certs/clients/client1.pem")?
        .set_default("ca_certs_dir", "../../tests/certs/ca/")?
        .set_default("client_auth_disabled", false)?;

    if let Ok(conf_path) = std::env::var("INTEGRATION_TESTS_CONF") {
        builder = builder.add_source(File::with_name(&conf_path).required(true));
    }

    if let Some(value) = args.issuer_addr {
        builder = builder.set_override("issuer_addr", value)?;
    }
    if let Some(value) = args.mqtt_interface_addr {
        builder = builder.set_override("mqtt_interface_addr", value)?;
    }
    if let Some(value) = args.cli_cert {
        builder = builder.set_override("cli_cert", value)?;
    }
    if let Some(value) = args.cli_key {
        builder = builder.set_override("cli_key", value)?;
    }
    if let Some(value) = args.ca_certs_dir {
        builder = builder.set_override("ca_certs_dir", value)?;
    }
    if let Some(value) = args.client_auth_disabled {
        builder = builder.set_override("client_auth_disabled", value)?;
    }

    let mut config: IntegrationTestsConfig = builder.build()?.try_deserialize()?;

    // Replace ~ with homedir
    if let Some(resolved) = resolve_tilde(&config.cli_cert) {
        config.cli_cert = resolved;
    }
    if let Some(resolved) = resolve_tilde(&config.cli_key) {
        config.cli_key = resolved;
    }
    if let Some(resolved) = resolve_tilde(&config.ca_certs_dir) {
        config.ca_certs_dir = resolved;
    }
    Ok(config)
}

fn resolve_tilde(path: &Path) -> Option<PathBuf> {
    if path.starts_with("~") {
        let mut new_path = path
            .to_str()
            .expect("failed to convert PathBuf to string")
            .to_owned();
        new_path.replace_range(
            0..1,
            dirs::home_dir()
                .expect("failed to get home dir")
                .to_str()
                .expect("failed to convert home dir to str"),
        );
        Some(PathBuf::from(new_path))
    } else {
        None
    }
}

static CONFIG: OnceLock<Arc<IntegrationTestsConfig>> = OnceLock::new();

pub(crate) fn get_test_config() -> &'static Arc<IntegrationTestsConfig> {
    CONFIG.get_or_init(|| {
        let args = IntegrationTestsArgs::parse();
        let config = load_config(args).expect("loading config failed");

        for line in display_config("integration tests", &config)
            .expect("displaying config values failed")
            .iter()
        {
            println!("{}", line);
        }

        Arc::new(config)
    })
}

#[tokio::test]
async fn t_fetch_tokens_pub_4() {
    let config = get_test_config();

    // TLS Config
    let tls_config = TlsConfigLoader::load_client_config(
        &config.cli_cert,
        &config.cli_key,
        &config.ca_certs_dir,
        config.client_auth_disabled,
    )
    .inspect_err(|err| panic!("{:?}", err));
    let tls_config = tls_config.unwrap();

    // Random algorithm
    let algo = [
        SupportedAlgorithm::Aes128Gcm,
        SupportedAlgorithm::Aes256Gcm,
        SupportedAlgorithm::Chacha20Poly1305,
    ]
    .choose(&mut rand::rng());
    assert!(algo.is_some());
    let algo = algo.unwrap();

    // issuer::Request
    let request = issuer::Request::new(true, 1u8, *algo, "aiueo/kakikukeko");

    // issuer address
    let issuer_addr = config
        .issuer_addr
        .to_socket_addrs()
        .inspect_err(|err| panic!("{:?}", err));
    let issuer_addr = issuer_addr.unwrap().next();
    assert!(issuer_addr.is_some());
    let issuer_addr = issuer_addr.unwrap();

    // Call fetched_res and check if success
    let _fetched_res = fetch_tokens(issuer_addr, tls_config, &request)
        .await
        .inspect_err(|err| panic!("{:?}", err));
}

#[derive(Debug)]
pub enum IntegrationTestsError {
    LoadConfigFailedError(ConfigError),
    DisplayConfigFailedError(),
    DirCreationFailedError(PathBuf),
    UnknownKeyAlgoError(String),
    InvalidRSAKeySizeError(usize),
    InvalidECDSACurveError(usize),
    KeyGenerationFailedError(rcgen::Error),
    CertSigningFailedError(rcgen::Error),
    SaveKeyCertFailedError(std::io::Error),
}

impl std::error::Error for IntegrationTestsError {}

impl std::fmt::Display for IntegrationTestsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrationTestsError::LoadConfigFailedError(e) => {
                write!(f, "failed to load configuration {}", e)
            }
            IntegrationTestsError::DisplayConfigFailedError() => {
                write!(f, "failed to display configuration")
            }
            IntegrationTestsError::DirCreationFailedError(path) => {
                write!(f, "failed to create a directory at {:?}", path)
            }
            IntegrationTestsError::UnknownKeyAlgoError(s) => {
                write!(f, "unknown key algo entered: {}", s)
            }
            IntegrationTestsError::InvalidRSAKeySizeError(u) => {
                write!(f, "invalid rsa key size entered: {}", u)
            }
            IntegrationTestsError::InvalidECDSACurveError(u) => {
                write!(f, "invalid ecdsa curve entered: {}", u)
            }
            IntegrationTestsError::KeyGenerationFailedError(e) => {
                write!(f, "generating keypair failed: {}", e)
            }
            IntegrationTestsError::CertSigningFailedError(e) => {
                write!(f, "signing certificate failed: {}", e)
            }
            IntegrationTestsError::SaveKeyCertFailedError(e) => {
                write!(f, "save key/cert failed: {}", e)
            }
        }
    }
}
