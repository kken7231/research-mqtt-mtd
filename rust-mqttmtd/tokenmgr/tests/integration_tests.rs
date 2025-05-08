use config::{Config, ConfigError, File};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::auth_serv::issuer;
use libmqttmtd::config_helper::display_config;
use libmqttmtd::consts::RANDOM_LEN;
use libmqttmtd::socket::tls_config::TlsConfigLoader;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokenmgr::errors::TokenFetchError;
use tokenmgr::fetch_tokens;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IntegrationTestsConfig {
    issuer_addr: String,
    mqtt_interface_addr: String,
    cli_cert: PathBuf,
    cli_key: PathBuf,
    ca_certs_dir: PathBuf,
    client_auth_disabled: bool,
}

fn load_config() -> Result<IntegrationTestsConfig, ConfigError> {
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

/// Helper function to get test config thru Arguments.
fn get_test_config() -> &'static A
rc<IntegrationTestsConfig> {
    CONFIG.get_or_init(|| {
        let config = load_config().expect("loading config failed");

        for line in display_config("integration tests", &config)
            .expect("displaying config values failed")
            .iter()
        {
            println!("{}", line);
        }

        Arc::new(config)
    })
}

fn get_tls_config(config: &Arc<IntegrationTestsConfig>) -> Arc<rustls::ClientConfig> {
    TlsConfigLoader::load_client_config(
        &config.cli_cert,
        &config.cli_key,
        &config.ca_certs_dir,
        config.client_auth_disabled,
    )
        .expect("failed to get tls_config out of config")
}

static AES128GCM: SupportedAlgorithm = SupportedAlgorithm::Aes128Gcm;
static AES256GCM: SupportedAlgorithm = SupportedAlgorithm::Aes128Gcm;
static CHACHA20POLY1305: SupportedAlgorithm = SupportedAlgorithm::Aes128Gcm;

static SUPPORTED_ALGORITHMS: [&'static SupportedAlgorithm; 3] =
    [&AES128GCM, &AES256GCM, &CHACHA20POLY1305];

fn get_random_algo() -> &'static SupportedAlgorithm {
    *SUPPORTED_ALGORITHMS
        .choose(&mut rand::rng())
        .expect("failed to choose random algo")
}

fn get_issuer_addr(config: &Arc<IntegrationTestsConfig>) -> SocketAddr {
    config
        .issuer_addr
        .to_socket_addrs()
        .inspect_err(|e| panic!("failed to convert issuer address: {:?}", e))
        .unwrap()
        .next()
        .expect("no address in issuer_addr")
}

#[tokio::test]
async fn t_fetch_tokens_pub_0() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(true, 0u8, *get_random_algo(), "topic/pubonly");

    // Call fetched_res and check if fail
    let fetched_res =
        fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await;
    assert!(fetched_res.is_err());
    assert!(match fetched_res.unwrap_err() {
        TokenFetchError::ErrorResponseFromIssuer => true,
        _ => false,
    });
}

#[tokio::test]
async fn t_fetch_tokens_pub_4() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(true, 1u8, *get_random_algo(), "topic/pubonly");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
}

#[tokio::test]
async fn t_fetch_tokens_pub_7f() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(true, 0x7Fu8, *get_random_algo(), "topic/pubonly");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
}

#[tokio::test]
async fn t_fetch_tokens_pub_80() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(true, 0x80u8, *get_random_algo(), "topic/pubonly");

    // Call fetched_res and check if fail
    let fetched_res =
        fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await;
    assert!(fetched_res.is_err());
    assert!(match fetched_res.unwrap_err() {
        TokenFetchError::ErrorResponseFromIssuer => true,
        _ => false,
    });
}


#[tokio::test]
async fn t_fetch_tokens_sub_0() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(false, 0u8, *get_random_algo(), "topic/subonly");

    // Call fetched_res and check if fail
    let fetched_res =
        fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await;
    assert!(fetched_res.is_err());
    assert!(match fetched_res.unwrap_err() {
        TokenFetchError::ErrorResponseFromIssuer => true,
        _ => false,
    });
}

#[tokio::test]
async fn t_fetch_tokens_sub_4() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(false, 1u8, *get_random_algo(), "topic/subonly");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
}

#[tokio::test]
async fn t_fetch_tokens_sub_7f() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(false, 0x7Fu8, *get_random_algo(), "topic/subonly");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
}

#[tokio::test]
async fn t_fetch_tokens_sub_80() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(false, 0x80u8, *get_random_algo(), "topic/subonly");

    // Call fetched_res and check if fail
    let fetched_res =
        fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await;
    assert!(fetched_res.is_err());
    assert!(match fetched_res.unwrap_err() {
        TokenFetchError::ErrorResponseFromIssuer => true,
        _ => false,
    });
}


#[tokio::test]
async fn t_fetch_tokens_pubsub_4() {
    let config = get_test_config();

    // issuer::Request
    let request = issuer::Request::new(false, 1u8, *get_random_algo(), "topic/pubsub");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    // issuer::Request
    let request = issuer::Request::new(true, 1u8, *get_random_algo(), "topic/pubsub");

    // Call fetched_res and check if success
    let fetched_res = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request)
        .await
        .inspect_err(|err| panic!("{:?}", err))
        .unwrap();

    assert_eq!(
        fetched_res.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
}
