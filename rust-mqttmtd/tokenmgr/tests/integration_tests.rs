use bytes::{Bytes, BytesMut};
use config::{Config, ConfigError, File};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::aead::algo::SupportedAlgorithm::{Aes128Gcm, Aes256Gcm, Chacha20Poly1305};
use libmqttmtd::auth_serv::issuer;
use libmqttmtd::config_helper::display_config;
use libmqttmtd::consts::RANDOM_LEN;
use libmqttmtd::socket::tls_config::TlsConfigLoader;
use rumqttc::v5;
use rumqttc::v5::mqttbytes::v5::Packet;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokenmgr::fetch_tokens;
use tokenmgr::tokenset::TokenSet;
use tokio::task;
use tokio::time::timeout;

const TEST_ISPUB_PUB: bool = true;
const TEST_ISPUB_SUB: bool = false;

const TEST_TOPIC_PUBONLY: &str = "topic/pubonly";
const TEST_TOPIC_SUBONLY: &str = "topic/subonly";
const TEST_TOPIC_PUBSUB: &str = "topic/pubsub";

const TEST_NUM_TOKENS_DIVIDED_BY_4: u8 = 2;
const TEST_ALGO: SupportedAlgorithm = Aes256Gcm;
const TEST_PAYLOAD: &str = "hello from a client";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IntegrationTestsConfig {
    issuer_host: String,
    issuer_port: u16,
    mqtt_interface_host: String,
    mqtt_interface_port: u16,
    cli_cert: PathBuf,
    cli_key: PathBuf,
    ca_certs_dir: PathBuf,
    client_auth_disabled: bool,
}

fn load_config() -> Result<IntegrationTestsConfig, ConfigError> {
    let mut builder = Config::builder()
        .set_default("issuer_host", "server")?
        .set_default("issuer_port", 3000)?
        .set_default("mqtt_interface_host", "server")?
        .set_default("mqtt_interface_port", 11883)?
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
fn get_test_config() -> &'static Arc<IntegrationTestsConfig> {
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

fn get_issuer_addr(config: &Arc<IntegrationTestsConfig>) -> SocketAddr {
    format!("{}:{}", config.issuer_host, config.issuer_port)
        .to_socket_addrs()
        .inspect_err(|e| panic!("failed to convert issuer address: {:?}", e))
        .unwrap()
        .next()
        .expect("no address in issuer_addr")
}

async fn mqtt_publish(
    broker_host: impl Into<String>,
    broker_port: u16,
    topic: String,
    payload: Bytes,
) -> Result<(), v5::ConnectionError> {
    let mut mqttoptions = v5::MqttOptions::new("client1", broker_host.into(), broker_port);
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    let (client, mut eventloop) = v5::AsyncClient::new(mqttoptions, 1);
    task::spawn(async move {
        client
            .publish(&topic, v5::mqttbytes::QoS::AtMostOnce, false, payload)
            .await
            .unwrap();
    });

    match timeout(Duration::from_secs(5), async {
        loop {
            match eventloop.poll().await {
                Ok(e) => println!("[mqtt_publish] Received event: {:?}", e),
                Err(e) => return Err(e),
            }
        }
    })
        .await
    {
        Ok(v) => v,
        Err(_) => panic!("[mqtt_publish] timeout"),
    }
}

async fn assert_subscribe(
    broker_host: impl Into<String>,
    broker_port: u16,
    topic: String,
    expected_payload: Bytes,
) {
    let mut mqttoptions = v5::MqttOptions::new("client1", broker_host.into(), broker_port);
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    let (client, mut eventloop) = v5::AsyncClient::new(mqttoptions, 1);
    client
        .subscribe(&topic, v5::mqttbytes::QoS::AtMostOnce)
        .await
        .unwrap();

    match timeout(Duration::from_secs(5), async {
        loop {
            match eventloop.poll().await {
                // Successfully publish detected
                Ok(v5::Event::Incoming(Packet::Publish(publish)))
                if publish.payload.eq(&expected_payload) =>
                    {
                        println!("[assert_subscribe] Received publish: {:?}", publish);
                        return;
                    }
                Ok(e) => println!("[assert_subscribe] Received event: {:?}", e),
                Err(e) => panic!("[assert_subscribe] Connection error: {:?}", e),
            }
        }
    })
        .await
    {
        Ok(v) => v,
        Err(_) => panic!("[assert_subscribe] timed out"),
    }
}

#[tokio::test]
async fn test_fetch_tokens_success_pub_4() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let num_tokens_divided_by_4 = 1u8; // num tokens = 4 (safe)

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_pub_7f() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let num_tokens_divided_by_4 = 0x7Fu8; // num tokens = 0x7F (safe)

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );
    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_sub_4() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let num_tokens_divided_by_4 = 4u8; // num tokens = 4 (safe)

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_SUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_SUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_sub_7f() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let num_tokens_divided_by_4 = 0x7fu8; // num tokens = 0x7F (safe)

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_SUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_SUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_pubsub_4() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let num_tokens_divided_by_4 = 1u8; // num tokens = 4 (safe)

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_PUBSUB,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_SUB,
        num_tokens_divided_by_4,
        TEST_ALGO,
        TEST_TOPIC_PUBSUB,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    assert_eq!(
        resp.all_randoms().len(),
        RANDOM_LEN * (request.num_tokens_divided_by_4() as usize).rotate_left(2)
    );

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_aes128gcm() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let algo = Aes128Gcm;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        algo,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Check both enc_key and nonce_base length
    assert_eq!(resp.enc_key().len(), algo.key_len());
    assert_eq!(resp.nonce_base().len(), algo.nonce_len());

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_aes256gcm() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let algo = Aes256Gcm;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        algo,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Check both enc_key and nonce_base length
    assert_eq!(resp.enc_key().len(), algo.key_len());
    assert_eq!(resp.nonce_base().len(), algo.nonce_len());

    Ok(())
}

#[tokio::test]
async fn test_fetch_tokens_success_chacha20poly1305() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let algo = Chacha20Poly1305;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        algo,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Check both enc_key and nonce_base length
    assert_eq!(resp.enc_key().len(), algo.key_len());
    assert_eq!(resp.nonce_base().len(), algo.nonce_len());

    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_success_idx_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();

    let broker_host = "server";
    let broker_port = match std::env::var("PROTOCOL") {
        Ok(val) if val == "plain" => 1883,
        Ok(val) if val == "tls" => 8883,
        Ok(val) if val == "websocket" => 8080,
        Ok(val) if val == "wss" => 8081,
        _ => panic!("no PROTOCOL set"),
    };

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_ALGO,
        TEST_TOPIC_PUBONLY,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Construct a TokenSet
    let mut token_set = TokenSet::from_issuer_req_resp(&request, resp)?;
    token_set.print_current_token();
    
    let first_token = token_set
        .get_current_b64token()
        .expect("failed to get first token");

    let mut payload_raw = BytesMut::from(TEST_PAYLOAD.as_bytes());

    let payload = token_set
        .seal(&mut payload_raw)
        .inspect_err(|e| panic!("failed to seal: {}", e))
        .unwrap();

    let topic_moved = token_set.topic().clone();
    task::spawn(async move {
        assert_subscribe(
            broker_host,
            broker_port,
            topic_moved,
            payload_raw.freeze(),
        )
            .await;
    });

    mqtt_publish(
        config.mqtt_interface_host.clone(),
        config.mqtt_interface_port,
        first_token,
        payload,
    )
        .await?;

    token_set.increment_token_idx();

    Ok(())
}

// #[tokio::test]
// async fn test_publish_success_idx_last() -> Result<(), Box<dyn std::error::Error>> {
//     todo!()
// }
//
// #[tokio::test]
// async fn test_publish_fail_wrong_token() -> Result<(), Box<dyn std::error::Error>> {
//     todo!()
// }
