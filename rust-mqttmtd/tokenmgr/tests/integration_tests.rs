use base64::{engine::general_purpose, Engine};
use bytes::{Bytes, BytesMut};
use config::{Config, ConfigError, File};
use libmqttmtd::{
    aead::algo::{
        SupportedAlgorithm,
        SupportedAlgorithm::{Aes128Gcm, Aes256Gcm, Chacha20Poly1305},
    },
    auth_serv::issuer,
    config_helper::display_config,
    consts::RANDOM_LEN,
    socket::tls_config::TlsConfigLoader,
};
use rumqttc::{v5, v5::mqttbytes::v5::Packet};
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, OnceLock},
    time::Duration,
};
use tokenmgr::{fetch_tokens, tokenset::TokenSet};
use tokio::{
    sync::{Notify, RwLock},
    task,
    time::timeout,
};
use uuid::{NoContext, Timestamp, Uuid};

const TEST_ISPUB_PUB: bool = true;
const TEST_ISPUB_SUB: bool = false;

const TEST_TOPIC_PUBONLY: &str = "topic/pubonly";
const TEST_TOPIC_SUBONLY: &str = "topic/subonly";
const TEST_TOPIC_PUBSUB: &str = "topic/pubsub";

const TEST_NUM_TOKENS_DIVIDED_BY_4: u8 = 2;
const TEST_ALGO: SupportedAlgorithm = Aes256Gcm;
const TEST_PAYLOAD: &str = "hello from a client";

const TEST_RUMQTTC_MAX_PACKET_SIZE: Option<u32> = Some(1024);

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
        .unwrap_or_else(|e| panic!("failed to convert issuer address: {:?}", e))
        .next()
        .expect("no address in issuer_addr")
}

async fn mqtt_publish(
    notify: impl Into<Option<Arc<Notify>>>,
    broker_host: impl Into<String>,
    broker_port: u16,
    topic: String,
    payload: Bytes,
) -> Result<(), v5::ConnectionError> {
    let notify = notify.into();
    if notify.is_some() {
        println!("[mqtt_publish] Waiting for subscribe signal...");
        notify.unwrap().notified().await;
        println!("[mqtt_publish] Received subscribe signal. Proceeding with publish.");
    }

    let mut mqttoptions = v5::MqttOptions::new(
        format!(
            "client1{}",
            Uuid::new_v7(Timestamp::now(NoContext)).to_string()
        ),
        broker_host.into(),
        broker_port,
    );
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    mqttoptions.set_max_packet_size(TEST_RUMQTTC_MAX_PACKET_SIZE);
    mqttoptions.set_network_options(
        rumqttc::NetworkOptions::default()
            .set_connection_timeout(2)
            .to_owned(),
    );
    let (client, mut eventloop) = v5::AsyncClient::new(mqttoptions, 1);
    client
        .publish(&topic, v5::mqttbytes::QoS::AtMostOnce, false, payload)
        .await
        .unwrap();

    timeout(Duration::from_secs(2), async {
        loop {
            match eventloop.poll().await {
                Ok(v5::Event::Outgoing(rumqttc::Outgoing::Publish(_))) => {
                    println!("[mqtt_publish] Publish sent");
                    return Ok(());
                }
                Ok(e) => println!("[mqtt_publish] Received event: {:?}", e),
                Err(e) => {
                    eprintln!("[assert_subscribe] error: {:?}", e);
                    return Err(e);
                }
            }
        }
    })
        .await
        .unwrap_or_else(|e| {
            eprintln!("[mqtt_publish] timed out");
            Err(v5::ConnectionError::Timeout(e))
        })
}

async fn assert_subscribe(
    notify: Arc<Notify>,
    broker_host: impl Into<String>,
    broker_port: u16,
    topic: String,
    expected_payload: impl Into<Bytes>,
) -> Result<(), v5::ConnectionError> {
    let mut mqttoptions = v5::MqttOptions::new(
        format!(
            "subscriber{}",
            Uuid::new_v7(Timestamp::now(NoContext)).to_string()
        ),
        broker_host.into(),
        broker_port,
    );
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    mqttoptions.set_max_packet_size(TEST_RUMQTTC_MAX_PACKET_SIZE);

    let (client, mut eventloop) = v5::AsyncClient::new(mqttoptions, 1);
    client
        .subscribe(&topic, v5::mqttbytes::QoS::AtMostOnce)
        .await
        .unwrap();

    timeout(Duration::from_secs(2), async {
        loop {
            match eventloop.poll().await {
                // Successfully publish detected
                Ok(v5::Event::Incoming(Packet::SubAck(suback))) => {
                    println!(
                        "[assert_subscribe] Received SUBACK, sending out signal: {:?}",
                        suback
                    );
                    notify.notify_one();
                }
                Ok(v5::Event::Incoming(Packet::Publish(publish))) => {
                    println!("[assert_subscribe] Received publish: {:?}", publish);
                    assert_eq!(publish.payload, expected_payload.into());
                    return Ok(());
                }
                Ok(e) => println!("[assert_subscribe] Received event: {:?}", e),
                Err(e) => {
                    eprintln!("[assert_subscribe] error: {:?}", e);
                    return Err(e);
                }
            }
        }
    })
        .await
        .unwrap_or_else(|e| {
            eprintln!("[assert_subscribe] timed out");
            Err(v5::ConnectionError::Timeout(e))
        })
}

async fn assert_subscribe_mqttmtd(
    token_set: &TokenSet,
    notify: Arc<Notify>,
    broker_host: impl Into<String>,
    broker_port: u16,
    subscription_topic: String,
    expected_topic_payload: Vec<(Bytes, Bytes)>,
    duration: Duration,
) -> Result<(), v5::ConnectionError> {
    let mut mqttoptions = v5::MqttOptions::new(
        format!(
            "subscriber{}",
            Uuid::new_v7(Timestamp::now(NoContext)).to_string()
        ),
        broker_host.into(),
        broker_port,
    );
    mqttoptions.set_keep_alive(Duration::from_secs(5));
    mqttoptions.set_max_packet_size(TEST_RUMQTTC_MAX_PACKET_SIZE);

    let (client, mut eventloop) = v5::AsyncClient::new(mqttoptions, 1);
    client
        .subscribe(&subscription_topic, v5::mqttbytes::QoS::AtMostOnce)
        .await
        .unwrap();

    timeout(duration, async {
        loop {
            match eventloop.poll().await {
                // Successfully publish detected
                Ok(v5::Event::Incoming(Packet::SubAck(suback))) => {
                    println!(
                        "[assert_subscribe] Received SUBACK, sending out signal: {:?}",
                        suback
                    );
                    notify.notify_one();
                }
                Ok(v5::Event::Incoming(Packet::Publish(publish))) => {
                    println!(
                        "[assert_subscribe] Received publish, decrypting...: {:?}",
                        publish
                    );
                    let mut in_out = BytesMut::from(&publish.payload[..]);
                    in_out.extend(
                        general_purpose::URL_SAFE_NO_PAD
                            .decode(publish.topic)
                            .unwrap_or_else(|e| panic!("{:?}", e)),
                    );
                    token_set
                        .open_serv2cli(publish.pkid, &mut in_out)
                        .unwrap_or_else(|e| panic!("{:?}", e));

                    let topic_len = (in_out[0] as usize).rotate_left(8) | (in_out[1] as usize);
                    let tag_len = 16;

                    let expected_pair = expected_topic_payload.first().unwrap().clone();
                    assert_eq!(&in_out[2..(2 + topic_len)], expected_pair.0);
                    assert_eq!(
                        &in_out[(2 + topic_len)..(in_out.len() - tag_len)],
                        expected_pair.1
                    );
                    return Ok(());
                }
                Ok(e) => println!("[assert_subscribe] Received event: {:?}", e),
                Err(e) => {
                    eprintln!("[assert_subscribe] error: {:?}", e);
                    return Err(e);
                }
            }
        }
    })
        .await
        .unwrap_or_else(|e| {
            eprintln!("[assert_subscribe] timed out");
            Err(v5::ConnectionError::Timeout(e))
        })
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

static UNUSED_TOPIC_IDX: LazyLock<RwLock<u8>> = LazyLock::new(|| RwLock::new(0));

async fn get_testing_topic() -> String {
    let mut idx = UNUSED_TOPIC_IDX.write().await;
    let topic = format!("topic/testing{}", *idx);
    *idx += 1;
    topic
}

#[tokio::test]
async fn test_mqtt_publish_success_idx_0() -> Result<(), Box<dyn std::error::Error>> {
    let broker_host = "server";
    let broker_port = 1883;

    let config = get_test_config();
    let topic = get_testing_topic().await;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_ALGO,
        topic,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Construct a TokenSet
    let mut token_set = TokenSet::from_issuer_req_resp(&request, resp)?;
    token_set.print_current_token();

    let first_token = token_set
        .get_current_b64token()
        .expect("failed to get first token");

    let payload_raw = TEST_PAYLOAD.as_bytes();
    let mut seal_in_out = BytesMut::from(payload_raw);

    let payload = token_set
        .seal_cli2serv(&mut seal_in_out)
        .unwrap_or_else(|e| panic!("failed to seal: {}", e));

    let topic_moved = token_set.topic().clone();

    let notify = Arc::new(Notify::new());
    let notify_arc = notify.clone();
    let _publisher = task::spawn(async move {
        mqtt_publish(
            notify_arc,
            config.mqtt_interface_host.clone(),
            config.mqtt_interface_port,
            first_token,
            payload,
        )
            .await
    });
    let subscriber = assert_subscribe(
        notify.clone(),
        broker_host,
        broker_port,
        topic_moved,
        payload_raw,
    )
        .await;

    assert!(subscriber.is_ok());

    token_set.increment_token_idx();

    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_success_all() -> Result<(), Box<dyn std::error::Error>> {
    let broker_host = "server";
    let broker_port = 1883;

    let config = get_test_config();
    let topic = get_testing_topic().await;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_ALGO,
        topic,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Construct a TokenSet
    let mut token_set = TokenSet::from_issuer_req_resp(&request, resp)?;

    // Loop thru all tokens
    for i in 0..(TEST_NUM_TOKENS_DIVIDED_BY_4 as u16).rotate_left(2) {
        println!("token index = {}", i);
        token_set.print_current_token();

        let token = token_set
            .get_current_b64token()
            .expect("failed to get a token");

        // payload
        let payload_raw = format!("{}{}", TEST_PAYLOAD, i);
        let mut seal_in_out = BytesMut::from(payload_raw.as_bytes());
        let payload = token_set
            .seal_cli2serv(&mut seal_in_out)
            .unwrap_or_else(|e| panic!("failed to seal: {}", e));

        let topic_moved = token_set.topic().clone();

        // Spawn publisher and subscriber
        let notify = Arc::new(Notify::new());
        let notify_arc = notify.clone();
        let _publisher = task::spawn(async move {
            mqtt_publish(
                notify_arc,
                config.mqtt_interface_host.clone(),
                config.mqtt_interface_port,
                token,
                payload,
            )
                .await
        });
        let subscriber = assert_subscribe(
            notify.clone(),
            broker_host,
            broker_port,
            topic_moved,
            payload_raw,
        )
            .await;

        assert!(subscriber.is_ok());

        token_set.increment_token_idx();
    }
    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_fail_wrong_token() -> Result<(), Box<dyn std::error::Error>> {
    let broker_host = "server";
    let broker_port = 1883;

    let config = get_test_config();
    let topic = get_testing_topic().await;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_ALGO,
        topic,
    )?;

    // Fetch tokens
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;

    // Construct a TokenSet
    let mut token_set = TokenSet::from_issuer_req_resp(&request, resp)?;
    token_set.print_current_token();

    let first_token = token_set
        .get_current_b64token()
        .expect("failed to get first token");
    let wrong_token = "0".repeat(first_token.chars().count());
    assert_ne!(first_token, wrong_token);

    let payload_raw = "test_publish_fail_wrong_token".as_bytes();
    let mut seal_in_out = BytesMut::from(payload_raw);

    let payload = token_set
        .seal_cli2serv(&mut seal_in_out)
        .unwrap_or_else(|e| panic!("failed to seal: {}", e));

    let topic_moved = token_set.topic().clone();

    let notify = Arc::new(Notify::new());
    let notify_arc = notify.clone();
    let _publisher = task::spawn(async move {
        mqtt_publish(
            notify_arc,
            config.mqtt_interface_host.clone(),
            config.mqtt_interface_port,
            wrong_token,
            payload,
        )
            .await
    });

    let subscriber = assert_subscribe(
        notify.clone(),
        broker_host,
        broker_port,
        topic_moved,
        payload_raw,
    )
        .await;

    match subscriber {
        Err(v5::ConnectionError::Timeout(_)) => {}
        other => panic!("unexpected: {:?}", other),
    }

    token_set.increment_token_idx();

    Ok(())
}

#[tokio::test]
async fn test_mqtt_subscribe_fail_wrong_token() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let topic = get_testing_topic().await;

    // issuer::Request
    let request = issuer::Request::new(
        TEST_ISPUB_SUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_ALGO,
        topic,
    )?;
    let resp = fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
    let token_set = TokenSet::from_issuer_req_resp(&request, resp)?;
    token_set.print_current_token();

    // wrong token generation
    let first_token = token_set
        .get_current_b64token()
        .expect("failed to get first token");
    let wrong_token = "0".repeat(first_token.chars().count());
    assert_ne!(first_token, wrong_token);

    let subscriber = assert_subscribe_mqttmtd(
        &token_set,
        Arc::new(Notify::new()),
        config.mqtt_interface_host.clone(),
        config.mqtt_interface_port,
        wrong_token,
        vec![],
        Duration::from_secs(2),
    )
        .await;

    assert!(subscriber.is_err());

    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_subscribe_success_idx_0() -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let topic = get_testing_topic().await;

    // First token for pub
    let token_set_pub;
    let first_token_pub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_PUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_pub = TokenSet::from_issuer_req_resp(&request, resp)?;
        first_token_pub = token_set_pub
            .get_current_b64token()
            .expect("failed to get first token");
    }

    // First token for sub
    let token_set_sub;
    let first_token_sub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_SUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_sub = TokenSet::from_issuer_req_resp(&request, resp)?;
        first_token_sub = token_set_sub
            .get_current_b64token()
            .expect("failed to get first token");
    }

    // payload
    let payload_raw = TEST_PAYLOAD.as_bytes();
    let mut seal_in_out = BytesMut::from(payload_raw);
    let payload = token_set_pub
        .seal_cli2serv(&mut seal_in_out)
        .unwrap_or_else(|e| panic!("failed to seal: {}", e));

    // Spawn publisher and subscriber
    let notify = Arc::new(Notify::new());
    let notify_arc = notify.clone();
    let _publisher = task::spawn(async move {
        mqtt_publish(
            notify_arc,
            config.mqtt_interface_host.clone(),
            config.mqtt_interface_port,
            first_token_pub,
            payload,
        )
            .await
    });
    let subscriber = assert_subscribe_mqttmtd(
        &token_set_sub,
        notify.clone(),
        config.mqtt_interface_host.clone(),
        config.mqtt_interface_port,
        first_token_sub,
        vec![(Bytes::from(topic), Bytes::from(payload_raw))],
        Duration::from_secs(5),
    )
        .await;

    assert!(subscriber.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_subscribe_success_sub_first_pub_all()
    -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let topic = get_testing_topic().await;

    // First token for pub
    let token_set_pub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_PUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_pub = TokenSet::from_issuer_req_resp(&request, resp)?;
    }

    // First token for sub
    let token_set_sub;
    let first_token_sub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_SUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_sub = TokenSet::from_issuer_req_resp(&request, resp)?;
        first_token_sub = token_set_sub
            .get_current_b64token()
            .expect("failed to get first token");
    }

    let notify = Arc::new(Notify::new());

    // Loop thru all tokens
    for i in 0..(TEST_NUM_TOKENS_DIVIDED_BY_4 as u16).rotate_left(2) {
        println!("token index = {}", i);
        token_set_pub.print_current_token();

        let token = token_set_pub
            .get_current_b64token()
            .expect("failed to get a token");

        // payload
        let payload_raw = format!("{}{}", TEST_PAYLOAD, i);
        let mut seal_in_out = BytesMut::from(payload_raw.as_bytes());
        let payload = token_set_pub
            .seal_cli2serv(&mut seal_in_out)
            .unwrap_or_else(|e| panic!("failed to seal: {}", e));

        let notify_arc = notify.clone();

        // Spawn publisher and subscriber
        let _publisher = task::spawn(async move {
            mqtt_publish(
                notify_arc,
                config.mqtt_interface_host.clone(),
                config.mqtt_interface_port,
                token,
                payload,
            )
                .await
        });
    }
    let subscriber = assert_subscribe_mqttmtd(
        &token_set_sub,
        notify,
        config.mqtt_interface_host.clone(),
        config.mqtt_interface_port,
        first_token_sub,
        (0..(TEST_NUM_TOKENS_DIVIDED_BY_4 as u16).rotate_left(2))
            .map(|i| {
                (
                    Bytes::from(topic.clone()),
                    Bytes::from(format!("{}{}", TEST_PAYLOAD, i)),
                )
            })
            .collect(),
        Duration::from_secs(15),
    )
        .await;

    assert!(subscriber.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_mqtt_publish_subscribe_success_sub_all_pub_all()
    -> Result<(), Box<dyn std::error::Error>> {
    let config = get_test_config();
    let topic = get_testing_topic().await;

    // First token for pub
    let mut token_set_pub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_PUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_pub = TokenSet::from_issuer_req_resp(&request, resp)?;
    }

    // First token for sub
    let mut token_set_sub;
    {
        let request = issuer::Request::new(
            TEST_ISPUB_SUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            TEST_ALGO,
            topic.clone(),
        )?;
        let resp =
            fetch_tokens(get_issuer_addr(&config), get_tls_config(&config), &request).await?;
        token_set_sub = TokenSet::from_issuer_req_resp(&request, resp)?;
    }

    // Loop thru all tokens
    for i in 0..(TEST_NUM_TOKENS_DIVIDED_BY_4 as u16).rotate_left(2) {
        println!("token index = {}", i);
        token_set_pub.print_current_token();

        let token_pub = token_set_pub
            .get_current_b64token()
            .expect("failed to get a token");

        let token_sub = token_set_sub
            .get_current_b64token()
            .expect("failed to get a token");

        // payload
        let payload_raw = format!("{}{}", TEST_PAYLOAD, i);
        let mut seal_in_out = BytesMut::from(payload_raw.as_bytes());
        let payload = token_set_pub
            .seal_cli2serv(&mut seal_in_out)
            .unwrap_or_else(|e| panic!("failed to seal: {}", e));

        let notify = Arc::new(Notify::new());
        let notify_arc = notify.clone();

        // Spawn publisher and subscriber
        let _publisher = task::spawn(async move {
            mqtt_publish(
                notify_arc,
                config.mqtt_interface_host.clone(),
                config.mqtt_interface_port,
                token_pub,
                payload,
            )
                .await
        });

        let subscriber = assert_subscribe_mqttmtd(
            &token_set_sub,
            notify.clone(),
            config.mqtt_interface_host.clone(),
            config.mqtt_interface_port,
            token_sub,
            vec![(
                Bytes::from(topic.clone()),
                Bytes::from(format!("{}{}", TEST_PAYLOAD, i)),
            )],
            Duration::from_secs(5),
        )
            .await;

        assert!(subscriber.is_ok());

        token_set_pub.increment_token_idx();
        token_set_sub.increment_token_idx();
    }

    Ok(())
}
