use base64::{engine::general_purpose, Engine};
use bytes::{BufMut, Bytes, BytesMut};
use libmqttmtd::{
    aead,
    aead::algo::{SupportedAlgorithm, SupportedAlgorithm::Aes128Gcm},
    auth_serv::verifier,
    socket::plain::client::PlainClient,
    utils,
};
use mqttbytes::v5::{Publish, Subscribe};
use std::{fmt::Display, sync::Arc};
use tokio::sync::RwLock;

/// Buffer to memorize subscription
#[derive(Debug)]
pub(super) struct ClientSubscriptionInfo {
    token_idx: u16,
    algo: SupportedAlgorithm,
    nonce_padding: Bytes,
    session_key: Bytes,
}

impl ClientSubscriptionInfo {
    pub(super) fn new() -> Self {
        Self {
            token_idx: 0,
            algo: Aes128Gcm,
            nonce_padding: Bytes::new(),
            session_key: Bytes::new(),
        }
    }
}

/// Replaces token and passes it down to Broker.
pub async fn unfreeze_subscribe(
    subscription_info: &Arc<RwLock<ClientSubscriptionInfo>>,
    verifier_addr: &str,
    enable_unix_sock: bool,
    mut subscribe: Subscribe,
) -> Result<Option<Subscribe>, SubscribeUnfreezeError> {
    if subscribe.filters.len() > 1 {
        return Err(SubscribeUnfreezeError::MultipleFilters);
    }

    // topic
    let mut filter = subscribe.filters.pop().unwrap();
    let token = filter.path;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| SubscribeUnfreezeError::TokenDecodeError(e))?;

    // verify
    let res: Option<verifier::ResponseReader>;
    {
        let req = verifier::Request::new(&decoded)
            .map_err(|e| SubscribeUnfreezeError::VerifierRequestCreateError(e))?;

        // Establish socket
        let mut stream = if enable_unix_sock {
            #[cfg(unix)]
            PlainClient::new_unix(verifier_addr, None)
                .connect()
                .await
                .map_err(|e| SubscribeUnfreezeError::VerifierConnectError(e))?
        } else {
            PlainClient::new_tcp(verifier_addr, None)
                .map_err(|e| SubscribeUnfreezeError::VerifierConnectError(e))?
                .connect()
                .await
                .map_err(|e| SubscribeUnfreezeError::VerifierConnectError(e))?
        };

        // Send req and receive resp
        let _ = req
            .write_to(&mut stream)
            .await
            .map_err(|e| SubscribeUnfreezeError::VerifierRequestWriteError(e))?;
        res = verifier::ResponseReader::read_from(&mut stream)
            .await
            .map_err(|e| SubscribeUnfreezeError::VerifierResponseReadError(e))?;
    } // stream

    if let Some(response) = res {
        filter.path = response.topic;
        subscribe.filters.push(filter);
        {
            let mut info = subscription_info.write().await;
            // Restore nonce_padding and token_idx
            let mut nonce_padding = BytesMut::zeroed(response.algo.nonce_len() - 4);
            nonce_padding.copy_from_slice(&response.nonce[..response.algo.nonce_len() - 4]);
            info.nonce_padding = nonce_padding.freeze();
            info.token_idx = u16::from_be_bytes([
                response.nonce[response.algo.nonce_len() - 2],
                response.nonce[response.algo.nonce_len() - 1],
            ]);
            println!("info.token_idx={}", info.token_idx);

            info.session_key = response.session_key;
            info.algo = response.algo;
        }

        Ok(Some(subscribe))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum SubscribeUnfreezeError {
    /// Indicates multiple filters in the packet.
    MultipleFilters,

    /// Wraps [base64::DecodeError]
    TokenDecodeError(base64::DecodeError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on
    /// request generation
    VerifierRequestCreateError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [libmqttmtd::socket::error::SocketError] error on client connect
    VerifierConnectError(libmqttmtd::socket::error::SocketError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on
    /// writing request
    VerifierRequestWriteError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on
    /// reading response
    VerifierResponseReadError(libmqttmtd::auth_serv::error::AuthServerParserError),
}

impl std::error::Error for SubscribeUnfreezeError {}
impl Display for SubscribeUnfreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscribeUnfreezeError::MultipleFilters => {
                write!(f, "multiple filters not supported")
            }
            SubscribeUnfreezeError::TokenDecodeError(e) => {
                write!(f, "token decoding (base64) failed: {}", e)
            }
            SubscribeUnfreezeError::VerifierRequestCreateError(e) => {
                write!(f, "failed to create a verifier request: {}", e)
            }
            SubscribeUnfreezeError::VerifierConnectError(e) => {
                write!(f, "failed to connect to verifier: {}", e)
            }
            SubscribeUnfreezeError::VerifierRequestWriteError(e) => {
                write!(f, "failed to write request to verifier: {}", e)
            }
            SubscribeUnfreezeError::VerifierResponseReadError(e) => {
                write!(f, "failed to read response from verifier: {}", e)
            }
        }
    }
}

/// Encrypts payload and passes it down to Client.
pub async fn freeze_subscribed_publish(
    subscription_info: &Arc<RwLock<ClientSubscriptionInfo>>,
    mut publish: Publish,
) -> Result<Option<Publish>, SubscribedPublishFreezeError> {
    let mut in_out: BytesMut;
    let tag: ring::aead::Tag;

    {
        let info = subscription_info.read().await;
        if info.session_key.len() != info.algo.key_len()
            || info.nonce_padding.len() != info.algo.nonce_len() - 4
        {
            println!("No valid subscription registered so far, blocking...",);
            return Ok(None);
        }

        // nonce
        let nonce = utils::get_nonce(
            info.algo,
            &info.nonce_padding[..],
            Some(publish.pkid),
            info.token_idx,
        );
        if nonce.is_none() {
            println!("Failed to calculate nonce, blocking...",);
            return Ok(None);
        }
        let nonce = nonce.unwrap();

        // seal
        in_out = BytesMut::with_capacity(2 + publish.topic.len() + publish.payload.len());
        in_out.put_u16(publish.topic.len() as u16);
        in_out.extend_from_slice(publish.topic.as_bytes());
        in_out.extend_from_slice(&publish.payload);
        tag = aead::seal(info.algo, &info.session_key, &nonce, &mut in_out)
            .map_err(|e| SubscribedPublishFreezeError::PayloadSealError(e))?;
    }

    // update the publish
    publish.topic = general_purpose::URL_SAFE_NO_PAD.encode(&tag);
    publish.payload = in_out.freeze();

    Ok(Some(publish))
}

#[derive(Debug)]
pub enum SubscribedPublishFreezeError {
    /// Wraps [ring::error::Unspecified] on sealing a packet
    PayloadSealError(ring::error::Unspecified),
}

impl std::error::Error for SubscribedPublishFreezeError {}
impl Display for SubscribedPublishFreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscribedPublishFreezeError::PayloadSealError(e) => {
                write!(f, "failed to seal a packet: {}", e)
            }
        }
    }
}
