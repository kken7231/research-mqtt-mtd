use base64::{engine::general_purpose, Engine};
use bytes::{BufMut, Bytes, BytesMut};
use libmqttmtd::{aead, aead::algo::{SupportedAlgorithm, SupportedAlgorithm::Aes128Gcm}, auth_serv::verifier, socket::plain::PlainClient, utils};
use mqttbytes::v5::{Publish, Subscribe};
use std::{fmt::Display, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug)]
pub(super) struct ClientSubscriptionInfo {
    is_subscribed: bool,
    token_idx: u16,
    algo: SupportedAlgorithm,
    nonce_base: u128,
    enc_key: Bytes,
}

impl ClientSubscriptionInfo {
    pub(super) fn new() -> Self {
        Self {
            is_subscribed: false,
            // dummy unused data below
            token_idx: 0,
            algo: Aes128Gcm,
            nonce_base: 0,
            enc_key: Bytes::new(),
        }
    }
}

/// Replaces token and passes it down to Broker.
pub async fn unfreeze_subscribe(
    subscription_info: &Arc<RwLock<ClientSubscriptionInfo>>,
    verifier_port: u16,
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
        let mut stream = PlainClient::new(format!("localhost:{}", verifier_port), None)
            .connect()
            .await
            .map_err(|e| SubscribeUnfreezeError::VerifierConnectError(e))?;
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
            if info.is_subscribed {
                info.token_idx += 1;
            } else {
                info.is_subscribed = true;
                info.token_idx = 0;
            }

            // Restore nonce_base
            let mut nonce_bytes = [0u8; 16];
            nonce_bytes[16 - response.algo.nonce_len()..].copy_from_slice(response.nonce.as_ref());
            let nonce = u128::from_be_bytes(nonce_bytes);
            let nonce_base = nonce - (info.token_idx as u128);

            info.nonce_base = nonce_base;
            info.enc_key = response.enc_key;
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
        if !info.is_subscribed {
            println!("No subscription registered so far, blocking...",);
            return Ok(None);
        }

        // nonce
        let nonce =
            info.nonce_base + ((publish.pkid as u128).rotate_left(16) | (info.token_idx as u128));
        let nonce = utils::nonce_from_u128_to_bytes(info.algo, nonce);
        
        // seal
        in_out = BytesMut::with_capacity(2 + publish.topic.len() + publish.payload.len());
        in_out.put_u16(publish.topic.len() as u16);
        in_out.extend_from_slice(publish.topic.as_bytes());
        in_out.extend_from_slice(&publish.payload);
        tag = aead::seal(info.algo, &info.enc_key, &nonce, &mut in_out)
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
