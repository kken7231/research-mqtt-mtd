use std::fmt::Display;

use base64::{engine::general_purpose, Engine};
use bytes::BytesMut;
use libmqttmtd::{
    aead::{self},
    auth_serv::verifier,
    socket::plain::PlainClient,
};
use mqttbytes::v5::Publish;
use crate::mqttinterface_println;

/// Decodes publish packet from clients, replaces token and passes it down to Broker.
pub async fn freeze_publish(
    verifier_port: u16,
    mut publish: Publish,
) -> Result<Option<Publish>, PublishFreezeError> {
    // topic
    let token = publish.topic;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| PublishFreezeError::TokenDecodeError(e))?;
    mqttinterface_println!("decoded: {:?}", decoded);
    
    // verify
    let res: Option<verifier::ResponseReader>;
    {
        let req = verifier::Request::new(&decoded)
            .map_err(|e| PublishFreezeError::VerifierRequestCreateError(e))?;
        let mut stream = PlainClient::new(format!("localhost:{}", verifier_port), None)
            .connect()
            .await
            .map_err(|e| PublishFreezeError::VerifierConnectError(e))?;
        let _ = req
            .write_to(&mut stream)
            .await
            .map_err(|e| PublishFreezeError::VerifierRequestWriteError(e))?;
        let mut buf = BytesMut::zeroed(verifier::REQ_RESP_MIN_BUFLEN);
        res = verifier::ResponseReader::read_from(&mut stream, &mut buf[..])
            .await
            .map_err(|e| PublishFreezeError::VerifierResponseReadError(e))?;
    } // stream

    if let Some(response) = res {
        let nonce_len = response.aead_algo.nonce_len();
        if nonce_len > response.nonce.len() {
            return Err(PublishFreezeError::NonceTooShortError);
        }

        let mut in_out = BytesMut::from(publish.payload);

        // open payload
        aead::open(
            response.aead_algo,
            &response.enc_key,
            &response.nonce,
            &mut in_out[..],
        )
            .map_err(|e| PublishFreezeError::PayloadOpenError(e))?;
        let tag_len = response.aead_algo.tag_len();

        publish.payload = in_out.split_to(tag_len).freeze();
        publish.topic = response.topic;

        Ok(Some(publish))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum PublishFreezeError {
    /// Wraps [base64::DecodeError]
    TokenDecodeError(base64::DecodeError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on request generation
    VerifierRequestCreateError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [libmqttmtd::socket::error::SocketError] error on client connect
    VerifierConnectError(libmqttmtd::socket::error::SocketError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on writing request
    VerifierRequestWriteError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError] error on reading response
    VerifierResponseReadError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [ring::error::Unspecified] on opening sealed payload
    PayloadOpenError(ring::error::Unspecified),

    /// Indicates that the nonce is too short
    NonceTooShortError,
}

impl std::error::Error for PublishFreezeError {}
impl Display for PublishFreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishFreezeError::TokenDecodeError(e) => {
                write!(f, "token decoding (base64) failed: {}", e)
            }
            PublishFreezeError::VerifierRequestCreateError(e) => {
                write!(f, "failed to create a verifier request: {}", e)
            }
            PublishFreezeError::VerifierConnectError(e) => {
                write!(f, "failed to connect to verifier: {}", e)
            }
            PublishFreezeError::VerifierRequestWriteError(e) => {
                write!(f, "failed to write request to verifier: {}", e)
            }
            PublishFreezeError::VerifierResponseReadError(e) => {
                write!(f, "failed to read response from verifier: {}", e)
            }
            PublishFreezeError::PayloadOpenError(e) => {
                write!(f, "failed to open a sealed message: {}", e)
            }
            PublishFreezeError::NonceTooShortError => {
                write!(f, "nonce is too short")
            }
        }
    }
}
