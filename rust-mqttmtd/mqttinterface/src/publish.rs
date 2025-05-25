use std::fmt::Display;

use base64::{engine::general_purpose, Engine};
use bytes::BytesMut;
use libmqttmtd::{
    aead::{self},
    auth_serv::verifier,
    socket::plain::PlainClient,
};
use mqttbytes::v5::Publish;

/// Decrypts publish packet from clients, replaces token and passes it down to
/// Broker.
pub async fn unfreeze_publish(
    verifier_port: u16,
    mut publish: Publish,
) -> Result<Option<Publish>, PublishUnfreezeError> {
    // topic
    let token = publish.topic;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| PublishUnfreezeError::TokenDecodeError(e))?;

    // verify
    let res: Option<verifier::ResponseReader>;
    {
        let req = verifier::Request::new(&decoded)
            .map_err(|e| PublishUnfreezeError::VerifierRequestCreateError(e))?;
        let mut stream = PlainClient::new(format!("localhost:{}", verifier_port), None)
            .connect()
            .await
            .map_err(|e| PublishUnfreezeError::VerifierConnectError(e))?;
        let _ = req
            .write_to(&mut stream)
            .await
            .map_err(|e| PublishUnfreezeError::VerifierRequestWriteError(e))?;
        res = verifier::ResponseReader::read_from(&mut stream)
            .await
            .map_err(|e| PublishUnfreezeError::VerifierResponseReadError(e))?;
    } // stream

    if let Some(response) = res {
        let nonce_len = response.algo.nonce_len();
        if nonce_len > response.nonce.len() {
            return Err(PublishUnfreezeError::NonceTooShortError);
        }

        let mut in_out = BytesMut::from(publish.payload);

        // open payload
        aead::open(
            response.algo,
            &response.enc_key,
            &response.nonce,
            &mut in_out[..],
        )
            .map_err(|e| PublishUnfreezeError::PayloadOpenError(e))?;
        let tag_len = response.algo.tag_len();
        in_out.truncate(in_out.len() - tag_len);
        publish.payload = in_out.freeze();
        publish.topic = response.topic;

        Ok(Some(publish))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum PublishUnfreezeError {
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

    /// Wraps [ring::error::Unspecified] on opening sealed payload
    PayloadOpenError(ring::error::Unspecified),

    /// Indicates that the nonce is too short
    NonceTooShortError,
}

impl std::error::Error for PublishUnfreezeError {}
impl Display for PublishUnfreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishUnfreezeError::TokenDecodeError(e) => {
                write!(f, "token decoding (base64) failed: {}", e)
            }
            PublishUnfreezeError::VerifierRequestCreateError(e) => {
                write!(f, "failed to create a verifier request: {}", e)
            }
            PublishUnfreezeError::VerifierConnectError(e) => {
                write!(f, "failed to connect to verifier: {}", e)
            }
            PublishUnfreezeError::VerifierRequestWriteError(e) => {
                write!(f, "failed to write request to verifier: {}", e)
            }
            PublishUnfreezeError::VerifierResponseReadError(e) => {
                write!(f, "failed to read response from verifier: {}", e)
            }
            PublishUnfreezeError::PayloadOpenError(e) => {
                write!(f, "failed to open a sealed message: {}", e)
            }
            PublishUnfreezeError::NonceTooShortError => {
                write!(f, "nonce is too short")
            }
        }
    }
}
