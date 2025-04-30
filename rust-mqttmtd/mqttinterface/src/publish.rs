use std::fmt::Display;

use base64::{Engine, engine::general_purpose};
use bytes::BytesMut;
use libmqttmtd::{
    aead::{self},
    auth_serv::verifier,
    socket::plain::PlainClient,
};
use mqttbytes::v5::Publish;

pub async fn publish_decode(
    verifier_port: u16,
    mut publish: Publish,
) -> Result<Option<Publish>, PublishDecodeError> {
    // topic
    let token = publish.topic;
    let decoded = general_purpose::STANDARD_NO_PAD.decode(token)?;

    // verify
    let res: Option<verifier::ResponseReader>;
    {
        let mut stream = PlainClient::new(format!("localhost:{}", verifier_port), None)
            .connect()
            .await?;
        let _req = verifier::Request::new(&decoded)?
            .write_to(&mut stream)
            .await?;
        let mut buf = BytesMut::with_capacity(1024);
        res = verifier::ResponseReader::read_from(&mut stream, &mut buf[..]).await?;
    } // stream

    if let Some(response) = res {
        let nonce_len = response.aead_algo.nonce_len();
        if nonce_len > response.nonce.len() {
            return Err(PublishDecodeError::NonceTooShortError);
        }

        let mut in_out = BytesMut::from(publish.payload);

        // open payload
        aead::open(
            response.aead_algo,
            &response.enc_key,
            &response.nonce,
            &mut in_out[..],
        )?;
        let tag_len = response.aead_algo.tag_len();

        publish.payload = in_out.split_to(tag_len).freeze();
        publish.topic = response.topic;

        Ok(Some(publish))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum PublishDecodeError {
    /// Wraps [base64::DecodeError]
    Base64DecodeError(base64::DecodeError),

    /// Wraps [libmqttmtd::auth_serv::error::AuthServerParserError]
    AuthServerPacketParseError(libmqttmtd::auth_serv::error::AuthServerParserError),

    /// Wraps [ring::error::Unspecified]
    RingDecodeError(ring::error::Unspecified),

    /// Wraps [libmqttmtd::socket::error::SocketError]
    AuthServerSocketError(libmqttmtd::socket::error::SocketError),

    /// Indicates that the nonce is too short
    NonceTooShortError,
}

impl std::error::Error for PublishDecodeError {}
impl Display for PublishDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishDecodeError::Base64DecodeError(e) => {
                write!(f, "base64 decode failed: {}", e)
            }
            PublishDecodeError::AuthServerPacketParseError(e) => {
                write!(f, "auth server packet parsing failed: {}", e)
            }
            PublishDecodeError::RingDecodeError(e) => {
                write!(f, "decoding with ring failed: {}", e)
            }
            PublishDecodeError::AuthServerSocketError(e) => {
                write!(f, "auth server socket failed: {}", e)
            }
            PublishDecodeError::NonceTooShortError => {
                write!(f, "nonce is too short")
            }
        }
    }
}

impl From<base64::DecodeError> for PublishDecodeError {
    fn from(value: base64::DecodeError) -> Self {
        PublishDecodeError::Base64DecodeError(value)
    }
}

impl From<libmqttmtd::auth_serv::error::AuthServerParserError> for PublishDecodeError {
    fn from(value: libmqttmtd::auth_serv::error::AuthServerParserError) -> Self {
        PublishDecodeError::AuthServerPacketParseError(value)
    }
}

impl From<ring::error::Unspecified> for PublishDecodeError {
    fn from(value: ring::error::Unspecified) -> Self {
        PublishDecodeError::RingDecodeError(value)
    }
}

impl From<libmqttmtd::socket::error::SocketError> for PublishDecodeError {
    fn from(value: libmqttmtd::socket::error::SocketError) -> Self {
        PublishDecodeError::AuthServerSocketError(value)
    }
}
