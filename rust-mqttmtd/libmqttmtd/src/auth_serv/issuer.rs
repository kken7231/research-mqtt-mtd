use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::error::{AuthServerParserError, IssuerRequestValidationError};
use crate::{aead::algo::SupportedAlgorithm, auth_serv_read, auth_serv_read_check_v2_header, auth_serv_read_into_new_bytes, auth_serv_read_u16, auth_serv_read_u8, auth_serv_write, auth_serv_write_v2_header, auth_serv_write_u16, auth_serv_write_u8, consts::{RANDOM_LEN, TIMESTAMP_LEN}};
use crate::consts::{PACKET_TYPE_ISSUER_REQUEST, PACKET_TYPE_ISSUER_RESPONSE};

/// # Request for Issuer interface
///
/// # Structure:
///
/// ## v1
/// 1. Compound byte
///   - bit 7 `is_pub`: tokens for pub/sub
///   - bit 6 `payload_aead_request`: on if optional aead requested
///   - bit 5-0 `num_tokens_divided_by_multiplier`: `num_tokens` is calculated
///     as multiplication with MULTIPLIER
/// 2. `topic_len` (u16, big endian): length of `topic`
/// 3. `topic`: Topic Names or Topic Filters
///
/// ## v2 (this implementation)
/// 0. header
/// 1. Compound byte
///   - bit 7: `is_pub`: tokens for pub/sub
///   - bit 6-0: `num_tokens_divided_by_4`: number of tokens divided by 4
/// 2. `algo` (u8): AEAD algorithm identifier according to
///    [libmqttmtd::aead::algo::SupportedAlgorithm]
/// 3. `topic_len` (u16, big endian): length of `topic`
/// 4. `topic`: Topic Names or Topic Filters
#[derive(Debug)]
pub struct Request {
    is_pub: bool,
    num_tokens_divided_by_4: u8,
    algo: SupportedAlgorithm,
    topic: String,
}

impl Request {
    pub fn new(
        is_pub: bool,
        num_tokens_divided_by_4: u8,
        algo: SupportedAlgorithm,
        topic: impl Into<String>,
    ) -> Result<Self, IssuerRequestValidationError> {
        let req = Self {
            is_pub,
            num_tokens_divided_by_4,
            algo,
            topic: topic.into(),
        };
        req.validate()?;
        Ok(req)
    }

    pub fn validate(&self) -> Result<(), IssuerRequestValidationError> {
        if self.num_tokens_divided_by_4 == 0 || self.num_tokens_divided_by_4 > 0x7F {
            return Err(IssuerRequestValidationError::NumTokensDiv4OutOfRangeError(
                self.num_tokens_divided_by_4,
            ));
        }
        if self.topic.len() == 0 {
            return Err(IssuerRequestValidationError::EmptyTopicError);
        }
        Ok(())
    }

    pub fn is_pub(&self) -> bool {
        self.is_pub
    }

    pub fn num_tokens_divided_by_4(&self) -> u8 {
        self.num_tokens_divided_by_4
    }

    pub fn algo(&self) -> SupportedAlgorithm {
        self.algo
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Self, AuthServerParserError> {
        // header
        auth_serv_read_check_v2_header!(stream, PACKET_TYPE_ISSUER_REQUEST);

        // compound
        let compound = auth_serv_read_u8!(stream);
        let is_pub = compound & 0x80 != 0;
        let num_tokens_divided_by_4 = compound & 0x7F;

        // algo
        let algo = SupportedAlgorithm::try_from(auth_serv_read_u8!(stream))?;

        // topic_len
        let topic_len = auth_serv_read_u16!(stream) as usize;

        // topic
        auth_serv_read_into_new_bytes!(topic, stream, topic_len);
        let topic = String::from_utf8(topic.to_vec())?;

        Ok(Self::new(is_pub, num_tokens_divided_by_4, algo, topic)?)
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        // Topic len check
        if self.topic.len() > 0xFFFF {
            return Err(AuthServerParserError::TopicTooLongError);
        }

        // HEADER
        let mut counter = auth_serv_write_v2_header!(stream, PACKET_TYPE_ISSUER_REQUEST);

        // Write to stream
        let mut first_byte = *self.num_tokens_divided_by_4.to_be_bytes().last().unwrap() & 0x7F;
        if self.is_pub {
            first_byte |= 0x80;
        }
        counter += auth_serv_write_u8!(stream, first_byte);
        counter += auth_serv_write_u8!(stream, self.algo as u8);
        counter += auth_serv_write_u16!(stream, self.topic.len() as u16);
        counter += auth_serv_write!(stream, self.topic.as_bytes());
        Ok(counter)
    }
}

/// # Response from Issuer interface
///
/// # Structure:
///
/// ## v1
/// 1. `enc_key` (optional)
/// 2. `timestamp`
/// 3. `all_random_bytes`
///
/// ## v2
/// 0. header
/// 1. `status` (u8, refer to [ResponseStatus])
/// 2. `enc_key`
/// 3. `nonce_base`
/// 4. `timestamp`
/// 5. `all_randoms` (length = num_tokens_divided_by_4*4*RANDOM_LEN)
pub struct ResponseWriter {
    enc_key: Bytes,
    nonce_base: Bytes,
    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: Bytes,
}

impl ResponseWriter {
    pub fn new(
        enc_key: Bytes,
        nonce_base: Bytes,
        timestamp: [u8; TIMESTAMP_LEN],
        all_randoms: Bytes,
    ) -> Self {
        Self {
            enc_key,
            nonce_base,
            timestamp,
            all_randoms,
        }
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, self::ResponseStatus::Error).await
    }

    pub async fn write_success_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(Some(self), stream, ResponseStatus::Success).await
    }

    async fn write_to<W: AsyncWrite + Unpin>(
        resp: Option<&Self>,
        stream: &mut W,
        status: ResponseStatus,
    ) -> Result<usize, AuthServerParserError> {
        // header
        let mut counter = auth_serv_write_v2_header!(stream, PACKET_TYPE_ISSUER_RESPONSE);

        // status
        counter += auth_serv_write_u8!(stream, status as u8);

        // status check
        if status != ResponseStatus::Success || resp.is_none() {
            return Ok(counter);
        }
        let resp = resp.unwrap();

        // other attributes if success
        counter += auth_serv_write!(stream, &resp.enc_key);
        counter += auth_serv_write!(stream, &resp.nonce_base);
        counter += auth_serv_write!(stream, &resp.timestamp);
        counter += auth_serv_write!(stream, &resp.all_randoms);
        Ok(counter)
    }
}

#[derive(Debug)]
pub struct ResponseReader {
    enc_key: Bytes,
    nonce_base: Bytes,
    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: Bytes,
}

impl ResponseReader {
    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn nonce_base(&self) -> &[u8] {
        &self.nonce_base
    }

    pub fn timestamp(&self) -> &[u8; TIMESTAMP_LEN] {
        &self.timestamp
    }

    pub fn all_randoms(&self) -> &[u8] {
        &self.all_randoms
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        algo: SupportedAlgorithm,
        num_tokens_divided_by_4: u8,
    ) -> Result<Option<Self>, AuthServerParserError> {
        // header
        auth_serv_read_check_v2_header!(stream, PACKET_TYPE_ISSUER_RESPONSE);

        // status
        let status = ResponseStatus::from(auth_serv_read_u8!(stream));
        if status != ResponseStatus::Success {
            return Ok(None);
        }

        // other attributes if success
        auth_serv_read_into_new_bytes!(enc_key, stream, algo.key_len());
        auth_serv_read_into_new_bytes!(nonce_base, stream, algo.nonce_len());
        auth_serv_read_into_new_bytes!(timestamp, stream, TIMESTAMP_LEN);
        auth_serv_read_into_new_bytes!(
            all_randoms,
            stream,
            ((num_tokens_divided_by_4 as usize) << 2) * RANDOM_LEN
        );

        Ok(Some(Self {
            enc_key,
            nonce_base,
            timestamp: timestamp.as_ref().try_into().unwrap(),
            all_randoms,
        }))
    }
}

#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ResponseStatus {
    Success = 0x01u8,
    Error = 0xFFu8,
}

impl From<u8> for ResponseStatus {
    fn from(value: u8) -> Self {
        if value == 1 {
            Self::Success
        } else {
            Self::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aead::algo::SupportedAlgorithm,
        auth_serv::{
            error::AuthServerParserError,
            issuer::{Request, ResponseReader, ResponseWriter},
        },
        consts::RANDOM_LEN,
    };

    use bytes::Bytes;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio_test::io::Builder;
    use crate::consts::{PACKET_TYPE_ISSUER_REQUEST, PACKET_TYPE_ISSUER_RESPONSE};

    #[tokio::test]
    async fn request_response_read_from_invalid_header() {
        // starts with invalid header
        let mut mock_stream = Builder::new().read(&[0x01]).build();

        let result = Request::read_from(&mut mock_stream).await;

        assert!(result.is_err());
        // Expect an IO error indicating unexpected EOF
        match result.unwrap_err() {
            AuthServerParserError::InvalidHeaderError(v) => {
                assert_eq!(v, 0x01u8)
            }
            _ => panic!(),
        };

        // Write in all the remained bytes
        let mut read_buf = [0u8; 4];
        let _ = mock_stream.read(&mut read_buf).await;

        // starts with invalid header
        let mut mock_stream = Builder::new().read(&[0x01]).build();

        let result = ResponseReader::read_from(
            &mut mock_stream,
            SupportedAlgorithm::Aes128Gcm, // Dummy algo (not used for error)
            1,        // Dummy num_tokens_divided_dy_4 (not used for error)
        )
            .await;

        assert!(result.is_err());
        // Expect an IO error indicating unexpected EOF
        match result.unwrap_err() {
            AuthServerParserError::InvalidHeaderError(v) => {
                assert_eq!(v, 0x01)
            }
            _ => panic!(),
        };

        // Write in all the remained bytes
        let mut read_buf = [0u8; 4];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    #[tokio::test]
    async fn request_write_read_roundtrip() {
        let original_req = Arc::new(
            Request::new(
                true,                          // is_pub
                5,                             // num_tokens_divided_dy_4 (fits in 7 bits)
                SupportedAlgorithm::Aes256Gcm, // algo
                "test/topic/req".to_string(),  // topic
            )
            .expect("failed to create a request"),
        );

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_ISSUER_REQUEST,
            0x85, // Compound byte: is_pub (1) | num_tokens_divided_dy_4 (5) = 0x85
            0x01, // AEAD Algo: Aes256Gcm (1)
            // Topic len: "test/topic/req" is 14 bytes (u16 BE)
            0x00, 0x0E, // Topic: "test/topic/req"
            b't', b'e', b's', b't', b'/', b't', b'o', b'p', b'i', b'c', b'/', b'r', b'e', b'q',
        ];

        // Mock stream to write to and then read from
        let mut write_stream = Builder::new().write(&expected_bytes[..]).build();

        let written_len = original_req
            .write_to(&mut write_stream)
            .await
            .expect("Failed to write request");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes[..]).build();

        let parsed_req = Request::read_from(&mut read_stream)
            .await
            .expect("Failed to read request");

        assert_eq!(parsed_req.is_pub, original_req.is_pub);
        assert_eq!(
            parsed_req.num_tokens_divided_by_4,
            original_req.num_tokens_divided_by_4
        );
        assert_eq!(parsed_req.algo, original_req.algo);
        assert_eq!(parsed_req.topic, original_req.topic);
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn request_write_to_topic_too_long() {
        let long_topic = "a".repeat(0xFFFF + 1); // Longer than u16 max
        let original_req = Request::new(true, 1, SupportedAlgorithm::Aes128Gcm, long_topic)
            .expect("failed to create a request");

        let mut mock_stream = Builder::new().build();
        let result = original_req.write_to(&mut mock_stream).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AuthServerParserError::TopicTooLongError => {}
            _ => panic!(),
        };
    }


    #[tokio::test]
    async fn response_write_read_success_roundtrip() {
        let enc_key = Bytes::from_static(&[
            0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
            0x33, 0x44,
        ]); // Dummy key
        let timestamp = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // Dummy timestamp
        let nonce_base = Bytes::from_static(&[
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]); // Dummy nonce_base
        let all_randoms = Bytes::from_static(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ]); // Dummy randoms (e.g., 1 token * 8 bytes)

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_ISSUER_RESPONSE,
            0x01, // Status: Success (1)
            0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
            0x33,
            0x44, /* enc_key: [0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33,
                   * 0x44, 0x11, 0x22, 0x33, 0x44] */
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, /* nonce_base: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD,
                   * 0xEE, 0xFF] */
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, // timestamp: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
            // all_randoms: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            // 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];

        let original_resp_writer = ResponseWriter::new(enc_key, nonce_base, timestamp, all_randoms);

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = original_resp_writer
            .write_success_to(&mut mock_stream)
            .await
            .expect("Failed to write response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        println!(
            "{}",
            (original_resp_writer.all_randoms.len() / RANDOM_LEN).rotate_right(2)
        );
        let parsed_resp_option = ResponseReader::read_from(
            &mut read_stream,
            SupportedAlgorithm::Aes128Gcm,
            (original_resp_writer.all_randoms.len() / RANDOM_LEN).rotate_right(2) as u8, // num_tokens_divided_dy_4
        )
        .await
        .expect("Failed to read response");

        assert!(parsed_resp_option.is_some());
        let parsed_resp = parsed_resp_option.unwrap();

        assert_eq!(
            parsed_resp.enc_key.as_ref(),
            original_resp_writer.enc_key.as_ref()
        );
        assert_eq!(parsed_resp.timestamp, timestamp);
        assert_eq!(
            parsed_resp.all_randoms.as_ref(),
            original_resp_writer.all_randoms.as_ref()
        );
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_write_read_error_roundtrip() {
        // Mock stream to write error response
        let expected_bytes = [
            0x20u8 | PACKET_TYPE_ISSUER_RESPONSE,
            // Status: Error (0xFF)
            0xFF,
        ];
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = ResponseWriter::write_error_to(&mut mock_stream)
            .await
            .expect("Failed to write error response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_resp_option = ResponseReader::read_from(
            &mut read_stream,
            SupportedAlgorithm::Aes128Gcm, // Dummy algo (not used for error)
            1,                             // Dummy num_tokens_divided_dy_4 (not used for error)
        )
        .await
        .expect("Failed to read response");

        assert!(
            parsed_resp_option.is_none(),
            "Error response should result in None"
        );
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }
}
