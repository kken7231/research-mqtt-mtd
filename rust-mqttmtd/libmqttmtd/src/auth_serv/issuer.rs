use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::error::{AuthServerParserError, IssuerRequestValidationError};
use crate::{
    aead::algo::SupportedAlgorithm,
    auth_serv_check_v2_header, auth_serv_v2_header, auth_serv_write,
    consts::{PACKET_TYPE_ISSUER_REQUEST, PACKET_TYPE_ISSUER_RESPONSE, TIMESTAMP_LEN},
    stream_read, stream_read_heap, stream_read_static, stream_read_topic,
};

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
        if self.topic.len() > 0xFFFF {
            return Err(IssuerRequestValidationError::TopicTooLongError);
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
        // read header, compound, algo and topic_len
        let mut buf = stream_read_static!(stream, 1 + 1 + 1 + 2);

        // header
        auth_serv_check_v2_header!(buf.get_u8(), PACKET_TYPE_ISSUER_REQUEST);

        // compound
        let compound = buf.get_u8();
        let is_pub = compound & 0x80 != 0;
        let num_tokens_divided_by_4 = compound & 0x7F;

        // algo
        let algo = SupportedAlgorithm::try_from(buf.get_u8())?;

        // topic_len
        let topic_len = buf.get_u16() as usize;

        // topic
        let topic = stream_read_topic!(stream, topic_len);

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

        // header, compound, algo and topic_len
        let mut buf = BytesMut::with_capacity(1 + 1 + 1 + 2 + self.topic.len());

        // HEADER
        buf.put_u8(auth_serv_v2_header!(PACKET_TYPE_ISSUER_REQUEST));

        // Write to stream
        let mut first_byte = *self.num_tokens_divided_by_4.to_be_bytes().last().unwrap() & 0x7F;
        if self.is_pub {
            first_byte |= 0x80;
        }
        buf.put_u8(first_byte);
        buf.put_u8(self.algo as u8);
        buf.put_u16(self.topic.len() as u16);
        buf.put_slice(self.topic.as_bytes());
        auth_serv_write!(stream, &buf[..]);
        Ok(buf.len())
    }
}

/// # Response from Issuer interface
///
/// # Structure:
///
/// ## v1
/// 1. `session_key` (optional)
/// 2. `timestamp`
/// 3. `all_random_bytes`
///
/// ## v2
/// 0. header
/// 1. `status` (u8, refer to [ResponseStatus])
/// 2. `session_key`
/// 3. `nonce_padding`
/// 4. `timestamp`
pub struct ResponseWriter {
    session_key: Bytes,
    nonce_padding: Bytes,
    timestamp: [u8; TIMESTAMP_LEN],
}

impl ResponseWriter {
    pub fn new(session_key: Bytes, nonce_padding: Bytes, timestamp: [u8; TIMESTAMP_LEN]) -> Self {
        Self {
            session_key,
            nonce_padding,
            timestamp,
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
        let is_full_resp = status == ResponseStatus::Success && resp.is_some();

        // Prep the buf
        let buf_capacity = if is_full_resp {
            // header, status, session_key, nonce_padding and timestamp
            let unwrapped = resp.unwrap();
            2 + unwrapped.session_key.len()
                + unwrapped.nonce_padding.len()
                + unwrapped.timestamp.len()
        } else {
            // only header and status
            2usize
        };
        let mut buf = BytesMut::with_capacity(buf_capacity);

        // header
        buf.put_u8(auth_serv_v2_header!(PACKET_TYPE_ISSUER_RESPONSE));

        // status
        buf.put_u8(status as u8);

        // status check
        if !is_full_resp {
            auth_serv_write!(stream, &buf[..]);
            return Ok(buf.len());
        }
        let resp = resp.unwrap();

        // other attributes if success
        buf.put_slice(&resp.session_key[..]);
        buf.put_slice(&resp.nonce_padding[..]);
        buf.put_slice(&resp.timestamp[..]);
        auth_serv_write!(stream, &buf[..]);
        Ok(buf.len())
    }
}

#[derive(Debug)]
pub struct ResponseReader {
    session_key: Bytes,
    nonce_padding: Bytes,
    timestamp: [u8; TIMESTAMP_LEN],
}

impl ResponseReader {
    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }

    pub fn nonce_padding(&self) -> &[u8] {
        &self.nonce_padding
    }

    pub fn timestamp(&self) -> &[u8; TIMESTAMP_LEN] {
        &self.timestamp
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        algo: SupportedAlgorithm,
    ) -> Result<Option<Self>, AuthServerParserError> {
        // read header and status
        let mut buf = stream_read_static!(stream, 2);

        // header
        auth_serv_check_v2_header!(buf.get_u8(), PACKET_TYPE_ISSUER_RESPONSE);

        // status
        let status = ResponseStatus::from(buf.get_u8());
        if status != ResponseStatus::Success {
            return Ok(None);
        }

        // other attributes if success
        let mut buf = stream_read_heap!(
            stream,
            algo.key_len() + algo.nonce_len() - 4 + TIMESTAMP_LEN
        );
        let session_key = buf.split_to(algo.key_len());
        let nonce_padding = buf.split_to(algo.nonce_len() - 4);
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        buf.copy_to_slice(&mut timestamp);

        Ok(Some(Self {
            session_key,
            nonce_padding,
            timestamp,
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
    };

    use crate::consts::{PACKET_TYPE_ISSUER_REQUEST, PACKET_TYPE_ISSUER_RESPONSE};
    use bytes::Bytes;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn request_response_read_from_invalid_header() {
        // starts with invalid header
        // at least a packet has 6 bytes
        let mut mock_stream = Builder::new()
            .read(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .build();

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
        let mut read_buf = [0u8; 6];
        let _ = mock_stream.read(&mut read_buf).await;

        // starts with invalid header
        let mut mock_stream = Builder::new()
            .read(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            .build();

        let result = ResponseReader::read_from(
            &mut mock_stream,
            SupportedAlgorithm::Aes128Gcm, // Dummy algo (not used for error)
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
        let mut read_buf = [0u8; 6];
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
            0x02, // AEAD Algo: Aes256Gcm (2)
            // Topic len: "test/topic/req" is 14 bytes (u16 BE)
            0x00,
            0x0E, // Topic: "test/topic/req"
            b't',
            b'e',
            b's',
            b't',
            b'/',
            b't',
            b'o',
            b'p',
            b'i',
            b'c',
            b'/',
            b'r',
            b'e',
            b'q',
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
    async fn response_write_read_success_roundtrip() {
        let session_key = Bytes::from_static(&[
            0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
            0x33, 0x44,
        ]); // Dummy key
        let timestamp = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // Dummy timestamp
        let nonce_padding = Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB]); // Dummy nonce_padding

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_ISSUER_RESPONSE,
            0x01, // Status: Success (1)
            0x11,
            0x22,
            0x33,
            0x44,
            0x11,
            0x22,
            0x33,
            0x44,
            0x11,
            0x22,
            0x33,
            0x44,
            0x11,
            0x22,
            0x33,
            0x44, /* session_key: [0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
                   * 0x33, 0x44, 0x11, 0x22, 0x33, 0x44] */
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0xAA,
            0xBB, /* nonce_padding: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB] */
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF, // timestamp: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        ];

        let original_resp_writer = ResponseWriter::new(session_key, nonce_padding, timestamp);

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = original_resp_writer
            .write_success_to(&mut mock_stream)
            .await
            .expect("Failed to write response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_resp_option =
            ResponseReader::read_from(&mut read_stream, SupportedAlgorithm::Aes128Gcm)
                .await
                .expect("Failed to read response");

        assert!(parsed_resp_option.is_some());
        let parsed_resp = parsed_resp_option.unwrap();

        assert_eq!(
            parsed_resp.session_key.as_ref(),
            original_resp_writer.session_key.as_ref()
        );
        assert_eq!(parsed_resp.timestamp, timestamp);
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
