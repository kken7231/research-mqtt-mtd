use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::error::AuthServerParserError;
use crate::{
    aead::algo::SupportedAlgorithm,
    auth_serv_read, auth_serv_read_check_v2_header, auth_serv_read_into_new_bytes,
    auth_serv_read_u8, auth_serv_read_u16, auth_serv_write, auth_serv_write_u8,
    auth_serv_write_u16, auth_serv_write_v2_header,
    consts::{PACKET_TYPE_VERIFIER_REQUEST, PACKET_TYPE_VERIFIER_RESPONSE, TOKEN_LEN},
};

/// # Request for Verifier interface
///
/// # Structure:
///
/// ## v1
/// 1. `is_pub`
/// 2. `token`
///
/// ## v2
/// 0. header
/// 1. `token`
#[derive(Debug)]
pub struct Request {
    token: [u8; TOKEN_LEN],
}

impl Request {
    /// Gets the token.
    pub fn token(&self) -> &[u8; TOKEN_LEN] {
        &self.token
    }

    /// Creates a new [Request].
    /// # Errors
    /// - `token`.len() == [TOKEN_LEN]
    ///   ([AuthServerParserError::BufferTooSmallError])
    pub fn new(token: &[u8]) -> Result<Self, AuthServerParserError> {
        if token.len() != TOKEN_LEN {
            return Err(AuthServerParserError::BufferTooSmallError);
        }
        let mut new_token = [0u8; TOKEN_LEN];
        new_token.copy_from_slice(&token[..TOKEN_LEN]);
        Ok(Self { token: new_token })
    }

    /// Reads a stream and returns a new [Request].
    /// # Errors
    /// - [AuthServerParserError::SocketReadError]
    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Self, AuthServerParserError> {
        // header
        auth_serv_read_check_v2_header!(stream, PACKET_TYPE_VERIFIER_REQUEST);

        let mut token = [0u8; TOKEN_LEN];
        auth_serv_read!(stream, &mut token);
        Ok(Self { token })
    }

    /// Writes [Request] to a stream.
    /// # Errors
    /// - [AuthServerParserError::SocketWriteError]
    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        // header
        let mut counter = auth_serv_write_v2_header!(stream, PACKET_TYPE_VERIFIER_REQUEST);

        counter += auth_serv_write!(stream, &self.token);
        Ok(counter)
    }
}

/// # Response from Verifier interface
///
/// # Structure:
///
/// ## v1
/// ```text
/// case success+enc:
///     [0:2]: token_idx, big endian
///     [2]: aead_type
///     [3:3+len_key]: enc_key
///     [3+len_key:3+len_key+2]: len_topic, big endian
///     [3+len_key+2:3+len_key+2+len_topic]: topic
/// case success+noenc:
///     [0:2]: len_topic, big endian
///     [2:len_topic]: topic
/// case fail:
///     (none)
/// ```
///
/// ## v2
/// ```text
/// 0. header
/// 1. status
/// case success:
///     2. compound byte
///         - bit 7: allowed_access_is_pub
///         - bit 3-0: algo (len=1 byte)
///             - 0: AES_128_GCM,
///             - 1: AES_256_GCM,
///             - 2: CHACHA20_POLY1305
///     3. len_topic, big endian (len=2 bytes)
///     4. topic (len=len_topic bytes)
///     5. enc_key
///     6. nonce
/// case fail:
///     (none)
/// case error:
///     (none)
/// ```

#[derive(Debug)]
pub struct ResponseReader {
    pub allowed_access_is_pub: bool,
    pub algo: SupportedAlgorithm,
    pub nonce: Bytes,
    pub topic: String,
    pub enc_key: Bytes,
}

impl ResponseReader {
    /// Reads a stream and returns a new [Request].
    /// # Errors
    /// - [AuthServerParserError::BufferTooSmallError]: buffer is too small
    /// - [AuthServerParserError::SocketReadError]: failed to read the stream
    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Option<Self>, AuthServerParserError> {
        // header
        auth_serv_read_check_v2_header!(stream, PACKET_TYPE_VERIFIER_RESPONSE);

        // status
        let status_raw = auth_serv_read_u8!(stream);
        let status = ResponseStatus::from(status_raw);
        if status != ResponseStatus::Success {
            return Ok(None);
        }

        // allowed_access, algo
        let compound = auth_serv_read_u8!(stream);
        let allowed_access_is_pub = compound & 0x80 != 0;
        let algo = SupportedAlgorithm::try_from(compound & 0xF)?;

        // topic_len
        let topic_len = auth_serv_read_u16!(stream) as usize;

        // topic (vector to convert in from_utf8)
        auth_serv_read_into_new_bytes!(topic, stream, topic_len);
        let topic = String::from_utf8(topic.to_vec())?;

        auth_serv_read_into_new_bytes!(enc_key, stream, algo.key_len());
        auth_serv_read_into_new_bytes!(nonce, stream, algo.nonce_len());

        Ok(Some(Self {
            allowed_access_is_pub,
            algo,
            nonce,
            topic,
            enc_key,
        }))
    }
}

#[derive(Debug)]
pub struct ResponseWriter {
    allowed_access_is_pub: bool,
    algo: SupportedAlgorithm,
    nonce: Bytes,
    topic: Bytes,
    enc_key: Bytes,
}

impl ResponseWriter {
    pub fn new(
        allowed_access_is_pub: bool,
        algo: SupportedAlgorithm,
        nonce: Bytes,
        topic: Bytes,
        enc_key: Bytes,
    ) -> Self {
        Self {
            allowed_access_is_pub,
            algo,
            nonce,
            topic,
            enc_key,
        }
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, ResponseStatus::Error).await
    }

    pub async fn write_failure_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, ResponseStatus::Failure).await
    }

    pub async fn write_success_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(Some(&self), stream, ResponseStatus::Success).await
    }

    async fn write_to<W: AsyncWrite + Unpin>(
        resp: Option<&Self>,
        stream: &mut W,
        status: ResponseStatus,
    ) -> Result<usize, AuthServerParserError> {
        if let Some(r) = resp {
            if r.topic.len() > 0xFFFF {
                return Err(AuthServerParserError::TopicTooLongError);
            }
        }

        // header
        let mut counter = auth_serv_write_v2_header!(stream, PACKET_TYPE_VERIFIER_RESPONSE);

        // status
        counter += auth_serv_write_u8!(stream, status as u8);
        if status != ResponseStatus::Success || resp.is_none() {
            return Ok(counter);
        }

        let resp = resp.unwrap();

        // other attributes if status is success
        let mut compound = resp.algo as u8;
        if resp.allowed_access_is_pub {
            compound |= 0x80;
        }
        counter += auth_serv_write_u8!(stream, compound);
        counter += auth_serv_write_u16!(stream, resp.topic.len() as u16);
        counter += auth_serv_write!(stream, &resp.topic);
        counter += auth_serv_write!(stream, &resp.enc_key);
        counter += auth_serv_write!(stream, &resp.nonce);
        Ok(counter)
    }
}

#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ResponseStatus {
    Success = 0x01u8,
    Failure = 0x02u8,
    Error = 0xFFu8,
}

impl From<u8> for ResponseStatus {
    fn from(value: u8) -> Self {
        match value {
            1 => ResponseStatus::Success,
            2 => ResponseStatus::Failure,
            _ => ResponseStatus::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aead::algo::SupportedAlgorithm,
        auth_serv::{
            error::AuthServerParserError,
            verifier::{Request, ResponseReader, ResponseStatus, ResponseWriter},
        },
        consts::{PACKET_TYPE_VERIFIER_REQUEST, PACKET_TYPE_VERIFIER_RESPONSE},
    };
    use bytes::Bytes;
    use tokio::io::AsyncReadExt;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn request_write_read_roundtrip() {
        let original_token = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]; // Example TOKEN_LEN bytes
        let original_req = Request {
            token: original_token,
        };

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_VERIFIER_REQUEST,
            // Token
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
        ];

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = original_req
            .write_to(&mut mock_stream)
            .await
            .expect("Failed to write request");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_req = Request::read_from(&mut read_stream)
            .await
            .expect("Failed to read request");

        assert_eq!(parsed_req.token, original_token);
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn request_read_from_not_enough_bytes() {
        let mut mock_stream = Builder::new()
            .read(&[0x20u8 | PACKET_TYPE_VERIFIER_REQUEST, 0x1, 0x2, 0x3])
            .build(); // Less than TOKEN_LEN bytes

        let result = Request::read_from(&mut mock_stream).await;

        assert!(result.is_err());
        // Expect an IO error indicating unexpected EOF
        match result.unwrap_err() {
            AuthServerParserError::SocketReadError(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof)
            }
            _ => panic!(),
        };

        // Write in all the remained bytes
        let mut read_buf = [0u8; 4];
        let _ = mock_stream.read(&mut read_buf).await;
    }

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

        let result = ResponseReader::read_from(&mut mock_stream).await;

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
    async fn response_write_read_success_roundtrip() {
        let original_resp_writer = ResponseWriter::new(
            true,                                 // allowed_access_is_pub
            SupportedAlgorithm::Chacha20Poly1305, // algo (2)
            Bytes::from_static(&[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ]), // nonce (12 bytes for CHACHA20)
            Bytes::from("verified/topic"),        // topic (14 bytes)
            Bytes::from_static(&[
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99,
            ]), // enc_key (32 bytes for CHACHA20)
        );

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_VERIFIER_RESPONSE,
            0x01, // Status: Success (1)
            0x82, // Compound byte: allowed_access_is_pub (1) | algo (2) = 0x82
            0x00,
            0x0E, // Topic len: 14 (u16 BE)
            b'v',
            b'e',
            b'r',
            b'i',
            b'f',
            b'i',
            b'e',
            b'd',
            b'/',
            b't',
            b'o',
            b'p',
            b'i',
            b'c', // Topic: "verified/topic" (14 bytes)
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99,
            0xAA,
            0xBB,
            0xCC,
            0xDD,
            0xEE,
            0xFF,
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88,
            0x99, // Enc Key (32 bytes)
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C, // Nonce (12 bytes)
        ];

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = original_resp_writer
            .write_success_to(&mut mock_stream)
            .await
            .expect("Failed to write success response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_resp_option = ResponseReader::read_from(&mut read_stream)
            .await
            .expect("Failed to read response");

        assert!(parsed_resp_option.is_some());
        let parsed_resp = parsed_resp_option.unwrap();

        assert_eq!(
            parsed_resp.allowed_access_is_pub,
            original_resp_writer.allowed_access_is_pub
        );
        assert_eq!(parsed_resp.algo, original_resp_writer.algo);
        assert_eq!(parsed_resp.nonce.as_ref(), original_resp_writer.nonce);
        assert_eq!(parsed_resp.topic, original_resp_writer.topic);
        assert_eq!(parsed_resp.enc_key.as_ref(), original_resp_writer.enc_key);
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_write_read_failure_roundtrip() {
        // Mock stream to write failure response
        let expected_bytes = [
            0x20u8 | PACKET_TYPE_VERIFIER_RESPONSE,
            // Status: Failure (1)
            ResponseStatus::Failure as u8,
        ];

        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = ResponseWriter::write_failure_to(&mut mock_stream)
            .await
            .expect("Failed to write failure response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_resp_option = ResponseReader::read_from(&mut read_stream)
            .await
            .expect("Failed to read response");

        assert!(
            parsed_resp_option.is_none(),
            "Failure response should result in None"
        );
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_write_read_error_roundtrip() {
        // Mock stream to write error response
        let expected_bytes = [
            0x20u8 | PACKET_TYPE_VERIFIER_RESPONSE,
            // Status: Error (0xFF)
            ResponseStatus::Error as u8,
        ];

        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let written_len = ResponseWriter::write_error_to(&mut mock_stream)
            .await
            .expect("Failed to write error response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let parsed_resp_option = ResponseReader::read_from(&mut read_stream)
            .await
            .expect("Failed to read response");

        assert!(
            parsed_resp_option.is_none(),
            "Error response should result in None"
        );
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }
}
