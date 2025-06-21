use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::error::AuthServerParserError;
use crate::{
    aead::algo::SupportedAlgorithm,
    auth_serv_check_v2_header, auth_serv_read, auth_serv_read_into_new_bytes,
    auth_serv_read_into_new_mut_bytes, auth_serv_v2_header, auth_serv_write,
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
        // read header and token
        auth_serv_read_into_new_bytes!(buf, stream, 1 + TOKEN_LEN);

        // header
        auth_serv_check_v2_header!(buf[0], PACKET_TYPE_VERIFIER_REQUEST);

        Ok(Self {
            token: *&buf[1..].try_into().unwrap(),
        })
    }

    /// Writes [Request] to a stream.
    /// # Errors
    /// - [AuthServerParserError::SocketWriteError]
    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        let mut buf = BytesMut::with_capacity(1 + TOKEN_LEN);
        buf.put_u8(auth_serv_v2_header!(PACKET_TYPE_VERIFIER_REQUEST));
        buf.put(&self.token[..]);
        auth_serv_write!(stream, &buf[..]);
        Ok(buf.len())
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
///     [3:3+len_key]: session_key
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
///             - 1: AES_128_GCM,
///             - 2: AES_256_GCM,
///             - 3: CHACHA20_POLY1305
///     3. len_topic, big endian (len=2 bytes)
///     4. topic (len=len_topic bytes)
///     5. session_key
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
    pub session_key: Bytes,
}

impl ResponseReader {
    /// Reads a stream and returns a new [Request].
    /// # Errors
    /// - [AuthServerParserError::BufferTooSmallError]: buffer is too small
    /// - [AuthServerParserError::SocketReadError]: failed to read the stream
    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Option<Self>, AuthServerParserError> {
        // read header and status
        auth_serv_read_into_new_mut_bytes!(buf, stream, 1 + 1);

        // header
        auth_serv_check_v2_header!(buf.get_u8(), PACKET_TYPE_VERIFIER_RESPONSE);

        // status
        let status = ResponseStatus::from(buf.get_u8());
        if status != ResponseStatus::Success {
            return Ok(None);
        }

        // read compound and topic_len
        auth_serv_read_into_new_mut_bytes!(buf, stream, 1 + 2);

        // allowed_access, algo
        let compound = buf.get_u8();
        let allowed_access_is_pub = compound & 0x80 != 0;
        let algo = SupportedAlgorithm::try_from(compound & 0xF)?;

        // topic_len
        let topic_len = buf.get_u16() as usize;

        // read topic, session_key and nonce
        auth_serv_read_into_new_mut_bytes!(
            buf,
            stream,
            topic_len + algo.key_len() + algo.nonce_len()
        );
        let topic = buf.split_to(topic_len);
        let session_key = buf.split_to(algo.key_len());
        let nonce = buf;

        // topic (vector to convert in from_utf8)
        let topic = String::from_utf8(topic.to_vec())?;

        Ok(Some(Self {
            allowed_access_is_pub,
            algo,
            nonce,
            topic,
            session_key,
        }))
    }
}

#[derive(Debug)]
pub struct ResponseWriter {
    allowed_access_is_pub: bool,
    algo: SupportedAlgorithm,
    nonce: Bytes,
    topic: Bytes,
    session_key: Bytes,
}

impl ResponseWriter {
    pub fn new(
        allowed_access_is_pub: bool,
        algo: SupportedAlgorithm,
        nonce: Bytes,
        topic: Bytes,
        session_key: Bytes,
    ) -> Self {
        Self {
            allowed_access_is_pub,
            algo,
            nonce,
            topic,
            session_key,
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
        let is_full_resp = status == ResponseStatus::Success && resp.is_some();

        // Prep the buf
        let buf_capacity = if is_full_resp {
            // header, status, compound, topic_len, topic, session_key, nonce
            let unwrapped = resp.unwrap();
            5 + unwrapped.topic.len() + unwrapped.session_key.len() + unwrapped.nonce.len()
        } else {
            // only header and status
            2usize
        };
        let mut buf = BytesMut::with_capacity(buf_capacity);

        // header
        buf.put_u8(auth_serv_v2_header!(PACKET_TYPE_VERIFIER_RESPONSE));

        // status
        buf.put_u8(status as u8);
        if !is_full_resp {
            auth_serv_write!(stream, &buf[..]);
            return Ok(buf.len());
        }

        let resp = resp.unwrap();

        // other attributes if status is success
        let mut compound = resp.algo as u8;
        if resp.allowed_access_is_pub {
            compound |= 0x80;
        }
        buf.put_u8(compound);
        buf.put_u16(resp.topic.len() as u16);
        buf.put_slice(&resp.topic[..]);
        buf.put_slice(&resp.session_key[..]);
        buf.put_slice(&resp.nonce[..]);
        auth_serv_write!(stream, &buf[..]);
        Ok(buf.len())
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
        // packet should have a fixed size of 1 + TOKEN_LEN
        let mut mock_stream = Builder::new().read(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]).build();

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
        let mut read_buf = [0u8; 13];
        let _ = mock_stream.read(&mut read_buf).await;

        // starts with invalid header
        let mut mock_stream = Builder::new().read(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]).build();

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
        let mut read_buf = [0u8; 13];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    #[tokio::test]
    async fn response_write_read_success_roundtrip() {
        let original_resp_writer = ResponseWriter::new(
            true,                                 // allowed_access_is_pub
            SupportedAlgorithm::Chacha20Poly1305, // algo (3)
            Bytes::from_static(&[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ]), // nonce (12 bytes for CHACHA20)
            Bytes::from("verified/topic"),        // topic (14 bytes)
            Bytes::from_static(&[
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99,
            ]), // session_key (32 bytes for CHACHA20)
        );

        let expected_bytes = [
            0x20u8 | PACKET_TYPE_VERIFIER_RESPONSE,
            0x01, // Status: Success (1)
            0x83, // Compound byte: allowed_access_is_pub (1) | algo (3) = 0x83
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
        assert_eq!(
            parsed_resp.session_key.as_ref(),
            original_resp_writer.session_key
        );
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
