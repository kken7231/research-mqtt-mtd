use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{aead::algo::SupportedAlgorithm, consts::TOKEN_LEN};

use super::error::AuthServerParserError;

/// Minimum required buffer length for the buf for both request parsing and response parsing.
pub const REQ_RESP_MIN_BUFLEN: usize = if REQUEST_MIN_BUFLEN > RESPONSE_MIN_BUFLEN {
    REQUEST_MIN_BUFLEN
} else {
    RESPONSE_MIN_BUFLEN
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
/// 1. `token`
#[derive(Debug)]
pub struct Request {
    token: [u8; TOKEN_LEN],
}

/// buffer not required
pub const REQUEST_MIN_BUFLEN: usize = 0;

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut hex_string = String::new();
        for byte in self.token {
            format!("{:02x}", byte).push_str(&mut hex_string);
        }
        write!(f, "verifier request: token:{}", hex_string)
    }
}

impl Request {
    pub fn token(&self) -> &[u8; TOKEN_LEN] {
        &self.token
    }

    pub fn new(token: &[u8]) -> Result<Self, AuthServerParserError> {
        if token.len() < TOKEN_LEN {
            Err(AuthServerParserError::BufferTooSmallError())
        } else {
            let mut new_token = [0u8; TOKEN_LEN];
            new_token.copy_from_slice(&token[..TOKEN_LEN]);
            Ok(Self { token: new_token })
        }
    }

    pub fn validate(&self) -> Vec<String> {
        vec![]
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Self, AuthServerParserError> {
        let mut token = [0u8; TOKEN_LEN];
        stream
            .read_exact(&mut token)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;

        Ok(Self { token })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.token)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.token.len())
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
/// 1. status
/// case success:
///     2. compound byte
///         - bit 7: allowed_access_is_pub
///         - bit 3-0: aead_algo (len=1 byte)
///             - 0: AES_128_GCM,
///             - 1: AES_256_GCM,
///             - 2: CHACHA20_POLY1305
///     3. nonce
///     4. len_topic, big endian (len=2 bytes)
///     5. topic (len=len_topic bytes)
///     6. enc_key (len=enc_key bytes)
/// case fail:
///     (none)
/// case error:
///     (none)
/// ```

#[derive(Debug)]
pub struct ResponseReader {
    pub allowed_access_is_pub: bool,
    pub aead_algo: SupportedAlgorithm,
    pub nonce: Bytes,
    pub topic: String,
    pub enc_key: Bytes,
}

/// buffer for status, len_topic, allowed_access, aead_type
pub const RESPONSE_MIN_BUFLEN: usize = 2;

impl ResponseReader {
    async fn _read_status<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<ResponseStatus, AuthServerParserError> {
        stream
            .read_exact(&mut buf[0..1])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(ResponseStatus::from(buf[0]))
    }

    async fn _read_is_pub_and_aead_algo<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<(bool, SupportedAlgorithm), AuthServerParserError> {
        stream
            .read_exact(&mut buf[0..1])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok((
            buf[0] & 0x80 != 0,
            SupportedAlgorithm::try_from(buf[0] & 0xF)?,
        ))
    }

    async fn _read_nonce<R: AsyncRead + Unpin>(
        stream: &mut R,
        nonce_len: usize,
    ) -> Result<Bytes, AuthServerParserError> {
        let mut nonce = BytesMut::zeroed(nonce_len);
        stream
            .read_exact(&mut nonce)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(nonce.freeze())
    }

    async fn _read_topic<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<String, AuthServerParserError> {
        // topic_len
        stream
            .read_exact(&mut buf[0..2])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        let topic_len = (usize::from(buf[0]) << 8) | (usize::from(buf[1]));

        // topic
        let mut topic = vec![0u8; topic_len];
        stream
            .read_exact(&mut topic)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;

        Ok(std::str::from_utf8(&topic[..])?.to_owned())
    }

    async fn _read_enc_key<R: AsyncRead + Unpin>(
        stream: &mut R,
        enc_key_len: usize,
    ) -> Result<Bytes, AuthServerParserError> {
        let mut enc_key = BytesMut::zeroed(enc_key_len);
        stream
            .read_exact(&mut enc_key)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(enc_key.freeze())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<Option<Self>, AuthServerParserError> {
        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < RESPONSE_MIN_BUFLEN => {
                return Err(AuthServerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; RESPONSE_MIN_BUFLEN][..],
        };

        // status
        let status = Self::_read_status(stream, buf).await?;
        if status != ResponseStatus::Success {
            return Ok(None);
        }

        // allowed_access, aead_algo
        let (allowed_access_is_pub, aead_algo) =
            Self::_read_is_pub_and_aead_algo(stream, buf).await?;

        // nonce
        let nonce = Self::_read_nonce(stream, aead_algo.nonce_len()).await?;

        // topic
        let topic = Self::_read_topic(stream, buf).await?;

        // enc_key
        let enc_key = Self::_read_enc_key(stream, aead_algo.key_len()).await?;

        Ok(Some(Self {
            nonce,
            allowed_access_is_pub,
            aead_algo,
            enc_key,
            topic,
        }))
    }
}

#[derive(Debug)]
pub struct ResponseWriter<'a, 'b, 'c> {
    allowed_access_is_pub: bool,
    aead_algo: SupportedAlgorithm,
    nonce: &'a [u8],
    topic: &'b str,
    enc_key: &'c [u8],
}

impl<'a, 'b, 'c> ResponseWriter<'a, 'b, 'c> {
    pub fn new(
        allowed_access_is_pub: bool,
        aead_algo: SupportedAlgorithm,
        nonce: &'a [u8],
        topic: &'b str,
        enc_key: &'c [u8],
    ) -> Self {
        Self {
            allowed_access_is_pub,
            aead_algo,
            nonce,
            topic,
            enc_key,
        }
    }

    async fn _write_status<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: &mut [u8],
        status: &ResponseStatus,
    ) -> Result<usize, AuthServerParserError> {
        buf[0] = *status as u8;
        stream
            .write_all(&mut buf[0..1])
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(1)
    }

    async fn _write_is_pub_and_aead_algo<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, AuthServerParserError> {
        buf[0] = if self.allowed_access_is_pub {
            0x80
        } else {
            0x00
        };
        buf[0] |= self.aead_algo as u8;
        stream
            .write_all(&mut buf[0..1])
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(1)
    }

    async fn _write_nonce<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.nonce)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.nonce.len())
    }

    async fn _write_topic<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, AuthServerParserError> {
        // topic_len
        let topic_len_bytes = self.topic.len().to_be_bytes();
        buf[0..2].copy_from_slice(&topic_len_bytes[topic_len_bytes.len() - 2..]);
        stream
            .write_all(&buf[0..2])
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;

        // topic
        stream
            .write_all(&self.topic.as_bytes())
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;

        Ok(2 + self.topic.len())
    }

    async fn _write_enc_key<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.enc_key)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.enc_key.len())
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Error).await
    }

    pub async fn write_failure_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Failure).await
    }

    pub async fn write_success_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(Some(&self), stream, buf, ResponseStatus::Success).await
    }

    async fn write_to<W: AsyncWrite + Unpin>(
        resp: Option<&Self>,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
        status: ResponseStatus,
    ) -> Result<usize, AuthServerParserError> {
        if let Some(r) = &resp {
            if r.topic.len() > 0xFFFF {
                return Err(AuthServerParserError::TopicTooLongError());
            }
        }

        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < RESPONSE_MIN_BUFLEN => {
                return Err(AuthServerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; RESPONSE_MIN_BUFLEN][..],
        };

        let mut cursor: usize = 0;

        // status
        cursor += Self::_write_status(stream, buf, &status).await?;
        if status != ResponseStatus::Success || resp.is_none() {
            return Ok(cursor);
        }

        let resp = resp.unwrap();

        // allowed_access, aead_algo
        cursor += resp._write_is_pub_and_aead_algo(stream, buf).await?;

        // nonce
        cursor += resp._write_nonce(stream).await?;

        // topic_len, topic
        cursor += resp._write_topic(stream, buf).await?;

        // enc_key
        cursor += resp._write_enc_key(stream).await?;

        Ok(cursor)
    }
}

#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ResponseStatus {
    Success = 0u8,
    Failure = 1u8,
    Error = 0xFFu8,
}

impl From<u8> for ResponseStatus {
    fn from(value: u8) -> Self {
        if value == 0 {
            Self::Success
        } else if value == 1 {
            Self::Failure
        } else {
            Self::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::algo::SupportedAlgorithm;
    use crate::auth_serv::{
        error::AuthServerParserError,
        verifier::{Request, ResponseReader, ResponseStatus, ResponseWriter},
    };
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

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&original_token).read(&[]).build();

        let written_len = original_req
            .write_to(&mut mock_stream)
            .await
            .expect("Failed to write request");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&original_token).build();

        let parsed_req = Request::read_from(&mut read_stream)
            .await
            .expect("Failed to read request");

        assert_eq!(parsed_req.token, original_token);
        assert_eq!(written_len, original_token.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn request_read_from_not_enough_bytes() {
        let mut mock_stream = Builder::new().read(&[0x01, 0x02, 0x03]).build(); // Less than TOKEN_LEN bytes

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
        let mut read_buf = [0u8; 3];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    #[tokio::test]
    async fn response_write_read_success_roundtrip() {
        let original_resp_writer = ResponseWriter::new(
            true,                                 // allowed_access_is_pub
            SupportedAlgorithm::Chacha20Poly1305, // aead_algo (2)
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            ], // nonce (12 bytes for CHACHA20)
            "verified/topic",                     // topic (14 bytes)
            &[
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                0x66, 0x77, 0x88, 0x99,
            ], // enc_key (32 bytes for CHACHA20)
        );

        let expected_bytes = [
            0x00, // Status: Success (0)
            0x82, // Compound byte: allowed_access_is_pub (1) | aead_algo (2) = 0x82
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, // Nonce (12 bytes)
            0x00, 0x0E, // Topic len: 14 (u16 BE)
            b'v', b'e', b'r', b'i', b'f', b'i', b'e', b'd', b'/', b't', b'o', b'p', b'i',
            b'c', // Topic: "verified/topic" (14 bytes)
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, // Enc Key (32 bytes)
        ];

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let mut write_buf = [0u8; 256]; // Provide buffer
        let written_len = original_resp_writer
            .write_success_to(&mut mock_stream, &mut write_buf[..])
            .await
            .expect("Failed to write success response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let mut read_buf = [0u8; 256]; // Provide buffer
        let parsed_resp_option = ResponseReader::read_from(&mut read_stream, &mut read_buf[..])
            .await
            .expect("Failed to read response");

        assert!(parsed_resp_option.is_some());
        let parsed_resp = parsed_resp_option.unwrap();

        assert_eq!(
            parsed_resp.allowed_access_is_pub,
            original_resp_writer.allowed_access_is_pub
        );
        assert_eq!(parsed_resp.aead_algo, original_resp_writer.aead_algo);
        assert_eq!(parsed_resp.nonce.as_ref(), original_resp_writer.nonce);
        assert_eq!(parsed_resp.topic, original_resp_writer.topic);
        assert_eq!(parsed_resp.enc_key.as_ref(), original_resp_writer.enc_key);
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_write_read_failure_roundtrip() {
        // Mock stream to write failure response
        let expected_bytes = [
            // Status: Failure (1)
            ResponseStatus::Failure as u8,
        ];

        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let mut write_buf = [0u8; 256]; // Provide buffer
        let written_len = ResponseWriter::write_failure_to(&mut mock_stream, &mut write_buf[..])
            .await
            .expect("Failed to write failure response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let mut read_buf = [0u8; 256]; // Provide buffer
        let parsed_resp_option = ResponseReader::read_from(&mut read_stream, &mut read_buf[..])
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
            // Status: Error (0xFF)
            ResponseStatus::Error as u8,
        ];

        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let mut write_buf = [0u8; 256]; // Provide buffer
        let written_len = ResponseWriter::write_error_to(&mut mock_stream, &mut write_buf[..])
            .await
            .expect("Failed to write error response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let mut read_buf = [0u8; 256]; // Provide buffer
        let parsed_resp_option = ResponseReader::read_from(&mut read_stream, &mut read_buf[..])
            .await
            .expect("Failed to read response");

        assert!(
            parsed_resp_option.is_none(),
            "Error response should result in None"
        );
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_read_from_buffer_too_small() {
        let mut mock_stream = Builder::new().read(&[0x00, 0x82, 0x01, 0x02]).build(); // Success + some data
        let mut small_buf = [0u8; 1]; // Buffer too small
        let result = ResponseReader::read_from(&mut mock_stream, &mut small_buf[..]).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            AuthServerParserError::BufferTooSmallError() => {}
            _ => panic!(),
        };

        // Write in all the remained bytes
        let mut read_buf = [0u8; 8];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    // Note: Testing the `handler` function directly is complex and requires
    // mocking the ATL interactions and controlling time.
}
