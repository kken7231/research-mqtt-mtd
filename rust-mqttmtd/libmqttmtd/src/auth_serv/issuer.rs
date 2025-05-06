use std::ops::Shl;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    aead::algo::SupportedAlgorithm,
    consts::{RANDOM_LEN, TIMESTAMP_LEN},
};

use super::error::AuthServerParserError;

/// # Request for Issuer interface
///
/// # Structure:
///
/// ## v1
/// 1. Compound byte
///   - bit 7 `is_pub`: tokens for pub/sub
///   - bit 6 `payload_aead_request`: on if optional aead requested
///   - bit 5-0 `num_tokens_divided_by_multiplier`: `num_tokens` is calculated as multiplication with MULTIPLIER
/// 2. `topic_len` (u16, big endian): length of `topic`
/// 3. `topic`: Topic Names or Topic Filters
///
/// ## v2 (this implementation)
/// 1. Compound byte
///   - bit 7: `is_pub`: tokens for pub/sub
///   - bit 6-0: `num_tokens_divided_by_4`: number of tokens divided by 4
/// 2. `aead_algo` (u8): AEAD algorithm identifier according to [libmqttmtd::aead::algo::SupportedAlgorithm]
/// 3. `topic_len` (u16, big endian): length of `topic`
/// 4. `topic`: Topic Names or Topic Filters
#[derive(Debug)]
pub struct Request {
    is_pub: bool,
    num_tokens_divided_by_4: u8,
    aead_algo: SupportedAlgorithm,
    topic: String,
}

/// buffer for (compound byte + aead_algo) and topic_len
pub const REQUEST_MIN_BUFLEN: usize = 2;

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "issuer resuest: is_pub:{}, num_tokens_divided_dy_4:{}, topic:\"{}\"",
            self.is_pub, self.num_tokens_divided_by_4, self.topic
        )
    }
}

impl Request {
    pub fn new(
        is_pub: bool,
        num_tokens_divided_by_4: u8,
        aead_algo: SupportedAlgorithm,
        topic: String,
    ) -> Self {
        Self {
            is_pub,
            num_tokens_divided_by_4,
            aead_algo,
            topic,
        }
    }

    pub fn is_pub(&self) -> bool {
        self.is_pub
    }

    pub fn num_tokens_divided_by_4(&self) -> u8 {
        self.num_tokens_divided_by_4
    }

    pub fn aead_algo(&self) -> SupportedAlgorithm {
        self.aead_algo
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    async fn _read_compound_aead_algo<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<(bool, u8, SupportedAlgorithm), AuthServerParserError> {
        stream
            .read_exact(&mut buf[0..2])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        let is_pub = buf[0] & 0x80 != 0;
        let num_tokens_divided_by_4 = buf[0] & 0x7F;
        let aead_algo = SupportedAlgorithm::try_from(buf[1])?;
        Ok((is_pub, num_tokens_divided_by_4, aead_algo))
    }

    async fn _write_compound_aead_algo<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, AuthServerParserError> {
        let mut first_byte = *self.num_tokens_divided_by_4.to_be_bytes().last().unwrap() & 0x7F;
        if self.is_pub {
            first_byte |= 0x80;
        }
        buf[0] = first_byte;
        buf[1] = self.aead_algo as u8;
        stream
            .write_all(&buf[0..2])
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(2)
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
        let topic_len = (usize::from(buf[0]) << 8) | usize::from(buf[1]);

        // topic
        let mut topic = vec![0u8; topic_len];
        stream
            .read_exact(&mut topic)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;

        Ok(std::str::from_utf8(&topic[..])?.to_owned())
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

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<Self, AuthServerParserError> {
        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < REQUEST_MIN_BUFLEN => {
                return Err(AuthServerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; REQUEST_MIN_BUFLEN][..],
        };

        // is_pub, num_tokens_divided_dy_4, aead_algo
        let (is_pub, num_tokens_divided_by_4, aead_algo) =
            Self::_read_compound_aead_algo(stream, buf).await?;

        // topic_len, topic
        let topic = Self::_read_topic(stream, buf).await?;

        Ok(Self {
            is_pub,
            num_tokens_divided_by_4,
            aead_algo,
            topic,
        })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        if self.topic.len() > 0xFFFF {
            return Err(AuthServerParserError::TopicTooLongError());
        }

        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < REQUEST_MIN_BUFLEN => {
                return Err(AuthServerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; REQUEST_MIN_BUFLEN][..],
        };

        let mut cursor: usize = 0;

        // is_pub, num_tokens_divided_dy_4, aead_algo
        cursor += self._write_compound_aead_algo(stream, buf).await?;

        // topic_len, topic
        cursor += self._write_topic(stream, buf).await?;

        Ok(cursor)
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
/// 1. `status` (u8, refer to [self::ResponseStatus])
/// 2. `enc_key`
/// 3. `nonce_base`
/// 4. `timestamp`
/// 5. `all_randoms` (length = num_tokens_divided_by_4*4*RANDOM_LEN)

pub struct ResponseWriter<'a, 'b, 'c> {
    enc_key: &'a [u8],
    nonce_base: &'b [u8],
    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: &'c [u8],
}

/// buffer for status
pub const RESPONSE_MIN_BUFLEN: usize = 1;

impl<'a, 'b, 'c> ResponseWriter<'a, 'b, 'c> {
    pub fn new(
        enc_key: &'a [u8],
        nonce_base: &'b [u8],
        timestamp: [u8; TIMESTAMP_LEN],
        all_randoms: &'c [u8],
    ) -> Self {
        Self {
            enc_key,
            nonce_base,
            timestamp,
            all_randoms,
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

    async fn _write_nonce_base<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.nonce_base)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.nonce_base.len())
    }

    async fn _write_timestamp<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.timestamp)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.timestamp.len())
    }

    async fn _write_all_randoms<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, AuthServerParserError> {
        stream
            .write_all(&self.all_randoms)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
        Ok(self.all_randoms.len())
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Error)
            .await
    }

    pub async fn write_success_to<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, AuthServerParserError> {
        Self::write_to(Some(self), stream, buf, ResponseStatus::Success).await
    }

    async fn write_to<W: AsyncWrite + Unpin>(
        resp: Option<&Self>,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
        status: ResponseStatus,
    ) -> Result<usize, AuthServerParserError> {
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

        // enc_key
        cursor += resp._write_enc_key(stream).await?;

        // nonce_base
        cursor += resp._write_nonce_base(stream).await?;

        // timestamp
        cursor += resp._write_timestamp(stream).await?;

        // all_random_bytes
        cursor += resp._write_all_randoms(stream).await?;

        Ok(cursor)
    }
}

#[derive(Debug)]
pub struct ResponseReader {
    enc_key: Box<[u8]>,
    nonce_base: Box<[u8]>,
    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: Box<[u8]>,
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

    async fn _read_enc_key<R: AsyncRead + Unpin>(
        stream: &mut R,
        enc_key_len: usize,
    ) -> Result<Box<[u8]>, AuthServerParserError> {
        let mut enc_key = vec![0u8; enc_key_len];
        stream
            .read_exact(&mut enc_key)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(enc_key.into_boxed_slice())
    }

    async fn _read_nonce_base<R: AsyncRead + Unpin>(
        stream: &mut R,
        nonce_len: usize,
    ) -> Result<Box<[u8]>, AuthServerParserError> {
        let mut nonce_base = vec![0u8; nonce_len];
        stream
            .read_exact(&mut nonce_base)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(nonce_base.into_boxed_slice())
    }

    async fn _read_timestamp<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<[u8; TIMESTAMP_LEN], AuthServerParserError> {
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        stream
            .read_exact(&mut timestamp[..])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(timestamp)
    }

    async fn _read_all_randoms<R: AsyncRead + Unpin>(
        stream: &mut R,
        num_tokens_divided_by_4: u8,
    ) -> Result<Box<[u8]>, AuthServerParserError> {
        let mut all_randoms = vec![0u8; (usize::from(num_tokens_divided_by_4) * RANDOM_LEN).shl(2)];
        stream
            .read_exact(&mut all_randoms)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        Ok(all_randoms.into_boxed_slice())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
        aead_algo: SupportedAlgorithm,
        num_tokens_divided_by_4: u8,
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

        // enc_key
        let enc_key = Self::_read_enc_key(stream, aead_algo.key_len()).await?;

        // nonce_base
        let nonce_base = Self::_read_nonce_base(stream, aead_algo.nonce_len()).await?;

        // timestamp
        let timestamp = Self::_read_timestamp(stream).await?;

        // all_randoms
        let all_randoms = Self::_read_all_randoms(stream, num_tokens_divided_by_4).await?;

        Ok(Some(Self {
            enc_key,
            nonce_base,
            timestamp,
            all_randoms,
        }))
    }
}

#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ResponseStatus {
    Success = 0u8,
    Error = 0xFFu8,
}

impl From<u8> for ResponseStatus {
    fn from(value: u8) -> Self {
        if value == 0 {
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

    use std::{ops::Shr, sync::Arc};
    use tokio::io::AsyncReadExt;
    use tokio_test::io::Builder;

    // Helper to create a dummy AccessTokenList for handler tests
    // fn create_dummy_atl() -> Arc<RwLock<AccessTokenList>> {
    //     Arc::new(RwLock::new(AccessTokenList::new()))
    // }

    #[tokio::test]
    async fn request_write_read_roundtrip() {
        let original_req = Arc::new(Request::new(
            true,                          // is_pub
            5,                             // num_tokens_divided_dy_4 (fits in 7 bits)
            SupportedAlgorithm::Aes256Gcm, // aead_algo
            "test/topic/req".to_string(),  // topic
        ));

        let expected_bytes = [
            0x85, // Compound byte: is_pub (1) | num_tokens_divided_dy_4 (5) = 0x85
            0x01, // AEAD Algo: Aes256Gcm (1)
            // Topic len: "test/topic/req" is 14 bytes (u16 BE)
            0x00, 0x0E, // Topic: "test/topic/req"
            b't', b'e', b's', b't', b'/', b't', b'o', b'p', b'i', b'c', b'/', b'r', b'e', b'q',
        ];

        // Mock stream to write to and then read from
        let mut write_stream = Builder::new().write(&expected_bytes[..]).build();

        let mut write_buf = [0u8; 256]; // Provide a large enough buffer
        let written_len = original_req
            .write_to(&mut write_stream, &mut write_buf[..])
            .await
            .expect("Failed to write request");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes[..]).build();

        let mut read_buf = [0u8; 256]; // Provide a large enough buffer
        let parsed_req = Request::read_from(&mut read_stream, &mut read_buf[..])
            .await
            .expect("Failed to read request");

        assert_eq!(parsed_req.is_pub, original_req.is_pub);
        assert_eq!(
            parsed_req.num_tokens_divided_by_4,
            original_req.num_tokens_divided_by_4
        );
        assert_eq!(parsed_req.aead_algo, original_req.aead_algo);
        assert_eq!(parsed_req.topic, original_req.topic);
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn request_read_from_buffer_too_small() {
        let mut mock_stream = Builder::new().read(&[0x85, 0x01]).build();

        let mut small_buf = [0u8; 1]; // Buffer too small
        let result = Request::read_from(&mut mock_stream, &mut small_buf[..]).await;

        assert!(result.is_err());
        assert!(
            match result.unwrap_err() {
                AuthServerParserError::BufferTooSmallError() => true,
                _ => false,
            }
        );

        // Read out all the remained bytes
        let mut read_buf = [0u8; 2];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    #[tokio::test]
    async fn request_write_to_topic_too_long() {
        let long_topic = "a".repeat(0xFFFF + 1); // Longer than u16 max
        let original_req = Request::new(true, 1, SupportedAlgorithm::Aes128Gcm, long_topic);

        let mut mock_stream = Builder::new().build();
        let mut buf = [0u8; 256];
        let result = original_req.write_to(&mut mock_stream, &mut buf[..]).await;

        assert!(result.is_err());
        assert!(
            match result.unwrap_err() {
                AuthServerParserError::TopicTooLongError() => true,
                _ => false,
            }
        );
    }

    #[tokio::test]
    async fn response_write_read_success_roundtrip() {
        let enc_key = vec![
            0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
            0x33, 0x44,
        ]
            .into_boxed_slice(); // Dummy key
        let timestamp = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // Dummy timestamp
        let nonce_base = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        ]; // Dummy nonce_base
        let all_randoms = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ]
            .into_boxed_slice(); // Dummy randoms (e.g., 1 token * 8 bytes)

        let expected_bytes = [
            0x00, // Status: Success (0)
            0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
            0x33,
            0x44, // enc_key: [0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44]
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, // nonce_base: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, // timestamp: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
            // all_randoms: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];

        let original_resp_writer =
            ResponseWriter::new(&enc_key, &nonce_base, timestamp, &all_randoms);

        // Mock stream to write to
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let mut write_buf = [0u8; 8]; // Provide buffer
        let written_len = original_resp_writer
            .write_success_to(&mut mock_stream, &mut write_buf[..])
            .await
            .expect("Failed to write response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let mut read_buf = [0u8; 8]; // Provide buffer
        println!("{}", (all_randoms.len() / RANDOM_LEN).shr(2));
        let parsed_resp_option = ResponseReader::read_from(
            &mut read_stream,
            &mut read_buf[..],
            SupportedAlgorithm::Aes128Gcm,
            (all_randoms.len() / RANDOM_LEN).shr(2) as u8, // num_tokens_divided_dy_4
        )
            .await
            .expect("Failed to read response");

        assert!(parsed_resp_option.is_some());
        let parsed_resp = parsed_resp_option.unwrap();

        assert_eq!(parsed_resp.enc_key.as_ref(), enc_key.as_ref());
        assert_eq!(parsed_resp.timestamp, timestamp);
        assert_eq!(parsed_resp.all_randoms.as_ref(), all_randoms.as_ref());
        assert_eq!(written_len, expected_bytes.len(), "Written length mismatch");
    }

    #[tokio::test]
    async fn response_write_read_error_roundtrip() {
        // Mock stream to write error response
        let expected_bytes = [
            // Status: Error (0xFF)
            0xFF,
        ];
        let mut mock_stream = Builder::new().write(&expected_bytes).read(&[]).build();

        let mut write_buf = [0u8; 256]; // Provide buffer
        let written_len = ResponseWriter::write_error_to(&mut mock_stream, &mut write_buf[..])
            .await
            .expect("Failed to write error response");

        // Now build a new mock stream with the expected bytes to read
        let mut read_stream = Builder::new().read(&expected_bytes).build();

        let mut read_buf = [0u8; 256]; // Provide buffer
        let parsed_resp_option = ResponseReader::read_from(
            &mut read_stream,
            &mut read_buf[..],
            SupportedAlgorithm::Aes128Gcm, // Dummy aead_algo (not used for error)
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

    #[tokio::test]
    async fn response_read_from_buffer_too_small() {
        let mut mock_stream = Builder::new().read(&[0x00, 0x11, 0x22]).build(); // Success status + some data
        let mut small_buf = [0u8; 0]; // Buffer too small
        let result = ResponseReader::read_from(
            &mut mock_stream,
            &mut small_buf[..],
            SupportedAlgorithm::Aes128Gcm,
            1,
        )
            .await;

        assert!(result.is_err());
        assert!(
            match result.unwrap_err() {
                AuthServerParserError::BufferTooSmallError() => true,
                _ => false,
            }
        );

        // Write in all the remained bytes
        let mut read_buf = [0u8; 3];
        let _ = mock_stream.read(&mut read_buf).await;
    }

    // // Note: Testing the `handler` function directly is more complex as it involves
    // // ATL interaction and random generation. You would need to mock ATL behavior
    // // or use a real ATL instance and control time for expiration tests.
    // // The tests above cover the serialization/deserialization logic which is a key part.
}
