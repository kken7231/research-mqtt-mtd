//! Issuer interface of auth server.

use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use libmqttmtd::{
    aead::algo::{SupportedAlgorithm, get_ring_algorithm},
    consts::{RANDOM_LEN, TIMESTAMP_LEN},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    atl::{AccessTokenList, TokenSet},
    error::IssuerParserError,
};

const REQ_RESP_MIN_BUFLEN: usize = if REQUEST_MIN_BUFLEN > RESPONSE_MIN_BUFLEN {
    RESPONSE_MIN_BUFLEN
} else {
    REQUEST_MIN_BUFLEN
};

pub async fn handler(
    atl: Arc<RwLock<AccessTokenList>>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
) {
    let mut buf = [0u8; REQ_RESP_MIN_BUFLEN];

    // Parse request
    let req = match Request::read_from(&mut stream, &mut buf[..]).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error reading issuer request: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    // Create a token set
    let token_set = match TokenSet::create_without_rand_init(
        req.num_tokens,
        req.topic,
        req.is_pub,
        Duration::from_secs(300),
        req.aead_algo,
        req.nonce_base,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error acquiring atl write lock: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    // Acquire a write lock
    let atl = match atl.try_write() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error acquiring atl write lock: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    // File a token_set
    let (token_set, masked_timestamp) = match atl.file(token_set) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error issuing a token set: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    //
    let token_set = match token_set.try_read() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error acquiring token_set read lock: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    let enc_key = token_set.get_enc_key();
    let timestamp = AccessTokenList::sparse_masked_u64_to_part(masked_timestamp);
    let all_randoms = token_set.get_all_randoms();

    // let enc_key = &[0u8; 32][..];
    // let timestamp = [0u8; 6];
    // let all_randoms = vec![[0u8; 6]];
    let status = ResponseStatus::Success;

    // Send response
    if let Err(e) = match status {
        ResponseStatus::Success => {
            ResponseWriter::new(&enc_key, timestamp, &all_randoms)
                .write_success_to(&mut stream, &mut buf[..])
                .await
        }
        _ => ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await,
    } {
        eprintln!("error sending out issuer response: {}", e);
    } else {
        println!("Issuer response sent out")
    }
}

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
///   - bit 6-0: `num_tokens`: number of tokens
/// 2. `aead_algo` (u8): AEAD algorithm identifier according to [libmqttmtd::aead::algo::SupportedAlgorithm]
/// 3. `nonce_base` (length based on `aead_algo`): base value for a counter nonce
/// 4. `topic_len` (u16, big endian): length of `topic`
/// 5. `topic`: Topic Names or Topic Filters
pub struct Request {
    is_pub: bool,
    num_tokens: usize,
    aead_algo: SupportedAlgorithm,
    nonce_base: u128,
    topic: String,
}

/// buffer for (compound byte + aead_algo) and topic_len
pub const REQUEST_MIN_BUFLEN: usize = 2;

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "issuer resuest: is_pub:{}, num_tokens:{}, topic:\"{}\"",
            self.is_pub, self.num_tokens, self.topic
        )
    }
}

impl Request {
    pub fn new(
        is_pub: bool,
        num_tokens: usize,
        aead_algo: SupportedAlgorithm,
        nonce_base: u128,
        topic: String,
    ) -> Self {
        Self {
            is_pub,
            num_tokens,
            aead_algo,
            nonce_base,
            topic,
        }
    }

    async fn _read_compound_aead_algo<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<(bool, usize, SupportedAlgorithm), IssuerParserError> {
        stream.read_exact(&mut buf[0..1]).await?;
        let is_pub = buf[0] & 0x80 != 0;
        let num_tokens = usize::from(buf[0] & 0x7F);
        let aead_algo = SupportedAlgorithm::try_from(buf[1])?;
        Ok((is_pub, num_tokens, aead_algo))
    }

    async fn _write_compound_aead_algo<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, IssuerParserError> {
        let mut first_byte = *self.num_tokens.to_be_bytes().last().unwrap();
        if self.is_pub {
            first_byte |= 0x80;
        }
        buf[0] = first_byte;
        buf[1] = self.aead_algo as u8;
        stream.write_all(&buf).await?;
        Ok(2)
    }

    async fn _read_nonce_base<R: AsyncRead + Unpin>(
        stream: &mut R,
        aead_algo: &SupportedAlgorithm,
    ) -> Result<u128, IssuerParserError> {
        let nonce_len = get_ring_algorithm(&aead_algo).nonce_len();
        let mut nonce = Vec::<u8>::with_capacity(nonce_len);
        unsafe { nonce.set_len(nonce_len) };
        stream.read_exact(&mut nonce).await?;
        let mut nonce_u128 = 0u128;
        nonce.iter().for_each(|b| {
            nonce_u128 = nonce_u128 << 8 + *b as u128;
        });

        Ok(nonce_u128)
    }

    async fn _write_nonce_base<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        let nonce_len = get_ring_algorithm(&self.aead_algo).nonce_len();
        let mut nonce_base = Vec::<u8>::with_capacity(nonce_len);
        self.nonce_base
            .to_be_bytes()
            .iter()
            .skip(128 / 8 - nonce_len)
            .enumerate()
            .for_each(|(i, b)| nonce_base[i] = *b);
        stream.write_all(&nonce_base).await?;
        Ok(nonce_len)
    }

    async fn _read_topic<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<String, IssuerParserError> {
        // topic_len
        stream.read_exact(&mut buf[0..1]).await?;
        let topic_len = usize::from(buf[1]) << 8 + usize::from(buf[2]);

        // topic
        let mut topic = Vec::<u8>::with_capacity(topic_len);
        unsafe { topic.set_len(topic_len) };
        stream.read_exact(&mut topic).await?;

        Ok(std::str::from_utf8(&topic[..])?.to_owned())
    }

    async fn _write_topic<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, IssuerParserError> {
        // topic_len
        let topic_len_bytes = self.topic.len().to_be_bytes();
        buf[0..2].copy_from_slice(&topic_len_bytes);
        stream.write_all(&buf[0..2]).await?;

        // topic
        stream.write_all(&self.topic.as_bytes()).await?;

        Ok(2 + self.topic.len())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<Self, IssuerParserError> {
        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < REQUEST_MIN_BUFLEN => {
                return Err(IssuerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; REQUEST_MIN_BUFLEN][..],
        };
        // is_pub, num_tokens, aead_algo
        let (is_pub, num_tokens, aead_algo) = Self::_read_compound_aead_algo(stream, buf).await?;

        // nonce
        let nonce_base = Self::_read_nonce_base(stream, &aead_algo).await?;

        // topic_len, topic
        let topic = Self::_read_topic(stream, buf).await?;

        Ok(Self {
            is_pub,
            num_tokens,
            aead_algo,
            nonce_base,
            topic,
        })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, IssuerParserError> {
        if self.topic.len() > 0xFFFF {
            return Err(IssuerParserError::TopicTooLongError());
        }

        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < REQUEST_MIN_BUFLEN => {
                return Err(IssuerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; REQUEST_MIN_BUFLEN][..],
        };

        let mut cursor: usize = 0;

        // is_pub, num_tokens, aead_algo
        cursor += self._write_compound_aead_algo(stream, buf).await?;

        // nonce
        cursor += self._write_nonce_base(stream).await?;

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
/// 3. `timestamp`
/// 4. `all_randoms` (length = num_tokens*RANDOM_LEN)

pub struct ResponseWriter<'a, 'b> {
    enc_key: &'a [u8],
    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: &'b [u8],
}

/// buffer for [0]
pub const RESPONSE_MIN_BUFLEN: usize = 1;

impl<'a, 'b> ResponseWriter<'a, 'b> {
    pub fn new(enc_key: &'a [u8], timestamp: [u8; TIMESTAMP_LEN], all_randoms: &'b [u8]) -> Self {
        Self {
            enc_key,
            timestamp,
            all_randoms,
        }
    }

    async fn _write_status<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: &mut [u8],
        status: &ResponseStatus,
    ) -> Result<usize, IssuerParserError> {
        buf[0] = *status as u8;
        stream.write_all(&mut buf[0..1]).await?;
        Ok(1)
    }

    async fn _write_enc_key<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.enc_key).await?;
        Ok(self.enc_key.len())
    }

    async fn _write_timestamp<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.timestamp).await?;
        Ok(self.timestamp.len())
    }

    async fn _write_all_randoms<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.all_randoms).await?;
        Ok(self.all_randoms.len())
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, IssuerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Error).await
    }

    pub async fn write_success_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, IssuerParserError> {
        Self::write_to(Some(self), stream, buf, ResponseStatus::Success).await
    }

    async fn write_to<W: AsyncWrite + Unpin>(
        resp: Option<Self>,
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
        status: ResponseStatus,
    ) -> Result<usize, IssuerParserError> {
        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < RESPONSE_MIN_BUFLEN => {
                return Err(IssuerParserError::BufferTooSmallError());
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

        // timestamp
        cursor += resp._write_timestamp(stream).await?;

        // all_random_bytes
        cursor += resp._write_all_randoms(stream).await?;

        Ok(cursor)
    }
}

pub struct ResponseReader {
    pub enc_key: Box<[u8]>,
    pub timestamp: [u8; TIMESTAMP_LEN],
    pub all_randoms: Box<[u8]>,
}

impl ResponseReader {
    async fn _read_status<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<ResponseStatus, IssuerParserError> {
        stream.read_exact(&mut buf[0..1]).await?;
        Ok(ResponseStatus::from(buf[0]))
    }

    async fn _read_enc_key<R: AsyncRead + Unpin>(
        stream: &mut R,
        enc_key_len: usize,
    ) -> Result<Box<[u8]>, IssuerParserError> {
        let mut enc_key = Vec::<u8>::with_capacity(enc_key_len);
        unsafe { enc_key.set_len(enc_key_len) };
        stream.read_exact(&mut enc_key).await?;
        Ok(enc_key.into_boxed_slice())
    }

    async fn _read_timestamp<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<[u8; TIMESTAMP_LEN], IssuerParserError> {
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        stream.read_exact(&mut timestamp[..]).await?;
        Ok(timestamp)
    }

    async fn _read_all_randoms<R: AsyncRead + Unpin>(
        stream: &mut R,
        num_tokens: usize,
    ) -> Result<Box<[u8]>, IssuerParserError> {
        let mut all_randoms = Vec::<u8>::with_capacity(num_tokens * RANDOM_LEN);
        unsafe { all_randoms.set_len(num_tokens * RANDOM_LEN) };
        stream.read_exact(&mut all_randoms).await?;
        Ok(all_randoms.into_boxed_slice())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
        enc_key_len: usize,
        num_tokens: usize,
    ) -> Result<Option<Self>, IssuerParserError> {
        // Buf len check
        let buf = match buf.into() {
            Some(b) if b.len() < RESPONSE_MIN_BUFLEN => {
                return Err(IssuerParserError::BufferTooSmallError());
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
        let enc_key = Self::_read_enc_key(stream, enc_key_len).await?;

        // timestamp
        let timestamp = Self::_read_timestamp(stream).await?;

        // all_randoms
        let all_randoms = Self::_read_all_randoms(stream, num_tokens).await?;

        Ok(Some(Self {
            enc_key,
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
