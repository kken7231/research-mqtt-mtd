//! Verifier interface of auth server.

use std::sync::Arc;

use libmqttmtd::{
    aead::algo::{SupportedAlgorithm, get_ring_algorithm},
    consts::TOKEN_LEN,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::RwLock,
};

use crate::{atl::AccessTokenList, error::IssuerParserError};

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
    let req = match Request::read_from(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error reading verifier request: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out verifier (error) response: {}", e);
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

    // Verify a request
    let token_set = match atl.verify(&req.token) {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("error acquiring atl write lock: {}", e);
            if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                eprintln!("error sending out issuer (error) response: {}", e);
            };
            return;
        }
    };

    // Send response
    let result = if let Some(token_set) = token_set {
        match token_set.try_read() {
            Ok(token_set) => {
                ResponseWriter::new(
                    token_set.get_is_pub(),
                    *token_set.get_aead_algo(),
                    &token_set.get_nonce()[..],
                    token_set.get_topic(),
                    token_set.get_enc_key(),
                )
                .write_success_to(&mut stream, &mut buf[..])
                .await
            }
            Err(e) => {
                eprintln!("error acquiring token_set read lock: {}", e);
                if let Err(e) = ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await {
                    eprintln!("error sending out issuer (error) response: {}", e);
                };
                return;
            }
        }
    } else {
        ResponseWriter::write_failure_to(&mut stream, &mut buf[..]).await
    };

    if let Err(e) = result {
        eprintln!("error sending out verifier response: {}", e);
    } else {
        println!("Verifier response sent out")
    }
}

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
    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<Self, IssuerParserError> {
        let mut token = [0u8; TOKEN_LEN];
        stream.read_exact(&mut token).await?;

        Ok(Self { token })
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(
        self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.token).await?;
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

pub struct ResponseReader {
    pub allowed_access_is_pub: bool,
    pub aead_algo: SupportedAlgorithm,
    pub nonce: Box<[u8]>,
    pub topic: String,
    pub enc_key: Box<[u8]>,
}

/// buffer for status, len_topic, allowed_access, aead_type
pub const RESPONSE_MIN_BUFLEN: usize = 2;

impl ResponseReader {
    async fn _read_status<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<ResponseStatus, IssuerParserError> {
        stream.read_exact(&mut buf[0..1]).await?;
        Ok(ResponseStatus::from(buf[0]))
    }

    async fn _read_is_pub_and_aead_algo<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: &mut [u8],
    ) -> Result<(bool, SupportedAlgorithm), IssuerParserError> {
        stream.read_exact(&mut buf[0..1]).await?;
        Ok((
            buf[0] & 0x80 != 0,
            SupportedAlgorithm::try_from(buf[0] & 0xF)?,
        ))
    }

    async fn _read_nonce<R: AsyncRead + Unpin>(
        stream: &mut R,
        nonce_len: usize,
    ) -> Result<Box<[u8]>, IssuerParserError> {
        let mut nonce = Vec::<u8>::with_capacity(nonce_len);
        unsafe { nonce.set_len(nonce_len) };
        stream.read_exact(&mut nonce).await?;
        Ok(nonce.into_boxed_slice())
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

    async fn _read_enc_key<R: AsyncRead + Unpin>(
        stream: &mut R,
        enc_key_len: usize,
    ) -> Result<Box<[u8]>, IssuerParserError> {
        let mut enc_key = Vec::<u8>::with_capacity(enc_key_len);
        unsafe { enc_key.set_len(enc_key_len) };
        stream.read_exact(&mut enc_key).await?;
        Ok(enc_key.into_boxed_slice())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(
        stream: &mut R,
        buf: impl Into<Option<&mut [u8]>>,
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

        // allowed_access, aead_algo
        let (allowed_access_is_pub, aead_algo) =
            Self::_read_is_pub_and_aead_algo(stream, buf).await?;

        let aead_algo_ring = get_ring_algorithm(&aead_algo);

        // nonce
        let nonce = Self::_read_nonce(stream, aead_algo_ring.nonce_len()).await?;

        // topic
        let topic = Self::_read_topic(stream, buf).await?;

        // enc_key
        let enc_key = Self::_read_enc_key(stream, aead_algo_ring.key_len()).await?;

        Ok(Some(Self {
            nonce,
            allowed_access_is_pub,
            aead_algo,
            enc_key,
            topic,
        }))
    }
}

pub struct ResponseWriter<'a, 'b> {
    allowed_access_is_pub: bool,
    aead_algo: SupportedAlgorithm,
    nonce: &'a [u8],
    topic: String,
    enc_key: &'b [u8],
}

impl<'a, 'b> ResponseWriter<'a, 'b> {
    pub fn new(
        allowed_access_is_pub: bool,
        aead_algo: SupportedAlgorithm,
        nonce: &'a [u8],
        topic: String,
        enc_key: &'b [u8],
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
    ) -> Result<usize, IssuerParserError> {
        buf[0] = *status as u8;
        stream.write_all(&mut buf[0..1]).await?;
        Ok(1)
    }

    async fn _write_is_pub_and_aead_algo<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
        buf: &mut [u8],
    ) -> Result<usize, IssuerParserError> {
        buf[0] = if self.allowed_access_is_pub {
            0x80
        } else {
            0x00
        };
        buf[0] |= self.aead_algo as u8;
        stream.write_all(&mut buf[0..1]).await?;
        Ok(1)
    }

    async fn _write_nonce<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.nonce).await?;
        Ok(self.nonce.len())
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

    async fn _write_enc_key<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<usize, IssuerParserError> {
        stream.write_all(&self.enc_key).await?;
        Ok(self.enc_key.len())
    }

    pub async fn write_error_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, IssuerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Error).await
    }

    pub async fn write_failure_to<W: AsyncWrite + Unpin>(
        stream: &mut W,
        buf: impl Into<Option<&mut [u8]>>,
    ) -> Result<usize, IssuerParserError> {
        Self::write_to(None, stream, buf, ResponseStatus::Failure).await
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
        if let Some(r) = &resp {
            if r.topic.len() > 0xFFFF {
                return Err(IssuerParserError::TopicTooLongError());
            }
        }

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
