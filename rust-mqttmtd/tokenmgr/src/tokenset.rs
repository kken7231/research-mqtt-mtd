// filename=(pub/sub)_(base64-encoded url-safe topic)_(token_idx)

use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{Engine, engine::general_purpose};
use bytes::{Bytes, BytesMut};
use libmqttmtd::{
    aead::algo::SupportedAlgorithm,
    auth_serv::issuer::{self, ResponseReader},
    consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN},
    socket::tls::TlsClient,
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::ToSocketAddrs,
};
use walkdir::WalkDir;

pub struct TokenSetMetaData {
    pub token_idx: u16,

    pub aead_algo: SupportedAlgorithm,
    pub enc_key: Bytes,
    pub nonce_base: Bytes,
    pub num_tokens: u16,
    pub timestamp: [u8; TIMESTAMP_LEN],
    pub all_randoms_offset: usize,
    pub cur_random: [u8; RANDOM_LEN],
}

impl TokenSetMetaData {
    pub fn current_token(&self) -> [u8; TOKEN_LEN] {
        let mut token = [0u8; TOKEN_LEN];
        token[..TIMESTAMP_LEN].copy_from_slice(&self.timestamp);
        token[TIMESTAMP_LEN..].copy_from_slice(&self.cur_random);
        token
    }

    pub fn read_from_file(
        filepath: &Path,
        cur_idx_offset: usize,
    ) -> Result<Self, TokenSetReadError> {
        let filename_osstr: &OsStr = match filepath.file_name() {
            Some(name) => name,
            None => return Err(TokenSetReadError::PathNotHavingFilenameError),
        };

        // Convert OsStr to a string slice. to_string_lossy handles non-UTF-8 filenames.
        let filename_str = filename_osstr.to_string_lossy();
        let curidx_slice = &filename_str[cur_idx_offset..];

        // Parse and get cur_idx from the filename
        let token_idx = curidx_slice.parse::<u16>();
        if let Err(_) = token_idx {
            return Err(TokenSetReadError::InvalidCurIdxInFilenameError(None));
        }
        let token_idx = token_idx.unwrap();
        if token_idx > 0x7F * 4 {
            return Err(TokenSetReadError::InvalidCurIdxInFilenameError(Some(
                token_idx,
            )));
        }

        // Start reading
        let mut file: fs::File = fs::File::open(filepath)?;
        let mut buf = [0u8; 2];
        let mut all_randoms_offset = 0usize;

        // aead_algo
        file.read_exact(&mut buf[0..1])?;
        let aead_algo = SupportedAlgorithm::try_from(buf[0])?;
        all_randoms_offset += 1;

        // enc_key
        let enc_key_len = aead_algo.key_len();
        let mut enc_key = BytesMut::with_capacity(enc_key_len);
        file.read_exact(&mut enc_key)?;
        let enc_key = enc_key.freeze();
        all_randoms_offset += enc_key_len;

        // nonce_base
        let nonce_len = aead_algo.nonce_len();
        let mut nonce_base = BytesMut::with_capacity(nonce_len);
        file.read_exact(&mut nonce_base)?;
        let nonce_base = nonce_base.freeze();
        all_randoms_offset += nonce_len;

        // num_tokens_divided_by_4
        file.read_exact(&mut buf[0..1])?;
        let num_tokens_divided_by_4 = buf[0];
        if num_tokens_divided_by_4 > 0x7F || num_tokens_divided_by_4 as u16 * 4 <= token_idx {
            return Err(TokenSetReadError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        }
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);
        all_randoms_offset += 1;

        // timestamp
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        file.read_exact(&mut timestamp[..])?;
        let timestamp = timestamp;
        all_randoms_offset += TIMESTAMP_LEN;

        // cur_random
        file.seek(std::io::SeekFrom::Current(
            token_idx as i64 * RANDOM_LEN as i64,
        ))?;
        let mut cur_random = [0u8; RANDOM_LEN];
        file.read_exact(&mut cur_random[..])?;
        let cur_random = cur_random;

        Ok(Self {
            aead_algo,
            token_idx,
            enc_key,
            nonce_base,
            num_tokens,
            timestamp,
            all_randoms_offset,
            cur_random,
        })
    }

    pub fn write_fetched_to_file(
        request: &issuer::Request,
        response: &ResponseReader,
        token_sets_dir: Arc<PathBuf>,
    ) -> Result<Self, TokenSetWriteError> {
        let pub_sub_dir = if request.is_pub() {
            token_sets_dir.join("pub")
        } else {
            token_sets_dir.join("sub")
        };
        fs::create_dir_all(token_sets_dir.as_path())?;

        let topic_encoded = general_purpose::URL_SAFE_NO_PAD.encode(request.topic());
        let filename = topic_encoded + "0";
        let filepath = pub_sub_dir.join(filename);
        let token_idx = 0u16;

        // Start reading
        let mut file: fs::File = fs::File::create(filepath)?;
        let mut buf = [0u8; 2];
        let mut all_randoms_offset = 0usize;

        // aead_algo
        let aead_algo = request.aead_algo();
        buf[0] = aead_algo as u8;
        file.write_all(&mut buf[0..1])?;
        all_randoms_offset += 1;

        // enc_key
        if response.enc_key().len() != aead_algo.key_len() {
            return Err(TokenSetWriteError::EncKeyLenMismatchError);
        }
        let enc_key = Bytes::from(response.enc_key().to_owned());
        file.write_all(&enc_key)?;
        all_randoms_offset += enc_key.len();

        // nonce_base
        if response.nonce_base().len() < aead_algo.nonce_len() {
            return Err(TokenSetWriteError::NonceLenMismatchError);
        }
        let nonce_base =
            Bytes::from(response.nonce_base()[(128 / 16 - aead_algo.nonce_len())..].to_owned());
        file.write_all(&nonce_base)?;
        all_randoms_offset += nonce_base.len();

        // num_tokens_divided_by_4
        buf[0] = request.num_tokens_divided_by_4();
        file.write_all(&mut buf[0..1])?;
        let num_tokens = (buf[0] as u16).rotate_left(2);
        all_randoms_offset += 1;

        // timestamp
        file.write_all(response.timestamp())?;
        let timestamp = response.timestamp().to_owned();
        all_randoms_offset += TIMESTAMP_LEN;

        // all_randoms
        file.write_all(response.all_randoms())?;
        let mut cur_random = [0u8; RANDOM_LEN];
        cur_random.copy_from_slice(&response.all_randoms()[..RANDOM_LEN]);
        let cur_random = cur_random;

        Ok(Self {
            aead_algo,
            token_idx,
            enc_key,
            nonce_base,
            num_tokens,
            timestamp,
            all_randoms_offset,
            cur_random,
        })
    }

    pub async fn write_current<W: AsyncWrite + Unpin>(
        &self,
        stream: &mut W,
    ) -> Result<(), tokio::io::Error> {
        // enc_key
        stream.write_all(&self.enc_key).await?;

        // nonce
        stream.write_all(&self.nonce_base).await?;

        // timestamp
        stream.write_all(&self.timestamp).await?;

        // cur_random
        stream.write_all(&self.cur_random).await?;

        Ok(())
    }
}

/// Error on reading a token set file
///
/// Indicates unique errors:
#[derive(Debug)]
pub enum TokenSetReadError {
    PathNotHavingFilenameError,
    InvalidCurIdxInFilenameError(Option<u16>),
    IoError(std::io::Error),
    AeadAlgoConversionError(libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError),
    InvalidNumTokensError(u8),
}

impl std::error::Error for TokenSetReadError {}

impl std::fmt::Display for TokenSetReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSetReadError::PathNotHavingFilenameError => {
                write!(f, "path does not have a filename")
            }
            TokenSetReadError::InvalidCurIdxInFilenameError(cur_idx_opt) => {
                if let Some(cur_idx) = cur_idx_opt {
                    write!(f, "cur_idx out of range ({})", cur_idx)
                } else {
                    write!(f, "invalid cur_idx")
                }
            }
            TokenSetReadError::IoError(e) => write!(f, "io::Error found: {}", e),
            TokenSetReadError::AeadAlgoConversionError(e) => {
                write!(f, "failed reading AEAD algorithm: {}", e)
            }
            TokenSetReadError::InvalidNumTokensError(v) => {
                write!(f, "invalid num_tokens (num_tokens_divided_by_4 = {})", v)
            }
        }
    }
}

impl From<std::io::Error> for TokenSetReadError {
    fn from(error: std::io::Error) -> Self {
        TokenSetReadError::IoError(error)
    }
}
impl From<libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError> for TokenSetReadError {
    fn from(error: libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError) -> Self {
        TokenSetReadError::AeadAlgoConversionError(error)
    }
}

/// Error on writing a token set file
///
/// Indicates unique errors:
#[derive(Debug)]
pub enum TokenSetWriteError {
    EncKeyLenMismatchError,
    NonceLenMismatchError,
    IoError(std::io::Error),
}

impl std::error::Error for TokenSetWriteError {}

impl std::fmt::Display for TokenSetWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSetWriteError::EncKeyLenMismatchError => write!(f, "enc key length mismatch"),
            TokenSetWriteError::NonceLenMismatchError => write!(f, "nonce length mismatch"),
            TokenSetWriteError::IoError(e) => write!(f, "io::Error found: {}", e),
        }
    }
}

impl From<std::io::Error> for TokenSetWriteError {
    fn from(error: std::io::Error) -> Self {
        TokenSetWriteError::IoError(error)
    }
}

pub async fn get_current_token_from_file<A: ToSocketAddrs + Send + 'static>(
    token_sets_dir: Arc<PathBuf>,
    issuer_addr: A,
    tls_config: Arc<rustls::ClientConfig>,
    request: &issuer::Request,
) -> Result<TokenSetMetaData, Box<dyn Error>> {
    let pub_sub_dir = if request.is_pub() { "pub" } else { "sub" };
    if token_sets_dir.join(pub_sub_dir).exists() && token_sets_dir.join(pub_sub_dir).is_dir() {
        let target_dir = token_sets_dir.join(pub_sub_dir);

        let topic_encoded = general_purpose::URL_SAFE_NO_PAD.encode(request.topic());

        for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.path().starts_with(topic_encoded.as_str()) && !entry.path_is_symlink() {
                match TokenSetMetaData::read_from_file(entry.path(), topic_encoded.len()) {
                    Ok(metadata) => return Ok(metadata),
                    Err(e) => {
                        eprintln!("found error in a token_set file, removing..: {}", e);
                        fs::remove_file(entry.path())?;
                    }
                };
                break;
            }
        }
    }

    // fetch tokens
    Ok(fetch_tokens(token_sets_dir, issuer_addr, tls_config, request).await?)
}

pub async fn fetch_tokens<A: ToSocketAddrs + Send + 'static>(
    token_sets_dir: Arc<PathBuf>,
    issuer_addr: A,
    tls_config: Arc<rustls::ClientConfig>,
    request: &issuer::Request,
) -> Result<TokenSetMetaData, TokenSetFetchError> {
    let mut issuer_stream = TlsClient::new(issuer_addr, None, tls_config)
        .connect("localhost")
        .await?;
    let mut buf = [0u8; 8];
    request.write_to(&mut issuer_stream, &mut buf[..]).await?;

    if let Some(success_response) = issuer::ResponseReader::read_from(
        &mut issuer_stream,
        &mut buf[..],
        request.aead_algo(),
        request.num_tokens_divided_by_4(),
    )
    .await?
    {
        let token_set =
            TokenSetMetaData::write_fetched_to_file(request, &success_response, token_sets_dir)?;
        Ok(token_set)
    } else {
        eprintln!("issuing tokens failed on server side");
        Err(TokenSetFetchError::IssuerServerError)
    }
}

/// Error on fetching a token set
///
/// Indicates unique errors:
#[derive(Debug)]
pub enum TokenSetFetchError {
    SocketError(libmqttmtd::socket::error::SocketError),
    IoError(std::io::Error),
    AuthServerPacketParseError(libmqttmtd::auth_serv::error::AuthServerParserError),
    TokenSetWriteError(TokenSetWriteError),
    IssuerServerError,
}

impl std::error::Error for TokenSetFetchError {}

impl std::fmt::Display for TokenSetFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenSetFetchError::SocketError(e) => write!(f, "socket error found: {}", e),
            TokenSetFetchError::IoError(e) => write!(f, "io::Error found: {}", e),
            TokenSetFetchError::AuthServerPacketParseError(e) => {
                write!(f, "parsing auth server request/response failed: {}", e)
            }
            TokenSetFetchError::TokenSetWriteError(e) => {
                write!(f, "writing a token_set file failed: {}", e)
            }
            TokenSetFetchError::IssuerServerError => {
                write!(f, "issuing tokens failed on server side")
            }
        }
    }
}

impl From<libmqttmtd::socket::error::SocketError> for TokenSetFetchError {
    fn from(error: libmqttmtd::socket::error::SocketError) -> Self {
        TokenSetFetchError::SocketError(error)
    }
}
impl From<std::io::Error> for TokenSetFetchError {
    fn from(error: std::io::Error) -> Self {
        TokenSetFetchError::IoError(error)
    }
}

impl From<libmqttmtd::auth_serv::error::AuthServerParserError> for TokenSetFetchError {
    fn from(error: libmqttmtd::auth_serv::error::AuthServerParserError) -> Self {
        TokenSetFetchError::AuthServerPacketParseError(error)
    }
}

impl From<TokenSetWriteError> for TokenSetFetchError {
    fn from(error: TokenSetWriteError) -> Self {
        TokenSetFetchError::TokenSetWriteError(error)
    }
}
