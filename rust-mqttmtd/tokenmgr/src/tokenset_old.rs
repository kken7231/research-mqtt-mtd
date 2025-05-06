// filename=(pub/sub)_(base64-encoded url-safe topic)_(token_idx)

use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{Read, Seek, Write},
    ops::Shl,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::errors::TokenSetFetchError;
use base64::{engine::general_purpose, Engine};
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
    ) -> Result<Self, TokensetReadError> {
        let filename_osstr: &OsStr = match filepath.file_name() {
            Some(name) => name,
            None => return Err(TokensetReadError::PathNotHavingFilenameError),
        };

        // Convert OsStr to a string slice. to_string_lossy handles non-UTF-8 filenames.
        let filename_str = filename_osstr.to_string_lossy();
        let curidx_slice = &filename_str[cur_idx_offset..];

        // Parse and get cur_idx from the filename
        let token_idx = curidx_slice.parse::<u16>();
        if let Err(_) = token_idx {
            return Err(TokensetReadError::InvalidCurIdxInFilenameError(None));
        }
        let token_idx = token_idx.unwrap();
        if token_idx > 0x7F * 4 {
            return Err(TokensetReadError::InvalidCurIdxInFilenameError(Some(
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
        let mut enc_key = BytesMut::zeroed(enc_key_len);
        file.read_exact(&mut enc_key)?;
        let enc_key = enc_key.freeze();
        all_randoms_offset += enc_key_len;

        // nonce_base
        let nonce_len = aead_algo.nonce_len();
        let mut nonce_base = BytesMut::zeroed(nonce_len);
        file.read_exact(&mut nonce_base)?;
        let nonce_base = nonce_base.freeze();
        all_randoms_offset += nonce_len;

        // num_tokens_divided_by_4
        file.read_exact(&mut buf[0..1])?;
        let num_tokens_divided_by_4 = buf[0];
        if num_tokens_divided_by_4 > 0x7F || num_tokens_divided_by_4 as u16 * 4 <= token_idx {
            return Err(TokensetReadError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        }
        let num_tokens = (num_tokens_divided_by_4 as u16).shl(2);
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
    ) -> Result<Self, TokensetWriteError> {
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
            return Err(TokensetWriteError::EncKeyLenMismatchError);
        }
        let enc_key = Bytes::from(response.enc_key().to_owned());
        file.write_all(&enc_key)?;
        all_randoms_offset += enc_key.len();

        // nonce_base
        if response.nonce_base().len() < aead_algo.nonce_len() {
            return Err(TokensetWriteError::NonceLenMismatchError);
        }
        let nonce_base =
            Bytes::from(response.nonce_base()[(128 / 16 - aead_algo.nonce_len())..].to_owned());
        file.write_all(&nonce_base)?;
        all_randoms_offset += nonce_base.len();

        // num_tokens_divided_by_4
        buf[0] = request.num_tokens_divided_by_4();
        file.write_all(&mut buf[0..1])?;
        let num_tokens = (buf[0] as u16).shl(2);
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
pub enum TokensetReadError {
    PathNotHavingFilenameError,
    InvalidCurIdxInFilenameError(Option<u16>),
    IoError(std::io::Error),
    AeadAlgoConversionError(libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError),
    InvalidNumTokensError(u8),
}

impl std::error::Error for TokensetReadError {}

impl std::fmt::Display for TokensetReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokensetReadError::PathNotHavingFilenameError => {
                write!(f, "path does not have a filename")
            }
            TokensetReadError::InvalidCurIdxInFilenameError(cur_idx_opt) => {
                if let Some(cur_idx) = cur_idx_opt {
                    write!(f, "cur_idx out of range ({})", cur_idx)
                } else {
                    write!(f, "invalid cur_idx")
                }
            }
            TokensetReadError::IoError(e) => write!(f, "io::Error found: {}", e),
            TokensetReadError::AeadAlgoConversionError(e) => {
                write!(f, "failed reading AEAD algorithm: {}", e)
            }
            TokensetReadError::InvalidNumTokensError(v) => {
                write!(f, "invalid num_tokens (num_tokens_divided_by_4 = {})", v)
            }
        }
    }
}

impl From<std::io::Error> for TokensetReadError {
    fn from(error: std::io::Error) -> Self {
        TokensetReadError::IoError(error)
    }
}
impl From<libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError> for TokensetReadError {
    fn from(error: libmqttmtd::aead::algo::AeadAlgorithmNotSupportedError) -> Self {
        TokensetReadError::AeadAlgoConversionError(error)
    }
}

/// Error on writing a token set file
///
/// Indicates unique errors:
#[derive(Debug)]
pub enum TokensetWriteError {
    EncKeyLenMismatchError,
    NonceLenMismatchError,
    IoError(std::io::Error),
}

impl std::error::Error for TokensetWriteError {}

impl std::fmt::Display for TokensetWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokensetWriteError::EncKeyLenMismatchError => write!(f, "enc key length mismatch"),
            TokensetWriteError::NonceLenMismatchError => write!(f, "nonce length mismatch"),
            TokensetWriteError::IoError(e) => write!(f, "io::Error found: {}", e),
        }
    }
}

impl From<std::io::Error> for TokensetWriteError {
    fn from(error: std::io::Error) -> Self {
        TokensetWriteError::IoError(error)
    }
}

pub async fn get_current_token_from_file<A: ToSocketAddrs + Send + 'static>(
    token_sets_dir: Arc<PathBuf>,
    request: &issuer::Request,
) -> Result<Option<[u8; TOKEN_LEN]>, Box<dyn Error>> {
    let pub_sub_dir = if request.is_pub() { "pub" } else { "sub" };
    if token_sets_dir.join(pub_sub_dir).exists() && token_sets_dir.join(pub_sub_dir).is_dir() {
        // pub/sub directory found
        let target_dir = token_sets_dir.join(pub_sub_dir);
        let topic_encoded = general_purpose::URL_SAFE_NO_PAD.encode(request.topic()).as_str();

        for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.path().starts_with(topic_encoded) && !entry.path_is_symlink() {
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
    Ok(None)
}

pub async fn fetch_tokens<A: ToSocketAddrs + Send + 'static>(
    issuer_addr: A,
    tls_config: Arc<rustls::ClientConfig>,
    request: &issuer::Request,
) -> Result<issuer::ResponseReader, TokenSetFetchError> {
    // Connect to the issuer
    let mut issuer_stream = TlsClient::new(issuer_addr, None, tls_config)
        .connect("localhost")
        .await?;
    let mut buf = [0u8; 8];

    // Write a request
    request.write_to(&mut issuer_stream, &mut buf[..]).await?;

    // Read the response
    if let Some(success_response) = issuer::ResponseReader::read_from(
        &mut issuer_stream,
        &mut buf[..],
        request.aead_algo(),
        request.num_tokens_divided_by_4(),
    )
        .await?
    {
        Ok(success_response)
    } else {
        eprintln!("issuing tokens failed on server side");
        Err(TokenSetFetchError::ErrorResponseFromIssuer)
    }
}

