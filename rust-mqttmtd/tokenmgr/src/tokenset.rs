use crate::errors::TokenSetError;
use base64::engine::general_purpose;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::auth_serv::issuer;
use libmqttmtd::consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN};
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Token set representation in the file or from the issuer Response
pub struct TokenSet {
    pub path: PathBuf,

    pub timestamp: [u8; TIMESTAMP_LEN],
    pub all_randoms: Vec<[u8; RANDOM_LEN]>,
    pub num_tokens: u16,
    pub token_idx: u16,
    pub topic: String,
    pub is_pub: bool,

    pub algo: SupportedAlgorithm,
    pub enc_key: Bytes,
    pub nonce_base: Bytes,
}

impl TokenSet {
    /// Helper function to encode topic string.
    fn topic_b64encode(topic: &str) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(topic)
    }

    /// Gets the current token. `None` if `token_idx` has reached `num_tokens`, otherwise `Some`.
    pub fn get_current_b64token(&self) -> Option<String> {
        if self.num_tokens > self.token_idx {
            let mut cur_token = [0u8; TOKEN_LEN];
            cur_token[..TIMESTAMP_LEN].copy_from_slice(&self.timestamp[..]);
            cur_token[TIMESTAMP_LEN..].copy_from_slice(&self.all_randoms[self.token_idx as usize]);
            Some(general_purpose::URL_SAFE_NO_PAD.encode(&cur_token))
        } else {
            None
        }
    }

    /// Constructs a token set from Issuer Request & Response. intentionally takes response's ownership.
    pub fn from_issuer_req_resp(
        request: &issuer::Request,
        response: issuer::ResponseReader,
        token_sets_dir: Arc<PathBuf>,
    ) -> Result<Self, TokenSetError> {
        let pub_sub_dir = if request.is_pub() {
            token_sets_dir.join("pub")
        } else {
            token_sets_dir.join("sub")
        };
        fs::create_dir_all(pub_sub_dir.as_path()).map_err(|e| TokenSetError::FileCreateError(e))?;

        let topic_encoded = Self::topic_b64encode(request.topic());
        let filename = format!("{}0", topic_encoded);
        let path = pub_sub_dir.join(filename);

        // aead_algo
        let algo = request.aead_algo();

        // nonce_base
        if response.nonce_base().len() < algo.nonce_len() {
            return Err(TokenSetError::NonceLenMismatchError(
                response.nonce_base().len(),
            ));
        }
        // num_tokens
        let num_tokens = (request.num_tokens_divided_by_4() as u16).rotate_left(2);

        // all_randoms
        let iter = response.all_randoms().chunks_exact(RANDOM_LEN);
        if iter.remainder().len() != 0 {
            return Err(TokenSetError::RandomLenMismatchError(
                iter.len() * RANDOM_LEN + iter.remainder().len(),
            ));
        }
        let mut all_randoms: Vec<[u8; RANDOM_LEN]> = Vec::with_capacity(num_tokens as usize);
        for rand in iter {
            let mut rand_bytes = [0u8; RANDOM_LEN];
            rand_bytes.copy_from_slice(rand);
            all_randoms.push(rand_bytes);
        }

        Ok(Self {
            path,
            timestamp: response.timestamp().clone(),
            all_randoms,
            num_tokens,
            token_idx: 0,
            topic: request.topic().to_owned(),
            is_pub: request.is_pub(),
            algo: request.aead_algo(),
            enc_key: Bytes::copy_from_slice(response.enc_key()),
            nonce_base: Bytes::copy_from_slice(response.nonce_base()),
        })
    }

    /// Constructs a token set from an existing file.
    pub fn from_file(path: PathBuf, is_pub: bool, topic: String) -> Result<Self, TokenSetError> {
        let topic_encoded = Self::topic_b64encode(&topic);

        let filename_osstr = match path.file_name() {
            Some(name) => name,
            None => return Err(TokenSetError::PathNotHavingFilenameError),
        };

        // Convert OsStr to a string slice. to_string_lossy handles non-UTF-8 filenames.
        let filename_str = filename_osstr.to_string_lossy();
        let curidx_slice = &filename_str[topic_encoded.len()..];

        // Parse and get cur_idx from the filename
        let token_idx = curidx_slice.parse::<u16>();
        if let Err(_) = token_idx {
            return Err(TokenSetError::InvalidCurIdxInFilenameError(None));
        }
        let token_idx = token_idx.unwrap();
        if token_idx > 0x7F * 4 {
            return Err(TokenSetError::InvalidCurIdxInFilenameError(Some(token_idx)));
        }

        // Start reading
        let mut file: fs::File =
            fs::File::open(&path).map_err(|e| TokenSetError::FileOpenError(e))?;
        let mut buf = [0u8; 2];

        // aead_algo
        file.read_exact(&mut buf[0..1])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let algo = SupportedAlgorithm::try_from(buf[0])
            .map_err(|e| TokenSetError::UnsupportedAlgorithmError(e))?;

        // enc_key
        let enc_key_len = algo.key_len();
        let mut enc_key = BytesMut::zeroed(enc_key_len);
        file.read_exact(&mut enc_key)
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let enc_key = enc_key.freeze();

        // nonce_base
        let nonce_len = algo.nonce_len();
        let mut nonce_base = BytesMut::zeroed(nonce_len);
        file.read_exact(&mut nonce_base)
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let nonce_base = nonce_base.freeze();

        // num_tokens_divided_by_4
        file.read_exact(&mut buf[0..1])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let num_tokens_divided_by_4 = buf[0];
        if num_tokens_divided_by_4 > 0x7F || num_tokens_divided_by_4 as u16 * 4 <= token_idx {
            return Err(TokenSetError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        }
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);

        // timestamp
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        file.read_exact(&mut timestamp[..])
            .map_err(|e| TokenSetError::FileReadError(e))?;

        // all_randoms
        file.seek_relative(token_idx as i64)
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let mut all_randoms: Vec<[u8; RANDOM_LEN]> = Vec::with_capacity(num_tokens as usize);
        all_randoms.resize(token_idx as usize, [0u8; RANDOM_LEN]); // fill unused slots with an empty bytes
        loop {
            let mut random = [0u8; RANDOM_LEN];
            match file
                .read(&mut random[..])
                .map_err(|e| TokenSetError::FileReadError(e))?
            {
                RANDOM_LEN => all_randoms.push(random),
                0 => break,
                other_len => {
                    return Err(TokenSetError::RandomLenMismatchError(
                        RANDOM_LEN * all_randoms.len() + other_len,
                    ));
                }
            };
        }

        Ok(Self {
            path,
            timestamp,
            all_randoms,
            num_tokens,
            token_idx,
            topic,
            is_pub,
            algo,
            enc_key,
            nonce_base,
        })
    }

    /// Save a token set to a file.
    pub fn to_file(&self) -> Result<(), TokenSetError> {
        // Start reading
        let mut file: fs::File =
            fs::File::create(&self.path).map_err(|e| TokenSetError::FileCreateError(e))?;
        let mut buf = [0u8; 2];

        // aead_algo
        buf[0] = self.algo as u8;
        file.write_all(&buf[0..1])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // enc_key
        if self.enc_key.len() != self.algo.key_len() {
            return Err(TokenSetError::EncKeyMismatchError(self.enc_key.len()));
        }
        file.write_all(&self.enc_key)
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // nonce_base
        if self.nonce_base.len() < self.algo.nonce_len() {
            return Err(TokenSetError::NonceLenMismatchError(self.nonce_base.len()));
        }
        file.write_all(&self.nonce_base)
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // num_tokens_divided_by_4
        buf[0] = self.num_tokens.rotate_right(2) as u8;
        file.write_all(&buf[0..1])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // timestamp
        file.write_all(&self.timestamp)
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // all_randoms
        for rand in self.all_randoms.iter() {
            file.write_all(rand)
                .map_err(|e| TokenSetError::FileWriteError(e))?;
        }

        Ok(())
    }

    /// Refreshes a token index in the filename.
    pub fn refresh_filename(&self) -> Result<(), TokenSetError> {
        let parent_dir = self.path.parent().unwrap_or_else(|| Path::new("/"));
        let topic_encoded = Self::topic_b64encode(&self.topic);
        let new_filename = format!("{}{}", topic_encoded, self.token_idx);

        fs::rename(&self.path, parent_dir.join(new_filename))
            .map_err(|e| TokenSetError::FileRenameError(e))?;
        Ok(())
    }
}
