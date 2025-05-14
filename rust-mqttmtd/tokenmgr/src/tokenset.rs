use crate::errors::TokenSetError;
use base64::engine::general_purpose;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::aead::{open, seal};
use libmqttmtd::auth_serv::issuer;
use libmqttmtd::consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN};
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

/// Token set representation in the file or from the issuer Response
#[derive(Debug)]
pub struct TokenSet {
    // May be empty or already removed, but it is refreshed once the file is saved or the structure
    // is loaded from the file.
    pub path: PathBuf,

    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: Bytes,
    num_tokens: u16,
    token_idx: u16,
    all_randoms_offset: u16,
    topic: String,
    is_pub: bool,

    algo: SupportedAlgorithm,
    enc_key: Bytes,
    nonce_base: u128,
}

impl TokenSet {
    /// Helper function to encode topic string.
    fn topic_b64encode(topic: impl Into<String>) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(topic.into())
    }

    /// Gets the current token. `None` if `token_idx` has reached `num_tokens`, otherwise `Some`.
    /// DOES NOT increment token_idx
    pub fn get_current_b64token(&self) -> Option<String> {
        let random_start = RANDOM_LEN * (self.token_idx - self.all_randoms_offset) as usize;
        let random_end = RANDOM_LEN + random_start;

        if self.all_randoms.len() >= random_end {
            let mut cur_token = [0u8; TOKEN_LEN];
            cur_token[..TIMESTAMP_LEN].copy_from_slice(&self.timestamp[..]);
            cur_token[TIMESTAMP_LEN..].copy_from_slice(&self.all_randoms[random_start..random_end]);

            Some(general_purpose::URL_SAFE_NO_PAD.encode(&cur_token))
        } else {
            None
        }
    }

    pub fn print_current_token(&self) {
        println!(
            "Current token: {}",
            self.timestamp
                .iter()
                .chain(self.all_randoms[..RANDOM_LEN].iter())
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
    }

    /// Increments `token_idx`.
    pub fn increment_token_idx(&mut self) {
        self.token_idx += 1;
    }

    /// Gets `topic`.
    pub fn topic(&self) -> String {
        self.topic.clone()
    }

    /// Seals payload with its AEAD algorithm
    pub fn seal(&self, payload: &mut [u8]) -> Result<Bytes, ring::error::Unspecified> {
        let tag = seal(self.algo, &self.enc_key, &self.get_nonce(), payload)?;
        let mut combined = BytesMut::from(&payload[..]);
        combined.extend_from_slice(tag.as_ref());
        Ok(combined.freeze())
    }

    /// Opens sealed payload with its AEAD algorithm
    pub fn open(&self, in_out: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        open(self.algo, &self.enc_key, &self.get_nonce(), in_out)
    }

    /// Gets a nonce.
    pub fn get_nonce(&self) -> Bytes {
        let nonce = self.nonce_base + self.token_idx as u128;
        let mut nonce_bytes = BytesMut::zeroed(self.algo.nonce_len());
        nonce
            .to_be_bytes()
            .iter()
            .skip(128 / 8 - self.algo.nonce_len())
            .enumerate()
            .for_each(|(i, b)| nonce_bytes[i] = *b);
        nonce_bytes.freeze()
    }

    /// Constructs a token set from Issuer Request & Response. intentionally takes response's ownership.
    pub fn from_issuer_req_resp(
        request: &issuer::Request,
        response: issuer::ResponseReader,
    ) -> Result<Self, TokenSetError> {
        // aead_algo
        let algo = request.aead_algo();

        // nonce_base
        if response.nonce_base().len() < algo.nonce_len() {
            return Err(TokenSetError::NonceLenMismatchError(
                response.nonce_base().len(),
            ));
        }
        let mut nonce_base_bytes = [0u8; 16];
        nonce_base_bytes[(16 - algo.nonce_len())..].copy_from_slice(&response.nonce_base());
        let nonce_base = u128::from_be_bytes(nonce_base_bytes);

        // num_tokens
        let num_tokens = (request.num_tokens_divided_by_4() as u16).rotate_left(2);

        // all_randoms
        if response.all_randoms().len() % RANDOM_LEN != 0 {
            return Err(TokenSetError::RandomLenMismatchError(
                response.all_randoms().len(),
            ));
        }
        let all_randoms = Bytes::copy_from_slice(response.all_randoms());

        Ok(Self {
            path: PathBuf::new(),
            timestamp: response.timestamp().clone(),
            all_randoms,
            num_tokens,
            token_idx: 0,
            all_randoms_offset: 0,
            topic: request.topic().to_owned(),
            is_pub: request.is_pub(),
            algo: request.aead_algo(),
            enc_key: Bytes::copy_from_slice(response.enc_key()),
            nonce_base,
        })
    }

    /// Constructs a token set from an existing file.
    pub fn from_file(path: PathBuf, is_pub: bool, topic: String) -> Result<Self, TokenSetError> {
        if !path.exists() || !path.is_file() {
            return Err(TokenSetError::FileNotFoundError(path));
        }
        let filename_osstr = match path.file_name() {
            Some(name) => name,
            None => return Err(TokenSetError::FileNotFoundError(path)),
        };

        let topic_encoded = Self::topic_b64encode(&topic);

        // Convert OsStr to a string slice. to_string_lossy handles non-UTF-8 filenames.
        let filename_str = filename_osstr.to_string_lossy();
        let curidx_slice = &filename_str[topic_encoded.len()..];

        // Parse and get cur_idx from the filename
        let token_idx = curidx_slice.parse::<u16>();
        if let Err(_) = token_idx {
            return Err(TokenSetError::InvalidCurIdxInFilenameError(None));
        }
        let file_token_idx = token_idx.unwrap();
        if file_token_idx > 0x7F * 4 {
            return Err(TokenSetError::InvalidCurIdxInFilenameError(Some(
                file_token_idx,
            )));
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
        let mut nonce_base_bytes = [0u8; 16];
        file.read_exact(&mut nonce_base_bytes[(16 - algo.nonce_len())..])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let nonce_base = u128::from_be_bytes(nonce_base_bytes);

        // num_tokens_divided_by_4
        file.read_exact(&mut buf[0..1])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let num_tokens_divided_by_4 = buf[0];
        if num_tokens_divided_by_4 > 0x7F || num_tokens_divided_by_4 as u16 * 4 <= file_token_idx {
            return Err(TokenSetError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        }
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);

        // timestamp
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        file.read_exact(&mut timestamp[..])
            .map_err(|e| TokenSetError::FileReadError(e))?;

        // file_all_randoms_offset
        file.read_exact(&mut buf[0..2])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let file_all_randoms_offset = u16::from_be_bytes(buf);
        if num_tokens <= file_all_randoms_offset {
            return Err(TokenSetError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        } else if file_token_idx < file_all_randoms_offset {
            return Err(TokenSetError::InvalidCurIdxInFilenameError(Some(
                file_token_idx,
            )));
        }

        // decide how many bytes to skip
        let skip_len = (file_token_idx - file_all_randoms_offset) * RANDOM_LEN as u16;
        file.seek_relative(skip_len as i64)
            .map_err(|e| TokenSetError::FileReadError(e))?;

        // all_randoms in this structure will have randoms from `token_idx` by skipping some bytes
        let mut all_randoms = BytesMut::zeroed((num_tokens - file_token_idx) as usize * RANDOM_LEN);
        let actual_read = file
            .read(&mut all_randoms)
            .map_err(|e| TokenSetError::FileReadError(e))?;
        if actual_read < (num_tokens - file_token_idx) as usize * RANDOM_LEN {
            return Err(TokenSetError::RandomLenMismatchError(actual_read));
        }
        let all_randoms = all_randoms.freeze();

        Ok(Self {
            path,
            timestamp,
            all_randoms,
            all_randoms_offset: file_token_idx,
            num_tokens,
            token_idx: file_token_idx,
            topic,
            is_pub,
            algo,
            enc_key,
            nonce_base,
        })
    }

    /// Save a token set to a file.
    pub fn save_to_file(&mut self, token_sets_dir: &Path) -> Result<(), TokenSetError> {
        // Remove old
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| TokenSetError::FileRemoveError(e))?;
        }

        let pub_sub_dir = if self.is_pub {
            token_sets_dir.join("pub")
        } else {
            token_sets_dir.join("sub")
        };

        fs::create_dir_all(pub_sub_dir.as_path()).map_err(|e| TokenSetError::FileCreateError(e))?;

        let topic_encoded = Self::topic_b64encode(&self.topic);
        let filename = format!("{}{}", topic_encoded, self.token_idx);
        let path = pub_sub_dir.join(filename);

        let mut file: fs::File =
            fs::File::create(&path).map_err(|e| TokenSetError::FileCreateError(e))?;
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
        file.write_all(&self.nonce_base.to_be_bytes()[(16 - self.algo.nonce_len())..])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // num_tokens_divided_by_4
        buf[0] = self.num_tokens.rotate_right(2) as u8;
        file.write_all(&buf[0..1])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // timestamp
        file.write_all(&self.timestamp)
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // all_randoms_offset
        // File's all_randoms_offset: the absolute original index where the random data in this file begins.
        file.write_all(&self.token_idx.to_be_bytes())
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // all_randoms
        let skip_len = (self.token_idx - self.all_randoms_offset) as usize * RANDOM_LEN;
        if skip_len > self.all_randoms.len() {
            return Err(TokenSetError::InvalidNumTokensError(
                self.num_tokens.rotate_right(2) as u8,
            ));
        }
        file.write_all(&self.all_randoms[skip_len..])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        self.path = path;
        Ok(())
    }

    /// Refreshes a token index in the filename.
    pub fn refresh_filename(&mut self) -> Result<(), TokenSetError> {
        if !self.path.exists() {
            return Err(TokenSetError::FileNotFoundError(self.path.clone()));
        }
        let parent_dir = self.path.parent().unwrap_or_else(|| Path::new("/"));
        let topic_encoded = Self::topic_b64encode(&self.topic);
        let new_path = parent_dir.join(format!("{}{}", topic_encoded, self.token_idx));

        fs::rename(&self.path, &new_path).map_err(|e| TokenSetError::FileRenameError(e))?;

        self.path = new_path;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
