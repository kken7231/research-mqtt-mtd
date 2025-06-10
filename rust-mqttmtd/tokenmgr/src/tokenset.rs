use crate::errors::TokenSetError;
use base64::{engine::general_purpose, Engine};
use bytes::{Bytes, BytesMut};
use libmqttmtd::utils::calculate_token;
use libmqttmtd::{
    aead::{algo::SupportedAlgorithm, open, seal},
    auth_serv::issuer,
    consts::TIMESTAMP_LEN,
    utils,
};
use ring::hmac::{Key, HMAC_SHA256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Token set representation in the file or from the issuer Response
#[derive(Debug)]
pub struct TokenSet {
    // May be empty or already removed, but it is refreshed once the file is saved or the structure
    // is loaded from the file.
    pub path: PathBuf,

    timestamp: [u8; TIMESTAMP_LEN],
    num_tokens: u16,
    token_idx: u16,
    topic: String,
    is_pub: bool,

    algo: SupportedAlgorithm,
    secret_key: Bytes,
    secret_key_for_hmac: Key,
    nonce_base: u128,
}

impl TokenSet {
    /// Helper function to encode topic string.
    fn topic_b64encode(topic: impl Into<String>) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(topic.into())
    }

    /// Gets the current token. `None` if `token_idx` has reached `num_tokens`,
    /// otherwise `Some`. DOES NOT increment token_idx
    pub fn get_current_b64token(&self) -> Option<String> {
        if self.token_idx < self.num_tokens {
            let cur_token = calculate_token(
                &self.timestamp,
                &self.secret_key_for_hmac,
                self.topic.as_str(),
                self.token_idx,
            );
            Some(general_purpose::URL_SAFE_NO_PAD.encode(&cur_token))
        } else {
            None
        }
    }

    pub fn print_current_token(&self) {
        println!(
            "Current token: {}",
            calculate_token(
                &self.timestamp,
                &self.secret_key_for_hmac,
                self.topic.as_str(),
                self.token_idx
            )
            .iter()
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

    /// Seals payload with its AEAD algorithm for the publish from client to
    /// broker
    pub fn seal_cli2serv(&self, payload: &mut [u8]) -> Result<Bytes, ring::error::Unspecified> {
        let tag = seal(
            self.algo,
            &self.secret_key,
            &self.get_nonce_for_cli2serv_pub(),
            payload,
        )?;
        let mut combined = BytesMut::from(&payload[..]);
        combined.extend_from_slice(tag.as_ref());
        Ok(combined.freeze())
    }

    /// Opens payload with its AEAD algorithm for the publish from client to
    /// broker
    pub fn open_cli2serv(&self, in_out: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        open(
            self.algo,
            &self.secret_key,
            &self.get_nonce_for_cli2serv_pub(),
            in_out,
        )
    }

    /// Seals payload with its AEAD algorithm for the publish from broker to
    /// client
    pub fn seal_serv2cli(
        &self,
        packet_id: u16,
        payload: &mut [u8],
    ) -> Result<Bytes, ring::error::Unspecified> {
        let tag = seal(
            self.algo,
            &self.secret_key,
            &self.get_nonce_for_serv2cli_pub(packet_id),
            payload,
        )?;
        let mut combined = BytesMut::from(&payload[..]);
        combined.extend_from_slice(tag.as_ref());
        Ok(combined.freeze())
    }

    /// Opens payload with its AEAD algorithm for the publish from broker to
    /// client
    pub fn open_serv2cli(
        &self,
        packet_id: u16,
        in_out: &mut [u8],
    ) -> Result<(), ring::error::Unspecified> {
        open(
            self.algo,
            &self.secret_key,
            &self.get_nonce_for_serv2cli_pub(packet_id),
            in_out,
        )
    }

    /// Gets a nonce for the publish from client to broker.
    pub fn get_nonce_for_cli2serv_pub(&self) -> Bytes {
        let nonce = self.nonce_base + (self.token_idx as u128);
        utils::nonce_from_u128_to_bytes(self.algo, nonce)
    }

    /// Gets a nonce for the publish from broker to client.
    pub fn get_nonce_for_serv2cli_pub(&self, packet_id: u16) -> Bytes {
        let nonce =
            self.nonce_base + ((packet_id as u128).rotate_left(16) | (self.token_idx as u128));
        utils::nonce_from_u128_to_bytes(self.algo, nonce)
    }

    /// Constructs a token set from Issuer Request & Response. intentionally
    /// takes response's ownership.
    pub fn from_issuer_req_resp(
        request: &issuer::Request,
        response: issuer::ResponseReader,
    ) -> Result<Self, TokenSetError> {
        // algo
        let algo = request.algo();

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

        Ok(Self {
            path: PathBuf::new(),
            timestamp: response.timestamp().clone(),
            num_tokens,
            token_idx: 0,
            topic: request.topic().to_owned(),
            is_pub: request.is_pub(),
            algo: request.algo(),
            secret_key: Bytes::copy_from_slice(response.secret_key()),
            secret_key_for_hmac: Key::new(HMAC_SHA256, response.secret_key()),
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

        // algo
        file.read_exact(&mut buf[0..1])
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let algo = SupportedAlgorithm::try_from(buf[0])
            .map_err(|e| TokenSetError::UnsupportedAlgorithmError(e))?;

        // secret_key
        let secret_key_len = algo.key_len();
        let mut secret_key = BytesMut::zeroed(secret_key_len);
        file.read_exact(&mut secret_key)
            .map_err(|e| TokenSetError::FileReadError(e))?;
        let secret_key = secret_key.freeze();

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

        Ok(Self {
            path,
            timestamp,
            num_tokens,
            token_idx: file_token_idx,
            topic,
            is_pub,
            algo,
            secret_key_for_hmac: Key::new(HMAC_SHA256, secret_key.as_ref()),
            secret_key,
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

        // algo
        buf[0] = self.algo as u8;
        file.write_all(&buf[0..1])
            .map_err(|e| TokenSetError::FileWriteError(e))?;

        // secret_key
        if self.secret_key.len() != self.algo.key_len() {
            return Err(TokenSetError::EncKeyMismatchError(self.secret_key.len()));
        }
        file.write_all(&self.secret_key)
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
