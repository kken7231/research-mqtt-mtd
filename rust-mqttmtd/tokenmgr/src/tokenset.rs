use bytes::{Bytes, BytesMut};
use libmqttmtd::aead::algo::SupportedAlgorithm;
use libmqttmtd::consts::{RANDOM_LEN, TIMESTAMP_LEN};
use std::error::Error;
use std::fs;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose;
use libmqttmtd::auth_serv::issuer;

pub struct TokenSet {
    path: PathBuf,

    timestamp: [u8; TIMESTAMP_LEN],
    all_randoms: Vec<[u8; RANDOM_LEN]>,
    num_tokens: u16,
    token_idx: u16,
    topic: String,
    is_pub: bool,

    algo: SupportedAlgorithm,
    enc_key: Bytes,
    nonce_base: Bytes,
}

impl TokenSet {
    /// Helper function to encode topic string
    fn topic_b64encode(topic: &str) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(topic)
    }
    
    pub fn from_issuer_req_resp(request: issuer::Request, response: issuer::ResponseReader,
                                token_sets_dir: Arc<PathBuf>) -> Result<Self, Box<dyn Error>> {
        let pub_sub_dir = if request.is_pub() {
            token_sets_dir.join("pub")
        } else {
            token_sets_dir.join("sub")
        };
        fs::create_dir_all(token_sets_dir.as_path())?;

        let topic_encoded = Self::topic_b64encode(request.topic());
        let filename = format!("{}0", topic_encoded);
        let path = pub_sub_dir.join(filename);

        // aead_algo
        let algo = request.aead_algo();

        // nonce_base
        if response.nonce_base().len() < request.aead_algo().nonce_len() {
            return Err(TokensetWriteError::NonceLenMismatchError);
        }
        // num_tokens
        let num_tokens = (request.num_tokens_divided_by_4() as u16).rotate_left(2);

        // all_randoms
        let iter = response.all_randoms().chunks_exact(RANDOM_LEN);
        if iter.remainder().len() != 0 {
            return Err(TokensetWriteError::NonceLenMismatchError);
        }
        let mut all_randoms: Vec<[u8; RANDOM_LEN]> = Vec::with_capacity(num_tokens as usize);
        for rand in iter {
            let rand_bytes = [0u8; RANDOM_LEN];
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
            enc_key: Bytes::from_owner(response.enc_key()),
            nonce_base: Bytes::from_owner(response.nonce_base()),
        })
    }

    pub fn from_file(path: PathBuf, is_pub: bool, topic: String) -> Result<Self, Box<dyn Error>> {
        let topic_encoded = Self::topic_b64encode(&topic).as_str();

        let filename_osstr = match path.file_name() {
            Some(name) => name,
            None => return Err(TokensetReadError::PathNotHavingFilenameError),
        };

        // Convert OsStr to a string slice. to_string_lossy handles non-UTF-8 filenames.
        let filename_str = filename_osstr.to_string_lossy();
        let curidx_slice = &filename_str[topic_encoded.len()..];

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
        let mut file: fs::File = fs::File::open(&path)?;
        let mut buf = [0u8; 2];

        // aead_algo
        file.read_exact(&mut buf[0..1])?;
        let algo = SupportedAlgorithm::try_from(buf[0])?;

        // enc_key
        let enc_key_len = algo.key_len();
        let mut enc_key = BytesMut::zeroed(enc_key_len);
        file.read_exact(&mut enc_key)?;
        let enc_key = enc_key.freeze();

        // nonce_base
        let nonce_len = algo.nonce_len();
        let mut nonce_base = BytesMut::zeroed(nonce_len);
        file.read_exact(&mut nonce_base)?;
        let nonce_base = nonce_base.freeze();

        // num_tokens_divided_by_4
        file.read_exact(&mut buf[0..1])?;
        let num_tokens_divided_by_4 = buf[0];
        if num_tokens_divided_by_4 > 0x7F || num_tokens_divided_by_4 as u16 * 4 <= token_idx {
            return Err(TokensetReadError::InvalidNumTokensError(
                num_tokens_divided_by_4,
            ));
        }
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);

        // timestamp
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        file.read_exact(&mut timestamp[..])?;
        let timestamp = timestamp;

        // all_randoms
        file.seek_relative(token_idx as i64)?;
        let mut all_randoms: Vec<[u8; RANDOM_LEN]> = Vec::with_capacity(num_tokens as usize);
        all_randoms.resize(token_idx as usize, [0u8; RANDOM_LEN]); // fill unused slots with an empty bytes
        loop {
            let mut random = [0u8; RANDOM_LEN];
            let len = file.read(&mut random[..])?;
            if len == RANDOM_LEN {
                all_randoms.push(random);
            } else if len == 0 {
                // EOF
                break;
            } else {
                return Err(TokensetReadError::);
            }
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

    pub fn to_file(
        self,
    ) -> Result<(), TokensetWriteError> {
        // Start reading
        let mut file: fs::File = fs::File::create(self.path)?;
        let mut buf = [0u8; 2];

        // aead_algo
        buf[0] = self.algo as u8;
        file.write_all(&buf[0..1])?;

        // enc_key
        if self.enc_key.len() != self.algo.key_len() {
            return Err(TokensetWriteError::EncKeyLenMismatchError);
        }
        file.write_all(&self.enc_key)?;

        // nonce_base
        if self.nonce_base.len() < self.algo.nonce_len() {
            return Err(TokensetWriteError::NonceLenMismatchError);
        }
        file.write_all(&self.nonce_base)?;

        // num_tokens_divided_by_4
        buf[0] = self.num_tokens.rotate_right(2) as u8;
        file.write_all(&buf[0..1])?;

        // timestamp
        file.write_all(&self.timestamp)?;

        // all_randoms
        for rand in self.all_randoms.iter() {
            file.write_all(rand)?;
        }

        Ok(())
    }

    pub fn refresh_filename(&self) -> Result<(), Box<dyn Error>> {
        let parent_dir = match self.path.parent() {
            Some(p) => p,
            None => return Err(),
        };
        let topic_encoded = Self::topic_b64encode(&self.topic).as_str();
        let new_filename = format!("{}{}", topic_encoded, self.token_idx);

        fs::rename(&self.path, parent_dir.join(new_filename))?;
        Ok(())
    }
}
