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

/// Token set representation in the file or from the issuer Response
#[derive(Debug, Clone)]
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
        let mut all_randoms =
            BytesMut::with_capacity((num_tokens - file_token_idx) as usize * RANDOM_LEN);
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
mod token_set_tests {
    use super::*;
    use base64::engine::general_purpose;
    // Import everything from the outer scope
    use base64::Engine;
    use bytes::Bytes;
    use libmqttmtd::aead::algo::SupportedAlgorithm;
    // Assuming these traits are defined in libmqttmtd
    use libmqttmtd::consts::{RANDOM_LEN, TIMESTAMP_LEN};
    use std::path::PathBuf;
    use std::sync::Arc;
    // Arc is still used in from_issuer_req_resp's original signature, keep it for the mock
    use tempfile::tempdir;

    // Define constants for testing (ensure these match the crate's actual consts and algo properties)
    // These are examples based on common AEAD properties.
    const TEST_TIMESTAMP: [u8; TIMESTAMP_LEN] = [1, 2, 3, 4, 5, 6];
    const TEST_RANDOM_1: [u8; RANDOM_LEN] = [9; RANDOM_LEN];
    const TEST_RANDOM_2: [u8; RANDOM_LEN] = [10; RANDOM_LEN];
    const TEST_RANDOM_3: [u8; RANDOM_LEN] = [11; RANDOM_LEN];
    const TEST_RANDOM_4: [u8; RANDOM_LEN] = [12; RANDOM_LEN];
    const TEST_RANDOM_5: [u8; RANDOM_LEN] = [13; RANDOM_LEN];
    const TEST_TOPIC: &str = "topic/pubsub";
    const TEST_PUB_TOPIC: &str = "topic/pubonly";
    const TEST_SUB_TOPIC: &str = "topic/subonly";

    // Assuming SupportedAlgorithm::Aes128Gcm exists with key_len 16 and nonce_len 12
    const TEST_ALGO: SupportedAlgorithm = SupportedAlgorithm::Aes128Gcm;
    const TEST_ENC_KEY: [u8; 16] = [1u8; 16]; // Key length for AES128-GCM
    const TEST_NONCE_BASE_VAL: u128 = 12345678901234567890; // Example large nonce base
    const TEST_NONCE_BASE_BYTES: [u8; 12] = [2u8; 12]; // Example nonce base bytes (12 for AES128-GCM)

    const TEST_NUM_TOKENS: u16 = 8; // Must be a multiple of 4
    const TEST_NUM_TOKENS_DIVIDED_BY_4: u8 = (TEST_NUM_TOKENS / 4) as u8;

    async fn new_response_reader(
        enc_key: Bytes,
        nonce_base: Bytes,
        timestamp: [u8; TIMESTAMP_LEN],
        all_randoms: Bytes,
        aead_algo: SupportedAlgorithm,
        num_tokens_divided_by_4: u8,
    ) -> Result<issuer::ResponseReader, Box<dyn std::error::Error>> {
        let writer = issuer::ResponseWriter::new(&enc_key, &nonce_base, timestamp, &all_randoms);
        let mut buf = [0u8; issuer::REQ_RESP_MIN_BUFLEN];

        let mut inner_vec: Vec<u8> = Vec::new();

        let write_result = writer
            .write_success_to(&mut inner_vec, &mut buf[..])
            .await?;

        let mut async_reader = tokio_util::io::StreamReader::new(futures::io::Cursor::new(inner_vec));

        Ok(issuer::ResponseReader::read_from(
            &mut async_reader,
            &mut buf[..],
            aead_algo,
            num_tokens_divided_by_4,
        )
            .await?
            .unwrap())
    }
    #[test]
    fn test_topic_b64encode() {
        assert_eq!(
            TokenSet::topic_b64encode("a/b/c"),
            general_purpose::URL_SAFE_NO_PAD.encode("a/b/c")
        );
        assert_eq!(
            TokenSet::topic_b64encode("test topic with spaces"),
            general_purpose::URL_SAFE_NO_PAD.encode("test topic with spaces")
        );
        assert_eq!(
            TokenSet::topic_b64encode(""),
            general_purpose::URL_SAFE_NO_PAD.encode("")
        );
        assert_eq!(
            TokenSet::topic_b64encode("あいうえお"),
            general_purpose::URL_SAFE_NO_PAD.encode("あいうえお")
        );
    }

    #[test]
    fn test_get_current_b64token() {
        let timestamp = TEST_TIMESTAMP;
        let randoms_vec = vec![TEST_RANDOM_1, TEST_RANDOM_2, TEST_RANDOM_3, TEST_RANDOM_4]; // Original randoms
        let all_randoms_buffer: Bytes = randoms_vec
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
            .into();
        let num_tokens = randoms_vec.len() as u16;

        let token_set = TokenSet {
            path: PathBuf::new(), // Not relevant for this test
            timestamp,
            all_randoms: all_randoms_buffer.clone(),
            num_tokens,
            token_idx: 0,          // Absolute index of the next token
            all_randoms_offset: 0, // Absolute index where all_randoms buffer starts
            topic: "dummy".to_string(),
            is_pub: true,
            algo: TEST_ALGO,       // Not relevant for this test
            enc_key: Bytes::new(), // Not relevant for this test
            nonce_base: 0,         // Not relevant for this test
        };

        // Get the first token (token_idx = 0)
        let expected_token_1_bytes: Vec<u8> = timestamp
            .iter()
            .chain(randoms_vec[0].iter()) // Use original random at index 0
            .cloned()
            .collect();
        let expected_token_1 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_1_bytes);
        assert_eq!(token_set.get_current_b64token(), Some(expected_token_1));

        // Simulate using the first token (increment token_idx)
        let mut token_set_idx1 = token_set.clone();
        token_set_idx1.token_idx = 1;

        // Get the second token (token_idx = 1)
        let expected_token_2_bytes: Vec<u8> = timestamp
            .iter()
            .chain(randoms_vec[1].iter()) // Use original random at index 1
            .cloned()
            .collect();
        let expected_token_2 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_2_bytes);
        assert_eq!(
            token_set_idx1.get_current_b64token(),
            Some(expected_token_2)
        );

        // Simulate a scenario where the all_randoms buffer starts at a non-zero offset
        let all_randoms_offset_non_zero: u16 = 1; // Buffer starts at original index 1
        let all_randoms_buffer_sliced: Bytes = randoms_vec[all_randoms_offset_non_zero as usize..]
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<u8>>()
            .into();

        let token_set_offset = TokenSet {
            path: PathBuf::new(),
            timestamp,
            all_randoms: all_randoms_buffer_sliced, // Buffer contains randoms from original index 1
            num_tokens,
            token_idx: 1, // Absolute index of the next token is 1
            all_randoms_offset: all_randoms_offset_non_zero, // Buffer starts at original index 1
            topic: "dummy".to_string(),
            is_pub: true,
            algo: TEST_ALGO,
            enc_key: Bytes::new(),
            nonce_base: 0,
        };

        // Get the token at absolute index 1. This corresponds to index (1 - 1) = 0 in the buffer.
        let expected_token_offset_bytes: Vec<u8> = timestamp
            .iter()
            .chain(randoms_vec[1].iter()) // Use original random at index 1
            .cloned()
            .collect();
        let expected_token_offset =
            general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_offset_bytes);
        assert_eq!(
            token_set_offset.get_current_b64token(),
            Some(expected_token_offset)
        );

        // Simulate using all tokens (token_idx reaches num_tokens)
        let mut token_set_idx_end = token_set.clone(); // Start with offset 0
        token_set_idx_end.token_idx = num_tokens; // Absolute index is num_tokens

        // Should return None because token_idx >= num_tokens
        // The condition `self.all_randoms.len() >= random_end` will also be false as random_start will be out of bounds
        assert_eq!(token_set_idx_end.get_current_b64token(), None);

        // Simulate index beyond num_tokens
        let mut token_set_idx_beyond = token_set.clone();
        token_set_idx_beyond.token_idx = num_tokens + 1;
        assert_eq!(token_set_idx_beyond.get_current_b64token(), None);
    }

    #[test]
    fn test_get_nonce() {
        let nonce_base_val = TEST_NONCE_BASE_VAL;
        let algo = TEST_ALGO; // Nonce len 12

        let token_set_base = TokenSet {
            path: PathBuf::new(),
            timestamp: TEST_TIMESTAMP, // Not relevant
            all_randoms: Bytes::new(), // Not relevant
            num_tokens: 1,             // Not relevant
            token_idx: 0,
            all_randoms_offset: 0,      // Not relevant
            topic: "dummy".to_string(), // Not relevant
            is_pub: true,               // Not relevant
            algo,
            enc_key: Bytes::new(), // Not relevant
            nonce_base: nonce_base_val,
        };

        // Test with token_idx = 0
        let expected_nonce_bytes_0: [u8; 16] = (nonce_base_val + 0).to_be_bytes();
        let expected_nonce_aes128_0: Bytes =
            Bytes::copy_from_slice(&expected_nonce_bytes_0[(16 - algo.nonce_len())..]); // Last 12 bytes
        assert_eq!(token_set_base.get_nonce(), expected_nonce_aes128_0);

        // Test with token_idx > 0
        let token_set_idx5 = TokenSet {
            token_idx: 5,
            ..token_set_base.clone() // Use fields from base, except token_idx
        };
        let expected_nonce_bytes_5: [u8; 16] = (nonce_base_val + 5).to_be_bytes();
        let expected_nonce_aes128_5: Bytes =
            Bytes::copy_from_slice(&expected_nonce_bytes_5[(16 - algo.nonce_len())..]); // Last 12 bytes
        assert_eq!(token_set_idx5.get_nonce(), expected_nonce_aes128_5);

        // Test with a different algorithm (assuming Aes256Gcm with nonce_len 12 exists)
        const TEST_ALGO_AES256GCM: SupportedAlgorithm = SupportedAlgorithm::Aes256Gcm; // Assuming this variant exists
        let token_set_algo = TokenSet {
            algo: TEST_ALGO_AES256GCM,
            ..token_set_base.clone()
        };
        let expected_nonce_aes256_0: Bytes = Bytes::copy_from_slice(
            &expected_nonce_bytes_0[(16 - TEST_ALGO_AES256GCM.nonce_len())..],
        ); // AES256-GCM commonly uses 12-byte nonces
        assert_eq!(token_set_algo.get_nonce(), expected_nonce_aes256_0);
    }

    #[tokio::test]
    async fn test_from_issuer_req_resp_success() -> Result<(), TokenSetError> {
        // token_sets_dir is not used in the final from_issuer_req_resp, but keep signature for mock
        let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
        let token_sets_dir = Arc::new(temp_dir.path().to_path_buf());

        let topic = TEST_PUB_TOPIC.to_string();
        let is_pub = true;
        let algo = TEST_ALGO;
        let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);

        let request = issuer::Request::new(is_pub, num_tokens_divided_by_4, algo, topic.clone())
            .inspect_err(|e| panic!("{:?}", e))
            .unwrap();

        let timestamp = TEST_TIMESTAMP;
        let all_randoms_vec = vec![
            TEST_RANDOM_1,
            TEST_RANDOM_2,
            TEST_RANDOM_3,
            TEST_RANDOM_4,
            TEST_RANDOM_5, // More randoms than num_tokens to test slicing
            [0u8; RANDOM_LEN],
            [0u8; RANDOM_LEN],
            [0u8; RANDOM_LEN], // Ensure enough randoms to match num_tokens for safety
        ];
        let all_randoms_bytes: Bytes = all_randoms_vec
            .clone()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
            .into();
        let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);

        let nonce_base_val = TEST_NONCE_BASE_VAL;
        let mut nonce_base_bytes_full = [0u8; 16];
        nonce_base_bytes_full[(16 - algo.nonce_len())..]
            .copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
        let nonce_base_from_bytes = u128::from_be_bytes(nonce_base_bytes_full);

        let response = new_response_reader(
            enc_key.clone(),
            Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]),
            timestamp,
            all_randoms_bytes.clone(),
            algo,
            num_tokens_divided_by_4,
        )
            .await
            .inspect_err(|e| panic!("{:?}", e))
            .unwrap();

        let token_set = TokenSet::from_issuer_req_resp(&request, response)?; // token_sets_dir is ignored

        // Path should be empty
        assert_eq!(token_set.path, PathBuf::new());
        assert_eq!(token_set.timestamp, timestamp);
        // all_randoms should contain all random bytes from the response
        assert_eq!(token_set.all_randoms, all_randoms_bytes);
        assert_eq!(token_set.num_tokens, num_tokens);
        assert_eq!(token_set.token_idx, 0);
        assert_eq!(token_set.all_randoms_offset, 0); // Should be initialized to 0
        assert_eq!(token_set.topic, topic);
        assert_eq!(token_set.is_pub, is_pub);
        assert_eq!(token_set.algo, algo);
        assert_eq!(token_set.enc_key, enc_key);

        // Check nonce_base conversion
        assert_eq!(token_set.nonce_base, nonce_base_from_bytes);

        Ok(())
    }
    //
    // #[test]
    // fn test_from_issuer_req_resp_error_nonce_len_mismatch() {
    //     // token_sets_dir is not used in the final from_issuer_req_resp, but keep signature for mock
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let token_sets_dir = Arc::new(temp_dir.path().to_path_buf());
    //
    //     let topic = TEST_PUB_TOPIC.to_string();
    //     let is_pub = true;
    //     let algo = TEST_ALGO;
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //
    //     let request = FakeRequest {
    //         topic: topic.clone(),
    //         is_pub,
    //         aead_algo: algo,
    //         num_tokens_divided_by_4,
    //     };
    //
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_bytes: Bytes = vec![TEST_RANDOM_1]
    //         .into_iter()
    //         .flatten()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     // Provide a nonce base shorter than required
    //     let nonce_base = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len() - 1]);
    //
    //     let response =
    //         FakeResponseReader::new(timestamp, all_randoms_bytes, enc_key, nonce_base.clone());
    //
    //     let result = TokenSet::from_issuer_req_resp(&request, response); // token_sets_dir is ignored
    //
    //     match result {
    //         Err(TokenSetError::NonceLenMismatchError(len)) => {
    //             assert_eq!(len, algo.nonce_len() - 1);
    //         }
    //         _ => panic!("Expected NonceLenMismatchError"),
    //     }
    // }
    //
    // #[test]
    // fn test_from_issuer_req_resp_error_random_len_mismatch() {
    //     // token_sets_dir is not used in the final from_issuer_req_resp, but keep signature for mock
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let token_sets_dir = Arc::new(temp_dir.path().to_path_buf());
    //
    //     let topic = TEST_PUB_TOPIC.to_string();
    //     let is_pub = true;
    //     let algo = TEST_ALGO;
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //
    //     let request = FakeRequest {
    //         topic: topic.clone(),
    //         is_pub,
    //         aead_algo: algo,
    //         num_tokens_divided_by_4,
    //     };
    //
    //     let timestamp = TEST_TIMESTAMP;
    //     // Provide randoms data that is not a multiple of RANDOM_LEN
    //     let mut all_randoms_bytes_vec: Vec<u8> =
    //         vec![TEST_RANDOM_1].into_iter().flatten().collect();
    //     all_randoms_bytes_vec.push(0); // Add an extra byte
    //     let all_randoms_bytes: Bytes = all_randoms_bytes_vec.into();
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //
    //     let response =
    //         FakeResponseReader::new(timestamp, all_randoms_bytes.clone(), enc_key, nonce_base);
    //
    //     let result = TokenSet::from_issuer_req_resp(&request, response); // token_sets_dir is ignored
    //
    //     match result {
    //         Err(TokenSetError::RandomLenMismatchError(len)) => {
    //             assert_eq!(len, all_randoms_bytes.len());
    //         }
    //         _ => panic!("Expected RandomLenMismatchError"),
    //     }
    // }
    //
    // // Helper to create a dummy file for from_file tests (Updated file format)
    // // The file_all_randoms_offset written to the file is the absolute original index
    // // where the random data in *this specific file* starts.
    // fn create_dummy_token_file(
    //     dir: &Path,
    //     topic: &str,
    //     filename_token_idx: u16,      // This goes in the filename
    //     file_all_randoms_offset: u16, // This goes in the file content
    //     algo: SupportedAlgorithm,
    //     enc_key: &[u8],
    //     nonce_base_bytes: &[u8], // Bytes for nonce_base
    //     num_tokens_divided_by_4: u8,
    //     timestamp: &[u8; TIMESTAMP_LEN],
    //     randoms_content_from_offset: &[u8], // The actual random bytes to write, starting from file_all_randoms_offset
    // ) -> Result<PathBuf, std::io::Error> {
    //     let topic_encoded = TokenSet::topic_b64encode(topic);
    //     let filename = format!("{}{}", topic_encoded, filename_token_idx);
    //     let file_path = dir.join(filename);
    //
    //     let mut file = fs::File::create(&file_path)?;
    //
    //     // aead_algo (1 byte)
    //     file.write_all(&[algo as u8])?;
    //     // enc_key (algo.key_len() bytes)
    //     file.write_all(enc_key)?;
    //     // nonce_base (algo.nonce_len() bytes)
    //     file.write_all(nonce_base_bytes)?;
    //     // num_tokens_divided_by_4 (1 byte)
    //     file.write_all(&[num_tokens_divided_by_4])?;
    //     // timestamp (TIMESTAMP_LEN bytes)
    //     file.write_all(timestamp)?;
    //     // file_all_randoms_offset (2 bytes) - This indicates where the data in *this file* starts
    //     file.write_all(&file_all_randoms_offset.to_be_bytes())?;
    //     // all_randoms (remaining bytes) - The randoms starting from file_all_randoms_offset
    //     file.write_all(randoms_content_from_offset)?;
    //
    //     Ok(file_path)
    // }
    //
    // #[test]
    // fn test_from_file_success_idx_0_offset_0() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let filename_token_idx: u16 = 0; // Filename index is 0
    //     let file_all_randoms_offset: u16 = 0; // File content starts at original index 0
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let mut expected_nonce_base_bytes_u128 = [0u8; 16];
    //     expected_nonce_base_bytes_u128[(16 - algo.nonce_len())..]
    //         .copy_from_slice(&nonce_base_bytes);
    //     let expected_nonce_base_u128 = u128::from_be_bytes(expected_nonce_base_bytes_u128);
    //
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_vec = vec![
    //         TEST_RANDOM_1,     // Index 0
    //         TEST_RANDOM_2,     // Index 1
    //         TEST_RANDOM_3,     // Index 2
    //         TEST_RANDOM_4,     // Index 3
    //         TEST_RANDOM_5,     // Index 4
    //         [0u8; RANDOM_LEN], // Index 5
    //         [0u8; RANDOM_LEN], // Index 6
    //         [0u8; RANDOM_LEN], // Index 7
    //     ]; // Total 8 randoms
    //
    //     // File content starts from file_all_randoms_offset (0) to num_tokens - 1 (7)
    //     let randoms_content_from_offset: Bytes = all_randoms_vec
    //         [file_all_randoms_offset as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         &topic,
    //         filename_token_idx,
    //         file_all_randoms_offset,
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let token_set = TokenSet::from_file(file_path.clone(), is_pub, topic.clone())?;
    //
    //     assert_eq!(token_set.path, file_path);
    //     assert_eq!(token_set.topic, topic);
    //     assert_eq!(token_set.is_pub, is_pub);
    //     assert_eq!(token_set.token_idx, filename_token_idx); // token_idx from filename (0)
    //     // all_randoms_offset in struct should be where the *loaded* buffer starts (filename index)
    //     assert_eq!(token_set.all_randoms_offset, filename_token_idx); // Corrected based on discussion
    //     assert_eq!(token_set.algo, algo);
    //     assert_eq!(token_set.enc_key, enc_key);
    //     assert_eq!(token_set.nonce_base, expected_nonce_base_u128);
    //     assert_eq!(token_set.num_tokens, num_tokens);
    //     assert_eq!(token_set.timestamp, timestamp);
    //
    //     // all_randoms should contain the randoms from filename_token_idx (0) onwards
    //     let expected_all_randoms_loaded: Bytes = all_randoms_vec
    //         [filename_token_idx as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     assert_eq!(token_set.all_randoms, expected_all_randoms_loaded);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_success_idx_greater_than_0_offset_equal_idx() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let filename_token_idx: u16 = 4; // Filename index is 4
    //     let file_all_randoms_offset: u16 = 4; // File content starts at original index 4
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let mut expected_nonce_base_bytes_u128 = [0u8; 16];
    //     expected_nonce_base_bytes_u128[(16 - algo.nonce_len())..]
    //         .copy_from_slice(&nonce_base_bytes);
    //     let expected_nonce_base_u128 = u128::from_be_bytes(expected_nonce_base_bytes_u128);
    //
    //     let num_tokens = TEST_NUM_TOKENS; // num_tokens = 8
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //
    //     // Simulate randoms in the file starting from index 4
    //     let all_randoms_vec = vec![
    //         TEST_RANDOM_1,     // Index 0
    //         TEST_RANDOM_2,     // Index 1
    //         TEST_RANDOM_3,     // Index 2
    //         TEST_RANDOM_4,     // Index 3
    //         TEST_RANDOM_5,     // Index 4 - File content starts here
    //         [0u8; RANDOM_LEN], // Index 5
    //         [0u8; RANDOM_LEN], // Index 6
    //         [0u8; RANDOM_LEN], // Index 7
    //     ]; // Total 8 randoms
    //
    //     // File content starts from file_all_randoms_offset (4) to num_tokens - 1 (7)
    //     let randoms_content_from_offset: Bytes = all_randoms_vec
    //         [file_all_randoms_offset as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         &topic,
    //         filename_token_idx,
    //         file_all_randoms_offset,
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let token_set = TokenSet::from_file(file_path.clone(), is_pub, topic.clone())?;
    //
    //     assert_eq!(token_set.path, file_path);
    //     assert_eq!(token_set.topic, topic);
    //     assert_eq!(token_set.is_pub, is_pub);
    //     assert_eq!(token_set.token_idx, filename_token_idx); // token_idx from filename (4)
    //     // all_randoms_offset in struct should be where the *loaded* buffer starts (filename index)
    //     assert_eq!(token_set.all_randoms_offset, filename_token_idx); // Corrected based on discussion
    //     assert_eq!(token_set.algo, algo);
    //     assert_eq!(token_set.enc_key, enc_key);
    //     assert_eq!(token_set.nonce_base, expected_nonce_base_u128);
    //     assert_eq!(token_set.num_tokens, num_tokens);
    //     assert_eq!(token_set.timestamp, timestamp);
    //
    //     // all_randoms should contain the randoms from filename_token_idx (4) onwards
    //     let expected_all_randoms_loaded: Bytes = all_randoms_vec
    //         [filename_token_idx as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     assert_eq!(token_set.all_randoms, expected_all_randoms_loaded);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_success_idx_greater_than_0_offset_less_than_idx() -> Result<(), TokenSetError>
    // {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let filename_token_idx: u16 = 6; // Filename index is 6
    //     let file_all_randoms_offset: u16 = 4; // File content starts at original index 4
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let mut expected_nonce_base_bytes_u128 = [0u8; 16];
    //     expected_nonce_base_bytes_u128[(16 - algo.nonce_len())..]
    //         .copy_from_slice(&nonce_base_bytes);
    //     let expected_nonce_base_u128 = u128::from_be_bytes(expected_nonce_base_bytes_u128);
    //
    //     let num_tokens = TEST_NUM_TOKENS; // num_tokens = 8
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //
    //     // Simulate randoms in the file starting from index 4
    //     let all_randoms_vec = vec![
    //         TEST_RANDOM_1,     // Index 0
    //         TEST_RANDOM_2,     // Index 1
    //         TEST_RANDOM_3,     // Index 2
    //         TEST_RANDOM_4,     // Index 3
    //         TEST_RANDOM_5,     // Index 4 - File content starts here
    //         [0u8; RANDOM_LEN], // Index 5
    //         [0u8; RANDOM_LEN], // Index 6
    //         [0u8; RANDOM_LEN], // Index 7
    //     ]; // Total 8 randoms
    //
    //     // File content starts from file_all_randoms_offset (4) to num_tokens - 1 (7)
    //     let randoms_content_from_offset: Bytes = all_randoms_vec
    //         [file_all_randoms_offset as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         &topic,
    //         filename_token_idx,
    //         file_all_randoms_offset,
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let token_set = TokenSet::from_file(file_path.clone(), is_pub, topic.clone())?;
    //
    //     assert_eq!(token_set.path, file_path);
    //     assert_eq!(token_set.topic, topic);
    //     assert_eq!(token_set.is_pub, is_pub);
    //     assert_eq!(token_set.token_idx, filename_token_idx); // token_idx from filename (6)
    //     // all_randoms_offset in struct should be where the *loaded* buffer starts (filename index)
    //     assert_eq!(token_set.all_randoms_offset, filename_token_idx); // Corrected based on discussion
    //     assert_eq!(token_set.algo, algo);
    //     assert_eq!(token_set.enc_key, enc_key);
    //     assert_eq!(token_set.nonce_base, expected_nonce_base_u128);
    //     assert_eq!(token_set.num_tokens, num_tokens);
    //     assert_eq!(token_set.timestamp, timestamp);
    //
    //     // The file content starts at original index 4. The seek skips (6 - 4) = 2 randoms (index 4 and 5).
    //     // The read starts from original index 6.
    //     let expected_all_randoms_loaded: Bytes = all_randoms_vec
    //         [filename_token_idx as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     assert_eq!(token_set.all_randoms, expected_all_randoms_loaded);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_file_not_found() -> Result<(), ()> {
    //     let non_existent_path = PathBuf::from("/non/existent/path/to/token_set");
    //     let result = TokenSet::from_file(non_existent_path, true, "dummy".to_string());
    //
    //     match result {
    //         Err(TokenSetError::FileOpenError(e)) => {
    //             assert_eq!(e.kind(), ErrorKind::NotFound);
    //         }
    //         _ => panic!("Expected FileOpenError with kind NotFound"),
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_path_not_having_filename() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let dir_path = temp_dir.path().to_path_buf();
    //
    //     let result = TokenSet::from_file(dir_path, true, "dummy".to_string());
    //
    //     match result {
    //         Err(TokenSetError::PathNotHavingFilenameError) => {}
    //         _ => panic!("Expected PathNotHavingFilenameError"),
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_invalid_cur_idx_in_filename() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC;
    //     let topic_encoded = TokenSet::topic_b64encode(topic);
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let file_all_randoms_offset = 0; // Doesn't matter for filename parsing errors
    //     let randoms_content_from_offset = Bytes::new();
    //
    //     // Invalid index format
    //     let invalid_filename = format!("{}abc", topic_encoded);
    //     let invalid_path_format = temp_dir.path().join(invalid_filename);
    //     // Need to create a file with enough bytes to read the header before parsing index
    //     create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         0, // Dummy index in filename
    //         file_all_randoms_offset,
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .expect("Failed to create dummy file for format test");
    //     // Manually rename it to the invalid filename
    //     fs::rename(
    //         temp_dir.path().join(format!("{}0", topic_encoded)),
    //         &invalid_path_format,
    //     )
    //         .expect("Failed to rename file for format test");
    //
    //     let result_format = TokenSet::from_file(invalid_path_format, true, topic.to_string());
    //     match result_format {
    //         Err(TokenSetError::InvalidCurIdxInFilenameError(None)) => {}
    //         _ => panic!("Expected InvalidCurIdxInFilenameError(None) for invalid format"),
    //     }
    //
    //     // Index too large (exceeding 0x7F * 4)
    //     let invalid_idx_large: u16 = 0x7F * 4 + 1;
    //     let invalid_filename_large = format!("{}{}", topic_encoded, invalid_idx_large);
    //     let invalid_path_large = temp_dir.path().join(invalid_filename_large);
    //     // Create a file with valid contents up to the point of num_tokens validation
    //     create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         invalid_idx_large,       // Filename index
    //         file_all_randoms_offset, // File offset
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset, // No randoms needed for this specific error case
    //     )
    //         .expect("Failed to create dummy file for large index test");
    //
    //     let result_large = TokenSet::from_file(invalid_path_large, true, topic.to_string());
    //     match result_large {
    //         Err(TokenSetError::InvalidCurIdxInFilenameError(Some(idx))) => {
    //             assert_eq!(idx, invalid_idx_large);
    //         }
    //         _ => panic!("Expected InvalidCurIdxInFilenameError(Some) for large index"),
    //     }
    //
    //     // filename_token_idx < file_all_randoms_offset
    //     let invalid_idx_less_than_offset: u16 = 2; // Less than file_all_randoms_offset = 4
    //     let valid_file_all_randoms_offset: u16 = 4;
    //     let invalid_filename_less = format!("{}{}", topic_encoded, invalid_idx_less_than_offset);
    //     let invalid_path_less = temp_dir.path().join(invalid_filename_less);
    //
    //     create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         invalid_idx_less_than_offset,  // Filename index
    //         valid_file_all_randoms_offset, // File offset
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset, // No randoms needed for this specific error case
    //     )
    //         .expect("Failed to create dummy file for less than offset test");
    //
    //     let result_less = TokenSet::from_file(invalid_path_less, true, topic.to_string());
    //     match result_less {
    //         Err(TokenSetError::InvalidCurIdxInFilenameError(Some(idx))) => {
    //             assert_eq!(idx, invalid_idx_less_than_offset);
    //         }
    //         _ => panic!(
    //             "Expected InvalidCurIdxInFilenameError(Some) for index less than file offset"
    //         ),
    //     }
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_file_read_error() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic_encoded = TokenSet::topic_b64encode(TEST_TOPIC);
    //     let filename = format!("{}0", topic_encoded);
    //     let file_path = temp_dir.path().join(filename);
    //
    //     // Create a file but close it immediately, simulating a file that cannot be read
    //     {
    //         let _file = fs::File::create(&file_path).expect("Failed to create dummy file");
    //     } // File is closed and dropped
    //
    //     let result = TokenSet::from_file(file_path, true, TEST_TOPIC.to_string());
    //
    //     match result {
    //         Err(TokenSetError::FileOpenError(_)) => {} // Expect an error when trying to open for reading
    //         _ => panic!("Expected FileOpenError when trying to read"),
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_unsupported_algorithm() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC;
    //     let token_idx = 0;
    //     let algo_byte = 0xFF; // Invalid algorithm byte
    //
    //     let topic_encoded = TokenSet::topic_b64encode(topic);
    //     let filename = format!("{}{}", topic_encoded, token_idx);
    //     let file_path = temp_dir.path().join(filename);
    //
    //     let mut file = fs::File::create(&file_path).expect("Failed to create dummy file");
    //     file.write_all(&[algo_byte]).expect("Failed to write algo"); // Write invalid algo
    //
    //     let result = TokenSet::from_file(file_path, true, topic.to_string());
    //
    //     match result {
    //         Err(TokenSetError::UnsupportedAlgorithmError(_)) => {} // We expect an error converting the byte
    //         _ => panic!("Expected UnsupportedAlgorithmError"),
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_nonce_len_mismatch_read() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC;
    //     let filename_token_idx = 0;
    //     let file_all_randoms_offset = 0;
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     // Write a nonce base shorter than expected by the algorithm
    //     let nonce_base_bytes_short =
    //         Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len() - 1]);
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let randoms_content_from_offset = Bytes::new();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         filename_token_idx,
    //         file_all_randoms_offset,
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes_short, // Write short nonce
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let result = TokenSet::from_file(file_path, true, topic.to_string());
    //
    //     match result {
    //         // The error will be FileReadError because read_exact will fail
    //         Err(TokenSetError::FileReadError(_)) => {}
    //         _ => panic!("Expected FileReadError (due to short nonce read)"),
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_invalid_num_tokens() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC;
    //     let filename_token_idx: u16 = 4; // filename_token_idx is 4
    //     let file_all_randoms_offset = 0; // File offset is 0
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     // num_tokens_divided_by_4 that results in num_tokens <= filename_token_idx
    //     let invalid_num_tokens_divided_by_4: u8 = (filename_token_idx / 4) as u8; // num_tokens will be filename_token_idx
    //     let timestamp = TEST_TIMESTAMP;
    //     let randoms_content_from_offset = Bytes::new();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         filename_token_idx,      // Filename index
    //         file_all_randoms_offset, // File offset
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         invalid_num_tokens_divided_by_4, // Write invalid num_tokens_divided_by_4
    //         &timestamp,
    //         &randoms_content_from_offset,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let result = TokenSet::from_file(file_path, true, topic.to_string());
    //
    //     match result {
    //         Err(TokenSetError::InvalidNumTokensError(n)) => {
    //             assert_eq!(n, invalid_num_tokens_divided_by_4);
    //         }
    //         _ => panic!("Expected InvalidNumTokensError for num_tokens <= token_idx"),
    //     }
    //
    //     // num_tokens <= file_all_randoms_offset
    //     let file_all_randoms_offset_high: u16 = TEST_NUM_TOKENS; // file_all_randoms_offset is 8
    //     let valid_num_tokens_divided_by_4: u8 = TEST_NUM_TOKENS_DIVIDED_BY_4; // num_tokens is 8
    //     let filename_token_idx_valid: u16 = 0;
    //
    //     let file_path_offset_high = create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         filename_token_idx_valid,     // Filename index
    //         file_all_randoms_offset_high, // File offset
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         valid_num_tokens_divided_by_4, // Valid num_tokens
    //         &timestamp,
    //         &randoms_content_from_offset, // No randoms needed
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let result_offset_high =
    //         TokenSet::from_file(file_path_offset_high, true, topic.to_string());
    //     match result_offset_high {
    //         Err(TokenSetError::InvalidNumTokensError(n)) => {
    //             assert_eq!(n, valid_num_tokens_divided_by_4); // Error returns the num_tokens_divided_by_4 value
    //         }
    //         _ => panic!("Expected InvalidNumTokensError for num_tokens <= file_all_randoms_offset"),
    //     }
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_from_file_error_random_len_mismatch_read() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC;
    //     let filename_token_idx = 0; // filename_token_idx is 0
    //     let file_all_randoms_offset = 0; // File offset is 0
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let num_tokens_divided_by_4 = 2; // num_tokens = 8
    //     let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2); // 8
    //     let timestamp = TEST_TIMESTAMP;
    //
    //     // Write fewer randoms than expected based on num_tokens and filename_token_idx
    //     // Expected length is (num_tokens - filename_token_idx) * RANDOM_LEN = (8 - 0) * RANDOM_LEN = 8 * RANDOM_LEN
    //     let all_randoms_vec = vec![TEST_RANDOM_1, TEST_RANDOM_2]; // Only 2 randoms
    //     let mut randoms_content_from_offset_vec: Vec<u8> =
    //         all_randoms_vec.iter().flatten().cloned().collect();
    //     randoms_content_from_offset_vec.push(0); // Add an extra byte to make length not a multiple of RANDOM_LEN at the end
    //     let randoms_content_from_offset: Bytes = randoms_content_from_offset_vec.into();
    //
    //     let file_path = create_dummy_token_file(
    //         temp_dir.path(),
    //         topic,
    //         filename_token_idx,
    //         file_all_randoms_offset, // File offset 0
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &randoms_content_from_offset, // Write incomplete randoms
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     let result = TokenSet::from_file(file_path, true, topic.to_string());
    //
    //     // The code expects to read (num_tokens - filename_token_idx) * RANDOM_LEN bytes.
    //     // We wrote fewer bytes. The `read` into the BytesMut will read what's available,
    //     // and then the check `if actual_read < expected_len` should trigger.
    //     match result {
    //         Err(TokenSetError::RandomLenMismatchError(actual_read)) => {
    //             assert_eq!(actual_read, randoms_content_from_offset.len());
    //         }
    //         _ => panic!("Expected RandomLenMismatchError when randoms are incomplete"),
    //     }
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_save_to_file_success() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let token_sets_dir = temp_dir.path().to_path_buf(); // Use PathBuf directly
    //
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let initial_token_idx: u16 = 2; // Simulate that 2 tokens have been used
    //     let all_randoms_offset: u16 = 0; // Simulate that the in-memory Bytes starts from the beginning
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base: u128 = TEST_NONCE_BASE_VAL;
    //     let num_tokens = TEST_NUM_TOKENS; // 8
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //
    //     let all_randoms_vec = vec![
    //         TEST_RANDOM_1,     // Index 0
    //         TEST_RANDOM_2,     // Index 1
    //         TEST_RANDOM_3, // Index 2 - Start of randoms to save (token_idx - all_randoms_offset = 2-0 = 2)
    //         TEST_RANDOM_4, // Index 3
    //         TEST_RANDOM_5, // Index 4
    //         [0u8; RANDOM_LEN], // Index 5
    //         [0u8; RANDOM_LEN], // Index 6
    //         [0u8; RANDOM_LEN], // Index 7
    //     ]; // Total 8 randoms
    //     // In-memory `all_randoms` Bytes contains all 8 randoms, starting at original index 0.
    //     let all_randoms_in_memory: Bytes = all_randoms_vec
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     // Create an initial TokenSet instance (e.g., loaded from a file or created)
    //     let mut token_set = TokenSet {
    //         path: PathBuf::new(), // Start with an empty path (like from_issuer_req_resp)
    //         timestamp,
    //         all_randoms: all_randoms_in_memory.clone(),
    //         num_tokens,
    //         token_idx: initial_token_idx, // The current index (will be filename index and file offset)
    //         all_randoms_offset,           // Where the in-memory Bytes starts (0)
    //         topic: topic.clone(),
    //         is_pub,
    //         algo,
    //         enc_key: enc_key.clone(),
    //         nonce_base,
    //     };
    //
    //     // Manually create the parent directory as save_to_file expects it
    //     let pub_sub_dir = if is_pub {
    //         token_sets_dir.join("pub")
    //     } else {
    //         token_sets_dir.join("sub")
    //     };
    //     fs::create_dir_all(&pub_sub_dir).map_err(|e| TokenSetError::FileCreateError(e))?;
    //
    //     // Save the token set to a file
    //     token_set.save_to_file(&token_sets_dir)?;
    //
    //     // Construct the expected file path
    //     let topic_encoded = TokenSet::topic_b64encode(&topic);
    //     let expected_filename = format!("{}{}", topic_encoded, initial_token_idx);
    //     let expected_file_path = pub_sub_dir.join(expected_filename);
    //
    //     // Verify the path field in the struct is updated
    //     assert_eq!(token_set.path, expected_file_path);
    //     assert!(expected_file_path.exists()); // Ensure the file was created
    //
    //     // Read the file back and verify its contents
    //     let mut file =
    //         fs::File::open(&expected_file_path).map_err(|e| TokenSetError::FileOpenError(e))?;
    //     let mut read_buf = Vec::new();
    //     file.read_to_end(&mut read_buf)
    //         .map_err(|e| TokenSetError::FileReadError(e))?;
    //
    //     let mut expected_bytes = Vec::new();
    //     // Header fields order: algo, enc_key, nonce_base, num_tokens_divided_by_4, timestamp, all_randoms_offset
    //     expected_bytes.push(algo as u8);
    //     expected_bytes.extend_from_slice(&enc_key);
    //     expected_bytes.extend_from_slice(&nonce_base.to_be_bytes()[(16 - algo.nonce_len())..]);
    //     expected_bytes.push(num_tokens.rotate_right(2) as u8);
    //     expected_bytes.extend_from_slice(&timestamp);
    //     // file_all_randoms_offset (which is struct.token_idx)
    //     expected_bytes.extend_from_slice(&initial_token_idx.to_be_bytes());
    //
    //     // all_randoms content - skips (token_idx - all_randoms_offset) from the in-memory Bytes
    //     let skip_len = (initial_token_idx - all_randoms_offset) as usize * RANDOM_LEN;
    //     // The bytes written are from index `skip_len` in `all_randoms_in_memory` to the end.
    //     expected_bytes.extend_from_slice(&all_randoms_in_memory[skip_len..]);
    //
    //     assert_eq!(read_buf, expected_bytes);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_save_to_file_success_replaces_old() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let token_sets_dir = temp_dir.path().to_path_buf();
    //
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let initial_token_idx: u16 = 0; // Old index
    //     let updated_token_idx: u16 = 2; // New index
    //     let all_randoms_offset: u16 = 0;
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base: u128 = TEST_NONCE_BASE_VAL;
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_in_memory: Bytes = vec![[0u8; RANDOM_LEN]; num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let pub_sub_dir = if is_pub {
    //         token_sets_dir.join("pub")
    //     } else {
    //         token_sets_dir.join("sub")
    //     };
    //     fs::create_dir_all(&pub_sub_dir).map_err(|e| TokenSetError::FileCreateError(e))?;
    //
    //     // Create an initial file to be replaced
    //     let initial_filename =
    //         format!("{}{}", TokenSet::topic_b64encode(&topic), initial_token_idx);
    //     let initial_file_path = pub_sub_dir.join(initial_filename);
    //     // Create a dummy file content for the old file (doesn't need to be fully correct)
    //     fs::File::create(&initial_file_path)
    //         .map_err(|e| TokenSetError::FileCreateError(e))?
    //         .write_all(b"dummy content")
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //     assert!(initial_file_path.exists());
    //
    //     // Create a TokenSet instance pointing to the old file, but with the new state
    //     let mut token_set = TokenSet {
    //         path: initial_file_path.clone(), // Path points to the old file
    //         timestamp,
    //         all_randoms: all_randoms_in_memory.clone(),
    //         num_tokens,
    //         token_idx: updated_token_idx, // New index for saving
    //         all_randoms_offset,
    //         topic: topic.clone(),
    //         is_pub,
    //         algo,
    //         enc_key: enc_key.clone(),
    //         nonce_base,
    //     };
    //
    //     // Save the token set - this should remove the old file and create a new one
    //     token_set.save_to_file(&token_sets_dir)?;
    //
    //     // Verify the old file is gone
    //     assert!(!initial_file_path.exists());
    //
    //     // Construct the expected new file path
    //     let topic_encoded = TokenSet::topic_b64encode(&topic);
    //     let expected_new_filename = format!("{}{}", topic_encoded, updated_token_idx);
    //     let expected_new_file_path = pub_sub_dir.join(expected_new_filename);
    //
    //     // Verify the path field in the struct is updated
    //     assert_eq!(token_set.path, expected_new_file_path);
    //     assert!(expected_new_file_path.exists()); // Ensure the new file was created
    //
    //     // Optional: Read the new file to verify content if needed (already tested in test_save_to_file_success)
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_save_to_file_error_enc_key_mismatch() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let token_sets_dir = temp_dir.path().to_path_buf();
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let token_idx = 0;
    //     let all_randoms_offset = 0;
    //     let algo = TEST_ALGO;
    //     let enc_key_wrong_len = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len() - 1]); // Wrong length
    //     let nonce_base: u128 = TEST_NONCE_BASE_VAL;
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms = Bytes::new();
    //
    //     let pub_sub_dir = if is_pub {
    //         token_sets_dir.join("pub")
    //     } else {
    //         token_sets_dir.join("sub")
    //     };
    //     fs::create_dir_all(&pub_sub_dir).expect("Failed to create dir");
    //
    //     let mut token_set = TokenSet {
    //         path: PathBuf::new(),
    //         timestamp,
    //         all_randoms,
    //         num_tokens,
    //         token_idx,
    //         all_randoms_offset,
    //         topic,
    //         is_pub,
    //         algo,
    //         enc_key: enc_key_wrong_len.clone(),
    //         nonce_base,
    //     };
    //
    //     let result = token_set.save_to_file(&token_sets_dir);
    //
    //     match result {
    //         Err(TokenSetError::EncKeyMismatchError(len)) => {
    //             assert_eq!(len, algo.key_len() - 1);
    //         }
    //         _ => panic!("Expected EncKeyMismatchError"),
    //     }
    //
    //     // Verify no file was created (or an incomplete one was potentially left, depending on OS/timing)
    //     // Checking for existence is tricky as create() might succeed before write_all fails.
    //     // A robust test might check file size if it exists. For simplicity, skip strict file check here.
    //     assert_eq!(token_set.path, PathBuf::new()); // Path should not be updated on error
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_save_to_file_error_file_create_error() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     // Use a read-only path to cause a creation error
    //     let readonly_dir = temp_dir.path().join("readonly");
    //     fs::create_dir(&readonly_dir).expect("Failed to create readonly dir");
    //     // Make it read-only (platform dependent, this is a common Unix approach)
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&readonly_dir)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o444); // Read-only
    //         fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");
    //     }
    //     // On Windows, making truly read-only might be more complex for directories.
    //     // This test might not work reliably on all platforms or configurations.
    //     // For a more robust test, mocking the file system is needed.
    //     // Given the difficulty, we'll accept potential flakiness or skip on certain platforms.
    //
    //     let token_sets_dir = readonly_dir; // Try to save inside a read-only dir
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let token_idx = 0;
    //     let all_randoms_offset = 0;
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base: u128 = TEST_NONCE_BASE_VAL;
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms = Bytes::new();
    //
    //     let mut token_set = TokenSet {
    //         path: PathBuf::new(),
    //         timestamp,
    //         all_randoms,
    //         num_tokens,
    //         token_idx,
    //         all_randoms_offset,
    //         topic,
    //         is_pub,
    //         algo,
    //         enc_key: enc_key.clone(),
    //         nonce_base,
    //     };
    //
    //     let result = token_set.save_to_file(&token_sets_dir);
    //
    //     #[cfg(unix)] // Check error kind only if permissions setting was attempted
    //     match result {
    //         Err(TokenSetError::FileCreateError(e)) => {
    //             // Expect a permission denied error or similar
    //             assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    //         }
    //         _ => panic!("Expected FileCreateError"),
    //     }
    //
    //     #[cfg(not(unix))] // For other platforms, just check for any FileCreateError
    //     match result {
    //         Err(TokenSetError::FileCreateError(_)) => {}
    //         _ => panic!("Expected FileCreateError"),
    //     }
    //
    //     assert_eq!(token_set.path, PathBuf::new()); // Path should not be updated on error
    //
    //     // Attempt to revert permissions if on Unix
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&readonly_dir)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o755); // Read/write
    //         fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");
    //     }
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_save_to_file_error_file_remove_error() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let token_sets_dir = temp_dir.path().to_path_buf();
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let initial_token_idx: u16 = 0; // Old index
    //     let updated_token_idx: u16 = 2; // New index
    //     let all_randoms_offset: u16 = 0;
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base: u128 = TEST_NONCE_BASE_VAL;
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_in_memory: Bytes = vec![[0u8; RANDOM_LEN]; num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let pub_sub_dir = if is_pub {
    //         token_sets_dir.join("pub")
    //     } else {
    //         token_sets_dir.join("sub")
    //     };
    //     fs::create_dir_all(&pub_sub_dir).expect("Failed to create dir");
    //
    //     // Create an initial file that *cannot* be removed
    //     let initial_filename =
    //         format!("{}{}", TokenSet::topic_b64encode(&topic), initial_token_idx);
    //     let initial_file_path = pub_sub_dir.join(initial_filename);
    //     // Create the file
    //     fs::File::create(&initial_file_path).expect("Failed to create file for remove error test");
    //     // Make it read-only to prevent removal (platform dependent)
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&initial_file_path)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o444); // Read-only
    //         fs::set_permissions(&initial_file_path, perms).expect("Failed to set permissions");
    //     }
    //     // On Windows, making truly unremovable might be more complex.
    //     // This test might not work reliably on all platforms or configurations.
    //
    //     // Create a TokenSet instance pointing to the unremovable file
    //     let mut token_set = TokenSet {
    //         path: initial_file_path.clone(), // Path points to the unremovable file
    //         timestamp,
    //         all_randoms: all_randoms_in_memory.clone(),
    //         num_tokens,
    //         token_idx: updated_token_idx, // New index for saving
    //         all_randoms_offset,
    //         topic: topic.clone(),
    //         is_pub,
    //         algo,
    //         enc_key: enc_key.clone(),
    //         nonce_base,
    //     };
    //
    //     // Attempt to save - this should fail on removal
    //     let result = token_set.save_to_file(&token_sets_dir);
    //
    //     #[cfg(unix)] // Check error kind only if permissions setting was attempted
    //     match result {
    //         Err(TokenSetError::FileRemoveError(e)) => {
    //             // Expect a permission denied error or similar
    //             assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    //         }
    //         _ => panic!("Expected FileRemoveError"),
    //     }
    //     #[cfg(not(unix))] // For other platforms, just check for any FileRemoveError
    //     match result {
    //         Err(TokenSetError::FileRemoveError(_)) => {}
    //         _ => panic!("Expected FileRemoveError"),
    //     }
    //
    //     // Verify the path field is NOT updated on error
    //     assert_eq!(token_set.path, initial_file_path); // Path should still point to the old file
    //
    //     // Verify the old file still exists
    //     assert!(initial_file_path.exists());
    //
    //     // Attempt to revert permissions if on Unix for cleanup
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&initial_file_path)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o644); // Read/write for owner
    //         fs::set_permissions(&initial_file_path, perms).expect("Failed to set permissions");
    //     }
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_refresh_filename_success() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let initial_token_idx: u16 = 0;
    //     let updated_token_idx: u16 = 5; // Simulate that 5 tokens have been used
    //
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let nonce_base = u128::from_be_bytes({
    //         let mut bytes = [0u8; 16];
    //         bytes[(16 - algo.nonce_len())..].copy_from_slice(&nonce_base_bytes);
    //         bytes
    //     });
    //     let num_tokens = TEST_NUM_TOKENS;
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_offset: u16 = 0; // Doesn't matter for this test
    //     let all_randoms = Bytes::new(); // Content doesn't matter for this test
    //
    //     let topic_encoded = TokenSet::topic_b64encode(&topic);
    //     let initial_filename = format!("{}{}", topic_encoded, initial_token_idx);
    //     let initial_file_path = temp_dir.path().join(initial_filename);
    //
    //     // Create the initial dummy file (using v2 format)
    //     create_dummy_token_file(
    //         temp_dir.path(),
    //         &topic,
    //         initial_token_idx, // Filename index
    //         0,                 // File offset (doesn't matter for this test)
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &all_randoms,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     // Create a TokenSet instance pointing to the initial file, but with updated token_idx
    //     let mut token_set = TokenSet {
    //         path: initial_file_path.clone(), // Path points to the old file
    //         timestamp,                       // Not relevant
    //         all_randoms,                     // Not relevant
    //         num_tokens,                      // Not relevant
    //         token_idx: updated_token_idx,    // The index that should be in the new filename
    //         all_randoms_offset,              // Not relevant
    //         topic: topic.clone(),
    //         is_pub,                   // Not relevant
    //         algo,                     // Not relevant
    //         enc_key: enc_key.clone(), // Not relevant
    //         nonce_base,               // Not relevant
    //     };
    //
    //     // Verify the initial file exists
    //     assert!(initial_file_path.exists());
    //
    //     // Refresh the filename
    //     token_set.refresh_filename()?;
    //
    //     // Verify the old file is gone
    //     assert!(!initial_file_path.exists());
    //
    //     // Verify the new file exists with the updated filename
    //     let new_filename = format!("{}{}", topic_encoded, updated_token_idx);
    //     let new_file_path = temp_dir.path().join(new_filename);
    //     assert!(new_file_path.exists());
    //
    //     // Verify the path field in the struct is updated
    //     assert_eq!(token_set.path, new_file_path);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_refresh_filename_error_file_not_found() -> Result<(), ()> {
    //     let non_existent_path = PathBuf::from("/non/existent/path/to/token_set_to_rename");
    //     let mut token_set = TokenSet {
    //         // Needs to be mutable to call refresh_filename
    //         path: non_existent_path.clone(),
    //         timestamp: TEST_TIMESTAMP,  // Dummy data
    //         all_randoms: Bytes::new(),  // Dummy data
    //         num_tokens: 0,              // Dummy data
    //         token_idx: 0,               // Dummy data
    //         all_randoms_offset: 0,      // Dummy data
    //         topic: "dummy".to_string(), // Dummy data
    //         is_pub: true,               // Dummy data
    //         algo: TEST_ALGO,            // Dummy data
    //         enc_key: Bytes::new(),      // Dummy data
    //         nonce_base: 0,              // Dummy data
    //     };
    //
    //     let result = token_set.refresh_filename();
    //
    //     match result {
    //         Err(TokenSetError::FileNotFoundError(p)) => {
    //             assert_eq!(p, non_existent_path);
    //         }
    //         _ => panic!("Expected FileNotFoundError"),
    //     }
    //     // Path should not be updated on error
    //     assert_eq!(token_set.path, non_existent_path);
    //
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_refresh_filename_error_file_rename_error() -> Result<(), ()> {
    //     let temp_dir = tempdir().expect("Failed to create temp dir");
    //     let topic = TEST_TOPIC.to_string();
    //     let is_pub = true;
    //     let initial_token_idx: u16 = 0;
    //     let updated_token_idx: u16 = 5; // Try to rename to a path where creation is not allowed
    //     let algo = TEST_ALGO;
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //     let nonce_base_bytes = Bytes::copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let num_tokens_divided_by_4 = TEST_NUM_TOKENS_DIVIDED_BY_4;
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_offset: u16 = 0;
    //     let all_randoms = Bytes::new();
    //
    //     let topic_encoded = TokenSet::topic_b64encode(&topic);
    //     let initial_filename = format!("{}{}", topic_encoded, initial_token_idx);
    //     let initial_file_path = temp_dir.path().join(initial_filename);
    //
    //     // Create the initial dummy file
    //     create_dummy_token_file(
    //         temp_dir.path(),
    //         &topic,
    //         initial_token_idx, // Filename index
    //         0,                 // File offset
    //         algo,
    //         &enc_key,
    //         &nonce_base_bytes,
    //         num_tokens_divided_by_4,
    //         &timestamp,
    //         &all_randoms,
    //     )
    //         .map_err(|e| TokenSetError::FileWriteError(e))?;
    //
    //     // Create a read-only directory where the new file cannot be created
    //     let readonly_dir = temp_dir.path().join("readonly_target");
    //     fs::create_dir(&readonly_dir).expect("Failed to create readonly_target dir");
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&readonly_dir)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o444); // Read-only
    //         fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");
    //     }
    //     // On Windows, making truly read-only might be more complex.
    //
    //     // Create a TokenSet instance pointing to the movable file, with a target in the read-only dir
    //     let mut token_set = TokenSet {
    //         path: initial_file_path.clone(),
    //         timestamp,                    // Not relevant
    //         all_randoms,                  // Not relevant
    //         num_tokens,                   // Not relevant
    //         token_idx: updated_token_idx, // Target index for filename
    //         all_randoms_offset,           // Not relevant
    //         topic: topic.clone(),
    //         is_pub,     // Not relevant
    //         algo,       // Not relevant
    //         enc_key,    // Not relevant
    //         nonce_base, // Not relevant
    //     };
    //
    //     // Manually change the path in the struct to point inside the read-only dir
    //     // This simulates a scenario where the intended parent dir for the new name is read-only
    //     let new_filename = format!("{}{}", topic_encoded, updated_token_idx);
    //     token_set.path = readonly_dir.join(new_filename);
    //
    //     // Attempt to refresh filename - should fail due to permission error at target
    //     let result = token_set.refresh_filename();
    //
    //     #[cfg(unix)] // Check error kind only if permissions setting was attempted
    //     match result {
    //         Err(TokenSetError::FileRenameError(e)) => {
    //             // Expect a permission denied error or similar when renaming INTO readonly dir
    //             assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    //         }
    //         _ => panic!("Expected FileRenameError"),
    //     }
    //
    //     #[cfg(not(unix))] // For other platforms, just check for any FileRenameError
    //     match result {
    //         Err(TokenSetError::FileRenameError(_)) => {}
    //         _ => panic!("Expected FileRenameError"),
    //     }
    //
    //     // Verify the path field is NOT updated on error
    //     assert_eq!(
    //         token_set.path,
    //         readonly_dir.join(format!("{}{}", topic_encoded, updated_token_idx))
    //     ); // Path should still be the intended target path
    //
    //     // Verify the original file still exists
    //     assert!(initial_file_path.exists());
    //
    //     // Attempt to revert permissions if on Unix for cleanup
    //     #[cfg(unix)]
    //     {
    //         use std::os::unix::fs::PermissionsExt;
    //         let mut perms = fs::metadata(&readonly_dir)
    //             .expect("Failed to get metadata")
    //             .permissions();
    //         perms.set_mode(0o755); // Read/write
    //         fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");
    //     }
    //
    //     Ok(())
    // }
    //
    // // Integration Test
    // #[test]
    // fn test_integration_save_load_use() -> Result<(), TokenSetError> {
    //     let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    //     let token_sets_dir = temp_dir.path().to_path_buf();
    //
    //     // Manually create pub directory as save_to_file expects it
    //     let pub_dir = token_sets_dir.join("pub");
    //     fs::create_dir_all(&pub_dir).map_err(|e| TokenSetError::FileCreateError(e))?;
    //
    //     let topic = TEST_PUB_TOPIC.to_string();
    //     let is_pub = true;
    //     let algo = TEST_ALGO;
    //     let num_tokens_divided_by_4 = 2; // num_tokens = 8
    //     let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2); // 8
    //
    //     let timestamp = TEST_TIMESTAMP;
    //     let all_randoms_vec = vec![
    //         TEST_RANDOM_1,     // Index 0
    //         TEST_RANDOM_2,     // Index 1
    //         TEST_RANDOM_3,     // Index 2
    //         TEST_RANDOM_4,     // Index 3
    //         TEST_RANDOM_5,     // Index 4
    //         [0u8; RANDOM_LEN], // Index 5
    //         [0u8; RANDOM_LEN], // Index 6
    //         [0u8; RANDOM_LEN], // Index 7
    //     ]; // Total 8 randoms
    //     // all_randoms buffer initially contains all randoms, starting at original index 0
    //     let all_randoms_in_memory: Bytes = all_randoms_vec
    //         .clone()
    //         .into_iter()
    //         .flatten()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     let nonce_base_val = TEST_NONCE_BASE_VAL;
    //     let mut nonce_base_bytes_full = [0u8; 16];
    //     nonce_base_bytes_full[(16 - algo.nonce_len())..]
    //         .copy_from_slice(&TEST_NONCE_BASE_BYTES[..algo.nonce_len()]);
    //     let nonce_base = u128::from_be_bytes(nonce_base_bytes_full);
    //
    //     let enc_key = Bytes::copy_from_slice(&TEST_ENC_KEY[..algo.key_len()]);
    //
    //     // Initial state (like from_issuer_req_resp, but manually setup for test)
    //     let mut token_set = TokenSet {
    //         path: PathBuf::new(), // Empty path initially
    //         timestamp,
    //         all_randoms: all_randoms_in_memory.clone(),
    //         num_tokens,
    //         token_idx: 0,          // Start at index 0
    //         all_randoms_offset: 0, // Buffer starts at index 0
    //         topic: topic.clone(),
    //         is_pub,
    //         algo,
    //         enc_key: enc_key.clone(),
    //         nonce_base,
    //     };
    //
    //     // 1. Save the initial token set to a file
    //     token_set.save_to_file(&token_sets_dir)?;
    //
    //     // Verify the path field in the struct is updated
    //     let topic_encoded = TokenSet::topic_b64encode(&topic);
    //     let initial_filename = format!("{}0", topic_encoded);
    //     let initial_file_path = pub_dir.join(initial_filename);
    //     assert_eq!(token_set.path, initial_file_path);
    //     assert!(initial_file_path.exists());
    //
    //     // 2. Simulate using some tokens (e.g., 3 tokens)
    //     let tokens_to_use: u16 = 3;
    //     let expected_token_content_after_use = all_randoms_vec[tokens_to_use as usize..]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //
    //     // Create a *new* TokenSet instance loaded from the file after using some tokens
    //     // This simulates loading the state at a later point.
    //     // Manually create the file with the state as if tokens were used and saved.
    //     // This is complex to simulate accurately without testing save/load cycles directly.
    //
    //     // Let's instead simulate loading from the file AS IS after the first save (token_idx 0)
    //     // and then simulate using tokens on the loaded instance.
    //
    //     // Load the token set from the file we just saved
    //     let loaded_token_set = TokenSet::from_file(token_set.path.clone(), is_pub, topic.clone())?;
    //
    //     // Verify initial loaded state
    //     assert_eq!(loaded_token_set.token_idx, 0); // Loaded from filename
    //     assert_eq!(loaded_token_set.all_randoms_offset, 0); // Loaded from file header (which was token_idx 0)
    //     // all_randoms buffer contains data from file_token_idx (0) onwards
    //     let expected_all_randoms_loaded_initial: Bytes = all_randoms_vec[0..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     assert_eq!(
    //         loaded_token_set.all_randoms,
    //         expected_all_randoms_loaded_initial
    //     );
    //     assert_eq!(loaded_token_set.num_tokens, num_tokens);
    //     assert_eq!(loaded_token_set.topic, topic);
    //
    //     // 3. Simulate using tokens on the loaded instance
    //     let mut current_loaded_token_set = loaded_token_set;
    //     let mut consumed_count = 0;
    //
    //     for i in 0..tokens_to_use {
    //         let expected_original_index = current_loaded_token_set.token_idx + consumed_count;
    //         let current_token_b64 = current_loaded_token_set
    //             .get_current_b64token()
    //             .expect("Should get a token");
    //
    //         // Verify the token content matches the random at the expected original index
    //         let expected_random = all_randoms_vec[expected_original_index as usize];
    //         let expected_token_bytes: Vec<u8> = current_loaded_token_set
    //             .timestamp
    //             .iter()
    //             .chain(expected_random.iter())
    //             .cloned()
    //             .collect();
    //         let expected_token_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_bytes);
    //         assert_eq!(current_token_b64, expected_token_b64);
    //
    //         // Manually update token_idx to simulate consumption
    //         current_loaded_token_set.token_idx += 1;
    //         consumed_count += 1;
    //     }
    //
    //     // After using tokens_to_use, token_idx should be tokens_to_use
    //     assert_eq!(current_loaded_token_set.token_idx, tokens_to_use);
    //
    //     // 4. Simulate saving the state after using tokens
    //     let old_file_path = current_loaded_token_set.path.clone(); // Path points to the file saved at token_idx 0
    //     current_loaded_token_set.save_to_file(&token_sets_dir)?; // Saves to a file named with token_idx (3)
    //
    //     // Verify the old file is removed
    //     assert!(!old_file_path.exists());
    //
    //     // Construct expected new file path (named with token_idx 3)
    //     let updated_filename = format!("{}{}", topic_encoded, current_loaded_token_set.token_idx);
    //     let updated_file_path = pub_dir.join(updated_filename);
    //     assert_eq!(current_loaded_token_set.path, updated_file_path);
    //     assert!(updated_file_path.exists());
    //
    //     // 5. Load from the state saved after using tokens
    //     let reloaded_token_set =
    //         TokenSet::from_file(current_loaded_token_set.path.clone(), is_pub, topic.clone())?;
    //
    //     // Verify reloaded state
    //     assert_eq!(reloaded_token_set.token_idx, tokens_to_use); // Loaded from filename (3)
    //     // all_randoms_offset should be where the loaded buffer starts (filename index)
    //     assert_eq!(reloaded_token_set.all_randoms_offset, tokens_to_use); // Corrected based on discussion
    //     // all_randoms buffer contains data from filename_token_idx (3) onwards
    //     let expected_all_randoms_loaded_reloaded: Bytes = all_randoms_vec
    //         [tokens_to_use as usize..num_tokens as usize]
    //         .iter()
    //         .flatten()
    //         .cloned()
    //         .collect::<Vec<u8>>()
    //         .into();
    //     assert_eq!(
    //         reloaded_token_set.all_randoms,
    //         expected_all_randoms_loaded_reloaded
    //     );
    //     assert_eq!(reloaded_token_set.num_tokens, num_tokens);
    //
    //     // 6. Continue using remaining tokens from the reloaded set
    //     let mut final_loaded_token_set = reloaded_token_set;
    //     let remaining_tokens = num_tokens - final_loaded_token_set.token_idx; // Tokens 3 to 7 (5 tokens)
    //     let mut consumed_count_reloaded = 0;
    //
    //     for i in 0..remaining_tokens {
    //         let expected_original_index =
    //             final_loaded_token_set.token_idx + consumed_count_reloaded;
    //         let current_token_b64 = final_loaded_token_set
    //             .get_current_b64token()
    //             .expect("Should get a token");
    //
    //         // Verify the token content matches the random at the expected original index
    //         let expected_random = all_randoms_vec[expected_original_index as usize];
    //         let expected_token_bytes: Vec<u8> = final_loaded_token_set
    //             .timestamp
    //             .iter()
    //             .chain(expected_random.iter())
    //             .cloned()
    //             .collect();
    //         let expected_token_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_bytes);
    //         assert_eq!(current_token_b64, expected_token_b64);
    //
    //         // Manually update token_idx
    //         final_loaded_token_set.token_idx += 1;
    //         consumed_count_reloaded += 1;
    //     }
    //
    //     // After using all remaining tokens, token_idx should be num_tokens
    //     assert_eq!(final_loaded_token_set.token_idx, num_tokens);
    //
    //     // Attempt to get a token when exhausted
    //     assert_eq!(final_loaded_token_set.get_current_b64token(), None);
    //
    //     Ok(())
    // }
}
