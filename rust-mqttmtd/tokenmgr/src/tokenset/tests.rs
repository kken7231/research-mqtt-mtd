use super::*;
use base64::engine::general_purpose;
// Import everything from the outer scope
use base64::Engine;
use bytes::Bytes;
use libmqttmtd::aead::algo::{
    SupportedAlgorithm,
    SupportedAlgorithm::{Aes128Gcm, Aes256Gcm},
};
// Assuming these traits are defined in libmqttmtd
use libmqttmtd::consts::{RANDOM_LEN, TIMESTAMP_LEN};
use rand::{RngCore, seq::IndexedRandom};
use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::tempdir;
use tokio_util::compat::FuturesAsyncReadCompatExt;

struct TestDataHydrator {
    rng: rand::rngs::ThreadRng,
}

impl TestDataHydrator {
    fn new() -> Self {
        Self { rng: rand::rng() }
    }

    fn get_test_timestamp() -> [u8; TIMESTAMP_LEN] {
        (&SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("failed to get epoch: {}", e))
            .as_nanos()
            .to_be_bytes()[64 / 8 + 1..64 / 8 + 1 + TIMESTAMP_LEN])
            .try_into()
            .unwrap_or_else(|e| panic!("failed to get bytes: {}", e))
    }

    fn get_test_randoms(&mut self, num_tokens: u16) -> Bytes {
        let mut all_randoms = BytesMut::zeroed(num_tokens as usize * RANDOM_LEN);
        self.rng.fill_bytes(&mut all_randoms[..]);
        all_randoms.freeze()
    }

    fn get_enc_nonce(
        &mut self,
        algo_opt: impl Into<Option<SupportedAlgorithm>>,
    ) -> (SupportedAlgorithm, Bytes, u128) {
        let algo = match algo_opt.into() {
            Some(algo) => algo,
            None => {
                *([
                    SupportedAlgorithm::Aes128Gcm,
                    SupportedAlgorithm::Aes256Gcm,
                    SupportedAlgorithm::Chacha20Poly1305,
                ]
                .choose(&mut self.rng)
                .unwrap())
            }
        };
        let mut nonce_base = [0u8; 16];
        self.rng
            .fill_bytes(&mut nonce_base[16 - algo.nonce_len()..]);
        let nonce_base = u128::from_be_bytes(nonce_base);
        let mut enc_key = BytesMut::zeroed(algo.key_len());
        self.rng.fill_bytes(&mut enc_key[..]);
        (algo, enc_key.freeze(), nonce_base)
    }

    fn get_token_set(
        &mut self,
        algo: impl Into<Option<SupportedAlgorithm>>,
        is_pub: bool,
        num_tokens_divided_by_4: u8,
        token_idx: u16,
        all_randoms_offset: u16,
        topic: impl Into<String>,
    ) -> TokenSet {
        let timestamp = Self::get_test_timestamp();
        let num_tokens = (num_tokens_divided_by_4 as u16).rotate_left(2);
        let all_randoms = self.get_test_randoms(num_tokens - all_randoms_offset);
        let (algo, enc_key, nonce_base) = self.get_enc_nonce(algo);
        TokenSet {
            path: PathBuf::new(),
            timestamp,
            all_randoms,
            num_tokens,
            token_idx,
            all_randoms_offset,
            topic: topic.into(),
            is_pub,
            algo,
            enc_key,
            nonce_base,
        }
    }
}

const TEST_TOPIC: &str = "topic/pubsub";
const TEST_NUM_TOKENS_DIVIDED_BY_4: u8 = 2;

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

    let _ = writer
        .write_success_to(&mut inner_vec, &mut buf[..])
        .await?;

    let mut async_reader = futures::io::Cursor::new(inner_vec).compat();

    Ok(issuer::ResponseReader::read_from(
        &mut async_reader,
        &mut buf[..],
        aead_algo,
        num_tokens_divided_by_4,
    )
    .await?
    .unwrap())
}

async fn req_res_from_tokenset(token_set: &TokenSet) -> (issuer::Request, issuer::ResponseReader) {
    let request = issuer::Request::new(
        token_set.is_pub,
        token_set.num_tokens.rotate_right(2) as u8,
        token_set.algo,
        token_set.topic.clone(),
    )
    .unwrap_or_else(|e| panic!("{:?}", e));

    let response = new_response_reader(
        token_set.enc_key.clone(),
        Bytes::copy_from_slice(
            &token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..],
        ),
        token_set.timestamp,
        token_set.all_randoms.clone(),
        token_set.algo,
        token_set.num_tokens.rotate_right(2) as u8,
    )
    .await
    .unwrap_or_else(|e| panic!("{:?}", e));

    (request, response)
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

const IS_PUB_PUB: bool = true;
// const IS_PUB_SUB: bool = false;

#[test]
fn test_get_current_b64token() {
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );

    // Get the first token (token_idx = 0)
    let mut expected_token_1_bytes = BytesMut::from(&token_set.timestamp[..]);
    expected_token_1_bytes.extend_from_slice(&token_set.all_randoms[..RANDOM_LEN]);
    let expected_token_1 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_1_bytes);
    assert_eq!(token_set.get_current_b64token(), Some(expected_token_1));

    // Simulate using the first token (increment token_idx)
    token_set.token_idx = 1;

    // Get the second token (token_idx = 1)
    let mut expected_token_2_bytes = BytesMut::from(&token_set.timestamp[..]);
    expected_token_2_bytes.extend_from_slice(&token_set.all_randoms[RANDOM_LEN..RANDOM_LEN * 2]);
    let expected_token_2 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_2_bytes);
    assert_eq!(token_set.get_current_b64token(), Some(expected_token_2));

    // Simulate a scenario where the all_randoms buffer starts at a non-zero offset
    let token_set_offset = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        1,
        1,
        "dummy",
    );

    // Get the token at absolute index 1. This corresponds to index (1 - 1) = 0 in
    // the buffer.
    let mut expected_token_offset_bytes = BytesMut::from(&token_set_offset.timestamp[..]);
    expected_token_offset_bytes.extend_from_slice(&token_set_offset.all_randoms[..RANDOM_LEN]);
    let expected_token_offset =
        general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_offset_bytes);
    assert_eq!(
        token_set_offset.get_current_b64token(),
        Some(expected_token_offset)
    );

    // Simulate using all tokens (token_idx reaches num_tokens)
    let mut token_set_idx_end = token_set_offset; // Start with offset 0
    token_set_idx_end.token_idx = token_set_idx_end.num_tokens; // Absolute index is num_tokens

    // Should return None because token_idx >= num_tokens
    // The condition `self.all_randoms.len() >= random_end` will also be false as
    // random_start will be out of bounds
    assert_eq!(token_set_idx_end.get_current_b64token(), None);

    // Simulate index beyond num_tokens
    let mut token_set_idx_beyond = token_set_idx_end;
    token_set_idx_beyond.token_idx = token_set_idx_beyond.num_tokens + 1;
    assert_eq!(token_set_idx_beyond.get_current_b64token(), None);
}

#[test]
fn test_get_nonce() {
    let mut hydrator = TestDataHydrator::new();
    let token_set = hydrator.get_token_set(
        Aes128Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );

    // Test with token_idx = 0
    let expected_nonce_bytes_0: [u8; 16] = (token_set.nonce_base + 0).to_be_bytes();
    let expected_nonce_aes128_0: Bytes =
        Bytes::copy_from_slice(&expected_nonce_bytes_0[(16 - token_set.algo.nonce_len())..]); // Last 12 bytes
    assert_eq!(
        token_set.get_nonce_for_cli2serv_pub(),
        expected_nonce_aes128_0
    );

    // Test with token_idx > 0
    let token_set_idx5 = hydrator.get_token_set(
        Aes128Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        5,
        0,
        "dummy",
    );
    let expected_nonce_bytes_5: [u8; 16] = (token_set_idx5.nonce_base + 5).to_be_bytes();
    let expected_nonce_aes128_5: Bytes =
        Bytes::copy_from_slice(&expected_nonce_bytes_5[(16 - Aes128Gcm.nonce_len())..]);
    assert_eq!(
        token_set_idx5.get_nonce_for_cli2serv_pub(),
        expected_nonce_aes128_5
    );

    // Test with a different algorithm (assuming Aes256Gcm with nonce_len 12 exists)
    let token_set_algo = hydrator.get_token_set(
        Aes256Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );
    let expected_nonce_bytes_0: [u8; 16] = token_set_algo.nonce_base.to_be_bytes();
    let expected_nonce_aes256_0: Bytes =
        Bytes::copy_from_slice(&expected_nonce_bytes_0[(16 - Aes256Gcm.nonce_len())..]); // AES256-GCM commonly uses 12-byte nonces
    assert_eq!(
        token_set_algo.get_nonce_for_cli2serv_pub(),
        expected_nonce_aes256_0
    );
}

#[tokio::test]
async fn test_seal_open_success() {
    let mut hydrator = TestDataHydrator::new();
    let token_set = hydrator.get_token_set(
        Aes256Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );
    let payload_raw = "hello from client";
    let mut in_out = BytesMut::from(payload_raw);
    let sealed_res = token_set.seal_cli2serv(&mut in_out);
    assert!(sealed_res.is_ok());
    let mut sealed = BytesMut::from(sealed_res.unwrap());

    let opened_res = token_set.open_cli2serv(&mut sealed);
    assert!(opened_res.is_ok());

    assert_eq!(payload_raw.as_bytes(), &sealed[..sealed.len() - 16]);
}

#[tokio::test]
async fn test_from_issuer_req_resp_success() {
    let mut hydrator = TestDataHydrator::new();
    let token_set_original = hydrator.get_token_set(
        Aes128Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );
    let (request, response) = req_res_from_tokenset(&token_set_original).await;

    let token_set =
        TokenSet::from_issuer_req_resp(&request, response).unwrap_or_else(|e| panic!("{:?}", e));

    // Path should be empty
    assert_eq!(token_set.path, PathBuf::new());
    assert_eq!(token_set.timestamp, token_set_original.timestamp);
    // all_randoms should contain all random bytes from the response
    assert_eq!(token_set.all_randoms, token_set_original.all_randoms);
    assert_eq!(token_set.num_tokens, token_set_original.num_tokens);
    assert_eq!(token_set.token_idx, token_set_original.token_idx);
    assert_eq!(
        token_set.all_randoms_offset,
        token_set_original.all_randoms_offset
    ); // Should be initialized to 0
    assert_eq!(token_set.topic, token_set_original.topic);
    assert_eq!(token_set.is_pub, token_set_original.is_pub);
    assert_eq!(token_set.algo, token_set_original.algo);
    assert_eq!(token_set.enc_key, token_set_original.enc_key);

    // Check nonce_base conversion
    assert_eq!(token_set.nonce_base, token_set_original.nonce_base);
}

// Helper to create a dummy file for from_file tests
// The file_all_randoms_offset written to the file is the absolute original
// index where the random data in *this specific file* starts.
fn create_dummy_token_file(
    filename_token_idx: u16,
    file_all_randoms_offset: u16,
    algo: impl Into<Option<SupportedAlgorithm>>,
    is_pub: bool,
    num_tokens_divided_by_4: u8,
    topic: impl Into<String>,
) -> (TokenSet, PathBuf) {
    let topic = topic.into();
    let topic_encoded = TokenSet::topic_b64encode(&topic);
    let filename = format!("{}{}", topic_encoded, filename_token_idx);
    let file_path = tempdir()
        .expect("failed to create a tempfile")
        .path()
        .join(filename);

    let mut token_set =
        TestDataHydrator::new().get_token_set(algo, is_pub, num_tokens_divided_by_4, 0, 0, topic);
    fs::create_dir_all(file_path.parent().unwrap()).expect("failed to create dirs");
    let mut file = fs::File::create_new(&file_path).expect("failed to create file");
    file.write_all(&[token_set.algo as u8])
        .expect("failed to write file");
    file.write_all(&token_set.enc_key)
        .expect("failed to write file");
    file.write_all(&token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..])
        .expect("failed to write file");
    file.write_all(&[token_set.num_tokens.rotate_right(2) as u8])
        .expect("failed to write file");
    file.write_all(&token_set.timestamp)
        .expect("failed to write file");
    file.write_all(&file_all_randoms_offset.to_be_bytes())
        .expect("failed to write file");
    file.write_all(&token_set.all_randoms[(file_all_randoms_offset as usize * RANDOM_LEN)..])
        .expect("failed to write file");
    token_set.path = file_path.clone();
    (token_set, file_path)
}

#[test]
fn test_from_file_success_idx_0_offset_0() {
    let filename_token_idx = 0u16;
    let file_all_randoms_offset = 0u16;

    let (token_set_original, file_path) = create_dummy_token_file(
        filename_token_idx,
        file_all_randoms_offset,
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        "dummy",
    );

    let token_set = TokenSet::from_file(
        file_path.clone(),
        token_set_original.is_pub,
        token_set_original.topic.clone(),
    )
    .unwrap_or_else(|e| panic!("failed to get a tokenset {}", e));

    assert_eq!(token_set.path, file_path);
    assert_eq!(token_set.topic, token_set_original.topic);
    assert_eq!(token_set.is_pub, token_set_original.is_pub);
    assert_eq!(token_set.token_idx, filename_token_idx);
    assert_eq!(token_set.all_randoms_offset, file_all_randoms_offset);
    assert_eq!(token_set.algo, token_set_original.algo);
    assert_eq!(token_set.enc_key, token_set_original.enc_key);
    assert_eq!(token_set.nonce_base, token_set_original.nonce_base);
    assert_eq!(token_set.num_tokens, token_set_original.num_tokens);
    assert_eq!(token_set.timestamp, token_set_original.timestamp);
    assert_eq!(token_set.all_randoms, token_set_original.all_randoms);
}

#[test]
fn test_from_file_success_idx_greater_than_0_offset_equal_idx() {
    let filename_token_idx = 4u16; // Filename index is 4
    let file_all_randoms_offset = 4u16; // File content starts at original index 4

    let (token_set_original, file_path) = create_dummy_token_file(
        filename_token_idx,
        file_all_randoms_offset,
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        "dummy",
    );

    let token_set = TokenSet::from_file(
        file_path.clone(),
        token_set_original.is_pub,
        token_set_original.topic.clone(),
    )
    .unwrap_or_else(|e| panic!("failed to get a tokenset {}", e));

    assert_eq!(token_set.path, file_path);
    assert_eq!(token_set.topic, token_set_original.topic);
    assert_eq!(token_set.is_pub, token_set_original.is_pub);
    assert_eq!(token_set.token_idx, filename_token_idx);
    assert_eq!(token_set.all_randoms_offset, file_all_randoms_offset);
    assert_eq!(token_set.algo, token_set_original.algo);
    assert_eq!(token_set.enc_key, token_set_original.enc_key);
    assert_eq!(token_set.nonce_base, token_set_original.nonce_base);
    assert_eq!(token_set.num_tokens, token_set_original.num_tokens);
    assert_eq!(token_set.timestamp, token_set_original.timestamp);
    assert_eq!(
        token_set.all_randoms,
        token_set_original.all_randoms[(filename_token_idx as usize * RANDOM_LEN)..]
    );
}

#[test]
fn test_from_file_success_idx_greater_than_0_offset_less_than_idx() {
    let filename_token_idx = 6u16; // Filename index is 6
    let file_all_randoms_offset = 4u16; // File content starts at original index 4

    let (token_set_original, file_path) = create_dummy_token_file(
        filename_token_idx,
        file_all_randoms_offset,
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_TOPIC,
    );

    let token_set = TokenSet::from_file(
        file_path.clone(),
        token_set_original.is_pub,
        token_set_original.topic.clone(),
    )
    .unwrap_or_else(|e| panic!("failed to get a tokenset {}", e));

    assert_eq!(token_set.path, file_path);
    assert_eq!(token_set.topic, token_set_original.topic);
    assert_eq!(token_set.is_pub, token_set_original.is_pub);
    assert_eq!(token_set.token_idx, filename_token_idx);
    assert_eq!(token_set.all_randoms_offset, filename_token_idx);
    assert_eq!(token_set.algo, token_set_original.algo);
    assert_eq!(token_set.enc_key, token_set_original.enc_key);
    assert_eq!(token_set.nonce_base, token_set_original.nonce_base);
    assert_eq!(token_set.num_tokens, token_set_original.num_tokens);
    assert_eq!(token_set.timestamp, token_set_original.timestamp);
    assert_eq!(
        token_set.all_randoms,
        token_set_original.all_randoms[(filename_token_idx as usize * RANDOM_LEN)..]
    );
}

#[test]
fn test_from_file_error_file_not_found() {
    let non_existent_path = PathBuf::from("/non/existent/path/to/token_set");
    let result = TokenSet::from_file(non_existent_path, true, "dummy".to_string());

    match result {
        Err(TokenSetError::FileNotFoundError(_)) => {}
        other => panic!("Expected FileNotFoundError: {:?}", other),
    };
}

#[test]
fn test_from_file_error_path_not_having_filename() {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let dir_path = temp_dir.path().to_path_buf();

    let result = TokenSet::from_file(dir_path, true, "dummy".to_string());

    match result {
        Err(TokenSetError::FileNotFoundError(_)) => {}
        other => panic!("Expected FileNotFoundError: {:?}", other),
    };
}

#[test]
fn test_from_file_error_invalid_cur_idx_in_filename() {
    let filename_token_idx = 6u16; // Filename index is 6
    let file_all_randoms_offset = 4u16; // File content starts at original index 4

    let (token_set_original, mut file_path) = create_dummy_token_file(
        filename_token_idx,
        file_all_randoms_offset,
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        TEST_TOPIC,
    );

    let token_set = TokenSet::from_file(
        file_path.clone(),
        token_set_original.is_pub,
        token_set_original.topic.clone(),
    )
    .unwrap_or_else(|e| panic!("failed to get a tokenset {}", e));
    let topic_encoded = TokenSet::topic_b64encode(token_set.topic.clone());

    // Invalid index format
    {
        let invalid_filename = format!("{}abc", topic_encoded);
        let invalid_path_format = (&file_path).parent().unwrap().join(invalid_filename);
        fs::rename(&file_path, &invalid_path_format)
            .expect("Failed to rename file for format test");
        file_path = invalid_path_format.clone();
        let result_format =
            TokenSet::from_file(invalid_path_format.clone(), true, token_set.topic.clone());
        match result_format {
            Err(TokenSetError::InvalidCurIdxInFilenameError(None)) => {}
            _ => panic!("Expected InvalidCurIdxInFilenameError(None) for invalid format"),
        }
    }

    // Index too large (exceeding 0x7F * 4)
    {
        let invalid_idx_large: u16 = 0x7F * 4 + 1;
        let invalid_filename_large = format!("{}{}", topic_encoded, invalid_idx_large);
        let invalid_path_large = (&file_path).parent().unwrap().join(invalid_filename_large);
        fs::rename(&file_path, &invalid_path_large)
            .expect("Failed to rename file for index large test");
        file_path = invalid_path_large.clone();
        let result_large =
            TokenSet::from_file(invalid_path_large.clone(), true, token_set.topic.clone());
        match result_large {
            Err(TokenSetError::InvalidCurIdxInFilenameError(Some(idx))) => {
                assert_eq!(idx, invalid_idx_large);
            }
            _ => panic!("Expected InvalidCurIdxInFilenameError(Some) for large index"),
        }
    }

    // filename_token_idx < file_all_randoms_offset
    {
        let invalid_idx_less_than_offset = 2u16; // Less than file_all_randoms_offset = 4
        // let valid_file_all_randoms_offset = 4u16;
        let invalid_filename_less = format!("{}{}", topic_encoded, invalid_idx_less_than_offset);
        let invalid_path_less = (&file_path).parent().unwrap().join(invalid_filename_less);
        fs::rename(&file_path, &invalid_path_less)
            .expect("Failed to rename file for index large test");
        let result_less = TokenSet::from_file(invalid_path_less, true, token_set.topic.clone());
        match result_less {
            Err(TokenSetError::InvalidCurIdxInFilenameError(Some(idx))) => {
                assert_eq!(idx, invalid_idx_less_than_offset);
            }
            _ => panic!(
                "Expected InvalidCurIdxInFilenameError(Some) for index less than file offset"
            ),
        }
    }
}

#[test]
fn test_from_file_error_unsupported_algorithm() -> Result<(), ()> {
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let topic = TEST_TOPIC;
    let token_idx = 0;
    let algo_byte = 0xFF; // Invalid algorithm byte

    let topic_encoded = TokenSet::topic_b64encode(topic);
    let filename = format!("{}{}", topic_encoded, token_idx);
    let file_path = temp_dir.path().join(filename);

    let mut file = fs::File::create(&file_path).expect("Failed to create dummy file");
    file.write_all(&[algo_byte]).expect("Failed to write algo"); // Write invalid algo

    let result = TokenSet::from_file(file_path, true, topic.to_string());

    match result {
        Err(TokenSetError::UnsupportedAlgorithmError(_)) => {} /* We expect an error converting */
        // the byte
        _ => panic!("Expected UnsupportedAlgorithmError"),
    }
    Ok(())
}

#[test]
fn test_from_file_error_nonce_len_mismatch_read() -> Result<(), ()> {
    let token_set = TestDataHydrator::new().get_token_set(
        Aes128Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        TEST_TOPIC,
    );

    let temp_dir = tempdir().expect("Failed to create temp dir");
    let topic_encoded = TokenSet::topic_b64encode(token_set.topic.clone());
    let filename = format!("{}0", topic_encoded);
    let file_path = temp_dir.path().join(filename);

    let mut file = fs::File::create(&file_path).expect("failed to create file");
    file.write_all(&[token_set.algo as u8])
        .expect("failed to write file");
    file.write_all(&token_set.enc_key)
        .expect("failed to write file");
    file.write_all(
        &token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..]
            [..token_set.algo.nonce_len() - 1],
    )
    .expect("failed to write file"); // too small nonce
    file.write_all(&[token_set.num_tokens.rotate_right(2) as u8])
        .expect("failed to write file");
    file.write_all(&token_set.timestamp)
        .expect("failed to write file");
    file.write_all(&0u16.to_be_bytes())
        .expect("failed to write file");
    file.write_all(&token_set.all_randoms[..])
        .expect("failed to write file");

    let result = TokenSet::from_file(file_path, true, token_set.topic.clone());

    match result {
        // The error will be FileReadError because read_exact will fail
        Ok(_) => panic!("Expected FileReadError or other errors (due to short nonce read)"),
        _ => {}
    }
    Ok(())
}

#[test]
fn test_from_file_error_invalid_num_tokens() {
    // num_tokens <= filename_token_idx
    {
        let filename_token_idx = 6u16;
        let file_all_randoms_offset = 0u16;
        let invalid_num_tokens_divided_by_4 = 1u8; // < TEST_NUM_TOKENS_DIVIDED_BY_4
        let token_set = TestDataHydrator::new().get_token_set(
            Aes128Gcm,
            IS_PUB_PUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            0,
            0,
            TEST_TOPIC,
        );
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let topic_encoded = TokenSet::topic_b64encode(token_set.topic.clone());
        let filename = format!("{}{}", topic_encoded, filename_token_idx);
        let file_path = temp_dir.path().join(filename);
        let mut file = fs::File::create(&file_path).expect("failed to create file");
        file.write_all(&[token_set.algo as u8])
            .expect("failed to write file");
        file.write_all(&token_set.enc_key)
            .expect("failed to write file");
        file.write_all(&token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..])
            .expect("failed to write file"); // too small nonce
        file.write_all(&[invalid_num_tokens_divided_by_4])
            .expect("failed to write file"); // invalid num_tokens
        file.write_all(&token_set.timestamp)
            .expect("failed to write file");
        file.write_all(&file_all_randoms_offset.to_be_bytes())
            .expect("failed to write file");

        let result =
            TokenSet::from_file(file_path.clone(), token_set.is_pub, token_set.topic.clone());

        match result {
            Err(TokenSetError::InvalidNumTokensError(n)) => {
                assert_eq!(n, invalid_num_tokens_divided_by_4);
            }
            _ => panic!("Expected InvalidNumTokensError for num_tokens <= token_idx"),
        }
    }

    // num_tokens <= file_all_randoms_offset
    {
        let filename_token_idx = 6u16;
        let file_all_randoms_offset = 6u16;
        let invalid_num_tokens_divided_by_4 = 1u8; // < TEST_NUM_TOKENS_DIVIDED_BY_4
        let token_set = TestDataHydrator::new().get_token_set(
            Aes128Gcm,
            IS_PUB_PUB,
            TEST_NUM_TOKENS_DIVIDED_BY_4,
            0,
            0,
            TEST_TOPIC,
        );
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let topic_encoded = TokenSet::topic_b64encode(token_set.topic.clone());
        let filename = format!("{}{}", topic_encoded, filename_token_idx);
        let file_path = temp_dir.path().join(filename);
        let mut file = fs::File::create(&file_path).expect("failed to create file");
        file.write_all(&[token_set.algo as u8])
            .expect("failed to write file");
        file.write_all(&token_set.enc_key)
            .expect("failed to write file");
        file.write_all(&token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..])
            .expect("failed to write file"); // too small nonce
        file.write_all(&[invalid_num_tokens_divided_by_4])
            .expect("failed to write file"); // invalid num_tokens
        file.write_all(&token_set.timestamp)
            .expect("failed to write file");
        file.write_all(&file_all_randoms_offset.to_be_bytes())
            .expect("failed to write file");

        let result =
            TokenSet::from_file(file_path.clone(), token_set.is_pub, token_set.topic.clone());

        match result {
            Err(TokenSetError::InvalidNumTokensError(n)) => {
                assert_eq!(n, invalid_num_tokens_divided_by_4);
            }
            _ => panic!("Expected InvalidNumTokensError for num_tokens <= token_idx"),
        }
    }
}

#[test]
fn test_from_file_error_random_len_mismatch_read() {
    let filename_token_idx = 0u16;
    let file_all_randoms_offset = 0u16;
    // Write fewer randoms than expected based on num_tokens and filename_token_idx
    // Expected length is (num_tokens - filename_token_idx) * RANDOM_LEN = (8 - 0) *
    // RANDOM_LEN = 8 * RANDOM_LEN
    let invalid_all_randoms_len = RANDOM_LEN;
    let token_set = TestDataHydrator::new().get_token_set(
        Aes128Gcm,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        TEST_TOPIC,
    );
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let topic_encoded = TokenSet::topic_b64encode(token_set.topic.clone());
    let filename = format!("{}{}", topic_encoded, filename_token_idx);
    let file_path = temp_dir.path().join(filename);
    let mut file = fs::File::create(&file_path).expect("failed to create file");
    file.write_all(&[token_set.algo as u8])
        .expect("failed to write file");
    file.write_all(&token_set.enc_key)
        .expect("failed to write file");
    file.write_all(&token_set.nonce_base.to_be_bytes()[16 - token_set.algo.nonce_len()..])
        .expect("failed to write file"); // too small nonce
    file.write_all(&[token_set.num_tokens.rotate_right(2) as u8])
        .expect("failed to write file"); // invalid num_tokens
    file.write_all(&token_set.timestamp)
        .expect("failed to write file");
    file.write_all(&file_all_randoms_offset.to_be_bytes())
        .expect("failed to write file");
    file.write_all(&token_set.all_randoms[..invalid_all_randoms_len])
        .expect("failed to write file");

    let result = TokenSet::from_file(file_path.clone(), token_set.is_pub, token_set.topic.clone());

    // The code expects to read (num_tokens - filename_token_idx) * RANDOM_LEN
    // bytes. We wrote fewer bytes. The `read` into the BytesMut will read
    // what's available, and then the check `if actual_read < expected_len`
    // should trigger.
    match result {
        Err(TokenSetError::RandomLenMismatchError(actual_read)) => {
            assert_eq!(actual_read, invalid_all_randoms_len);
        }
        _ => panic!("Expected RandomLenMismatchError when randoms are incomplete"),
    }
}

#[test]
fn test_save_to_file_success() {
    let token_sets_dir = tempdir()
        .expect("failed to create tempdir")
        .path()
        .to_path_buf();
    let initial_token_idx = 2u16;
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        2,
        0,
        TEST_TOPIC,
    );

    // Save the token set to a file
    token_set
        .save_to_file(&token_sets_dir)
        .unwrap_or_else(|e| panic!("{:?}", e));

    // Construct the expected file path
    let topic_encoded = TokenSet::topic_b64encode(&token_set.topic);
    let expected_filename = format!("{}{}", topic_encoded, initial_token_idx);
    let expected_file_path = token_sets_dir.join("pub").join(expected_filename);

    // Verify the path field in the struct is updated
    assert_eq!(token_set.path, expected_file_path);
    assert!(expected_file_path.exists()); // Ensure the file was created

    // Read the file back and verify its contents
    let mut file = fs::File::open(&expected_file_path).unwrap_or_else(|e| panic!("{:?}", e));
    let mut read_buf = Vec::new();
    file.read_to_end(&mut read_buf)
        .unwrap_or_else(|e| panic!("{:?}", e));

    let mut expected_bytes = Vec::new();
    // Header fields order: algo, enc_key, nonce_base, num_tokens_divided_by_4,
    // timestamp, all_randoms_offset
    expected_bytes.push(token_set.algo as u8);
    expected_bytes.extend_from_slice(&token_set.enc_key);
    expected_bytes.extend_from_slice(
        &token_set.nonce_base.to_be_bytes()[(16 - token_set.algo.nonce_len())..],
    );
    expected_bytes.push(token_set.num_tokens.rotate_right(2) as u8);
    expected_bytes.extend_from_slice(&token_set.timestamp);
    // file_all_randoms_offset (which is struct.token_idx)
    expected_bytes.extend_from_slice(&initial_token_idx.to_be_bytes());

    // all_randoms content - skips (token_idx - all_randoms_offset) from the
    // in-memory Bytes
    let skip_len = (initial_token_idx - token_set.all_randoms_offset) as usize * RANDOM_LEN;
    // The bytes written are from index `skip_len` in `all_randoms_in_memory` to the
    // end.
    expected_bytes.extend_from_slice(&token_set.all_randoms[skip_len..]);

    assert_eq!(read_buf, expected_bytes);
}

#[test]
fn test_save_to_file_success_replaces_old() {
    let token_sets_dir = tempdir()
        .expect("failed to create tempdir")
        .path()
        .to_path_buf();
    let initial_token_idx = 2u16;
    let updated_token_idx = 4u16;
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        updated_token_idx,
        0,
        TEST_TOPIC,
    );
    let pub_sub_dir = token_sets_dir.join("pub");
    fs::create_dir_all(&pub_sub_dir).unwrap_or_else(|e| panic!("{:?}", e));

    // Create an initial file to be replaced
    let initial_filename = format!(
        "{}{}",
        TokenSet::topic_b64encode(&token_set.topic),
        initial_token_idx
    );
    let initial_file_path = pub_sub_dir.join(initial_filename);
    // Create a dummy file content for the old file (doesn't need to be fully
    // correct)
    fs::File::create(&initial_file_path)
        .unwrap_or_else(|e| panic!("{:?}", e))
        .write_all(b"dummy content")
        .unwrap_or_else(|e| panic!("{:?}", e));
    assert!(initial_file_path.exists());
    token_set.path = initial_file_path.clone();

    // Save the token set - this should remove the old file and create a new one
    token_set
        .save_to_file(&token_sets_dir)
        .unwrap_or_else(|e| panic!("{:?}", e));

    // Verify the old file is gone
    assert!(!initial_file_path.exists());

    // Construct the expected new file path
    let topic_encoded = TokenSet::topic_b64encode(&token_set.topic);
    let expected_new_filename = format!("{}{}", topic_encoded, updated_token_idx);
    let expected_new_file_path = pub_sub_dir.join(expected_new_filename);

    // Verify the path field in the struct is updated
    assert_eq!(token_set.path, expected_new_file_path);
    assert!(expected_new_file_path.exists()); // Ensure the new file was created
}

#[test]
fn test_save_to_file_error_enc_key_mismatch() {
    let token_sets_dir = tempdir()
        .expect("failed to create tempdir")
        .path()
        .to_path_buf();
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        TEST_TOPIC,
    );
    token_set.enc_key = BytesMut::zeroed(token_set.algo.key_len() - 1).freeze(); // wrong len

    let result = token_set.save_to_file(&token_sets_dir);

    match result {
        Err(TokenSetError::EncKeyMismatchError(len)) => {
            assert_eq!(len, token_set.algo.key_len() - 1);
        }
        _ => panic!("Expected EncKeyMismatchError"),
    }

    // Verify no file was created (or an incomplete one was potentially left,
    // depending on OS/timing) Checking for existence is tricky as create()
    // might succeed before write_all fails. A robust test might check file size
    // if it exists. For simplicity, skip strict file check here.
    assert_eq!(token_set.path, PathBuf::new()); // Path should not be updated on error
}

#[test]
fn test_save_to_file_error_file_create_error() {
    #[cfg(not(unix))]
    panic!("this test is exclusive to unix filesystem");

    let temp_dir = tempdir().expect("Failed to create temp dir");
    // Use a read-only path to cause a creation error
    let readonly_dir = temp_dir.path().join("readonly");
    fs::create_dir(&readonly_dir).expect("Failed to create readonly dir");

    // Make it read-only
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&readonly_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o444); // Read-only
    fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");

    println!(
        "{:o}",
        fs::metadata(&readonly_dir)
            .expect("...")
            .permissions()
            .mode()
    );

    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        TEST_TOPIC,
    );

    let result = token_set.save_to_file(&readonly_dir);

    match result {
        Err(TokenSetError::FileCreateError(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        }
        Ok(_) => panic!("Expected FileCreateError but Ok returned. Maybe you are root?"),
        other => panic!("Expected FileCreateError: {:?}", other),
    }

    assert_eq!(token_set.path, PathBuf::new()); // Path should not be updated on error

    // Attempt to revert permissions
    let mut perms = fs::metadata(&readonly_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o755); // Read/write
    fs::set_permissions(&readonly_dir, perms).expect("Failed to set permissions");
}

#[test]
fn test_save_to_file_error_file_remove_error() {
    #[cfg(not(unix))]
    panic!("this test is exclusive to unix filesystem");

    let initial_token_idx = 0u16;
    let updated_token_idx = 1u16;
    let is_pub = IS_PUB_PUB;
    let topic = TEST_TOPIC;

    let temp_dir = tempdir().expect("Failed to create temp dir");
    let token_sets_dir = temp_dir.path();
    let pub_sub_dir = if is_pub {
        token_sets_dir.join("pub")
    } else {
        token_sets_dir.join("sub")
    };
    fs::create_dir_all(&pub_sub_dir).expect("Failed to create dir");

    // Create an initial file that *cannot* be removed
    let initial_filename = format!("{}{}", TokenSet::topic_b64encode(topic), initial_token_idx);
    let initial_file_path = pub_sub_dir.join(initial_filename);
    fs::File::create(&initial_file_path).expect("Failed to create file for remove error test");

    // Make pub_sub_dir read-only to prevent removal of the children files (platform
    // dependent)
    let mut perms = fs::metadata(&pub_sub_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o555); // Read and execute, no write (execute for exists())
    fs::set_permissions(&pub_sub_dir, perms).expect("Failed to set permissions");

    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        is_pub,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        updated_token_idx, // not initial_token_idx
        0,
        topic,
    );
    token_set.path = initial_file_path.clone();

    // Attempt to save - this should fail on removal
    let result = token_set.save_to_file(&token_sets_dir);

    match result {
        Err(TokenSetError::FileRemoveError(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        }
        Ok(_) => panic!("Expected FileCreateError but Ok returned. Maybe you are root?"),
        other => panic!("Expected FileRemoveError: {:?}", other),
    }

    // Verify the path field is NOT updated on error
    assert_eq!(token_set.path, initial_file_path); // Path should still point to the old file

    // Verify the old file still exists
    assert!(initial_file_path.exists());

    // Attempt to revert permissions if on Unix for cleanup
    let mut perms = fs::metadata(&pub_sub_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o755); // Read/write for owner
    fs::set_permissions(&pub_sub_dir, perms).expect("Failed to set permissions");
}

#[test]
fn test_refresh_filename_success() {
    let initial_token_idx = 0u16;
    let updated_token_idx = 5u16; // Simulate that 5 tokens have been used
    let topic = TEST_TOPIC;

    let (mut token_set, initial_file_path) = create_dummy_token_file(
        initial_token_idx,
        0,
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        topic,
    );

    // Verify the initial file exists
    assert!(initial_file_path.exists());

    token_set.token_idx = updated_token_idx;

    // Refresh the filename
    token_set
        .refresh_filename()
        .unwrap_or_else(|e| panic!("{:?}", e));

    // Verify the old file is gone
    assert!(!initial_file_path.exists());

    // Verify the new file exists with the updated filename
    let new_filename = format!("{}{}", TokenSet::topic_b64encode(topic), updated_token_idx);
    let new_file_path = initial_file_path.parent().unwrap().join(new_filename);
    assert!(new_file_path.exists());

    // Verify the path field in the struct is updated
    assert_eq!(token_set.path, new_file_path);
}

#[test]
fn test_refresh_filename_error_file_not_found() {
    let non_existent_path = PathBuf::from("/non/existent/path/to/token_set_to_rename");
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        IS_PUB_PUB,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        "dummy",
    );
    token_set.path = non_existent_path.clone();

    let result = token_set.refresh_filename();

    match result {
        Err(TokenSetError::FileNotFoundError(p)) => {
            assert_eq!(p, non_existent_path);
        }
        _ => panic!("Expected FileNotFoundError"),
    }
    // Path should not be updated on error
    assert_eq!(token_set.path, non_existent_path);
}

#[test]
fn test_refresh_filename_error_file_rename_error() {
    #[cfg(not(unix))]
    panic!("this test is exclusive to unix filesystem");

    let is_pub = true;
    let topic = TEST_TOPIC;
    let initial_token_idx: u16 = 0;
    let updated_token_idx: u16 = 5; // Try to rename to a path where creation is not allowed

    // Create the initial dummy file
    let (mut token_set, initial_file_path) = create_dummy_token_file(
        initial_token_idx,
        0,
        None,
        is_pub,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        topic,
    );

    // Make a parent_dir readonly where the new file cannot be created
    let parent_dir = initial_file_path.parent().unwrap();
    let mut perms = fs::metadata(&parent_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o555); // Read and excute only
    fs::set_permissions(&parent_dir, perms).expect("Failed to set permissions");

    // Attempt to refresh filename - should fail due to permission error at target
    token_set.token_idx = updated_token_idx;
    let result = token_set.refresh_filename();

    match result {
        Err(TokenSetError::FileRenameError(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
        }
        other => panic!("Expected FileRenameError: {:?}", other),
    }

    // Verify the path field is NOT updated on error
    assert_eq!(token_set.path, initial_file_path);

    // Verify the original file still exists
    assert!(initial_file_path.exists());

    // Attempt to revert permissions for cleanup
    let mut perms = fs::metadata(&parent_dir)
        .expect("Failed to get metadata")
        .permissions();
    perms.set_mode(0o755); // Read/write
    fs::set_permissions(&parent_dir, perms).expect("Failed to set permissions");
}

// Integration Test
#[test]
fn test_integration_save_load_use() -> Result<(), TokenSetError> {
    let temp_dir = tempdir().map_err(|e| TokenSetError::FileCreateError(e))?;
    let token_sets_dir = temp_dir.path().to_path_buf();

    let is_pub = IS_PUB_PUB;
    let topic = TEST_TOPIC;

    // Manually create pub directory as save_to_file expects it
    let pub_dir = token_sets_dir.join("pub");
    fs::create_dir_all(&pub_dir).map_err(|e| TokenSetError::FileCreateError(e))?;

    // Initial state (like from_issuer_req_resp, but manually setup for test)
    let mut token_set = TestDataHydrator::new().get_token_set(
        None,
        is_pub,
        TEST_NUM_TOKENS_DIVIDED_BY_4,
        0,
        0,
        topic,
    );

    // 1. Save the initial token set to a file
    token_set.save_to_file(&token_sets_dir)?;

    // Verify the path field in the struct is updated
    let topic_encoded = TokenSet::topic_b64encode(topic);
    let initial_filename = format!("{}0", topic_encoded);
    let initial_file_path = pub_dir.join(initial_filename);
    assert_eq!(token_set.path, initial_file_path);
    assert!(initial_file_path.exists());

    // 2. Simulate using some tokens (e.g., 3 tokens)
    let tokens_to_use: u16 = 3;
    let expected_token_content_after_use =
        &token_set.all_randoms[(tokens_to_use as usize * RANDOM_LEN)..];

    // Create a *new* TokenSet instance loaded from the file after using some tokens
    // This simulates loading the state at a later point.
    // Manually create the file with the state as if tokens were used and saved.
    // This is complex to simulate accurately without testing save/load cycles
    // directly.

    // Let's instead simulate loading from the file AS IS after the first save
    // (token_idx 0) and then simulate using tokens on the loaded instance.

    // Load the token set from the file we just saved
    let loaded_token_set = TokenSet::from_file(token_set.path.clone(), is_pub, topic.to_string())?;

    // Verify initial loaded state
    assert_eq!(loaded_token_set.token_idx, token_set.token_idx); // Loaded from filename
    assert_eq!(
        loaded_token_set.all_randoms_offset,
        token_set.all_randoms_offset
    ); // Loaded from file header (which was token_idx 0)
    // all_randoms buffer contains data from file_token_idx (0) onwards
    assert_eq!(loaded_token_set.all_randoms, token_set.all_randoms);
    assert_eq!(loaded_token_set.num_tokens, token_set.num_tokens);
    assert_eq!(loaded_token_set.topic, token_set.topic);

    // 3. Simulate using tokens on the loaded instance
    let mut current_loaded_token_set = loaded_token_set;
    let mut consumed_count = 0;

    for _ in 0..tokens_to_use {
        let current_token_b64 = current_loaded_token_set
            .get_current_b64token()
            .expect("Should get a token");

        // Verify the token content matches the random at the expected original index
        let expected_random = &token_set.all_randoms
            [(consumed_count * RANDOM_LEN)..((consumed_count + 1) * RANDOM_LEN)];
        let expected_token_bytes: Vec<u8> = current_loaded_token_set
            .timestamp
            .iter()
            .chain(expected_random.iter())
            .cloned()
            .collect();
        let expected_token_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_bytes);
        assert_eq!(current_token_b64, expected_token_b64);

        // Manually update token_idx to simulate consumption
        current_loaded_token_set.token_idx += 1;
        consumed_count += 1;
    }

    // After using tokens_to_use, token_idx should be tokens_to_use
    assert_eq!(current_loaded_token_set.token_idx, tokens_to_use);

    // 4. Simulate saving the state after using tokens
    let old_file_path = current_loaded_token_set.path.clone(); // Path points to the file saved at token_idx 0
    current_loaded_token_set.save_to_file(&token_sets_dir)?; // Saves to a file named with token_idx (3)

    // Verify the old file is removed
    assert!(!old_file_path.exists());

    // Construct expected new file path (named with token_idx 3)
    let updated_filename = format!("{}{}", topic_encoded, current_loaded_token_set.token_idx);
    let updated_file_path = pub_dir.join(updated_filename);
    assert_eq!(current_loaded_token_set.path, updated_file_path);
    assert!(updated_file_path.exists());

    // 5. Load from the state saved after using tokens
    let reloaded_token_set = TokenSet::from_file(
        current_loaded_token_set.path.clone(),
        is_pub,
        topic.to_string(),
    )?;

    // Verify reloaded state
    assert_eq!(reloaded_token_set.token_idx, tokens_to_use); // Loaded from filename (3)
    // all_randoms_offset should be where the loaded buffer starts (filename index)
    assert_eq!(reloaded_token_set.all_randoms_offset, tokens_to_use); // Corrected based on discussion
    // all_randoms buffer contains data from filename_token_idx (3) onwards
    assert_eq!(
        reloaded_token_set.all_randoms,
        expected_token_content_after_use
    );
    assert_eq!(reloaded_token_set.num_tokens, token_set.num_tokens);

    // 6. Continue using remaining tokens from the reloaded set
    let mut final_loaded_token_set = reloaded_token_set;
    let remaining_tokens = token_set.num_tokens - final_loaded_token_set.token_idx; // Tokens 3 to 7 (5 tokens)
    let mut consumed_count_reloaded = 0usize;

    for _ in 0..remaining_tokens {
        let expected_original_index = consumed_count_reloaded + tokens_to_use as usize;
        let current_token_b64 = final_loaded_token_set
            .get_current_b64token()
            .expect("Should get a token");

        // Verify the token content matches the random at the expected original index
        let expected_random = &token_set.all_randoms
            [(expected_original_index * RANDOM_LEN)..(expected_original_index + 1) * RANDOM_LEN];
        let expected_token_bytes: Vec<u8> = final_loaded_token_set
            .timestamp
            .iter()
            .chain(expected_random.iter())
            .cloned()
            .collect();
        let expected_token_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&expected_token_bytes);
        assert_eq!(current_token_b64, expected_token_b64);

        // Manually update token_idx
        final_loaded_token_set.token_idx += 1;
        consumed_count_reloaded += 1;
    }

    // After using all remaining tokens, token_idx should be num_tokens
    assert_eq!(final_loaded_token_set.token_idx, token_set.num_tokens);

    // Attempt to get a token when exhausted
    assert_eq!(final_loaded_token_set.get_current_b64token(), None);

    Ok(())
}
