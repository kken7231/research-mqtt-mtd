use crate::aead::algo::SupportedAlgorithm;
use crate::consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN};
use bytes::{BufMut, Bytes, BytesMut};
use ring::hmac::Key;

pub fn nonce_from_u128_to_bytes(algo: SupportedAlgorithm, u: u128) -> Bytes {
    let mut nonce_bytes = BytesMut::with_capacity(algo.nonce_len());
    (0..algo.nonce_len()).for_each(|i| {
        nonce_bytes.put_u8(((u >> (8 * (algo.nonce_len() - i - 1))) & 0xFF) as u8);
    });
    nonce_bytes.freeze()
}

pub fn nonce_from_bytes_to_u128(algo: SupportedAlgorithm, bs: Bytes) -> u128 {
    let mut nonce = 0u128;
    bs.iter().take(algo.nonce_len()).for_each(|b| {
        nonce |= *b as u128;
        nonce <<= 8
    });
    nonce
}

pub fn calculate_random(key: &Key, topic: &str, token_idx: u16) -> Bytes {
    let topic_counter_str = format!("{}{}", topic, token_idx);
    let topic_counter = topic_counter_str.as_bytes();
    Bytes::copy_from_slice(&ring::hmac::sign(key, &topic_counter).as_ref()[..RANDOM_LEN])
}

pub fn calculate_token(
    timestamp: &[u8; TIMESTAMP_LEN],
    key: &Key,
    topic: &str,
    token_idx: u16,
) -> [u8; TOKEN_LEN] {
    let mut token = [0u8; TOKEN_LEN];
    token[..TIMESTAMP_LEN].copy_from_slice(timestamp);
    token[TIMESTAMP_LEN..].copy_from_slice(&calculate_random(key, topic, token_idx));
    token
}
