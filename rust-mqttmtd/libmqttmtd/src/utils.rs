use crate::aead::algo::SupportedAlgorithm;
use crate::consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN};
use bytes::{BufMut, Bytes, BytesMut};
use ring::hmac::Key;

pub fn get_nonce(
    algo: SupportedAlgorithm,
    nonce_padding: &[u8],
    packet_id: Option<u16>,
    token_idx: u16,
) -> Option<Bytes> {
    if algo.nonce_len() - 4 != nonce_padding.len() {
        return None;
    }
    let mut nonce = BytesMut::with_capacity(algo.nonce_len());
    nonce.put(nonce_padding);
    nonce.put_u16(packet_id.unwrap_or(0));
    nonce.put_u16(token_idx);
    Some(nonce.freeze())
}

pub fn calculate_random(key: &Key, topic: &str, token_idx: u16) -> Bytes {
    let mut topic_and_idx = BytesMut::with_capacity(topic.len() + 2);
    topic_and_idx.put(topic.as_bytes());
    topic_and_idx.put_u16(token_idx);
    Bytes::copy_from_slice(&ring::hmac::sign(key, &topic_and_idx[..]).as_ref()[..RANDOM_LEN])
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
