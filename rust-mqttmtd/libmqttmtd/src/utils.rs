use crate::aead::algo::SupportedAlgorithm;
use bytes::{BufMut, Bytes, BytesMut};

pub fn nonce_from_u128_to_bytes(algo: SupportedAlgorithm, u: u128) -> Bytes {
    let mut nonce_bytes = BytesMut::with_capacity(algo.nonce_len());
    (0..algo.nonce_len()).for_each(|i| {
        nonce_bytes.put_u8(((u >> (8 * i)) & 0xFF) as u8);
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

