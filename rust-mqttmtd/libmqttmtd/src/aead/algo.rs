use ring::aead::{MAX_TAG_LEN, NONCE_LEN};

/// Enumerates algorithms supported. TLSv1.3 compatible.
/// 4 bits length
#[repr(u8)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum SupportedAlgorithm {
    Aes128Gcm = 0,
    Aes256Gcm = 1,
    Chacha20Poly1305 = 2,
}

impl SupportedAlgorithm {
    pub fn key_len(&self) -> usize {
        match self {
            SupportedAlgorithm::Aes128Gcm => 16usize,
            SupportedAlgorithm::Aes256Gcm => 32usize,
            SupportedAlgorithm::Chacha20Poly1305 => 32usize,
        }
    }

    pub fn nonce_len(&self) -> usize {
        match self {
            SupportedAlgorithm::Aes128Gcm => NONCE_LEN,
            SupportedAlgorithm::Aes256Gcm => NONCE_LEN,
            SupportedAlgorithm::Chacha20Poly1305 => NONCE_LEN,
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            SupportedAlgorithm::Aes128Gcm => MAX_TAG_LEN,
            SupportedAlgorithm::Aes256Gcm => MAX_TAG_LEN,
            SupportedAlgorithm::Chacha20Poly1305 => MAX_TAG_LEN,
        }
    }

    pub fn ring_algo(&self) -> &'static ring::aead::Algorithm {
        match self {
            SupportedAlgorithm::Aes128Gcm => &ring::aead::AES_128_GCM,
            SupportedAlgorithm::Aes256Gcm => &ring::aead::AES_256_GCM,
            SupportedAlgorithm::Chacha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }
}

impl TryFrom<u8> for SupportedAlgorithm {
    type Error = AeadAlgorithmNotSupportedError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            v if v == SupportedAlgorithm::Aes128Gcm as u8 => Ok(SupportedAlgorithm::Aes128Gcm),
            v if v == SupportedAlgorithm::Aes256Gcm as u8 => Ok(SupportedAlgorithm::Aes256Gcm),
            v if v == SupportedAlgorithm::Chacha20Poly1305 as u8 => {
                Ok(SupportedAlgorithm::Chacha20Poly1305)
            }
            _ => Err(AeadAlgorithmNotSupportedError {}),
        }
    }
}

#[derive(Debug)]
pub struct AeadAlgorithmNotSupportedError {}

impl std::error::Error for AeadAlgorithmNotSupportedError {}

impl std::fmt::Display for AeadAlgorithmNotSupportedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "algorithm not supported")
    }
}
