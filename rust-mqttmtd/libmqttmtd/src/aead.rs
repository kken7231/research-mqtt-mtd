//! States Seal/Open functions

use algo::SupportedAlgorithm;
use ring::aead::{Aad, LessSafeKey, Nonce, Tag, UnboundKey};

pub mod algo;

/// Seals a plaintext. `in_out` will be the ciphertext without the tag.
/// Refer to [`ring::aead::SealingKey::seal_in_place_separate_tag()`]
pub fn seal(
    algo: SupportedAlgorithm,
    key: &[u8],
    nonce: &[u8],
    mut in_out: &mut [u8],
) -> Result<Tag, ring::error::Unspecified> {
    let key = UnboundKey::new(algo.ring_algo(), &key[..])?;
    let key = LessSafeKey::new(key);

    let nonce = Nonce::try_assume_unique_for_key(&nonce)?;

    let tag = key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)?;

    Ok(tag)
}

/// Opens a sealed message. `in_out` must be the ciphertext followed by the tag.
/// Refer to [`ring::aead::OpeningKey::open_in_place()`]
pub fn open(
    algo: SupportedAlgorithm,
    key: &[u8],
    nonce: &[u8],
    mut in_out: &mut [u8],
) -> Result<(), ring::error::Unspecified> {
    let key = UnboundKey::new(algo.ring_algo(), &key[..])?;
    let key = LessSafeKey::new(key);

    let nonce = Nonce::try_assume_unique_for_key(&nonce)?;

    key.open_in_place(nonce, Aad::empty(), &mut in_out)?;

    Ok(())
}
