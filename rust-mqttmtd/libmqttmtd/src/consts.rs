//! Predefines a few constants.

pub const TIMESTAMP_LEN: usize = 6;
pub const RANDOM_LEN: usize = 6;
pub const TOKEN_LEN: usize = TIMESTAMP_LEN + RANDOM_LEN;

pub const MAGIC_NUM: u32 = 0x4D51ED00;
pub const MAGIC_NUM_MASK: u32 = 0xFFFFFF00;

pub const PACKET_TYPE_ISSUER_REQUEST: u8 = 0b0000;
pub const PACKET_TYPE_ISSUER_RESPONSE: u8 = 0b0001;
pub const PACKET_TYPE_VERIFIER_REQUEST: u8 = 0b0100;
pub const PACKET_TYPE_VERIFIER_RESPONSE: u8 = 0b0101;
