//! Predefines a few constants.

pub const TIMESTAMP_LEN: usize = 6;
pub const RANDOM_LEN: usize = 6;
pub const TOKEN_LEN: usize = TIMESTAMP_LEN + RANDOM_LEN;

pub const MQTT_MTD_V2_PACKET_MAGIC_NUMBER: u32 = 0x4D51ED02;
