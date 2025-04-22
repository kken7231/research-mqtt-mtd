//! Issuer interface of auth server.

use std::{error::Error, io};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::aead::NonceSequence;

use crate::error::IssuerParserError;

/// # Request for Issuer interface
/// ## v1
/// ```text
/// [0]:
/// 	bit 7: is_pub
/// 	bit 6: payload_aead_requested
// 	bit 5-0: num_tokens_divided_by_multiplier
/// [1:3]: len_topic, big endian
/// [3:3+len_topic]: topic
/// ```
///
/// ## v2
/// ```text
/// [0]:
/// 	bit 7: is_pub
/// 	bit 6-0: num_tokens
/// [1:3]: len_topic, big endian
/// [3:3+len_topic]: topic
/// ```
pub struct Request {}

impl std::fmt::Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        
    }
}

impl Request {
    pub fn get_is_pub(bytes: &[u8]) -> Result<bool, IssuerParserError> {
        match bytes.get(0) {
            Some(v) => Ok(v & 0x80 != 0),
            None => Err(IssuerParserError::BufferTooSmallError()),
        }
    }

    pub fn get_num_tokens(bytes: &[u8]) -> Result<u8, IssuerParserError> {
        match bytes.get(0) {
            Some(v) => Ok(v & 0x7F),
            None => Err(IssuerParserError::BufferTooSmallError()),
        }
    }

    pub fn get_topic(bytes: &[u8]) -> Result<&str, IssuerParserError> {
        if bytes.len() < 3 {
            return Err(IssuerParserError::BufferTooSmallError());
        }
        let topic_len:usize = u16::from_be_bytes( [bytes[1], bytes[2]]).into();
        if bytes.len() < 3 + topic_len {
            return Err(IssuerParserError::BufferTooSmallError());
        }
        
        match std::str::from_utf8(&bytes[3..3+topic_len]) {
            Err(_e) => Err(IssuerParserError::UTF8ConversionError()),
            Ok(s) => Ok(s),
        }
    }

    pub fn put_encoded_to_buf(is_pub: bool, num_tokens: u8, topic: &str, buf: &mut [u8]) -> Result<usize, IssuerParserError> {
        if buf.len() < 3+topic.len() {
            return Err(IssuerParserError::BufferTooSmallError());
        }
        let mut cursor: usize = 0;
        let mut first_byte = num_tokens;
        if is_pub {
            first_byte |= 0x80;
        }
        buf[cursor] = first_byte;
        cursor += 1;
        

        if topic.len() > 0xFFFF {
            return Err(IssuerParserError::ParameterTooBigError());
        }
        let topic_len_bytes = topic.len().to_be_bytes();
        buf[cursor..cursor + 2].copy_from_slice(&topic_len_bytes);
        cursor += 2;
    
        buf[cursor..cursor + topic.len()].copy_from_slice(topic.as_bytes());
        cursor += topic.len();
        
        Ok(cursor)
    }
}


/// # Response from Issuer interface
/// ## v1
/// ```text
/// | enc_key(optional) | timestamp | all_random_bytes |
/// ```
///
/// ## v2
/// ```text
/// | enc_key | timestamp | all_random_bytes |
/// ```
pub struct Response<N: NonceSequence> {
    enc_key: ring::aead::SealingKey<N>,
    timestamp: u64,
    all_random_bytes: Bytes,
}

impl<N: NonceSequence> Response<N> {
    pub fn new(&ring::) {
        
    }

    pub fn encode_len(&self) -> usize {
        3 + self.topic.len()
    }

    pub fn put_encoded_to_buf(self, mut buf: BytesMut) -> Result<usize, Box<dyn Error>> {
        if !buf.try_reclaim(3 + self.topic.len()) {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "").into());
        }
        let mut first_byte = self.num_tokens;
        if self.is_pub {
            first_byte |= 0x80;
        }
        buf.put_u8(first_byte);
        buf.put_u16(self.topic.len().try_into()?);
        buf.put(self.topic.as_bytes());

        Ok(3 + self.topic.len())
    }
}
