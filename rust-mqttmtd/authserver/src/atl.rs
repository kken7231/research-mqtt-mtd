//! Defines Access Token List (ATL).

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use libmqttmtd::{
    aead::algo::{SupportedAlgorithm, get_ring_algorithm},
    consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN},
};
use ring::{
    aead::NONCE_LEN,
    rand::{SecureRandom, SystemRandom},
};
use tokio::sync::RwLock;

use crate::error::ATLError;

#[derive(Debug)]
pub struct TokenSet {
    masked_timestamp: u64,
    expiration_timestamp: u64,

    all_randoms: Box<[u8]>,
    num_tokens: usize,
    token_idx: usize,
    topic: String,
    is_pub: bool,
    valid_dur: Duration,

    algo: SupportedAlgorithm,
    enc_key: Box<[u8]>,
    nonce_base: u128,
}

impl TokenSet {
    /// # Parameters:
    /// - `valid_dur`: must be less than one year, otherwise error thrown
    pub fn create_without_rand_init(
        num_tokens: usize,
        topic: String,
        is_pub: bool,
        valid_dur: Duration,
        algo: SupportedAlgorithm,
        nonce_base: u128,
    ) -> Result<Self, ATLError> {
        if valid_dur >= Duration::from_secs(60 * 60 * 24 * 365) {
            return Err(ATLError::ValidDurationTooLongError(valid_dur));
        }

        Ok(Self {
            masked_timestamp: 0,
            expiration_timestamp: 0,
            all_randoms: Box::new([0u8; 0]),
            num_tokens,
            token_idx: 0usize,
            topic,
            is_pub,
            valid_dur,
            algo,
            enc_key: Box::new([0u8; 0]),
            nonce_base,
        })
    }

    pub fn get_enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn get_topic(&self) -> String {
        self.topic.clone()
    }

    pub fn get_is_pub(&self) -> bool {
        self.is_pub
    }

    pub fn get_all_randoms(&self) -> &[u8] {
        &self.all_randoms
    }

    pub fn get_current_random(&self) -> Result<&[u8], ATLError> {
        if (self.token_idx + 1) * RANDOM_LEN < self.all_randoms.len() {
            Ok(&self.all_randoms[self.token_idx * RANDOM_LEN..(self.token_idx + 1) * RANDOM_LEN])
        } else {
            Err(ATLError::TokenIdxOutOfBoundError(self.token_idx))
        }
    }

    pub fn get_nonce(&self) -> [u8; NONCE_LEN] {
        let nonce = self.nonce_base + self.token_idx as u128;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce
            .to_be_bytes()
            .iter()
            .skip(128 / 8 - NONCE_LEN)
            .enumerate()
            .for_each(|(i, b)| nonce_bytes[i] = *b);
        nonce_bytes
    }

    pub fn get_aead_algo(&self) -> &SupportedAlgorithm {
        &self.algo
    }
}

type FullTimestamp = u64;
type MaskedTimestamp = u64;
#[derive(Debug)]
pub struct AccessTokenList {
    /// Arc for shared ownership across threads.
    /// RwLock for concurrent readers or exclusive writer access.
    /// Key: expiration datetime
    inner_sorted: Arc<RwLock<BTreeMap<FullTimestamp, Arc<RwLock<TokenSet>>>>>,

    /// Hashmap for faster lookup on token verification
    /// Key: masked timestamp
    /// Value: key of inner_sorted (expiration datetime)
    inner_lookup: Arc<RwLock<HashMap<MaskedTimestamp, Arc<RwLock<TokenSet>>>>>,

    /// Random Generator
    rng: SystemRandom,
}

impl AccessTokenList {
    pub fn new() -> Self {
        Self {
            inner_sorted: Arc::new(RwLock::new(BTreeMap::new())),
            inner_lookup: Arc::new(RwLock::new(HashMap::new())),
            rng: SystemRandom::new(),
        }
    }

    /// Helper function to get the current timestamp as u64 nanoseconds since epoch.
    fn get_current_timestamp() -> Result<u64, ATLError> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos()
            .try_into()?)
    }

    /// Helper function to get the masked timestamp (bytes [2:8] as u64) from a full u64 timestamp.
    /// Assumes Big Endian byte order for slicing.
    fn get_masked_timestamp(full_timestamp: FullTimestamp) -> MaskedTimestamp {
        // Mask to keep only bits corresponding to bytes 2 through 7
        full_timestamp & 0x0000FFFFFFFFFF00u64
    }

    /// Helper function to assemble a masked u64 from a [u8; 6] timestamp part.
    /// Assumes Big Endian byte order for placement.
    pub fn assemble_masked_u64_from_part(part: &[u8; 6]) -> MaskedTimestamp {
        let mut bytes = [0u8; 8];
        // Place the 6 bytes into bytes 2-7 positions (indices 2 to 7)
        // Assumes Big Endian interpretation for this layout
        bytes[2..8].copy_from_slice(part);
        u64::from_be_bytes(bytes)
    }

    /// Helper function to sparse a masked u64 to a [u8; 6] timestamp part.
    /// Assumes Big Endian byte order for placement.
    pub fn sparse_masked_u64_to_part(masked_timestamp: MaskedTimestamp) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        // Place the 6 bytes into bytes 2-7 positions (indices 2 to 7)
        // Assumes Big Endian interpretation for this layout
        bytes[..].copy_from_slice(&masked_timestamp.to_be_bytes()[2..8]);
        bytes
    }

    /// Issues a new timestamp (nanoseconds since epoch) and files the token set
    /// to the map.
    /// Acquires a write lock. O(log n) for `sorted_map` + O(1) for `lookup_map`
    pub fn file(&self, mut token_set: TokenSet) -> Result<(Arc<RwLock<TokenSet>>, u64), ATLError> {
        // Fill all_randoms
        let mut all_randoms = Vec::<u8>::with_capacity(token_set.num_tokens * RANDOM_LEN);
        unsafe {
            all_randoms.set_len(token_set.num_tokens * RANDOM_LEN);
        }
        self.rng.fill(&mut all_randoms)?;
        token_set.all_randoms = all_randoms.into_boxed_slice();

        // Fill enc_key
        let mut enc_key = Vec::<u8>::with_capacity(get_ring_algorithm(&token_set.algo).key_len());
        self.rng.fill(&mut enc_key)?;
        token_set.enc_key = enc_key.into_boxed_slice();

        self.file_without_rand_init(token_set)
    }

    /// Files the token set to the map.
    /// Acquires a write lock. O(log n) for `sorted_map` + O(1) for `lookup_map`
    pub fn file_without_rand_init(
        &self,
        mut token_set: TokenSet,
    ) -> Result<(Arc<RwLock<TokenSet>>, u64), ATLError> {
        // Acquire a write lock first
        let mut sorted_map = self.inner_sorted.try_write()?;
        let mut lookup_map = self.inner_lookup.try_write()?;

        // Get the current timestamp after write lock acquired
        let full_timestamp = Self::get_current_timestamp()?;
        let masked_timestamp = Self::get_masked_timestamp(full_timestamp.clone());
        let expiration_timestamp =
            match full_timestamp.checked_add(token_set.valid_dur.as_nanos().try_into()?) {
                None => return Err(ATLError::ValidDurationTooLongError(token_set.valid_dur)),
                Some(ts) => ts,
            };

        token_set.masked_timestamp = masked_timestamp;
        token_set.expiration_timestamp = expiration_timestamp;

        // Add the new entry. Because we issue timestamps sequentially,
        // and SystemTime is generally monotonic (or increases),
        // pushing to the end maintains the sorted order by timestamp.
        let arced = Arc::new(RwLock::new(token_set));
        sorted_map.insert(expiration_timestamp, arced.clone());
        lookup_map.insert(masked_timestamp, arced.clone());

        Ok((arced, full_timestamp))
    }

    /// Removes expired tokens from the beginning up to a given full timestamp.
    /// Acquires a write lock. O(log n) to find cutoff + O(k) for draining, where
    /// k is a number of removed entries.
    /// Returns a number of removed token sets.
    pub fn remove_expired(&self) -> Result<usize, ATLError> {
        // Get the current timestamp before write lock acquired
        let current_timestamp = Self::get_current_timestamp()?;

        // Acquire a write lock
        let mut sorted_map = self.inner_sorted.try_write()?;
        let mut lookup_map = self.inner_lookup.try_write()?;

        // Split with the boundary (O(log n))
        let new_sorted_map = sorted_map.split_off(&current_timestamp);

        // Remove items from lookup_map
        // lookup_map: O(k)
        let count = sorted_map.len();
        for removed in sorted_map.iter() {
            // Acquire a read lock
            let token_set = removed.1.try_read()?;

            if let None = lookup_map.remove(&token_set.masked_timestamp) {
                return Err(ATLError::TwoMapsNotConsistentError());
            };
        }

        // Finally swap
        *sorted_map = new_sorted_map;

        Ok(count)
    }

    /// Revokes (drops) a specific token by its masked timestamp.
    /// Acquires a write lock. O(log n) complexity.
    pub fn revoke_token(&self, masked_timestamp: MaskedTimestamp) -> Result<bool, ATLError> {
        // Acquire a read lock
        let lookup_map = self.inner_lookup.try_write()?;

        // Look up in lookup_map (O(1))
        let token_set = match lookup_map.get(&masked_timestamp) {
            None => return Ok(false),
            Some(ts) => ts,
        };

        // Acquire a read lock and get expiration timestamp
        let expiration_timestamp = &token_set.try_read()?.expiration_timestamp;

        // Acquire a write lock
        let mut lookup_map = self.inner_lookup.try_write()?;
        let mut sorted_map = self.inner_sorted.try_write()?;

        // Remove entry from sorted_map (O(log n))
        if let None = sorted_map.remove(expiration_timestamp) {
            return Err(ATLError::TwoMapsNotConsistentError());
        }

        // Remove entry from lookup_map (O(1))
        lookup_map.remove(&masked_timestamp);

        Ok(true)
    }

    /// Looks up a specific token and verify it.
    /// Acquires a write lock. O(log n) complexity.
    pub fn verify(
        &self,
        token: &[u8; TOKEN_LEN],
    ) -> Result<Option<Arc<RwLock<TokenSet>>>, ATLError> {
        // Prepare masked timestamp and random bytes
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        let mut random = [0u8; RANDOM_LEN];
        timestamp.copy_from_slice(&token[..TIMESTAMP_LEN]);
        random.copy_from_slice(&token[TIMESTAMP_LEN..TOKEN_LEN]);
        let masked_timestamp = Self::assemble_masked_u64_from_part(&timestamp);

        // Acquire a write lock
        let lookup_map = self.inner_lookup.try_write()?;

        // Look up timestamp in lookup_map (O(1))
        let token_set_arc = match lookup_map.get(&masked_timestamp) {
            None => return Ok(None),
            Some(ts) => ts,
        };

        let mut token_set = token_set_arc.try_write()?;

        // Verify random
        let cur_random = token_set.get_current_random()?;
        if cur_random.eq(&random) {
            if token_set.token_idx >= token_set.num_tokens - 1 {
                if self.revoke_token(masked_timestamp).is_err() {
                    panic!("failed revoking token");
                }
            }
            token_set.token_idx += 1;
            Ok(Some(token_set_arc.clone()))
        } else {
            Ok(None)
        }
    }
}
