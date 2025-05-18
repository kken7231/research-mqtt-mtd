//! Defines Access Token List (ATL).

use crate::error::ATLError;
use bytes::{Bytes, BytesMut};
use libmqttmtd::auth_serv::{issuer, verifier};
use libmqttmtd::{
    aead::algo::SupportedAlgorithm,
    consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN},
    utils,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// # Set of tokens
/// Owns various parameters for a set of token. To be added in [AccessTokenList] after wrapped with [tokio::sync::Mutex] and [std::sync::Arc].
#[derive(Debug)]
pub(crate) struct TokenSet {
    masked_timestamp: u64,
    expiration_timestamp: u64,

    all_randoms: Bytes,
    num_tokens: u16,
    token_idx: u16,
    topic: String,
    is_pub: bool,
    valid_dur: Duration,

    algo: SupportedAlgorithm,
    enc_key: Bytes,
    nonce_base: u128,
}

impl TokenSet {
    /// Initializes a new [TokenSet]. Random values such as `enc_key` and `nonce_base` are not initialized here.
    /// Initialization of those values is what [AccessTokenList] is responsible for.
    /// # Parameters:
    /// - `valid_dur`: must be less than one year, otherwise error thrown
    pub(crate) fn new(
        num_tokens_divided_by_4: u8,
        topic: String,
        is_pub: bool,
        valid_dur: Duration,
        algo: SupportedAlgorithm,
    ) -> Result<Self, ATLError> {
        if valid_dur >= Duration::from_secs(60 * 60 * 24 * 365) {
            return Err(ATLError::ValidDurationTooLongError(valid_dur));
        }
        if num_tokens_divided_by_4 == 0 || num_tokens_divided_by_4 > 0x7F {
            return Err(ATLError::InvalidNumTokensDiv4Error(num_tokens_divided_by_4));
        }
        if topic.len() == 0 {
            return Err(ATLError::EmptyTopicError);
        }

        Ok(Self {
            masked_timestamp: 0,
            expiration_timestamp: 0,
            all_randoms: Bytes::new(),
            num_tokens: (num_tokens_divided_by_4 as u16).rotate_left(2),
            token_idx: 0u16,
            topic,
            is_pub,
            valid_dur,
            algo,
            enc_key: Bytes::new(),
            nonce_base: 0u128,
        })
    }

    pub(crate) fn current_random(&self) -> Result<&[u8], ATLError> {
        let token_idx_usize = self.token_idx as usize;
        if (token_idx_usize + 1) * RANDOM_LEN <= self.all_randoms.len() {
            Ok(&self.all_randoms[token_idx_usize * RANDOM_LEN..(token_idx_usize + 1) * RANDOM_LEN])
        } else {
            Err(ATLError::TokenIdxOutOfBoundError(self.token_idx))
        }
    }

    pub(crate) fn current_token(&self) -> Result<[u8; TOKEN_LEN], ATLError> {
        let timestamp = AccessTokenList::sparse_masked_u64_to_part(self.masked_timestamp);
        let random = self.current_random()?;
        let mut token = [0u8; TOKEN_LEN];
        token[..TIMESTAMP_LEN].copy_from_slice(&timestamp);
        token[TIMESTAMP_LEN..].copy_from_slice(random);

        Ok(token)
    }

    pub(crate) fn current_nonce(&self) -> Bytes {
        let nonce = self.nonce_base + self.token_idx as u128;
        utils::nonce_from_u128_to_bytes(self.algo, nonce)
    }
}

type FullTimestamp = u64;
type MaskedTimestamp = u64;

/// !important: Locking order is 1) inner_sorted and 2) inner_lookup.
#[derive(Debug)]
pub(crate) struct AccessTokenList {
    /// Arc for shared ownership across threads.
    /// Mutex for concurrent readers or exclusive writer access.
    /// Key: expiration datetime
    inner_sorted: Arc<Mutex<BTreeMap<FullTimestamp, Arc<Mutex<TokenSet>>>>>,

    /// Hashmap for faster lookup on token verification
    /// Key: masked timestamp
    /// Value: key of inner_sorted (expiration datetime)
    inner_lookup: Arc<Mutex<HashMap<MaskedTimestamp, Arc<Mutex<TokenSet>>>>>,

    /// Random Generator
    rng: SystemRandom,
}

impl AccessTokenList {
    pub(crate) fn new() -> Self {
        Self {
            inner_sorted: Arc::new(Mutex::new(BTreeMap::new())),
            inner_lookup: Arc::new(Mutex::new(HashMap::new())),
            rng: SystemRandom::new(),
        }
    }

    /// Helper function to get the current timestamp as u64 nanoseconds since
    /// epoch.
    fn get_current_timestamp() -> Result<u64, ATLError> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ATLError::NegativeTimeDifferenceError(e))?
            .as_nanos() as u64)
    }

    /// Helper function to get the masked timestamp (bytes [1:7] as u64) from a
    /// full u64 timestamp. Assumes Big Endian byte order for slicing.
    fn get_masked_timestamp(full_timestamp: FullTimestamp) -> MaskedTimestamp {
        full_timestamp & 0x00_FF_FF_FF_FF_FF_FF_00u64
    }

    /// Helper function to assemble a masked u64 from a [u8; 6] timestamp part.
    /// Assumes Big Endian byte order for placement.
    fn assemble_masked_u64_from_part(part: &[u8; 6]) -> MaskedTimestamp {
        let mut bytes = [0u8; 8];
        bytes[1..7].copy_from_slice(part);
        u64::from_be_bytes(bytes)
    }

    /// Helper function to sparse a masked u64 to a [u8; 6] timestamp part.
    /// Assumes Big Endian byte order for placement.
    fn sparse_masked_u64_to_part(masked_timestamp: MaskedTimestamp) -> [u8; 6] {
        let mut bytes = [0u8; 6];
        bytes[..].copy_from_slice(&masked_timestamp.to_be_bytes()[1..7]);
        bytes
    }

    /// Issues a new timestamp (nanoseconds since epoch) and files the token set
    /// to the map.
    /// Acquires a lock. O(log n) for `sorted_map` + O(1) for `lookup_map`
    pub async fn file(
        &self,
        mut token_set: TokenSet,
    ) -> Result<(issuer::ResponseWriter, u64), ATLError> {
        // Fill all_randoms
        let mut all_randoms = BytesMut::zeroed(token_set.num_tokens as usize * RANDOM_LEN);
        let mut generated_tokens: HashSet<[u8; RANDOM_LEN]> = HashSet::new();
        let mut cur_idx = 0usize;
        // To ensure uniqueness of all_randoms, we use hashset
        while generated_tokens.len() < token_set.num_tokens as usize {
            let mut current_token_bytes = [0u8; RANDOM_LEN];
            self.rng
                .fill(&mut current_token_bytes)
                .map_err(|e| ATLError::RandGenError(e))?;
            if generated_tokens.insert(current_token_bytes.clone()) {
                all_randoms[cur_idx..(cur_idx + RANDOM_LEN)].copy_from_slice(&current_token_bytes);
                cur_idx += RANDOM_LEN;
            }
        }
        token_set.all_randoms = all_randoms.freeze();

        // Fill enc_key
        let mut enc_key = BytesMut::zeroed(token_set.algo.key_len());
        self.rng
            .fill(&mut enc_key)
            .map_err(|e| ATLError::RandGenError(e))?;
        token_set.enc_key = enc_key.freeze();

        // Fill nonce_base
        let mut nonce_base = [0u8; 16];
        self.rng
            .fill(&mut nonce_base[16 - token_set.algo.nonce_len()..])
            .map_err(|e| ATLError::RandGenError(e))?;
        token_set.nonce_base = u128::from_be_bytes(nonce_base);

        self.file_without_rand_init(token_set).await
    }

    /// Files the token set to the map.
    /// O(log n) for `sorted_map` + O(1) for `lookup_map`
    ///
    /// # Locks
    /// - `inner_sorted`
    /// - `inner_lookup`
    pub async fn file_without_rand_init(
        &self,
        mut token_set: TokenSet,
    ) -> Result<(issuer::ResponseWriter, u64), ATLError> {
        // Acquire a lock first
        let mut sorted_map = self.inner_sorted.lock().await;
        let mut lookup_map = self.inner_lookup.lock().await;

        // Get the current timestamp after lock acquired
        let full_timestamp = Self::get_current_timestamp()?;
        let masked_timestamp = Self::get_masked_timestamp(full_timestamp.clone());
        let expiration_timestamp =
            match full_timestamp.checked_add(token_set.valid_dur.as_nanos() as u64) {
                None => return Err(ATLError::ValidDurationTooLongError(token_set.valid_dur)),
                Some(ts) => ts,
            };

        token_set.masked_timestamp = masked_timestamp;
        token_set.expiration_timestamp = expiration_timestamp;

        // Copy to issuer::ResponseWriter
        let resp = issuer::ResponseWriter::new(
            token_set.enc_key.clone(),
            utils::nonce_from_u128_to_bytes(token_set.algo, token_set.nonce_base),
            Self::sparse_masked_u64_to_part(token_set.masked_timestamp),
            token_set.all_randoms.clone(),
        );

        // Add the new entry. Because we issue timestamps sequentially,
        // and SystemTime is generally monotonic (or increases),
        // pushing to the end maintains the sorted order by timestamp.
        let arced = Arc::new(Mutex::new(token_set));
        sorted_map.insert(expiration_timestamp, arced.clone());
        lookup_map.insert(masked_timestamp, arced.clone());

        Ok((resp, full_timestamp))
    }

    /// Removes expired tokens from the beginning up to a given full timestamp.
    /// O(log n) to find cutoff + O(k) for draining, where
    /// k is a number of removed entries.
    /// Returns a number of removed token sets.
    ///
    /// # Locks
    /// - `inner_sorted`
    /// - `inner_lookup`
    /// - TokenSets that are to be removed
    pub async fn remove_expired(&self) -> Result<usize, ATLError> {
        // Get the current timestamp before lock acquired
        let current_timestamp = Self::get_current_timestamp()?;

        // Acquire a lock
        let mut sorted_map = self.inner_sorted.lock().await;

        let new_sorted_map: BTreeMap<u64, Arc<Mutex<TokenSet>>>;
        let count: usize;
        {
            let mut lookup_map = self.inner_lookup.lock().await;

            // Split with the boundary (O(log n))
            new_sorted_map = sorted_map.split_off(&current_timestamp);

            // Remove items from lookup_map
            // lookup_map: O(k)
            count = sorted_map.len();
            for removed in sorted_map.iter() {
                let token_set = removed.1.lock().await;

                if let None = lookup_map.remove(&token_set.masked_timestamp) {
                    return Err(ATLError::TwoMapsNotConsistentError());
                };
            }
        } // self.inner_lookup lock

        // Finally swap
        *sorted_map = new_sorted_map;

        Ok(count)
    }

    /// Revokes (drops) a specific token by its masked timestamp.
    /// O(log n) complexity.
    ///
    /// # Locks
    /// - `inner_sorted`
    /// - `inner_lookup`
    /// - TokenSet that found
    pub async fn revoke_token(&self, masked_timestamp: MaskedTimestamp) -> Result<bool, ATLError> {
        // Acquire a lock
        let mut sorted_map = self.inner_sorted.lock().await;
        let mut lookup_map = self.inner_lookup.lock().await;

        // Look up in lookup_map (O(1))
        let token_set = match lookup_map.get(&masked_timestamp) {
            None => return Ok(false),
            Some(ts) => ts,
        };

        // Remove an entry from lookup_map with expiration timestamp
        {
            let expiration_timestamp = token_set.lock().await.expiration_timestamp;

            // Remove entry from sorted_map (O(log n))
            if let None = sorted_map.remove(&expiration_timestamp) {
                return Err(ATLError::TwoMapsNotConsistentError());
            }
        } // token_set lock

        // Remove an entry from lookup_map (O(1))
        lookup_map.remove(&masked_timestamp);

        Ok(true)
    }

    /// Looks up a specific token and verify it.
    /// O(log n) complexity.
    /// Increments `token_idx`.
    ///
    /// # Locks
    /// - `inner_lookup`
    /// - TokenSet that found
    pub async fn verify(
        &self,
        token: &[u8; TOKEN_LEN],
    ) -> Result<Option<verifier::ResponseWriter>, ATLError> {
        // Prepare masked timestamp and random bytes
        let mut timestamp = [0u8; TIMESTAMP_LEN];
        let mut random = [0u8; RANDOM_LEN];
        timestamp.copy_from_slice(&token[..TIMESTAMP_LEN]);
        random.copy_from_slice(&token[TIMESTAMP_LEN..TOKEN_LEN]);
        let masked_timestamp = Self::assemble_masked_u64_from_part(&timestamp);

        // Acquire a lock
        let revocation_needed;
        let res: Result<Option<verifier::ResponseWriter>, ATLError>;
        {
            let lookup_map = self.inner_lookup.lock().await;
            // Look up timestamp in lookup_map (O(1))
            let token_set_arc = match lookup_map.get(&masked_timestamp) {
                None => return Ok(None),
                Some(ts) => ts,
            };
            let mut token_set = token_set_arc.lock().await;

            // Verification
            let current_timestamp: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ATLError::NegativeTimeDifferenceError(e))?
                .as_nanos() as u64;
            let is_expired = current_timestamp >= token_set.expiration_timestamp;
            let is_idx_out_of_bounds = token_set.token_idx >= token_set.num_tokens;

            if !is_expired && !is_idx_out_of_bounds && token_set.current_random()?.eq(&random) {
                // Verification success
                // Construct a new ResponseWriter
                let resp = verifier::ResponseWriter::new(
                    token_set.is_pub,
                    token_set.algo,
                    token_set.current_nonce().clone(),
                    Bytes::from(token_set.topic.clone()),
                    token_set.enc_key.to_owned(),
                );

                // Increment and revocation check
                token_set.token_idx += 1;
                revocation_needed = token_set.token_idx >= token_set.num_tokens;

                res = Ok(Some(resp));
            } else {
                // Verification failed
                revocation_needed = is_expired || is_idx_out_of_bounds;

                res = Ok(None);
            };
        } // self.inner_lookup lock & token_set_arc lock

        if revocation_needed {
            if let Err(e) = self.revoke_token(masked_timestamp).await {
                panic!("failed revoking {}: {}", masked_timestamp, e)
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        atl::{AccessTokenList, TokenSet},
        error::ATLError,
    };
    use bytes::Bytes;
    use libmqttmtd::{
        aead::algo::SupportedAlgorithm,
        consts::{RANDOM_LEN, TIMESTAMP_LEN, TOKEN_LEN},
    };
    use std::time::Duration;

    // Helper to create a basic ATL instance
    fn create_atl() -> AccessTokenList {
        AccessTokenList::new()
    }

    // Helper to create a basic TokenSet for testing
    fn create_test_token_set(num_tokens_divided_by_4: u8, valid_dur: Duration) -> TokenSet {
        TokenSet::new(
            num_tokens_divided_by_4,
            "test/topic".to_string(),
            true, // is_pub
            valid_dur,
            SupportedAlgorithm::Aes128Gcm,
        )
        .expect("Failed to create test TokenSet")
    }

    #[tokio::test]
    async fn token_set_create_without_rand_init_valid_duration() {
        let valid_dur = Duration::from_secs(364 * 24 * 3600); // Less than a year
        let token_set = TokenSet::new(
            10,
            "topic".to_string(),
            true,
            valid_dur,
            SupportedAlgorithm::Aes128Gcm,
        );
        assert!(token_set.is_ok());
        assert_eq!(token_set.unwrap().valid_dur, valid_dur);
    }

    #[tokio::test]
    async fn token_set_create_without_rand_init_invalid_duration() {
        let invalid_dur = Duration::from_secs(366 * 24 * 3600); // More than a year
        let token_set = TokenSet::new(
            10,
            "topic".to_string(),
            true,
            invalid_dur,
            SupportedAlgorithm::Aes128Gcm,
        );
        assert!(token_set.is_err());
        match token_set.unwrap_err() {
            ATLError::ValidDurationTooLongError(d) if d == invalid_dur => {}
            _ => panic!(),
        };
    }

    #[tokio::test]
    async fn atl_file_and_verify_multiple_tokens() {
        let atl = create_atl();
        let token_set = create_test_token_set(1, Duration::from_secs(60));

        // File the token set (generates randoms and key)
        let (_, full_timestamp) = atl.file(token_set).await.expect("Failed to file token set");

        // Look up the token_set
        let masked_timestamp = AccessTokenList::get_masked_timestamp(full_timestamp);
        let timestamp = AccessTokenList::sparse_masked_u64_to_part(masked_timestamp);
        let all_randoms: Bytes;
        {
            let lookup_map = atl.inner_lookup.lock().await;
            let token_set = lookup_map
                .get(&masked_timestamp)
                .expect("Failed to get token set")
                .lock()
                .await;
            all_randoms = token_set.all_randoms.clone();
        }

        for i in 0..4usize {
            // Manually construct a token using the filed data
            let mut token = [0u8; TOKEN_LEN];
            token[..TIMESTAMP_LEN].copy_from_slice(&timestamp[..]);
            token[TIMESTAMP_LEN..]
                .copy_from_slice(&all_randoms[(RANDOM_LEN * i)..(RANDOM_LEN * (i + 1))]);

            // Verify resp and the token_set
            let resp = atl.verify(&token).await.expect("Verification failed");
            assert!(resp.is_some(), "failed to verify at {}", i);
            if i < 3 {
                let lookup_map = atl.inner_lookup.lock().await;
                let token_set = lookup_map
                    .get(&masked_timestamp)
                    .expect("Failed to get token set")
                    .lock()
                    .await;
                assert_eq!(
                    token_set.token_idx,
                    i as u16 + 1,
                    "token_idx should be incremented"
                );
            }
        }

        // The token set should be revoked after the last token is used
        assert!(
            atl.inner_lookup
                .lock()
                .await
                .get(&masked_timestamp)
                .is_none(),
            "TokenSet should be revoked"
        );
    }

    #[tokio::test]
    async fn atl_verify_invalid_random() {
        let atl = create_atl();
        let token_set = create_test_token_set(1, Duration::from_secs(60));

        let (_, full_timestamp) = atl.file(token_set).await.expect("Failed to file token set");

        let masked_timestamp = AccessTokenList::get_masked_timestamp(full_timestamp);
        let timestamp = AccessTokenList::sparse_masked_u64_to_part(masked_timestamp);
        let mut token = [0u8; TOKEN_LEN];
        token[..TIMESTAMP_LEN].copy_from_slice(&timestamp);
        // Use invalid random bytes
        token[TIMESTAMP_LEN..].copy_from_slice(&[0xFF; RANDOM_LEN]);

        let resp = atl.verify(&token).await.expect("Verification failed");

        assert!(
            resp.is_none(),
            "Verification should fail for invalid random"
        );

        // The token set should NOT be revoked
        assert!(
            atl.inner_lookup
                .lock()
                .await
                .get(&masked_timestamp)
                .is_some(),
            "TokenSet should not be revoked after failed verification"
        );
    }

    #[tokio::test]
    async fn atl_verify_non_existent_masked_timestamp() {
        let atl = create_atl();
        let mut token = [0u8; TOKEN_LEN];
        // Use a masked timestamp that doesn't exist in the ATL
        token[..TIMESTAMP_LEN].copy_from_slice(&[0xAA; TIMESTAMP_LEN]);
        token[TIMESTAMP_LEN..].copy_from_slice(&[0xBB; RANDOM_LEN]);

        let verified_token_set_arc = atl.verify(&token).await.expect("Verification failed");

        assert!(
            verified_token_set_arc.is_none(),
            "Verification should fail for non-existent timestamp"
        );
    }

    #[tokio::test]
    async fn atl_verify_expired() {
        let atl = create_atl();
        let short_duration = Duration::from_millis(10); // Will expire quickly
        let long_duration = Duration::from_secs(1000); // Will not expire quickly

        // File tokens with different expiration times
        let ts1 = create_test_token_set(1, short_duration);
        let (_, full_timestamp1) = atl.file(ts1).await.expect("File ts1 failed");
        let masked_timestamp1 = AccessTokenList::get_masked_timestamp(full_timestamp1);

        tokio::time::sleep(Duration::from_millis(20)).await; // Wait for ts1 to expire

        let ts2 = create_test_token_set(1, long_duration);
        let (_, full_timestamp2) = atl.file(ts2).await.expect("File ts2 failed");
        let masked_timestamp2 = AccessTokenList::get_masked_timestamp(full_timestamp2);

        let ts3 = create_test_token_set(1, short_duration);
        let (_, full_timestamp3) = atl.file(ts3).await.expect("File ts3 failed");
        let masked_timestamp3 = AccessTokenList::get_masked_timestamp(full_timestamp3);

        tokio::time::sleep(Duration::from_millis(20)).await; // Wait for ts3 to expire

        // Check initial state (all should be present)
        let token1: [u8; TOKEN_LEN];
        {
            let lookup_map = atl.inner_lookup.lock().await;
            assert!(lookup_map.get(&masked_timestamp1).is_some());
            assert!(lookup_map.get(&masked_timestamp2).is_some());
            assert!(lookup_map.get(&masked_timestamp3).is_some());
        }

        // Depending on exact timing and system clock, it could potentially be 3 if ts2
        // also expired, but with 1000s duration it's highly unlikely in a test.
        // ts1 check - fail
        {
            let lookup_map = atl.inner_lookup.lock().await;

            let token_set1 = lookup_map
                .get(&masked_timestamp1)
                .expect("Failed to get token set")
                .lock()
                .await;
            token1 = token_set1
                .current_token()
                .expect("failed constructing the current token");
        }
        let resp = atl.verify(&token1).await.expect("Verification failed");
        assert!(
            resp.is_none(),
            "Verification should fail for an expired token"
        );

        // ts2 check - success
        let token2: [u8; TOKEN_LEN];
        {
            let lookup_map = atl.inner_lookup.lock().await;

            let token_set2 = lookup_map
                .get(&masked_timestamp2)
                .expect("Failed to get token set")
                .lock()
                .await;
            token2 = token_set2
                .current_token()
                .expect("failed constructing the current token");
        }
        let resp = atl.verify(&token2).await.expect("Verification failed");
        assert!(resp.is_some(), "Verification should pass for a valid token");

        // ts3 check - fail
        let token3: [u8; TOKEN_LEN];
        {
            let lookup_map = atl.inner_lookup.lock().await;

            let token_set3 = lookup_map
                .get(&masked_timestamp3)
                .expect("Failed to get token set")
                .lock()
                .await;
            token3 = token_set3
                .current_token()
                .expect("failed constructing the current token");
        }
        let resp = atl.verify(&token3).await.expect("Verification failed");
        assert!(
            resp.is_none(),
            "Verification should fail for an expired token"
        );
    }

    #[tokio::test]
    async fn atl_remove_expired() {
        let atl = create_atl();
        let short_duration = Duration::from_millis(10); // Will expire quickly
        let long_duration = Duration::from_secs(1000); // Will not expire quickly

        // File tokens with different expiration times
        let ts1 = create_test_token_set(1, short_duration);
        let (_, full_timestamp1) = atl.file(ts1).await.expect("File ts1 failed");
        let masked_timestamp1 = AccessTokenList::get_masked_timestamp(full_timestamp1);

        tokio::time::sleep(Duration::from_millis(20)).await; // Wait for ts1 to expire

        let ts2 = create_test_token_set(1, long_duration);
        let (_, full_timestamp2) = atl.file(ts2).await.expect("File ts2 failed");
        let masked_timestamp2 = AccessTokenList::get_masked_timestamp(full_timestamp2);

        let ts3 = create_test_token_set(1, short_duration);
        let (_, full_timestamp3) = atl.file(ts3).await.expect("File ts3 failed");
        let masked_timestamp3 = AccessTokenList::get_masked_timestamp(full_timestamp3);

        tokio::time::sleep(Duration::from_millis(20)).await; // Wait for ts3 to expire

        // Check initial state (all should be present)
        {
            let lookup_map = atl.inner_lookup.lock().await;
            assert!(lookup_map.get(&masked_timestamp1).is_some());
            assert!(lookup_map.get(&masked_timestamp2).is_some());
            assert!(lookup_map.get(&masked_timestamp3).is_some());
        } // atl.inner_lookup lock

        // Remove expired tokens
        let removed_count = atl.remove_expired().await.expect("remove_expired failed");

        // At least 2 tokens should be removed (ts1 and ts3)
        // Depending on exact timing and system clock, it could potentially be 3 if ts2
        // also expired, but with 1000s duration it's highly unlikely in a test.
        // Let's assert it's at least 2, and check which ones remain.
        assert!(
            removed_count >= 2,
            "Expected at least 2 tokens to be removed, but got {}",
            removed_count
        );

        // Check state after removal
        {
            let lookup_map = atl.inner_lookup.lock().await;
            assert!(
                lookup_map.get(&masked_timestamp1).is_none(),
                "ts1 should be removed"
            );
            assert!(
                lookup_map.get(&masked_timestamp3).is_none(),
                "ts3 should be removed"
            );
            assert!(
                lookup_map.get(&masked_timestamp2).is_some(),
                "ts2 should NOT be removed"
            );
        } // atl.inner_lookup lock

        let sorted_map = atl.inner_sorted.lock().await;
        // Check sorted map state - only ts2 should remain
        assert_eq!(
            sorted_map.len(),
            1,
            "Expected 1 token set remaining in sorted map"
        );
        assert_eq!(
            sorted_map
                .values()
                .next()
                .unwrap()
                .lock()
                .await
                .masked_timestamp,
            masked_timestamp2
        );
    }

    #[tokio::test]
    async fn atl_revoke_token() {
        let atl = create_atl();
        let ts1 = create_test_token_set(1, Duration::from_secs(60));
        let (_, full_timestamp1) = atl.file(ts1).await.expect("File ts1 failed");
        let masked_timestamp1 = AccessTokenList::get_masked_timestamp(full_timestamp1);
        let expiration_ts1 = full_timestamp1 + Duration::from_secs(60).as_nanos() as u64;

        let ts2 = create_test_token_set(1, Duration::from_secs(60));
        let (_, full_timestamp2) = atl.file(ts2).await.expect("File ts2 failed");
        let masked_timestamp2 = AccessTokenList::get_masked_timestamp(full_timestamp2);
        let expiration_ts2 = full_timestamp2 + Duration::from_secs(60).as_nanos() as u64;

        // Check initial state
        {
            let lookup_map = atl.inner_lookup.lock().await;
            let sorted_map = atl.inner_sorted.lock().await;
            println!(
                "{:?}, {}, {}",
                sorted_map.keys().collect::<Vec<_>>(),
                expiration_ts1,
                expiration_ts2
            );
            assert_eq!(lookup_map.len(), 2);
            assert_eq!(sorted_map.len(), 2);
            assert!(lookup_map.contains_key(&masked_timestamp1));
            assert!(lookup_map.contains_key(&masked_timestamp2));
            assert!(sorted_map.contains_key(&expiration_ts1));
            assert!(sorted_map.contains_key(&expiration_ts2));
        } // atl.inner_lookup lock & atl.inner_sorted lock

        // Revoke ts1
        let revoked = atl
            .revoke_token(masked_timestamp1)
            .await
            .expect("Revoke ts1 failed");
        assert!(revoked, "Revoking existing token should return true");

        // Check state after revoking ts1
        {
            let lookup_map = atl.inner_lookup.lock().await;
            let sorted_map = atl.inner_sorted.lock().await;
            assert_eq!(lookup_map.len(), 1);
            assert_eq!(sorted_map.len(), 1);
            assert!(!lookup_map.contains_key(&masked_timestamp1));
            assert!(lookup_map.contains_key(&masked_timestamp2));
            assert!(!sorted_map.contains_key(&expiration_ts1));
            assert!(sorted_map.contains_key(&expiration_ts2));
        } // atl.inner_lookup lock & atl.inner_sorted lock

        // Try to revoke ts1 again
        let revoked_again = atl
            .revoke_token(masked_timestamp1)
            .await
            .expect("Revoke ts1 again failed");
        assert!(
            !revoked_again,
            "Revoking non-existent token should return false"
        );

        // Revoke ts2
        let revoked_ts2 = atl
            .revoke_token(masked_timestamp2)
            .await
            .expect("Revoke ts2 failed");
        assert!(revoked_ts2, "Revoking existing token should return true");

        // Check state after revoking ts2
        let lookup_map = atl.inner_lookup.lock().await;
        let sorted_map = atl.inner_sorted.lock().await;
        assert_eq!(lookup_map.len(), 0);
        assert_eq!(sorted_map.len(), 0);
    }

    #[tokio::test]
    async fn atl_assemble_and_sparse_masked_timestamp() {
        let full_timestamp: u64 = 0x1122334455667788; // Example timestamp
        let masked_timestamp = AccessTokenList::get_masked_timestamp(full_timestamp);
        // Expected masked: 0x0022334455667700 (bytes 2-7)
        assert_eq!(masked_timestamp, 0x0022334455667700u64);

        let sparse_part = AccessTokenList::sparse_masked_u64_to_part(masked_timestamp);
        // Expected sparse part: [0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        assert_eq!(sparse_part, [0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        let assembled_masked_timestamp =
            AccessTokenList::assemble_masked_u64_from_part(&sparse_part);
        // Expected assembled: 0x0022334455667700
        assert_eq!(assembled_masked_timestamp, masked_timestamp);

        // Test with another timestamp
        let full_timestamp2: u64 = 0xAABBCCDDEEFF1122;
        let masked_timestamp2 = AccessTokenList::get_masked_timestamp(full_timestamp2);
        assert_eq!(masked_timestamp2, 0x00BBCCDDEEFF1100u64);
        let sparse_part2 = AccessTokenList::sparse_masked_u64_to_part(masked_timestamp2);
        assert_eq!(sparse_part2, [0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11]);
        let assembled_masked_timestamp2 =
            AccessTokenList::assemble_masked_u64_from_part(&sparse_part2);
        assert_eq!(assembled_masked_timestamp2, masked_timestamp2);
    }
}
