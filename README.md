# MQTT-MTD

[![Rust CI on v2](https://github.com/kken7231/research-mqtt-mtd/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/kken7231/research-mqtt-mtd/actions/workflows/rust_ci.yml)

## Auth Server Packet Mapping

### Common components

#### Packet header

- Magic number (3 bytes): `0x4D51ED`
- Compound byte (1 byte)
    - bit 7-4: MQTT-MTD version
    - bit 3-0: Packet type
        - `0b0000`: Issuer request
        - `0b0001`: Issuer response
        - `0b0100`: Verifier request
        - `0b0101`: Verifier response

#### Aead algorithm

- `0`: AES_128_GCM
- `1`: AES_256_GCM
- `2`: CHACHA20_POLY1305

#### Topic

- Length (2 bytes) - Length of the topic (big endian)
- Topic - UTF-8 encoded Topic Name/Filter

### Issuer

#### Request

- Packet header
- Compound byte (1 byte)
    - bit 7: Request for pub - On if requests for pub tokens, otherwise sub.
    - bit 6-0: Requested number of tokens divided by 4
- AEAD algorithm (1 byte)
- Topic

#### Response

- Packet header
- Status (1 byte) - Indicates issuance result.
    - `0x01`: Success
    - `0xFF`: Error
- (Status == Success) Encryption key (length depends on the AEAD algorithm in the request) - Key to be used on payload
  encryption.
- (Status == Success) Nonce base (12 bytes) - Nonce base to be used on payload encryption.
- (Status == Success) Timestamp (6 bytes) - Timestamp to be used as `timestamp` in one-time tokens.
- (Status == Success) All randoms (`num_tokens_divided_by_4`  x 4 x 6 bytes) - Collection of random bytes to be used as
  `random` in one-time tokens.

### Verifier

#### Request
- Packet header
- Token (12 bytes) - Token to be checked.

### Response
- Packet header
- Status (1 byte) - Indicates verification result.
  - `0x01`: Success
  - `0x02`: Failure
  - `0xFF`: Error
- (Status == Success) Compound byte (1 byte)
    - bit 7: Allowed access is pub - On if pub verified, otherwise sub.
    - bit 6-0: AEAD algorithm
- (Status == Success) Topic
- (Status == Success) Encryption key (length depends on the AEAD algorithm) - Key to be used on payload
  decryption.
- (Status == Success) Nonce(12 bytes) - Nonce to be used on payload decryption.


