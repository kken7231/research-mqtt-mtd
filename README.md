# MQTT-MTD

[![Rust CI on v2](https://github.com/kken7231/research-mqtt-mtd/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/kken7231/research-mqtt-mtd/actions/workflows/rust_ci.yml)

## Auth Server Packet Mapping

### Common components

#### Packet header

- bit 7-4: MQTT-MTD version
- bit 3-0: Packet type
    - `0b0000`: Issuer request
    - `0b0001`: Issuer response
    - `0b0100`: Verifier request
    - `0b0101`: Verifier response

#### Aead algorithm

- `1`: AES_128_GCM
- `2`: AES_256_GCM
- `3`: CHACHA20_POLY1305

### Issuer

#### Request

| Index | Component | Sub component      | Length                  |                                                          |
|-------|-----------|--------------------|-------------------------|----------------------------------------------------------|
| 0     | Header    | -                  | 1 byte                  | `0x20`                                                   |
| 1     | Compound  |                    | 1 byte                  |                                                          |
|       |           | `is_pub`           | 1 bit                   | bit 7: On if requested for publish, otherwise subscribe. |
|       |           | `num_tokens_div_4` | 7 bits                  | bit 6-0: Requested number of tokens divided by 4.        |
| 2     | Algorithm | -                  | 1 byte                  | AEAD algorithm                                           |
| 3     | Topic     |                    | (2 + `topic_len`) bytes | Topic Name / Topic Filter                                |
|       |           | `topic_len`        | 2 bytes                 | Length of the topic in big endian.                       |
|       |           | `topic`            | `topic_len` bytes       | Topic Name / Topic Filter                                |

#### Response

| Index                           | Component      | Length                |                                                                          |
|---------------------------------|----------------|-----------------------|--------------------------------------------------------------------------|
| 0                               | Header         | 1 byte                | `0x21`                                                                   |
| 1                               | Status         | 1 byte                | Issuance result.<br/> - `0x01`: Success<br/> - `0xFF`: Error             |
| 2                               | *Session key   | `key_len` bytes       | Secret key that is to be used for encryption and HMAC random generation. |
| 2 + `key_len`                   | *Nonce padding | `nonce_len - 4` bytes | Nonce padding that is to be used for constructing a nonce.               |
| 2 + `key_len` + `nonce_len - 4` | *Timestamp     | 6 bytes               | Timestamp that will be in tokens.                                        |

Components with * are present only when Status == `Success`

### Verifier

#### Request

| Index | Component | Length    |                      |
|-------|-----------|-----------|----------------------|
| 0     | Header    | 1 byte    | `0x24`               |
| 1     | Token     | var bytes | Token to be checked. |

#### Response

| Index                       | Component    | Sub component | Length                  |                                                                                         |
|-----------------------------|--------------|---------------|-------------------------|-----------------------------------------------------------------------------------------|
| 0                           | Header       | -             | 1 byte                  | `0x25`                                                                                  |
| 1                           | Status       | -             | 1 byte                  | Verification result.<br/> - `0x01`: Success<br/> - `0x02`: Failure<br/> - `0xFF`: Error |
| 2                           | *Compound    |               | 1 byte                  |                                                                                         |
|                             |              | `is_pub`      | 1 bit                   | bit 7: On if verified for publish, otherwise subscribe.                                 |
|                             |              | `algo`        | 7 bits                  | bit 6-0: AEAD algorithm                                                                 |
| 3                           | *Topic       |               | (2 + `topic_len`) bytes | Topic Name / Topic Filter                                                               |
|                             |              | `topic_len`   | 2 bytes                 | Length of the topic in big endian.                                                      |
|                             |              | `topic`       | `topic_len` bytes       | Topic Name / Topic Filter                                                               |
| 5 + `topic_len`             | *Session key | -             | `key_len` bytes         | Secret key that is to be used for encryption and HMAC random generation.                |
| 5 + `topic_len` + `key_len` | *Nonce       | -             | `nonce_len` bytes       | Nonce that is to be used for encryption.                                                |

Components with * are present only when Status == `Success`
