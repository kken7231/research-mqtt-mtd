package consts

import "time"

const (
	BIT_7 = 0x80
	BIT_6 = 0x40
	BIT_5 = 0x20
	BIT_4 = 0x10
	BIT_3 = 0x08
	BIT_2 = 0x04
	BIT_1 = 0x02
	BIT_0 = 0x01
)

const (
	// MQTT Standard Values

	MAX_UTF8_ENCODED_STRING_SIZE = 0xFFFF
)

const (
	SOCK_CONTEXT_CANCELABLE_KEY = "IsCancelable"
	NONCE_BASE                  = 123456

	TIMESTAMP_LEN    = 6
	RANDOM_BYTES_LEN = 6
	TOKEN_SIZE       = TIMESTAMP_LEN + RANDOM_BYTES_LEN

	TOKEN_EXPIRATION_DURATION = time.Hour * 24 * 7

	TOKEN_NUM_MULTIPLIER = 16
)
