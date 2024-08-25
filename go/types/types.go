package types

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"mqttmtd/consts"
	"os"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"gopkg.in/yaml.v2"
)

/*
Access Type expression for ACL.
*/
type ACLAccessType byte

const (
	// Allow Pub Only
	AccessPub ACLAccessType = consts.BIT_0
	// Allow Sub Only
	AccessSub ACLAccessType = consts.BIT_1
	// Allow Both Pub & Sub
	AccessPubSub ACLAccessType = AccessPub | AccessSub
)

func (a ACLAccessType) String() string {
	return [...]string{"Pub", "Sub", "PubSub"}[a-1]
}

func (a *ACLAccessType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch s {
	case "Pub":
		*a = AccessPub
	case "Sub":
		*a = AccessSub
	case "PubSub":
		*a = AccessPubSub
	default:
		return fmt.Errorf("invalid access type: %s", s)
	}
	return nil
}

/*
Access Control List that Issuer will refer to. Entries can be loaded from the .yml file.
*/
type AccessControlList struct {
	sync.Mutex
	Entries map[string]map[string]ACLAccessType
}

func (acl *AccessControlList) LoadFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	err = yaml.UnmarshalStrict(data, &acl.Entries)
	if err != nil {
		return err
	}
	return nil
}

/*
Cipher Types that can be used to seal publish messages from both Client->Server and Server->Client.
*/
type PayloadCipherType uint16

const (
	PAYLOAD_CIPHER_NONE PayloadCipherType = 0x0

	// Value corresponds to TLSv1.3 cipher suites

	PAYLOAD_CIPHER_AES_128_GCM_SHA256       PayloadCipherType = 0x1301
	PAYLOAD_CIPHER_AES_256_GCM_SHA384       PayloadCipherType = 0x1302
	PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256 PayloadCipherType = 0x1303
	PAYLOAD_CIPHER_AES_128_CCM_SHA256       PayloadCipherType = 0x1304
)

func (p PayloadCipherType) IsValidCipherType() bool {
	return p == PAYLOAD_CIPHER_AES_128_GCM_SHA256 ||
		p == PAYLOAD_CIPHER_AES_256_GCM_SHA384 ||
		p == PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256 ||
		p == PAYLOAD_CIPHER_AES_128_CCM_SHA256
}

func (p PayloadCipherType) GetKeyLen() int {
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		return 16
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		return 32
	}
	return 0
}

func (p PayloadCipherType) GetHashLen() int {
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		return 32
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		return 48
	}
	return 0
}

func (p PayloadCipherType) GetNonceLen() int {
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		return 12
	}
	return 0
}

func (p PayloadCipherType) SealMessage(plaintext []byte, encKey []byte, nonceSpice uint64) (sealed []byte, err error) {
	var (
		hash      []byte
		nonce     []byte
		encrypted []byte
	)

	// Hash computation
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		hasher := sha256.New()
		hasher.Write(plaintext)
		hash = hasher.Sum(nil)
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		hasher := sha512.New384()
		hasher.Write(plaintext)
		hash = hasher.Sum(nil)
	}

	// Encryption
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		var (
			block  cipher.Block
			aesGCM cipher.AEAD
		)
		block, err = aes.NewCipher(encKey)
		if err != nil {
			err = fmt.Errorf("failed to create AES cipher block: %w", err)
			return
		}
		aesGCM, err = cipher.NewGCM(block)
		if err != nil {
			err = fmt.Errorf("failed to create AES GCM mode: %w", err)
			return
		}
		nonce = make([]byte, aesGCM.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(consts.NONCE_BASE)+nonceSpice)
		encrypted = aesGCM.Seal(nil, nonce, plaintext, nil)
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		var (
			c20p1305 cipher.AEAD
		)
		c20p1305, err = chacha20poly1305.New(encKey)
		if err != nil {
			err = fmt.Errorf("failed to create CHACHA20_POLY1305 cipher: %w", err)
			return
		}
		nonce = make([]byte, c20p1305.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(consts.NONCE_BASE)+nonceSpice)
		encrypted = c20p1305.Seal(nil, nonce, plaintext, nil)
	}

	// Combine encrypted message and hash into the sealed payload (encrypted + hash)
	sealed = append(encrypted, hash...)
	return
}

func (p PayloadCipherType) OpenMessage(payload []byte, encKey []byte, nonceSpice uint64) (decrypted []byte, err error) {
	var (
		hash         []byte
		nonce        []byte
		encrypted    []byte
		hashComputed []byte
	)

	// Extract encrypted message and hash
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		if len(payload) <= 32 {
			return nil, fmt.Errorf("payload too short")
		}
		encrypted = payload[:len(payload)-32]
		hash = payload[len(payload)-32:]
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		if len(payload) <= 48 {
			return nil, fmt.Errorf("payload too short")
		}
		encrypted = payload[:len(payload)-48]
		hash = payload[len(payload)-48:]
	}

	// Decryption
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		var (
			block  cipher.Block
			aesGCM cipher.AEAD
		)
		block, err = aes.NewCipher(encKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
		}
		aesGCM, err = cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES GCM mode: %w", err)
		}
		nonce = make([]byte, aesGCM.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(consts.NONCE_BASE)+nonceSpice)
		decrypted, err = aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		var (
			c20p1305 cipher.AEAD
		)
		c20p1305, err = chacha20poly1305.New(encKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create CHACHA20_POLY1305 cipher: %w", err)
		}
		nonce = make([]byte, c20p1305.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(consts.NONCE_BASE)+nonceSpice)
		decrypted, err = c20p1305.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	}

	// Compute the hash of the decrypted message
	switch p {
	case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		hasher := sha256.New()
		hasher.Write(decrypted)
		hashComputed = hasher.Sum(nil)
	case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		hasher := sha512.New384()
		hasher.Write(decrypted)
		hashComputed = hasher.Sum(nil)
	}

	// Verify the hash
	if !bytes.Equal(hash, hashComputed) {
		return nil, fmt.Errorf("hash verification failed")
	}
	return
}

/*
Request To Issuer.
*/
type IssuerRequest struct {
	// Flag - 1 byte
	AccessTypeIsPub                   bool // bit 7
	PayloadCipherRequested            bool // bit 6
	NumberOfTokensDividedByMultiplier byte // bit 5-0, [1, 0x1F], the actual number is calculated after multiplication with consts.TOKEN_NUM_MULTIPLIER

	// Payload Cipher Type - 2 bytes (absent when PayloadCipherRequested == false)
	PayloadCipherType PayloadCipherType

	// Topic - 2 bytes (length) + variable num of bytes (content) when parsed to bytes
	Topic []byte
}

func (ireq IssuerRequest) ToBytes() (ireqBytes []byte, err error) {
	var (
		ireqBytesLen    int = 0
		ireqBytesCurPos int = 0
		flag            [1]byte
		cipherType      [2]byte
		topicLen        [2]byte
	)
	// Flag
	flag[0] = 0
	if ireq.AccessTypeIsPub {
		flag[0] |= consts.BIT_7
	}
	if ireq.PayloadCipherRequested {
		flag[0] |= consts.BIT_6
	}
	if ireq.NumberOfTokensDividedByMultiplier < 1 || ireq.NumberOfTokensDividedByMultiplier > 0x1F {
		err = fmt.Errorf("field NumberOfTokens is not in the range of [1, 0x1F]")
		return
	} else {
		flag[0] |= ireq.NumberOfTokensDividedByMultiplier
	}
	ireqBytesLen += len(flag)

	// Payload Cipher Type
	if ireq.PayloadCipherRequested {
		binary.BigEndian.PutUint16(cipherType[:], uint16(ireq.PayloadCipherType))
		ireqBytesLen += len(cipherType)
	}

	// Topic
	if len(ireq.Topic) > consts.MAX_UTF8_ENCODED_STRING_SIZE {
		err = fmt.Errorf("length of field Topic is longer than %d", consts.MAX_UTF8_ENCODED_STRING_SIZE)
		return
	}
	binary.BigEndian.PutUint16(topicLen[:], uint16(len(ireq.Topic)))
	ireqBytesLen += len(topicLen) + len(ireq.Topic)

	// Concatenate
	ireqBytes = make([]byte, ireqBytesLen)

	copy(ireqBytes[ireqBytesCurPos:], flag[:])
	ireqBytesCurPos += len(flag)

	if ireq.PayloadCipherRequested {
		copy(ireqBytes[ireqBytesCurPos:], cipherType[:])
		ireqBytesCurPos += len(cipherType)
	}

	copy(ireqBytes[ireqBytesCurPos:], topicLen[:])
	ireqBytesCurPos += len(topicLen)

	copy(ireqBytes[ireqBytesCurPos:], ireq.Topic)
	ireqBytesCurPos += len(ireq.Topic)

	if ireqBytesCurPos != ireqBytesLen {
		ireqBytes = nil
		err = fmt.Errorf("error in copying content into ireqBytes")
	}
	return
}

/*
Response from Issuer.
*/
type IssuerResponse struct {
	// Encryption Key (absent when PayloadCipherRequested == false in the request)
	EncryptionKey []byte

	// Timestamp - (consts.TIMESTAMP_LEN) bytes
	Timestamp []byte

	// All Random Bytes Generated
	AllRandomBytes []byte
}

/*
Request to Verifier.
*/
type VerifierRequest struct {
	// Flag - 1 byte
	AccessTypeIsPub bool // bit 7

	// Token - (consts.TOKEN_SIZE) bytes
	Token []byte
}

func (vreq VerifierRequest) ToBytes() (vreqBytes []byte, err error) {
	var (
		vreqBytesLen    int = 0
		vreqBytesCurPos int = 0
		flag            [1]byte
	)
	// Flag
	flag[0] = 0
	if vreq.AccessTypeIsPub {
		flag[0] |= consts.BIT_7
	}
	vreqBytesLen += len(flag)

	// Token
	if len(vreq.Token) != consts.TOKEN_SIZE {
		err = fmt.Errorf("length of field Token is not %d", consts.TOKEN_SIZE)
		return
	}
	vreqBytesLen += len(vreq.Token)

	// Concatenate
	vreqBytes = make([]byte, vreqBytesLen)

	copy(vreqBytes[vreqBytesCurPos:], flag[:])
	vreqBytesCurPos += len(flag)

	copy(vreqBytes[vreqBytesCurPos:], vreq.Token)
	vreqBytesCurPos += len(vreq.Token)

	if vreqBytesCurPos != vreqBytesLen {
		vreqBytes = nil
		err = fmt.Errorf("error in copying content into vreqBytes")
	}
	return
}

type VerificationResultCode byte

const (
	VerfSuccess                   VerificationResultCode = 0x0
	VerfSuccessReloadNeeded       VerificationResultCode = 0x1
	VerfSuccessEncKey             VerificationResultCode = 0x20
	VerfSuccessEncKeyReloadNeeded VerificationResultCode = 0x21
	VerfFail                      VerificationResultCode = 0x80
	VerfSuspicious                VerificationResultCode = 0x81
)

func (vrescode VerificationResultCode) IsSuccess() bool {
	return vrescode == VerfSuccess ||
		vrescode == VerfSuccessReloadNeeded ||
		vrescode == VerfSuccessEncKey ||
		vrescode == VerfSuccessEncKeyReloadNeeded
}
func (vrescode VerificationResultCode) IsSuccessEncKey() bool {
	return vrescode == VerfSuccessEncKey ||
		vrescode == VerfSuccessEncKeyReloadNeeded
}

/*
Response from Verifier.
*/
type VerifierResponse struct {
	// Result Code - byte
	ResultCode VerificationResultCode

	// Current Token Index (present only if ResultCode is of SuccessEncKey) - 2 bytes
	TokenIndex uint16

	// Payload Cipher Type (present only if ResultCode is of SuccessEncKey) - 2 bytes
	PayloadCipherType PayloadCipherType

	// Encryption Key (present only if ResultCode is of SuccessEncKey)
	EncryptionKey []byte

	// Topic (present only if ResultCode is of Success) - 2 bytes (length) + variable num of bytes (content) when parsed to bytes
	Topic []byte
}

func (vresp VerifierResponse) ToBytes() (vrespBytes []byte, err error) {
	var (
		vrespBytesLen    int = 0
		vrespBytesCurPos int = 0
		resultCode       [1]byte
		tokenIndex       [2]byte
		cipherType       [2]byte
		topicLen         [2]byte
	)
	// Result Code
	resultCode[0] = byte(vresp.ResultCode)
	vrespBytesLen += len(resultCode)

	if vresp.ResultCode.IsSuccessEncKey() {
		// Token Index
		binary.BigEndian.PutUint16(tokenIndex[:], uint16(vresp.TokenIndex))
		vrespBytesLen += len(tokenIndex)

		// Payload Cipher Type
		binary.BigEndian.PutUint16(cipherType[:], uint16(vresp.PayloadCipherType))
		vrespBytesLen += len(cipherType)

		// Encryption Key
		vrespBytesLen += len(vresp.EncryptionKey)
	}

	if vresp.ResultCode.IsSuccess() {
		// Topic
		if len(vresp.Topic) > consts.MAX_UTF8_ENCODED_STRING_SIZE {
			err = fmt.Errorf("length of field Topic is longer than %d", consts.MAX_UTF8_ENCODED_STRING_SIZE)
			return
		}
		binary.BigEndian.PutUint16(topicLen[:], uint16(len(vresp.Topic)))
		vrespBytesLen += len(topicLen) + len(vresp.Topic)
	}

	// Concatenate
	vrespBytes = make([]byte, vrespBytesLen)

	copy(vrespBytes[vrespBytesCurPos:], resultCode[:])
	vrespBytesCurPos += len(resultCode)

	if vresp.ResultCode.IsSuccessEncKey() {
		copy(vrespBytes[vrespBytesCurPos:], tokenIndex[:])
		vrespBytesCurPos += len(tokenIndex)

		copy(vrespBytes[vrespBytesCurPos:], cipherType[:])
		vrespBytesCurPos += len(cipherType)

		copy(vrespBytes[vrespBytesCurPos:], vresp.EncryptionKey)
		vrespBytesCurPos += len(vresp.EncryptionKey)
	}

	if vresp.ResultCode.IsSuccess() {
		copy(vrespBytes[vrespBytesCurPos:], topicLen[:])
		vrespBytesCurPos += len(topicLen)

		copy(vrespBytes[vrespBytesCurPos:], vresp.Topic)
		vrespBytesCurPos += len(vresp.Topic)
	}

	if vrespBytesCurPos != vrespBytesLen {
		vrespBytes = nil
		err = fmt.Errorf("error in copying content into vrespBytes")
	}
	return
}
