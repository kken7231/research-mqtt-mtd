package types

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
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
AEAD Types that can be used to seal publish messages from both Client->Server and Server->Client.
*/
type PayloadAEADType uint8

const (
	PAYLOAD_AEAD_NONE PayloadAEADType = 0x0
	// Referred to TLSv1.3 cipher suites

	PAYLOAD_AEAD_AES_128_GCM       PayloadAEADType = 0x1
	PAYLOAD_AEAD_AES_256_GCM       PayloadAEADType = 0x2
	PAYLOAD_AEAD_CHACHA20_POLY1305 PayloadAEADType = 0x3
)

func (p PayloadAEADType) IsEncryptionEnabled() bool {
	return p == PAYLOAD_AEAD_AES_128_GCM ||
		p == PAYLOAD_AEAD_AES_256_GCM ||
		p == PAYLOAD_AEAD_CHACHA20_POLY1305
}

func (p PayloadAEADType) GetKeyLen() int {
	switch p {
	case PAYLOAD_AEAD_AES_128_GCM:
		return 16
	case PAYLOAD_AEAD_AES_256_GCM:
		fallthrough
	case PAYLOAD_AEAD_CHACHA20_POLY1305:
		return 32
	}
	return 0
}

func (p PayloadAEADType) GetNonceLen() int {
	switch p {
	case PAYLOAD_AEAD_AES_128_GCM:
		fallthrough
	case PAYLOAD_AEAD_CHACHA20_POLY1305:
		fallthrough
	case PAYLOAD_AEAD_AES_256_GCM:
		return 12
	}
	return 0
}

func (p PayloadAEADType) SealMessage(plaintext []byte, encKey []byte, nonceSpice uint64) (sealed []byte, err error) {
	var (
		nonce []byte
	)
	fmt.Printf("Sealing Message. Type: %d\n", p)
	switch p {
	case PAYLOAD_AEAD_AES_128_GCM:
		fallthrough
	case PAYLOAD_AEAD_AES_256_GCM:
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
		sealed = aesGCM.Seal(nil, nonce, plaintext, nil)
	case PAYLOAD_AEAD_CHACHA20_POLY1305:
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
		sealed = c20p1305.Seal(nil, nonce, plaintext, nil)
	}
	return
}

func (p PayloadAEADType) OpenMessage(payload []byte, encKey []byte, nonceSpice uint64) (decrypted []byte, err error) {
	var (
		nonce []byte
	)
	fmt.Printf("Opening Message. Type: %d\n", p)
	switch p {
	case PAYLOAD_AEAD_AES_128_GCM:
		fallthrough
	case PAYLOAD_AEAD_AES_256_GCM:
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
		fmt.Println("Nonce: ", hex.EncodeToString(nonce))
		fmt.Println("EncKey: ", hex.EncodeToString(encKey))
		fmt.Println("Payload: ", hex.EncodeToString(payload))

		decrypted, err = aesGCM.Open(nil, nonce, payload, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	case PAYLOAD_AEAD_CHACHA20_POLY1305:
		var (
			c20p1305 cipher.AEAD
		)
		c20p1305, err = chacha20poly1305.New(encKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create CHACHA20_POLY1305 cipher: %w", err)
		}
		nonce = make([]byte, c20p1305.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(consts.NONCE_BASE)+nonceSpice)
		decrypted, err = c20p1305.Open(nil, nonce, payload, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	}
	return
}

/*
Request To Issuer.
*/
type IssuerRequest struct {
	// Flag - 1 byte
	AccessTypeIsPub                   bool // bit 7
	PayloadAEADRequested              bool // bit 6
	NumberOfTokensDividedByMultiplier byte // bit 5-0, [1, 0x1F], the actual number is calculated after multiplication with consts.TOKEN_NUM_MULTIPLIER

	// Payload AEAD Type - 1 byte (absent when PayloadAEADRequested == false)
	PayloadAEADType PayloadAEADType

	// Topic - 2 bytes (length) + variable num of bytes (content) when parsed to bytes
	Topic []byte
}

/*
Response from Issuer.
*/
type IssuerResponse struct {
	// Encryption Key (absent when PayloadAEADRequested == false in the request)
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

	// Payload AEAD Type (present only if ResultCode is of SuccessEncKey) - 1 byte
	PayloadAEADType PayloadAEADType

	// Encryption Key (present only if ResultCode is of SuccessEncKey)
	EncryptionKey []byte

	// Topic (present only if ResultCode is of Success) - 2 bytes (length) + variable num of bytes (content) when parsed to bytes
	Topic []byte
}
