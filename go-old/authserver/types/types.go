package types

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

type AccessType byte

const (
	AccessPub    AccessType = 1
	AccessSub    AccessType = 2
	AccessPubSub AccessType = AccessPub | AccessSub
)

// Implement Stringer interface for better print
func (a AccessType) String() string {
	return [...]string{"Pub", "Sub", "PubSub"}[a-1]
}

// Implement UnmarshalYAML to convert YAML string to AccessType
func (a *AccessType) UnmarshalYAML(unmarshal func(interface{}) error) error {
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

type PayloadCipherType uint16

const (
	// Referred to TLSv1.3 cipher suites

	PAYLOAD_CIPHER_NONE                     PayloadCipherType = 0x0
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

type VerificationResponseCode byte

const (
	VerfSuccess                   VerificationResponseCode = 0x0
	VerfSuccessReloadNeeded       VerificationResponseCode = 0x1
	VerfSuccessEncKey             VerificationResponseCode = 0x20
	VerfSuccessEncKeyReloadNeeded VerificationResponseCode = 0x21
	VerfFail                      VerificationResponseCode = 0x80
	VerfSuspicious                VerificationResponseCode = 0x81
)

type AccessControlList struct { // Access Control List
	sync.Mutex
	Entries map[string]map[string]AccessType
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
