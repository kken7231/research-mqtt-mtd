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

type VerificationResponse byte

const (
	VerfSuccess VerificationResponse = iota
	VerfSuccessReloadNeeded
	VerfFail
	VerfSuspicious
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
