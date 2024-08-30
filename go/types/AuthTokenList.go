package types

import (
	"bytes"
	"fmt"
	"mqttmtd/consts"
	"sync"
	"time"
)

// Auth Token List: List of tokens available in a doubly linked list. Entries are appended as issued, so are sorted with timestamp
type AuthTokenList struct {
	sync.Mutex
	head *ATLEntry
	tail *ATLEntry
}

type ATLEntry struct {
	// ACL Info
	Topic      []byte
	ClientName []byte

	// Token Info
	AccessTypeIsPub        bool
	Timestamp              [1 + consts.TIMESTAMP_LEN]byte // size = 1 + consts.TIMESTAMP_LEN, in order to distinguish expired tokens
	AllRandomData          []byte                         // onmemory: all random data / localfile: utf8-encoded filepath
	CurrentValidRandomData []byte
	TokenCount             uint16
	CurrentValidTokenIdx   uint16

	// Payload AEAD
	PayloadAEADType PayloadAEADType
	PayloadEncKey   []byte // must be nil if PayloadAEADType.IsEncryptionEnabled() == false

	// Doubly Linked List Properties
	prev *ATLEntry
	next *ATLEntry
}

func (atl *AuthTokenList) removeFirst() bool {
	if atl.head == nil {
		return false
	}
	atl.head = atl.head.next
	if atl.head == nil {
		atl.tail = nil
	}
	return true
}

func (atl *AuthTokenList) Remove(entry *ATLEntry) bool {
	if entry == nil {
		return false
	}
	if entry.prev == nil {
		// entry is head
		atl.removeFirst()
	} else {
		entry.prev.next = entry.next
	}

	if entry.next == nil {
		// entry is tail
		atl.tail = entry.prev
	}
	return true
}

func (atl *AuthTokenList) RevokeEntry(clientName []byte, topic []byte, accessTypeIsPub bool) (err error) {
	var entry *ATLEntry
	entry, err = atl.lookupEntryWithClientNameTopicAndAccessType(clientName, topic, accessTypeIsPub)
	if err != nil {
		err = fmt.Errorf("found error during revocation: %v", err)
		return
	}
	if entry != nil {
		if entry.prev == nil {
			atl.removeFirst()
		} else {
			atl.Remove(entry)
		}
	}
	return nil
}

func (atl *AuthTokenList) AppendEntry(entry *ATLEntry) (err error) {
	if (atl.head == nil && atl.head != nil) || (atl.head != nil && atl.head == nil) {
		err = fmt.Errorf("couldn't append an entry, because either one of atl.first and atl.last is nil and the other is non-nil")
		return
	}

	if atl.head == nil {
		atl.head = entry
	} else {
		atl.tail.next = entry
		entry.prev = atl.tail
	}
	atl.tail = entry
	return
}

func (atl *AuthTokenList) RemoveExpired() {
	var (
		entryTime uint64
		newHead   *ATLEntry = atl.head
		newTail   *ATLEntry = atl.tail
	)

	for ; newHead != nil; newHead = newHead.next {
		entryTime = 0
		for i := 0; i < 1+consts.TIMESTAMP_LEN; i++ {
			entryTime |= uint64(newHead.Timestamp[i])
			entryTime <<= 8
		}
		if entryTime > uint64(time.Now().Add(-1*consts.TOKEN_EXPIRATION_DURATION).UnixNano()) {
			break
		}
	}
	if newHead == nil {
		newTail = nil
	}
	atl.head = newHead
	if newHead != nil {
		atl.head.prev = nil
	}
	atl.tail = newTail
	if newTail != nil {
		atl.tail.next = nil
	}
}

func (atl *AuthTokenList) LookupEntryWithToken(token []byte) (entry *ATLEntry, err error) {
	if len(token) != consts.TOKEN_SIZE {
		err = fmt.Errorf("length of token %v is not %d", token, consts.TOKEN_SIZE)
		return
	}

	var (
		MSB byte
	)
	if atl.head == nil {
		return
	}
	MSB = atl.head.Timestamp[0]
	entry = atl.head
	for ; entry != nil; entry = entry.next {
		if entry.Timestamp[0] != MSB {
			continue
		}

		if bytes.Equal(entry.Timestamp[1:1+consts.TIMESTAMP_LEN], token[:consts.TIMESTAMP_LEN]) {
			// timestamp matched
			var entryTime uint64 = 0
			for i := 0; i < 1+consts.TIMESTAMP_LEN; i++ {
				entryTime |= uint64(entry.Timestamp[i])
				entryTime <<= 8
			}
			// expiration check
			if entryTime > uint64(time.Now().Add(-1*consts.TOKEN_EXPIRATION_DURATION).UnixNano()) {
				// not expired
				if bytes.Equal(entry.CurrentValidRandomData, token[consts.TIMESTAMP_LEN:consts.TOKEN_SIZE]) {
					// random bytes matched (found)
					break
				} else {
					// random bytes not matched, seems like old or too new random bytes which are generated at the same time (not found
					entry = nil
					break
				}
			} else {
				// increment MSB by 1 to skip unnecessary timestamp comparison
				MSB++
				continue
			}
		}
	}
	return
}

func (atl *AuthTokenList) lookupEntryWithClientNameTopicAndAccessType(clientName []byte, topic []byte, accessTypeIsPub bool) (entry *ATLEntry, err error) {
	if len(topic) == 0 {
		err = fmt.Errorf("length of topic %v is zero", topic)
		return
	}
	for entry = atl.head; entry != nil; entry = entry.next {
		if bytes.Equal(topic, entry.Topic) && bytes.Equal(clientName, entry.ClientName) && accessTypeIsPub == entry.AccessTypeIsPub {
			break
		}
	}
	return
}

func (atl *AuthTokenList) ForEachEntry(handler func(int, *ATLEntry)) {
	var (
		i     int       = 0
		entry *ATLEntry = atl.head
	)
	for entry != nil {
		handler(i, entry)
		entry = entry.next
		i++
	}
}
