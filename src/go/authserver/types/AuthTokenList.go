package types

import (
	"bytes"
	"fmt"
	"go/authserver/consts"
	"sync"
	"time"
)

type AuthTokenList struct { // Auth Token List
	sync.Mutex
	first *ATLEntry
	last  *ATLEntry
}

type ATLEntry struct {
	Timestamp          [1 + consts.TIMESTAMP_LEN]byte
	RandomBytes        [consts.RANDOM_BYTES_LEN]byte
	NumRemainingTokens byte
	AccessType         AccessType
	ClientName         []byte
	Topic              []byte
	next               *ATLEntry
}

func (atl *AuthTokenList) removeFirstEntry() bool {
	if atl.first == nil {
		return false
	}
	atl.first = atl.first.next
	if atl.first == nil {
		atl.last = nil
	}
	return true
}

func (atl *AuthTokenList) RemoveEntry(previous *ATLEntry) bool {
	if previous == nil || previous.next == nil {
		return false
	}
	previous.next = previous.next.next
	if previous.next == nil {
		atl.last = previous
	}
	return true
}

func (atl *AuthTokenList) replaceEntries(first *ATLEntry, last *ATLEntry) error {
	if first == nil || last == nil {
		return fmt.Errorf("first and last cannot be nil")
	}

	atl.first = first
	atl.last = last
	return nil
}

func (atl *AuthTokenList) RevokeEntry(clientName []byte, topic []byte) error {
	previous, entry, err := atl.lookupEntryWithClientNameAndTopic(clientName, topic)
	if err != nil {
		return fmt.Errorf("found error during revocation: %v", err)
	}
	if entry != nil {
		if previous == nil {
			atl.removeFirstEntry()
		} else {
			atl.RemoveEntry(previous)
		}
	}
	return nil
}

func (atl *AuthTokenList) AppendEntry(entry *ATLEntry) error {
	if (atl.first == nil && atl.first != nil) || (atl.first != nil && atl.first == nil) {
		return fmt.Errorf("couldn't append an entry, because either one of atl.first and atl.last is nil and the other is non-nil")
	}

	if atl.first == nil {
		atl.first = entry
	} else {
		// atl.last is present if atl.first is non-nil, because atl.first and atl.last take only two states; (both nil) and (both non-nil)
		atl.insertEntryAfter(atl.last, entry)
	}
	atl.last = entry
	return nil
}

func (atl *AuthTokenList) insertEntryAfter(after *ATLEntry, toBeAdded *ATLEntry) {
	toBeAdded.next = after.next
	after.next = toBeAdded
}

func (atl *AuthTokenList) RemoveExpired() {
	var (
		entryTime uint64
		newFirst  *ATLEntry = atl.first
		newLast   *ATLEntry = atl.last
	)

	for ; newFirst != nil; newFirst = newFirst.next {
		entryTime = 0
		for i := 0; i < 1+consts.TIMESTAMP_LEN; i++ {
			entryTime |= uint64(newFirst.Timestamp[i])
			entryTime <<= 8
		}
		if entryTime > uint64(time.Now().Add(-1*consts.TIME_REVOCATION).UnixNano()) {
			break
		}
	}
	if newFirst == nil {
		newLast = nil
	}
	atl.replaceEntries(newFirst, newLast)
}

// returns previous ENTRY
func (atl *AuthTokenList) LookupEntryWithToken(token []byte) (previous *ATLEntry, entry *ATLEntry, err error) {
	if len(token) != consts.TOKEN_SIZE {
		err = fmt.Errorf("length of token %v is not %d", token, consts.TOKEN_SIZE)
		return
	}

	var (
		// numCommonBytes  int = 0
		// newlyCommon     int
		// timestampFrgmnt []byte
		// tokenFrgmnt     []byte
		MSB byte
	)
	if atl.first == nil {
		return
	}
	// timestampFrgmnt = atl.first.Timestamp[1:]
	// tokenFrgmnt = token
	MSB = atl.first.Timestamp[0]
	for entry = atl.first; entry != nil; func() {
		previous = entry
		entry = entry.next
	}() {
		if entry.Timestamp[0] != MSB {
			continue
		}

		if bytes.Equal(entry.Timestamp[1:1+consts.TIMESTAMP_LEN], token[:consts.TIMESTAMP_LEN]) {
			var entryTime uint64 = 0
			for i := 0; i < 1+consts.TIMESTAMP_LEN; i++ {
				entryTime |= uint64(entry.Timestamp[i])
				entryTime <<= 8
			}
			// revocation check
			if entryTime > uint64(time.Now().Add(-1*consts.TIME_REVOCATION).UnixNano()) {
				if bytes.Equal(entry.RandomBytes[:], token[consts.TIMESTAMP_LEN:consts.TOKEN_SIZE]) {
					// found
					return
				}
				// not found
				return nil, nil, nil
			} else {
				MSB++
				continue
			}
		}

		// for newlyCommon = 0; newlyCommon < len(timestampFrgmnt) && newlyCommon < len(tokenFrgmnt) && timestampFrgmnt[newlyCommon] != tokenFrgmnt[newlyCommon]; newlyCommon++ {
		// }

		// if numCommonBytes == 0 {
		// 	// 2nd MSB maybe common
		// 	if newlyCommon > 1 {
		// 		numCommonBytes = newlyCommon - 1
		// 		timestampFrgmnt = entry.Timestamp[1+(numCommonBytes-1):]
		// 		tokenFrgmnt = token[(numCommonBytes - 1):consts.TIMESTAMP_LEN]
		// 	}
		// } else {
		// 	// 2nd to (numCommonBytes+1)th MSBs are identical
		// 	if newlyCommon == 0 {
		// 		// Search ended with zero common with given MSB
		// 		MSB++
		// 		numCommonBytes = 0
		// 		continue
		// 	}

		// 	numCommonBytes += newlyCommon - 1
		// 	if numCommonBytes == consts.TIMESTAMP_LEN {
		// 		var entryTime uint64 = 0
		// 		for i := 0; i < 1+consts.TIMESTAMP_LEN; i++ {
		// 			entryTime |= uint64(entry.Timestamp[i])
		// 			entryTime <<= 8
		// 		}
		// 		if entryTime > uint64(time.Now().Add(-1*consts.TIME_REVOCATION).UnixNano()) {
		// 			// found
		// 			return
		// 		} else {
		// 			// Search ended with zero common with given MSB
		// 			MSB++
		// 			numCommonBytes = 0
		// 			continue
		// 		}
		// 	} else {
		// 		timestampFrgmnt = entry.Timestamp[1+(numCommonBytes-1):]
		// 		tokenFrgmnt = token[(numCommonBytes - 1):consts.TIMESTAMP_LEN]
		// 	}
		// }
	}
	return
}

func (atl *AuthTokenList) lookupEntryWithClientNameAndTopic(clientName []byte, topic []byte) (*ATLEntry, *ATLEntry, error) {
	if len(topic) == 0 {
		return nil, nil, fmt.Errorf("length of topic %v is zero", topic)
	}

	var previousEntry *ATLEntry = nil

	for entry := atl.first; entry != nil; func() {
		previousEntry = entry
		entry = entry.next
	}() {
		if bytes.Equal(topic, entry.Topic) && bytes.Equal(clientName, entry.ClientName) {
			return previousEntry, entry, nil
		}
	}
	return previousEntry, nil, nil
}

func (atl *AuthTokenList) ForEachEntry(handler func(int, *ATLEntry)) {
	var (
		i     int       = 0
		entry *ATLEntry = atl.first
	)
	for ; entry != nil; entry = entry.next {
		handler(i, entry)
	}
}
