//go:build onmemory

package types

import (
	"go/authserver/consts"
)

type ATLEntry struct {
	Timestamp          [1 + consts.TIMESTAMP_LEN]byte
	RandomBytes        []byte
	RandomBytesIndex   byte
	NumRemainingTokens byte
	AccessType         AccessType
	ClientName         []byte
	Topic              []byte
	next               *ATLEntry
}

func (atlentry *ATLEntry) getCurrentRandomBytes() []byte {
	return atlentry.RandomBytes[atlentry.RandomBytesIndex*consts.RANDOM_BYTES_LEN : (atlentry.RandomBytesIndex+1)*consts.RANDOM_BYTES_LEN]
}
