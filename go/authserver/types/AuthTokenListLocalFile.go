//go:build !onmemory

package types

import (
	"go/authserver/consts"
)

type ATLEntry struct {
	Timestamp          [1 + consts.TIMESTAMP_LEN]byte
	RandomBytes        [consts.RANDOM_BYTES_LEN]byte
	NumRemainingTokens byte
	AccessType         AccessType
	ClientName         []byte
	Topic              []byte
	next               *ATLEntry
}

func (atlentry *ATLEntry) getCurrentRandomBytes() []byte {
	return atlentry.RandomBytes[:]
}
