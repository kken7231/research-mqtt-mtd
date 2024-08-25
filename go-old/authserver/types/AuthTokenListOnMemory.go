//go:build onmemory

package types

import (
	"go/authserver/consts"
)

type ATLEntry struct {
	ATLEntryCommon
	RandomBytes      []byte
	RandomBytesIndex uint16
	next             *ATLEntry
}

func (atlentry *ATLEntry) getCurrentRandomBytes() []byte {
	return atlentry.RandomBytes[atlentry.RandomBytesIndex*consts.RANDOM_BYTES_LEN : (atlentry.RandomBytesIndex+1)*consts.RANDOM_BYTES_LEN]
}
