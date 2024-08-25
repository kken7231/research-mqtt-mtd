//go:build !onmemory

package types

import (
	"go/authserver/consts"
)

type ATLEntry struct {
	ATLEntryCommon
	RandomBytes [consts.RANDOM_BYTES_LEN]byte
	next        *ATLEntry
}

func (atlentry *ATLEntry) getCurrentRandomBytes() []byte {
	return atlentry.RandomBytes[:]
}
