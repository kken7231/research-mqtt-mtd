//go:build onmemory

package verifier

import (
	"go/authserver/types"
)

func popTokenAndRefreshToken(atl *types.AuthTokenList, previous *types.ATLEntry, entry *types.ATLEntry, buf *[]byte) (err error) {
	if entry.NumRemainingTokens == 0 {
		atl.RemoveEntry(previous)
		(*buf)[0] = byte(types.VerfSuccessReloadNeeded)
	} else {
		entry.RandomBytesIndex++
		entry.NumRemainingTokens--
		(*buf)[0] = byte(types.VerfSuccess)
	}
	return
}
