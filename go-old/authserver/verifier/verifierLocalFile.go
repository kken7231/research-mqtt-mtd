//go:build !onmemory

package verifier

import (
	"go/authserver/funcs"
	"go/authserver/types"
)

func popTokenAndRefreshToken(atl *types.AuthTokenList, previous *types.ATLEntry, entry *types.ATLEntry, buf *[]byte) (err error) {
	var poppedToken []byte
	poppedToken, err = funcs.PopRandomBytesFromFile(entry.Timestamp)
	if err != nil {
		atl.RemoveEntry(previous)
		(*buf)[0] = byte(types.VerfSuccessReloadNeeded)
	} else if poppedToken == nil {
		atl.RemoveEntry(previous)
		(*buf)[0] = byte(types.VerfSuccessReloadNeeded)
	} else {
		entry.RandomBytes = [6]byte(poppedToken)
		entry.NumRemainingTokens--
		(*buf)[0] = byte(types.VerfSuccess)
	}
	return
}
