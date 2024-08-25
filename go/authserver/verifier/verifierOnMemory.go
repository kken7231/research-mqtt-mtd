//go:build onmemory

package verifier

import (
	"mqttmtd/consts"
	"mqttmtd/types"
)

func refreshCurrentValidRandomBytes(atl *types.AuthTokenList, entry *types.ATLEntry) (resultCode types.VerificationResultCode, err error) {
	if entry.CurrentValidRandomBytesIdx+1 >= entry.RandomBytesLen {
		atl.Lock()
		atl.Remove(entry)
		atl.Unlock()
		if entry.PayloadCipherType.IsValidCipherType() {
			resultCode = types.VerfSuccessEncKeyReloadNeeded
		} else {
			resultCode = types.VerfSuccessReloadNeeded
		}
	} else {
		atl.Lock()
		entry.CurrentValidRandomBytesIdx++
		entry.CurrentValidRandomBytes = entry.AllRandomBytes[entry.CurrentValidRandomBytesIdx*consts.RANDOM_BYTES_LEN : (entry.CurrentValidRandomBytesIdx+1)*consts.RANDOM_BYTES_LEN]
		atl.Unlock()
		if entry.PayloadCipherType.IsValidCipherType() {
			resultCode = types.VerfSuccessEncKey
		} else {
			resultCode = types.VerfSuccess
		}
	}
	return
}
