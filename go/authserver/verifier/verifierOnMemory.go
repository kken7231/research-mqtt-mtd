//go:build onmemory

package verifier

import (
	"mqttmtd/consts"
	"mqttmtd/types"
)

func updateCurrentValidRandomBytes(atl *types.AuthTokenList, entry *types.ATLEntry) (resultCode types.VerificationResultCode, err error) {
	if entry.CurrentValidTokenIdx+1 >= entry.TokenCount {
		atl.Lock()
		atl.Remove(entry)
		atl.Unlock()
		if entry.PayloadAEADType.IsEncryptionEnabled() {
			resultCode = types.VerfSuccessEncKeyReloadNeeded
		} else {
			resultCode = types.VerfSuccessReloadNeeded
		}
	} else {
		atl.Lock()
		entry.CurrentValidTokenIdx++
		entry.CurrentValidRandomData = entry.AllRandomData[entry.CurrentValidTokenIdx*consts.RANDOM_BYTES_LEN : (entry.CurrentValidTokenIdx+1)*consts.RANDOM_BYTES_LEN]
		atl.Unlock()
		if entry.PayloadAEADType.IsEncryptionEnabled() {
			resultCode = types.VerfSuccessEncKey
		} else {
			resultCode = types.VerfSuccess
		}
	}
	return
}
