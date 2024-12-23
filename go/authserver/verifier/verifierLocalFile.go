//go:build !onmemory

package verifier

import (
	"fmt"
	"io"
	"mqttmtd/consts"
	"mqttmtd/types"
	"os"
	"unsafe"
)

func updateCurrentValidRandomBytes(atl *types.AuthTokenList, entry *types.ATLEntry) (resultCode types.VerificationResultCode, err error) {
	randomBytesFilePath := unsafe.String(unsafe.SliceData(entry.AllRandomData), len(entry.AllRandomData))
	if _, err = os.Stat(randomBytesFilePath); err == nil {
		// Random Bytes File Found
		var (
			n                            int
			isAlreadyClosed              bool = false
			fileAndEntryNeedsToBeRemoved bool = false
			randomBytesFile              *os.File
			curValidRandomBytes          []byte
		)
		randomBytesFile, err = os.Open(randomBytesFilePath)
		if err != nil {
			err = fmt.Errorf("failed opening file to pop a token: %v", err)
			return
		}
		defer func() {
			if fileAndEntryNeedsToBeRemoved {
				randomBytesFile.Close()
				if oserr := os.Remove(randomBytesFilePath); oserr != nil {
					err = fmt.Errorf("failed removing file %s: %v maybe preceding error? %v", randomBytesFilePath, oserr, err)
				}
				atl.Lock()
				atl.Remove(entry)
				atl.Unlock()
			} else if !isAlreadyClosed {
				randomBytesFile.Close()
			}
		}()

		// Seek to the next random bytes
		if _, err = randomBytesFile.Seek(int64(entry.CurrentValidTokenIdx+1)*int64(consts.RANDOM_BYTES_LEN), io.SeekStart); err != nil {
			err = fmt.Errorf("failed seeking to the next valid token: %v", err)
			if entry.PayloadAEADType.IsEncryptionEnabled() {
				resultCode = types.VerfSuccessEncKeyReloadNeeded
			} else {
				resultCode = types.VerfSuccessReloadNeeded
			}
			fileAndEntryNeedsToBeRemoved = true
			return
		}

		// Read next random bytes
		curValidRandomBytes = make([]byte, consts.RANDOM_BYTES_LEN)
		if n, err = randomBytesFile.Read(curValidRandomBytes); err != nil {
			fmt.Printf("failed reading the next valid token, probably the last token: %v\n", err)
			err = nil
			if entry.PayloadAEADType.IsEncryptionEnabled() {
				resultCode = types.VerfSuccessEncKeyReloadNeeded
			} else {
				resultCode = types.VerfSuccessReloadNeeded
			}
			fileAndEntryNeedsToBeRemoved = true
			return
		}
		if n != consts.RANDOM_BYTES_LEN {
			err = fmt.Errorf("failed reading the next valid token, length too short: %v", err)
			if entry.PayloadAEADType.IsEncryptionEnabled() {
				resultCode = types.VerfSuccessEncKeyReloadNeeded
			} else {
				resultCode = types.VerfSuccessReloadNeeded
			}
			fileAndEntryNeedsToBeRemoved = true
			return
		}
		atl.Lock()
		entry.CurrentValidRandomData = curValidRandomBytes
		entry.CurrentValidTokenIdx++
		atl.Unlock()
		if entry.PayloadAEADType.IsEncryptionEnabled() {
			resultCode = types.VerfSuccessEncKey
		} else {
			resultCode = types.VerfSuccess
		}
	} else {
		// No Random Bytes File Found
		atl.Lock()
		atl.Remove(entry)
		atl.Unlock()
		if entry.PayloadAEADType.IsEncryptionEnabled() {
			resultCode = types.VerfSuccessEncKeyReloadNeeded
		} else {
			resultCode = types.VerfSuccessReloadNeeded
		}
	}
	return
}
