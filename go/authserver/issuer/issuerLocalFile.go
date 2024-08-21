//go:build !onmemory

package issuer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"go/authserver/consts"
	"go/authserver/funcs"
	"go/authserver/types"
	"net"
	"os"
	"time"
	"unsafe"
)

func gatherTokenIngredients(atl *types.AuthTokenList, conn net.Conn, clientName string, reqAccessType types.AccessType, reqNumTokens byte, reqTopic []byte, remoteAddr string) (err error) {
	// Timestamp
	var (
		now         int64 = time.Now().UnixNano()
		timestamp   [1 + consts.TIMESTAMP_LEN]byte
		randomBytes []byte = make([]byte, consts.RANDOM_BYTES_LEN*reqNumTokens)
		tokenFile   *os.File
		completed   bool = false
	)
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
	}

	if reqNumTokens > 1 {
		// File creation
		if err = os.MkdirAll(consts.DEFAULT_FILEPATH_TOKENS_DIR, 0666); err != nil {
			fmt.Printf("issuer(%s): Failed mkdir -p to save tokens: %v\n", remoteAddr, err)
			return
		}
		tokenFilePath := consts.DEFAULT_FILEPATH_TOKENS_DIR + base64.RawURLEncoding.EncodeToString(timestamp[:])
		tokenFile, err = os.Create(tokenFilePath)
		if err != nil {
			fmt.Printf("issuer(%s): Failed opening file to save tokens: %v\n", remoteAddr, err)
			return
		}
		defer func() {
			tokenFile.Close()
			if !completed {
				fmt.Printf("issuer(%s): Ended token generation incomplete : %v\n", remoteAddr, err)
				if err = os.Remove(tokenFilePath); err != nil {
					fmt.Printf("issuer(%s): Failed removing file %s to recover from tokenFile creation failure: %v\n", remoteAddr, tokenFilePath, err)
					return
				}
			}
		}()
	}
	if _, err = funcs.ConnWrite(conn, timestamp[1:], 0); err != nil {
		fmt.Printf("issuer(%s): Error sending out timestamp: %v\n", remoteAddr, err)
		return
	}

	// Random bytes
	var n int
	n, err = rand.Read(randomBytes)
	if err != nil {
		fmt.Printf("issuer(%s): Error generating random bytes: %v\n", remoteAddr, err)
		return
	}
	if n != consts.RANDOM_BYTES_LEN*int(reqNumTokens) {
		fmt.Printf("issuer(%s): Failed generating random bytes: length is inadequate\n", remoteAddr)
		return
	}
	tokenFile.Write(randomBytes[consts.RANDOM_BYTES_LEN:])
	if _, err = funcs.ConnWrite(conn, randomBytes, 0); err != nil {
		fmt.Printf("issuer(%s): Error sending out random bytes: %v\n", remoteAddr, err)
		return
	}
	var firstRandomBytes [consts.RANDOM_BYTES_LEN]byte
	copy(firstRandomBytes[:], randomBytes[:consts.RANDOM_BYTES_LEN])

	// ATL update
	atl.Lock()
	atl.RevokeEntry(unsafe.Slice(unsafe.StringData(clientName), len(clientName)), reqTopic, reqAccessType)
	atl.AppendEntry(&types.ATLEntry{
		Timestamp:          timestamp,
		RandomBytes:        firstRandomBytes,
		NumRemainingTokens: reqNumTokens - 1,
		AccessType:         reqAccessType,
		Topic:              reqTopic,
		ClientName:         unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
	})
	atl.Unlock()

	completed = true
	return
}
