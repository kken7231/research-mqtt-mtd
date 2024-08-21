//go:build onmemory

package issuer

import (
	"crypto/rand"
	"fmt"
	"go/authserver/consts"
	"go/authserver/funcs"
	"go/authserver/types"
	"net"
	"time"
	"unsafe"
)

func gatherTokenIngredients(atl *types.AuthTokenList, conn net.Conn, clientName string, reqAccessType types.AccessType, reqNumTokens byte, reqTopic []byte, remoteAddr string) (err error) {
	// Timestamp
	var (
		now         int64 = time.Now().UnixNano()
		timestamp   [1 + consts.TIMESTAMP_LEN]byte
		randomBytes []byte = make([]byte, consts.RANDOM_BYTES_LEN*reqNumTokens)
	)
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
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
	if _, err = funcs.ConnWrite(conn, randomBytes, 0); err != nil {
		fmt.Printf("issuer(%s): Error sending out random bytes: %v\n", remoteAddr, err)
		return
	}

	// ATL update
	atl.Lock()
	atl.RevokeEntry(unsafe.Slice(unsafe.StringData(clientName), len(clientName)), reqTopic, reqAccessType)
	atl.AppendEntry(&types.ATLEntry{
		Timestamp:          timestamp,
		RandomBytes:        randomBytes,
		RandomBytesIndex:   0,
		NumRemainingTokens: reqNumTokens - 1,
		AccessType:         reqAccessType,
		Topic:              reqTopic,
		ClientName:         unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
	})
	atl.Unlock()

	return
}
