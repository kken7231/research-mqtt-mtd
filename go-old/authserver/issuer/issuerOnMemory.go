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

func gatherTokenIngredients(atl *types.AuthTokenList, conn net.Conn, clientName string, reqAccessType types.AccessType, reqNumTokens uint16, reqPayloadCipherType types.PayloadCipherType, reqTopic []byte, remoteAddr string) (err error) {
	var (
		now         int64 = time.Now().UnixNano()
		encKey      []byte
		n           int
		timestamp   [1 + consts.TIMESTAMP_LEN]byte
		randomBytes []byte = make([]byte, consts.RANDOM_BYTES_LEN*reqNumTokens)
	)

	// Encryption Key
	if reqPayloadCipherType.IsValidCipherType() {
		var keyByteLen int
		switch reqPayloadCipherType {
		case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
			fallthrough
		case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
			keyByteLen = 16
		case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
			fallthrough
		case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
			keyByteLen = 32
		}
		encKey = make([]byte, keyByteLen)

		n, err = rand.Read(encKey)
		if err != nil {
			fmt.Printf("issuer(%s): Error generating encryption key: %v\n", remoteAddr, err)
			return
		}
		if n != keyByteLen {
			fmt.Printf("issuer(%s): Failed generating encryption key: length is inadequate\n", remoteAddr)
			return
		}
		if _, err = funcs.ConnWrite(conn, encKey, 0); err != nil {
			fmt.Printf("issuer(%s): Error sending out encryption key: %v\n", remoteAddr, err)
			return
		}
	}

	// Timestamp
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
	}

	if _, err = funcs.ConnWrite(conn, timestamp[1:], 0); err != nil {
		fmt.Printf("issuer(%s): Error sending out timestamp: %v\n", remoteAddr, err)
		return
	}

	// Random bytes
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
		ATLEntryCommon: types.ATLEntryCommon{
			Timestamp:          timestamp,
			NumRemainingTokens: reqNumTokens,
			AccessType:         reqAccessType,
			Topic:              reqTopic,
			ClientName:         unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
			PayloadCipherType:  reqPayloadCipherType,
			PayloadEncKey:      encKey,
		},
		RandomBytes:      randomBytes,
		RandomBytesIndex: 0,
	})
	atl.Unlock()

	return
}
