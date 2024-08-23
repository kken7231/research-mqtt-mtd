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

func gatherTokenIngredients(atl *types.AuthTokenList, conn net.Conn, clientName string, reqAccessType types.AccessType, reqNumTokens uint16, reqPayloadCipherType types.PayloadCipherType, reqTopic []byte, remoteAddr string) (err error) {
	var (
		now         int64 = time.Now().UnixNano()
		encKey      []byte
		n           int
		timestamp   [1 + consts.TIMESTAMP_LEN]byte
		randomBytes []byte = make([]byte, consts.RANDOM_BYTES_LEN*reqNumTokens)
		tokenFile   *os.File
		completed   bool = false
	)

	// Local File Store
	// Filename: timestamp based
	// [0]: Flag
	//   0x00: No Payload Cipher
	//   0xFF: Payload Cipher Enabled
	// [1:3]: Payload Cipher Type (if requested)
	// [1(3 if cipher on):]: Random Bytes

	// Timestamp
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
		if _, err = tokenFile.Write([]byte{0xFF, byte(reqPayloadCipherType >> 8), byte(reqPayloadCipherType & 0xFF)}); err != nil {
			fmt.Printf("failed writing cipherFlag and cipherType: %v", err)
			return
		}
		if _, err = tokenFile.Write(encKey); err != nil {
			fmt.Printf("failed writing encryption key: %v", err)
			return
		}
		if _, err = funcs.ConnWrite(conn, encKey, 0); err != nil {
			fmt.Printf("issuer(%s): Error sending out encryption key: %v\n", remoteAddr, err)
			return
		}
	} else {
		if _, err = tokenFile.Write([]byte{0x00}); err != nil {
			fmt.Printf("failed writing cipherFlag(none): %v", err)
			return
		}
	}

	// Timestamp
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
	if _, err = tokenFile.Write(randomBytes[consts.RANDOM_BYTES_LEN:]); err != nil {
		fmt.Printf("failed writing random bytes: %v", err)
		return
	}
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
		ATLEntryCommon: types.ATLEntryCommon{
			Timestamp:          timestamp,
			NumRemainingTokens: reqNumTokens,
			AccessType:         reqAccessType,
			Topic:              reqTopic,
			ClientName:         unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
			PayloadCipherType:  reqPayloadCipherType,
			PayloadEncKey:      encKey,
		},
		RandomBytes: firstRandomBytes,
	})
	atl.Unlock()

	completed = true
	return
}
