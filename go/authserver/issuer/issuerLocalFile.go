//go:build !onmemory

package issuer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"mqttmtd/config"
	"mqttmtd/consts"
	"mqttmtd/funcs"
	"mqttmtd/types"
	"net"
	"os"
	"time"
	"unsafe"
)

func generateAndSendIssuerResponse(atl *types.AuthTokenList, conn net.Conn, clientName string, request types.IssuerRequest, remoteAddr string) (err error) {
	var (
		now                     int64 = time.Now().UnixNano()
		encKey                  []byte
		n                       int
		timestamp               [1 + consts.TIMESTAMP_LEN]byte
		allRandomBytes          []byte
		currentValidRandomBytes []byte
		randomBytesFile         *os.File
		randomBytesFilePath     string
		completed               bool = false
	)

	// Timestamp
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
	}

	// File creation
	if err = os.MkdirAll(config.Server.FilePaths.TokensDirPath, 0666); err != nil {
		fmt.Printf("issuer(%s): Failed mkdir -p to save tokens: %v\n", remoteAddr, err)
		return
	}
	randomBytesFilePath = config.Server.FilePaths.TokensDirPath + base64.RawURLEncoding.EncodeToString(timestamp[:])
	randomBytesFile, err = os.Create(randomBytesFilePath)
	if err != nil {
		fmt.Printf("issuer(%s): Failed opening file to save random bytes: %v\n", remoteAddr, err)
		return
	}
	defer func() {
		randomBytesFile.Close()
		if !completed {
			fmt.Printf("issuer(%s): Ended token generation incomplete : %v\n", remoteAddr, err)
			if err = os.Remove(randomBytesFilePath); err != nil {
				fmt.Printf("issuer(%s): Failed removing file %s to recover from tokenFile creation failure: %v\n", remoteAddr, randomBytesFilePath, err)
				return
			}
		}
	}()

	if request.PayloadCipherRequested {
		// Encryption Key
		encKey = make([]byte, request.PayloadCipherType.GetKeyLen())
		n, err = rand.Read(encKey)
		if err != nil {
			fmt.Printf("issuer(%s): Error generating encryption key: %v\n", remoteAddr, err)
			return
		}
		if n != request.PayloadCipherType.GetKeyLen() {
			fmt.Printf("issuer(%s): Failed generating encryption key: length is inadequate\n", remoteAddr)
			return
		}
	}

	// Random Bytes
	allRandomBytes = make([]byte, consts.RANDOM_BYTES_LEN*int(request.NumberOfTokensDividedByMultiplier)*consts.TOKEN_NUM_MULTIPLIER)
	n, err = rand.Read(allRandomBytes)
	if err != nil {
		fmt.Printf("issuer(%s): Error generating random bytes: %v\n", remoteAddr, err)
		return
	}
	if n != consts.RANDOM_BYTES_LEN*int(request.NumberOfTokensDividedByMultiplier)*consts.TOKEN_NUM_MULTIPLIER {
		fmt.Printf("issuer(%s): Failed generating random bytes: length is inadequate\n", remoteAddr)
		return
	}
	if _, err = randomBytesFile.Write(allRandomBytes); err != nil {
		fmt.Printf("issuer(%s): Error writing random bytes to a file: %v\n", remoteAddr, err)
		return
	}
	currentValidRandomBytes = make([]byte, consts.RANDOM_BYTES_LEN)
	copy(currentValidRandomBytes, allRandomBytes[:consts.RANDOM_BYTES_LEN])

	// Send Response
	issuerResponse := types.IssuerResponse{
		EncryptionKey:  encKey,
		Timestamp:      timestamp[:],
		AllRandomBytes: allRandomBytes,
	}
	if err = funcs.SendIssuerResponse(context.TODO(), conn, config.Server.SocketTimeout.External, issuerResponse); err != nil {
		fmt.Printf("issuer(%s): Error sending out an issue response: %v\n", remoteAddr, err)
		return
	}

	// ATL update
	atl.Lock()
	atl.RevokeEntry(unsafe.Slice(unsafe.StringData(clientName), len(clientName)), request.Topic, request.AccessTypeIsPub)
	atl.AppendEntry(&types.ATLEntry{
		Topic:                      request.Topic,
		ClientName:                 unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
		AccessTypeIsPub:            request.AccessTypeIsPub,
		Timestamp:                  timestamp,
		AllRandomBytes:             []byte(randomBytesFilePath),
		RandomBytesLen:             uint16(request.NumberOfTokensDividedByMultiplier)*1 + consts.TOKEN_NUM_MULTIPLIER,
		CurrentValidRandomBytes:    currentValidRandomBytes,
		CurrentValidRandomBytesIdx: 0,
		PayloadCipherType:          request.PayloadCipherType,
		PayloadEncKey:              encKey,
	})
	atl.Unlock()

	completed = true
	return
}
