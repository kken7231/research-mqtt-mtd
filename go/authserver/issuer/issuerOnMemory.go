//go:build onmemory

package issuer

import (
	"context"
	"crypto/rand"
	"fmt"
	"mqttmtd/config"
	"mqttmtd/consts"
	"mqttmtd/funcs"
	"mqttmtd/types"
	"net"
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
	)

	// Timestamp
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
	}

	if request.PayloadAEADRequested {
		// Encryption Key
		encKey = make([]byte, request.PayloadAEADType.GetKeyLen())
		n, err = rand.Read(encKey)
		if err != nil {
			fmt.Printf("issuer(%s): Error generating encryption key: %v\n", remoteAddr, err)
			return
		}
		if n != request.PayloadAEADType.GetKeyLen() {
			fmt.Printf("issuer(%s): Failed generating encryption key: length is inadequate\n", remoteAddr)
			return
		}
	}

	// Random Bytes
	allRandomBytes = make([]byte, consts.RANDOM_BYTES_LEN*request.NumberOfTokensDividedByMultiplier*consts.TOKEN_NUM_MULTIPLIER)
	n, err = rand.Read(allRandomBytes)
	if err != nil {
		fmt.Printf("issuer(%s): Error generating random bytes: %v\n", remoteAddr, err)
		return
	}
	if n != consts.RANDOM_BYTES_LEN*int(request.NumberOfTokensDividedByMultiplier)*consts.TOKEN_NUM_MULTIPLIER {
		fmt.Printf("issuer(%s): Failed generating random bytes: length is inadequate\n", remoteAddr)
		return
	}
	currentValidRandomBytes = make([]byte, consts.RANDOM_BYTES_LEN)
	copy(currentValidRandomBytes, allRandomBytes[:consts.RANDOM_BYTES_LEN])

	// Send Response
	issuerResponse := types.IssuerResponse{
		EncryptionKey:  encKey,
		Timestamp:      timestamp[1:],
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
		Topic:                  request.Topic,
		ClientName:             unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
		AccessTypeIsPub:        request.AccessTypeIsPub,
		Timestamp:              timestamp,
		AllRandomData:          allRandomBytes,
		TokenCount:             uint16(request.NumberOfTokensDividedByMultiplier) * consts.TOKEN_NUM_MULTIPLIER,
		CurrentValidRandomData: currentValidRandomBytes,
		CurrentValidTokenIdx:   0,
		PayloadAEADType:        request.PayloadAEADType,
		PayloadEncKey:          encKey,
	})
	atl.Unlock()
	return
}
