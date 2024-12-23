package verifier

import (
	"context"
	"fmt"
	"log"
	"mqttmtd/config"
	"mqttmtd/funcs"
	"mqttmtd/types"
	"net"
)

func Run(atl *types.AuthTokenList) {
	fmt.Printf("Starting verifier server on port %d\n", config.Server.Ports.Verifier)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Server.Ports.Verifier))
	if err != nil {
		log.Fatalf("Verifier - Failed to start plain listener: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Verifier - Failed to accept plain connection:", err)
			continue
		}
		go tokenVerifierHandler(conn, atl)
	}
}

func tokenVerifierHandler(conn net.Conn, atl *types.AuthTokenList) {
	defer func() {
		addr := conn.RemoteAddr().String()
		conn.Close()
		fmt.Printf("Verifier - Closed connection with %s\n", addr)
	}()
	remoteAddr := conn.RemoteAddr().String()

	var (
		err              error
		verifierRequest  types.VerifierRequest
		verifierResponse types.VerifierResponse
	)
	// Receive Request
	verifierRequest, err = funcs.ParseVerifierRequest(context.TODO(), conn, config.Server.SocketTimeout.External)
	if err != nil {
		fmt.Printf("verifier(%s): Failed reading a request: %v\n", remoteAddr, err)
		return
	}

	// ATL Lookup
	atl.Lock()
	entry, err := atl.LookupEntryWithToken(verifierRequest.Token)
	atl.Unlock()
	if err != nil {
		fmt.Printf("verifier(%s): Failed token verification with error: %v\n", remoteAddr, err)
		return
	}

	// Construct Response
	if (entry == nil) || (entry.AccessTypeIsPub != verifierRequest.AccessTypeIsPub) {
		// Verification Failed
		fmt.Printf("verifier(%s): Verification failed\n", remoteAddr)
		verifierResponse = types.VerifierResponse{
			ResultCode: types.VerfFail,
		}
	}
	var (
		curValidTokenIdx uint16                = entry.CurrentValidTokenIdx
		payloadAEADType  types.PayloadAEADType = entry.PayloadAEADType
		payloadEncKey    []byte                = entry.PayloadEncKey
		topic            []byte                = entry.Topic
	)
	if resultCode, err := updateCurrentValidRandomBytes(atl, entry); err != nil {
		// Internal Value Refresh Failed
		fmt.Printf("verifier(%s): Failed token update with error: %v\n", remoteAddr, err)
		verifierResponse = types.VerifierResponse{
			ResultCode: types.VerfFail,
		}
	} else {
		// Internal Value Refreshed
		if resultCode.IsSuccessEncKey() {
			verifierResponse = types.VerifierResponse{
				ResultCode:      resultCode,
				TokenIndex:      curValidTokenIdx,
				PayloadAEADType: payloadAEADType,
				EncryptionKey:   payloadEncKey,
				Topic:           topic,
			}
		} else if resultCode.IsSuccess() {
			verifierResponse = types.VerifierResponse{
				ResultCode: resultCode,
				Topic:      topic,
			}
		} else {
			fmt.Printf("verifier(%s): Unexpected result code: %d\n", remoteAddr, resultCode)
			return
		}
	}

	fmt.Printf("verifier(%s): ResultCode: 0x%02x\n", remoteAddr, verifierResponse.ResultCode)

	if err = funcs.SendVerifierResponse(context.TODO(), conn, config.Server.SocketTimeout.Local, verifierResponse); err != nil {
		fmt.Printf("verifier(%s): Error sending out a response: %v\n", remoteAddr, err)
		return
	}
}
