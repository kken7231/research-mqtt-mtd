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
	fmt.Printf("Starting verifier server at port %d\n", config.Server.Ports.Verifier)
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
	defer atl.Unlock()
	entry, err := atl.LookupEntryWithToken(verifierRequest.Token)
	if err != nil {
		fmt.Printf("verifier(%s): Failed token verification with error: %v\n", remoteAddr, err)
		return
	}

	// Construct Response
	if entry == nil || entry.AccessTypeIsPub == verifierRequest.AccessTypeIsPub {
		// Verification Failed
		verifierResponse = types.VerifierResponse{
			ResultCode: types.VerfFail,
		}
	} else if resultCode, err := refreshCurrentValidRandomBytes(atl, entry); err != nil {
		// Internal Value Refresh Failed
		verifierResponse = types.VerifierResponse{
			ResultCode: types.VerfFail,
		}
	} else {
		// Internal Value Refreshed
		if resultCode.IsSuccessEncKey() {
			verifierResponse = types.VerifierResponse{
				ResultCode:        resultCode,
				TokenIndex:        entry.CurrentValidRandomBytesIdx,
				PayloadCipherType: entry.PayloadCipherType,
				EncryptionKey:     entry.PayloadEncKey,
				Topic:             entry.Topic,
			}
		} else if resultCode.IsSuccess() {
			verifierResponse = types.VerifierResponse{
				ResultCode: resultCode,
				Topic:      entry.Topic,
			}
		} else {
			verifierResponse = types.VerifierResponse{
				ResultCode: resultCode,
			}
		}
	}

	if err = funcs.SendVerifierResponse(context.TODO(), conn, config.Server.SocketTimeout.Local, verifierResponse); err != nil {
		fmt.Printf("verifier(%s): Error sending out a response: %v\n", remoteAddr, err)
		return
	}
}
