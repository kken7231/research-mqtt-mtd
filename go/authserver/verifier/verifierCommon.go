package verifier

import (
	"encoding/binary"
	"fmt"
	"go/authserver/consts"
	"go/authserver/funcs"
	"go/authserver/types"
	"go/common"
	"log"
	"net"
	"time"
)

func Run(atl *types.AuthTokenList) {
	fmt.Printf("Starting verifier server at %s\n", consts.LADDR_VERIFIER)
	listener, err := net.Listen("tcp", consts.LADDR_VERIFIER)
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

	// Verification Request
	// [0]: Access Type (0-Sub, 1-Pub)
	// [1:1+TOKEN_SIZE]: Token

	buf := make([]byte, consts.TOKEN_SIZE+1)
	n, err := funcs.ConnRead(conn, &buf, time.Millisecond*500)
	if err != nil {
		fmt.Printf("verifier(%s): Failed reading token: %v\n", remoteAddr, err)
		return
	}
	if n != consts.TOKEN_SIZE+1 {
		fmt.Printf("verifier(%s): Failed reading token: length is inadequate\n", remoteAddr)
		return
	}

	var reqAccessType types.AccessType
	if buf[0]&0x80 != 0 {
		reqAccessType = types.AccessPub
	} else {
		reqAccessType = types.AccessSub
	}
	token := buf[1:]

	// Token validation
	atl.Lock()
	defer atl.Unlock()

	previous, entry, err := atl.LookupEntryWithToken(token)
	if err != nil {
		fmt.Printf("verifier(%s): Failed token verification with error: %v\n", remoteAddr, err)
		return
	}

	// Verification Response
	// [0]: result code (according to types.VerificationResponse)
	// [1:3]: Number of Token Remained
	// [3:5]: Payload Cipher Type
	// [5:5+keyLen]: Payload Encryption Key
	// [3:5(5+keyLen:5++keyLen+2 if cipher)]: topic length
	// [5:(5+keyLen+2: if cipher)]: topic

	if entry == nil || (entry.AccessType&reqAccessType) == 0 {
		common.SetLen(&buf, 1)
		buf[0] = byte(types.VerfFail)
	} else {
		binary.BigEndian.PutUint16(buf[1:3], uint16(entry.NumRemainingTokens))

		var curIdx int
		if entry.PayloadCipherType.IsValidCipherType() {
			var keyByteLen int
			switch entry.PayloadCipherType {
			case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
				fallthrough
			case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
				keyByteLen = 16
			case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
				fallthrough
			case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
				keyByteLen = 32
			}
			common.SetLen(&buf, 5+keyByteLen+2+len(entry.Topic))
			binary.BigEndian.PutUint16(buf[3:5], uint16(entry.PayloadCipherType))
			copy(buf[5:5+keyByteLen], entry.PayloadEncKey)
			curIdx = 5 + keyByteLen
		} else {
			common.SetLen(&buf, 5+len(entry.Topic))
			curIdx = 3
		}

		binary.BigEndian.PutUint16(buf[curIdx:curIdx+2], uint16(len(entry.Topic)))
		copy(buf[curIdx+2:], entry.Topic)

		err = popTokenAndRefreshToken(atl, previous, entry, &buf)
		if entry.PayloadCipherType.IsValidCipherType() {
			buf[0] |= 0x20
		}

		if err != nil {
			fmt.Printf("verifier(%s): Failed token update with error: %v\n", remoteAddr, err)
		}
	}

	if _, err = funcs.ConnWrite(conn, buf, 0); err != nil {
		fmt.Printf("verifier(%s): Error sending out: %v\n", remoteAddr, err)
		return
	}
}
