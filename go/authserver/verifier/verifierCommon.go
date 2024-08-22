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

	buf := make([]byte, consts.TOKEN_SIZE+1) // 1 byte for size check
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

	if entry == nil || (entry.AccessType&reqAccessType) == 0 {
		common.SetLen(&buf, 1)
		buf[0] = byte(types.VerfFail)
	} else {
		common.SetLen(&buf, len(entry.Topic)+3)
		binary.BigEndian.PutUint16(buf[1:], uint16(len(entry.Topic)))
		copy(buf[3:], entry.Topic)

		err = popTokenAndRefreshToken(atl, previous, entry, &buf)

		if err != nil {
			fmt.Printf("verifier(%s): Failed token update with error: %v\n", remoteAddr, err)
		}
	}

	if _, err = funcs.ConnWrite(conn, buf, 0); err != nil {
		fmt.Printf("verifier(%s): Error sending out: %v\n", remoteAddr, err)
		return
	}
}
