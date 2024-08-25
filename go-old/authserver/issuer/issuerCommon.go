package issuer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"go/authserver/consts"
	"go/authserver/funcs"
	"go/authserver/types"
	"go/common"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"
)

func Run(acl *types.AccessControlList, atl *types.AuthTokenList) {
	fmt.Printf("Starting issuer server at %s\n", consts.LADDR_ISSUER)
	cert, err := tls.LoadX509KeyPair(consts.SERVER_CRTFILE, consts.SERVER_KEYFILE)
	if err != nil {
		log.Fatalf("Issuer - Failed to load server certificate: %v", err)
	}

	caCert, err := os.ReadFile(consts.CA_CRTFILE)
	if err != nil {
		log.Fatalf("Issuer - Failed to load ca certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    caCertPool,
	}

	listener, err := tls.Listen("tcp", consts.LADDR_ISSUER, config)
	if err != nil {
		log.Fatalf("Issuer - Failed to start mTLS listener: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Issuer - Failed to accept mTLS connection: %v\n", err)
			continue
		}
		fmt.Printf("Issuer - Accepted mTLS connection from %s\n", conn.RemoteAddr().String())
		go tokenIssuerHandler(conn.(*tls.Conn), acl, atl)
	}
}

func tokenIssuerHandler(conn *tls.Conn, acl *types.AccessControlList, atl *types.AuthTokenList) {
	defer func() {
		addr := conn.RemoteAddr().String()
		conn.Close()
		fmt.Printf("Issuer - Closed mTLS connection with %s\n", addr)
	}()
	remoteAddr := conn.RemoteAddr().String()
	if err := conn.Handshake(); err != nil {
		fmt.Printf("issuer(%s): TLS Handshake failed: %v\n", remoteAddr, err)
		return
	}

	// mTLS connection validation and client identity extraction
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		fmt.Printf("issuer(%s): No certificate found %v\n", remoteAddr, state)
		return
	}
	clientCert := state.PeerCertificates[0]
	clientName := ""
	for _, email := range clientCert.EmailAddresses {
		if strings.HasSuffix(email, "@mqtt.mtd") {
			clientName = email[:len(email)-len("@mqtt.mtd")]
		}
	}
	if clientName == "" {
		fmt.Printf("issuer(%s): No MQTT MTD identity found!\n", remoteAddr)
		return
	}

	// Token Issue Request
	// [0]: Flag
	//   bit 7: Pub Access Requested (0-false, 1-true)
	//   bit 6: Sub Access Requested (0-false, 1-true)
	//   bit 5: Payload Encryption Key Requested (0-false, 1-true, only regards pub)
	//   bit 4-0: Requested number of tokens divided by TOKEN_NUM_MULTIPLIER
	// [1:3]: Payload Cipher Type (if requested)
	// [1(3 if cipher on)]: Length of Topic Name/Filter
	// [2:2+TopicLen(4:4+TopicLen if cipher on)]: Topic Name/Filter

	buf := make([]byte, 1)
	if _, err := funcs.ConnRead(conn, &buf, time.Millisecond*500); err != nil {
		fmt.Printf("issuer(%s): Failed reading a heading byte: %v\n", remoteAddr, err)
		return
	}
	var (
		reqAccessTypeByte       byte = 0
		reqAccessType           types.AccessType
		reqPayloadCipherEnabled bool
		reqPayloadCipherType    types.PayloadCipherType
		reqNumTokens            uint16
		reqTopicLen             byte
		reqTopic                []byte
		reqTopicStr             string
	)
	if buf[0]&0x80 != 0 {
		reqAccessTypeByte |= byte(types.AccessPub)
	}
	if buf[0]&0x40 != 0 {
		reqAccessTypeByte |= byte(types.AccessSub)
	}
	if reqAccessTypeByte == 0 {
		fmt.Printf("issuer(%s): Requested Access cannot be empty\n", remoteAddr)
		return
	}
	reqAccessType = types.AccessType(reqAccessTypeByte)
	reqPayloadCipherEnabled = buf[0]&0x20 != 0
	reqNumTokens = uint16(buf[0]&0x1F) * consts.TOKEN_NUM_MULTIPLIER
	if reqNumTokens == 0 {
		fmt.Printf("issuer(%s): Using default number of tokens: %d\n", remoteAddr, consts.DEFAULT_NUM_TOKENS)
		reqNumTokens = consts.DEFAULT_NUM_TOKENS
	}

	if reqPayloadCipherEnabled {
		common.SetLen(&buf, 3)
		if _, err := funcs.ConnRead(conn, &buf, time.Millisecond*500); err != nil {
			fmt.Printf("issuer(%s): Failed reading the topic len: %v\n", remoteAddr, err)
			return
		}
		reqPayloadCipherType = types.PayloadCipherType(uint16(buf[0])<<8 | uint16(buf[1]))
		if !reqPayloadCipherType.IsValidCipherType() {
			fmt.Printf("issuer(%s): Invalid cipher type: %d\n", remoteAddr, reqPayloadCipherType)
			return
		}
		reqTopicLen = buf[2]
	} else {
		if _, err := funcs.ConnRead(conn, &buf, time.Millisecond*500); err != nil {
			fmt.Printf("issuer(%s): Failed reading the topic len: %v\n", remoteAddr, err)
			return
		}
		reqTopicLen = buf[0]
	}
	if reqTopicLen == 0 {
		fmt.Printf("issuer(%s): Topic length cannot be 0\n", remoteAddr)
		return
	}
	reqTopic = make([]byte, reqTopicLen)
	n, err := funcs.ConnRead(conn, &reqTopic, time.Millisecond*500)
	if err != nil {
		fmt.Printf("issuer(%s): Failed reading topic with error: %v\n", remoteAddr, err)
		return
	} else if n != int(reqTopicLen) {
		fmt.Printf("issuer(%s): Failed reading topic: length is inadequate\n", remoteAddr)
		return
	} else if !utf8.Valid(reqTopic) {
		fmt.Printf("issuer(%s): Failed reading topic: topic is not aligned with utf-8\n", remoteAddr)
		return
	}
	reqTopicStr = unsafe.String(unsafe.SliceData(reqTopic), reqTopicLen)

	// ACL lookup
	acl.Lock()
	clientACLEntry, found := acl.Entries[clientName]
	if !found {
		fmt.Printf("issuer(%s): ClientName %s not found in ACL\n", remoteAddr, clientName)
		acl.Unlock()
		return
	}
	grantedAccessType, found := clientACLEntry[reqTopicStr]
	if !found {
		fmt.Printf("issuer(%s): TopicName %s for ClientName %s not found in ACL\n", remoteAddr, reqTopicStr, clientName)
		acl.Unlock()
		return
	}
	acl.Unlock()

	if grantedAccessType&reqAccessType == 0 {
		fmt.Printf("issuer(%s): TopicName %s for ClientName %s not permitted for accessType %s: granted=%s\n", remoteAddr, reqTopicStr, clientName, reqAccessType.String(), grantedAccessType.String())
		return
	}

	// Token Issuer Response
	// [0]: result code (according to types.VerificationResponse)
	// [1:1+keyLen]: Payload Encryption Key
	// [1:1+TIMESTAMP_LEN(1+keyLen:1+keyLen+TIMESTAMP_LEN if cipher requested)]: timestamp
	// [1+TIMESTAMP_LEN:(1+keyLen+TIMESTAMP_LEN: if cipher requested)]: random bytes

	gatherTokenIngredients(atl, conn, clientName, reqAccessType, reqNumTokens, reqPayloadCipherType, reqTopic, remoteAddr)
}
