package issuer

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"go/authserver/consts"
	"go/authserver/funcs"
	"go/authserver/types"
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
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    caCertPool,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
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

	// Data verification
	// [0]: Flag
	//   bit 7: Pub Access Requested (0-false, 1-true)
	//   bit 6: Sub Access Requested (0-false, 1-true)
	//   bit 5-0: Requested number of tokens divided by 4 (max 252 tokens)
	// [1]: Length of Topic Name/Filter
	// [2:2+TopicLen]: Topic Name/Filter
	buf := make([]byte, 2)
	if _, err := funcs.ConnRead(conn, &buf, time.Millisecond*500); err != nil {
		fmt.Printf("issuer(%s): Failed reading two bytes: %v\n", remoteAddr, err)
		return
	}
	var (
		reqAccessTypeByte byte = 0
		reqAccessType     types.AccessType
		reqNumTokens      byte
		reqTopicLen       byte
		reqTopic          []byte
		reqTopicStr       string
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
	reqNumTokens = (buf[0] & 0x3F) * 4
	if reqNumTokens == 0 {
		fmt.Printf("issuer(%s): Using default number of tokens: %d\n", remoteAddr, consts.DEFAULT_NUM_TOKENS)
		reqNumTokens = consts.DEFAULT_NUM_TOKENS
	}
	reqTopicLen = buf[1]
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
		fmt.Printf("issuer(%s): ClientName %s not permitted for accessType %s: granted=%s\n", remoteAddr, clientName, reqAccessType.String(), grantedAccessType.String())
		return
	}

	// Timestamp
	var (
		now         int64 = time.Now().UnixNano()
		timestamp   [1 + consts.TIMESTAMP_LEN]byte
		randomBytes []byte = make([]byte, consts.RANDOM_BYTES_LEN)
		tokenFile   *os.File
		completed   bool = false
	)
	for i := consts.TIMESTAMP_LEN; i >= 0; i-- {
		now >>= 8
		timestamp[i] = byte(now & 0xFF)
	}

	if reqNumTokens > 1 {
		// File creation
		if err := os.MkdirAll(consts.DEFAULT_FILEPATH_TOKENS_DIR, 0666); err != nil {
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
	if _, err = funcs.ConnWrite(conn, timestamp[1:], 0); err != nil {
		fmt.Printf("issuer(%s): Error sending out timestamp: %v\n", remoteAddr, err)
		return
	}

	// Random bytes
	var firstRandomBytes [consts.RANDOM_BYTES_LEN]byte
	for i := 0; i < int(reqNumTokens); i++ {
		n, err = rand.Read(randomBytes)
		if err != nil {
			fmt.Printf("issuer(%s): Error generating random bytes: %v\n", remoteAddr, err)
			return
		}
		if n != consts.RANDOM_BYTES_LEN {
			fmt.Printf("issuer(%s): Failed generating random bytes: length is inadequate\n", remoteAddr)
			return
		}
		if i > 0 {
			tokenFile.Write(randomBytes)
		} else {
			for j := 0; j < consts.RANDOM_BYTES_LEN; j++ {
				firstRandomBytes[j] = randomBytes[j]
			}
		}
		if _, err = funcs.ConnWrite(conn, randomBytes, 0); err != nil {
			fmt.Printf("issuer(%s): Error sending out random bytes: %v\n", remoteAddr, err)
			return
		}
	}

	// ATL update
	atl.Lock()
	atl.RevokeEntry(unsafe.Slice(unsafe.StringData(clientName), len(clientName)), reqTopic)
	atl.AppendEntry(&types.ATLEntry{
		Timestamp:          timestamp,
		RandomBytes:        firstRandomBytes,
		NumRemainingTokens: reqNumTokens - 1,
		AccessType:         reqAccessType,
		Topic:              reqTopic,
		ClientName:         unsafe.Slice(unsafe.StringData(clientName), len(clientName)),
	})
	atl.Unlock()

	completed = true
}
