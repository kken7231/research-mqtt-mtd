package issuer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"mqttmtd/config"
	"mqttmtd/funcs"
	"mqttmtd/types"
	"os"
	"strings"
	"unsafe"
)

func Run(acl *types.AccessControlList, atl *types.AuthTokenList) {
	fmt.Printf("Starting issuer server on port %d\n", config.Server.Ports.Issuer)
	cert, err := tls.LoadX509KeyPair(config.Server.Certs.ServerCertFilePath, config.Server.Certs.ServerKeyFilePath)
	if err != nil {
		log.Fatalf("Issuer - Failed to load server certificate: %v", err)
	}

	caCert, err := os.ReadFile(config.Server.Certs.CaCertFilePath)
	if err != nil {
		log.Fatalf("Issuer - Failed to load ca certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    caCertPool,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", config.Server.Ports.Issuer), tlsConf)
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

	var (
		err                 error
		issuerRequest       types.IssuerRequest
		requestedAccessType types.ACLAccessType
	)
	// Receive Request
	issuerRequest, err = funcs.ParseIssuerRequest(context.TODO(), conn, config.Server.SocketTimeout.External)
	if err != nil {
		fmt.Printf("issuer(%s): Failed reading a request: %v\n", remoteAddr, err)
		return
	}

	// ACL Lookup
	acl.Lock()
	clientACLEntry, found := acl.Entries[clientName]
	if !found {
		fmt.Printf("issuer(%s): ClientName %s not found in ACL\n", remoteAddr, clientName)
		acl.Unlock()
		return
	}
	topicStr := unsafe.String(unsafe.SliceData(issuerRequest.Topic), len(issuerRequest.Topic))
	grantedAccessType, found := clientACLEntry[topicStr]
	if !found {
		fmt.Printf("issuer(%s): Topic %s for ClientName %s not found in ACL\n", remoteAddr, topicStr, clientName)
		acl.Unlock()
		return
	}
	acl.Unlock()

	if issuerRequest.AccessTypeIsPub {
		requestedAccessType = types.AccessPub
	} else {
		requestedAccessType = types.AccessSub
	}
	if grantedAccessType&requestedAccessType == 0 {
		fmt.Printf("issuer(%s): Topic %s for ClientName %s not permitted for accessType %s: granted=%s\n", remoteAddr, topicStr, clientName, requestedAccessType.String(), grantedAccessType.String())
		return
	}

	// Generate Tokens & Send Response
	generateAndSendIssuerResponse(atl, conn, clientName, issuerRequest, remoteAddr)
}
