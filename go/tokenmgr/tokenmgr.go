package tokenmgr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"go/common"
)

type AccessType byte

const (
	AccessPub    AccessType = 1
	AccessSub    AccessType = 2
	AccessPubSub AccessType = AccessPub | AccessSub
)

func (a AccessType) String() string {
	return [...]string{"Pub", "Sub", "PubSub"}[a-1]
}

type PayloadCipherType uint16

const (
	// Referred to TLSv1.3 cipher suites

	PAYLOAD_CIPHER_NONE                     PayloadCipherType = 0x0
	PAYLOAD_CIPHER_AES_128_GCM_SHA256       PayloadCipherType = 0x1301
	PAYLOAD_CIPHER_AES_256_GCM_SHA384       PayloadCipherType = 0x1302
	PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256 PayloadCipherType = 0x1303
	PAYLOAD_CIPHER_AES_128_CCM_SHA256       PayloadCipherType = 0x1304
)

type FetchRequest struct {
	NumTokens         uint16
	AccessType        AccessType
	CaCrt             string
	ClientCrt         string
	ClientKey         string
	PayloadCipherType PayloadCipherType
}

func (p PayloadCipherType) IsValidCipherType() bool {
	return p == PAYLOAD_CIPHER_AES_128_GCM_SHA256 ||
		p == PAYLOAD_CIPHER_AES_256_GCM_SHA384 ||
		p == PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256 ||
		p == PAYLOAD_CIPHER_AES_128_CCM_SHA256
}

const (
	TOKENS_DIR = "/mqttmtd/tokens/"

	// if server uses mDNS
	// RADDR_ISSUER     = "server.local:18883"
	// RADDR_MQTTBroker = "server.local:1883"
	// else (like docker)
	RADDR_ISSUER     = "server:18883"
	RADDR_MQTTBroker = "server:1883"

	TIMESTAMP_LEN    = 6
	RANDOM_BYTES_LEN = 6
	TOKEN_SIZE       = TIMESTAMP_LEN + RANDOM_BYTES_LEN

	TOKEN_NUM_MULTIPLIER = 16
	ENCKEY_BITLEN        = 128

	TIME_REVOCATION     = time.Hour * 24 * 7
	NONCE_BASE      int = 123456
)

func connRead(conn net.Conn, dst *[]byte, timeout time.Duration) (n int, err error) {
	return common.ConnReadBase(conn, dst, timeout)
}

func connWrite(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	return common.ConnWriteBase(conn, data, timeout)
}

func fetchTokens(req FetchRequest, topic []byte, tokenFilePath string) (encKey []byte, numTokensRemained int, timestamp []byte, randomBytes []byte, err error) {
	if len(topic) > 0x7F {
		return nil, 0, nil, nil, fmt.Errorf("topic must be less than 0x7F letters")
	}
	if !utf8.Valid(topic) {
		return nil, 0, nil, nil, fmt.Errorf("failed fetching: topic is not aligned with utf-8")
	}
	if req.NumTokens%TOKEN_NUM_MULTIPLIER != 0 || req.NumTokens < TOKEN_NUM_MULTIPLIER || req.NumTokens > 0x1F*TOKEN_NUM_MULTIPLIER {
		return nil, 0, nil, nil, fmt.Errorf("failed fetching: numTokens is inappropriate: %d", req.NumTokens)
	}

	cert, err := tls.LoadX509KeyPair(req.ClientCrt, req.ClientKey)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	caCert, err := os.ReadFile(req.CaCrt)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed to load ca certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "server.local",
	}

	conn, err := tls.Dial("tcp", RADDR_ISSUER, config)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error connecting to mTLS server: %v", err)
	}
	fmt.Println("Opened mTLS connection with ", conn.RemoteAddr().String())
	defer func() {
		conn.Close()
		fmt.Println("Closed mTLS connection with ", conn.RemoteAddr().String())
	}()
	// Token File
	var (
		tokenFile *os.File
		completed bool = false
	)

	tokenFile, err = os.Create(tokenFilePath)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed opening file to save tokens: %v", err)
	}
	defer func() {
		tokenFile.Close()
		if !completed {
			fmt.Println("Ended token fetching incomplete : ", err)
			if err = os.Remove(tokenFilePath); err != nil {
				fmt.Printf("failed removing file %s to recover from tokenFile creation failure: %v\n", tokenFilePath, err)
				return
			}
		}
	}()

	firstByte := []byte{byte(req.NumTokens / TOKEN_NUM_MULTIPLIER)}
	if req.AccessType == AccessPub || req.AccessType == AccessPubSub {
		firstByte[0] |= 0x80
	}
	if req.AccessType == AccessSub || req.AccessType == AccessPubSub {
		firstByte[0] |= 0x40
	}
	if req.PayloadCipherType.IsValidCipherType() {
		firstByte[0] |= 0x20
	}
	if _, err = connWrite(conn, firstByte, 0); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error sending out request info: %v", err)
	}

	if req.PayloadCipherType.IsValidCipherType() {
		payloadEncKeyTypeAndTopicLen := make([]byte, 3)
		binary.BigEndian.PutUint16(payloadEncKeyTypeAndTopicLen[:2], uint16(req.PayloadCipherType))
		payloadEncKeyTypeAndTopicLen[2] = byte(len(topic))
		if _, err = connWrite(conn, payloadEncKeyTypeAndTopicLen, 0); err != nil {
			return nil, 0, nil, nil, fmt.Errorf("error sending payload enc keytype and topic len: %v", err)
		}
	} else {
		if _, err = connWrite(conn, []byte{byte(len(topic))}, 0); err != nil {
			return nil, 0, nil, nil, fmt.Errorf("error sending payload enc keytype and topic len: %v", err)
		}
	}

	if _, err = connWrite(conn, topic, 0); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error sending topic out: %v", err)
	}

	// Encryption Key
	if req.PayloadCipherType.IsValidCipherType() {
		var keyByteLen int
		switch req.PayloadCipherType {
		case PAYLOAD_CIPHER_AES_128_GCM_SHA256:
			fallthrough
		case PAYLOAD_CIPHER_AES_128_CCM_SHA256:
			keyByteLen = 16
		case PAYLOAD_CIPHER_AES_256_GCM_SHA384:
			fallthrough
		case PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
			keyByteLen = 32
		}
		encKey = make([]byte, keyByteLen)

		n, err := connRead(conn, &encKey, 0)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("failed reading encryption key with error: %v", err)
		} else if n != keyByteLen {
			return nil, 0, nil, nil, fmt.Errorf("failed reading encryption key: length is inadequate")
		}
		if _, err = tokenFile.Write([]byte{0xFF, byte(req.PayloadCipherType >> 8), byte(req.PayloadCipherType & 0xFF)}); err != nil {
			return nil, 0, nil, nil, fmt.Errorf("failed writing cipherFlag and cipherType: %v", err)
		}
		if _, err = tokenFile.Write(encKey); err != nil {
			return nil, 0, nil, nil, fmt.Errorf("failed writing encryption key: %v", err)
		}
	} else {
		if _, err = tokenFile.Write([]byte{0x00}); err != nil {
			return nil, 0, nil, nil, fmt.Errorf("failed writing cipherFlag(none): %v", err)
		}
	}

	// Timestamp
	timestamp = make([]byte, TIMESTAMP_LEN)
	n, err := connRead(conn, &timestamp, 0)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed reading topic with error: %v", err)
	} else if n != int(TIMESTAMP_LEN) {
		return nil, 0, nil, nil, fmt.Errorf("failed reading topic: length is inadequate")
	}
	// CLIENT ONLY: write timestamp
	if _, err = tokenFile.Write(timestamp); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed writing timestamp: %v", err)
	}

	// Random Bytes
	var numTokensInt = int(req.NumTokens)
	randomBytesAll := make([]byte, RANDOM_BYTES_LEN*numTokensInt)
	if _, err := connRead(conn, &randomBytesAll, time.Minute); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error reading tokens: %v", err)
	}
	if _, err = tokenFile.Write(randomBytesAll[RANDOM_BYTES_LEN:]); err != nil {
		return nil, 0, nil, nil, fmt.Errorf("failed writing random bytes: %v", err)
	}
	randomBytes = randomBytesAll[:RANDOM_BYTES_LEN]
	numTokensRemained = int(req.NumTokens)
	completed = true
	return
}

func popRandomBytesFromFile(tokenFilePath string) (encKey []byte, numTokensRemained int, timestamp []byte, token []byte, err error) {
	var numTokensInTheFile int
	encKey, numTokensInTheFile, timestamp, token, err = common.PopRandomBytesFromFileBase(tokenFilePath, TIMESTAMP_LEN, RANDOM_BYTES_LEN, true, true)
	numTokensRemained = numTokensInTheFile
	return
}

func GetToken(topic string, fetchReq FetchRequest) (encKey []byte, numTokensRemained int, timestamp []byte, token []byte, err error) {
	if fetchReq.NumTokens < TOKEN_NUM_MULTIPLIER || 0x1F*TOKEN_NUM_MULTIPLIER < fetchReq.NumTokens || fetchReq.NumTokens%TOKEN_NUM_MULTIPLIER != 0 {
		log.Fatalf("Invalid number of token generation. It must be between [%d, 0x1F*%d] and multiples of %d\n", TOKEN_NUM_MULTIPLIER, TOKEN_NUM_MULTIPLIER, TOKEN_NUM_MULTIPLIER)
	}
	topic = strings.TrimSpace(topic)

	if err := os.MkdirAll(TOKENS_DIR, 0666); err != nil {
		log.Fatalf("Failed creating Tokens directory at %s: %v", TOKENS_DIR, err)
	}
	tokenFilePath := TOKENS_DIR + fetchReq.AccessType.String() + base64.RawURLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	encKey, numTokensRemained, timestamp, token, err = popRandomBytesFromFile(tokenFilePath)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("error when popping random bytes from file: %v", err)
	}
	if timestamp == nil || token == nil {
		encKey, numTokensRemained, timestamp, token, err = fetchTokens(fetchReq, unsafe.Slice(unsafe.StringData(topic), len(topic)), tokenFilePath)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("error when fetching random bytes from server: %v", err)
		}
		if timestamp == nil || token == nil {
			return nil, 0, nil, nil, fmt.Errorf("unexpectedly failed fetching tokens")
		}
	}
	return
}
