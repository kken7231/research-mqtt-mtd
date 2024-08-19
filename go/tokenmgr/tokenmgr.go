package tokenmgr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

type FetchRequest struct {
	NumTokens  byte
	AccessType AccessType
	CaCrt      string
	ClientCrt  string
	ClientKey  string
}

const (
	TOKENS_DIR = "/mqttmtd/tokens/"

	RADDR_ISSUER     = "192.168.11.11:18883"
	RADDR_MQTTBroker = "192.168.11.11:1883"

	TIMESTAMP_LEN    = 6
	RANDOM_BYTES_LEN = 6
	TOKEN_SIZE       = TIMESTAMP_LEN + RANDOM_BYTES_LEN

	TIME_REVOCATION = time.Hour * 24 * 7
)

func connRead(conn net.Conn, dst *[]byte, timeout time.Duration) (n int, err error) {
	return common.ConnReadBase(conn, dst, timeout)
}

func connWrite(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	return common.ConnWriteBase(conn, data, timeout)
}

func fetchTokens(req FetchRequest, topic []byte, tokenFilePath string) ([]byte, []byte, error) {
	if len(topic) > 0x7F {
		return nil, nil, fmt.Errorf("topic must be less than 0x7F letters")
	}
	if !utf8.Valid(topic) {
		return nil, nil, fmt.Errorf("failed fetching: topic is not aligned with utf-8")
	}
	if req.NumTokens%4 != 0 || req.NumTokens < 4 || req.NumTokens > 0x3F*4 {
		return nil, nil, fmt.Errorf("failed fetching: numTokens is inappropriate: %d", req.NumTokens)
	}

	cert, err := tls.LoadX509KeyPair(req.ClientCrt, req.ClientKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	caCert, err := os.ReadFile(req.CaCrt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load ca certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "server",
	}

	conn, err := tls.Dial("tcp", RADDR_ISSUER, config)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to mTLS server: %v", err)
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
		return nil, nil, fmt.Errorf("failed opening file to save tokens: %v", err)
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

	// Info
	firstTwoBytes := []byte{byte(req.NumTokens / 4), byte(len(topic))}
	if req.AccessType == AccessPub || req.AccessType == AccessPubSub {
		firstTwoBytes[0] |= 0x80
	}
	if req.AccessType == AccessSub || req.AccessType == AccessPubSub {
		firstTwoBytes[0] |= 0x40
	}
	if _, err = connWrite(conn, firstTwoBytes, 0); err != nil {
		return nil, nil, fmt.Errorf("error sending out request info: %v", err)
	}
	if _, err = connWrite(conn, topic, 0); err != nil {
		return nil, nil, fmt.Errorf("error sending topic out: %v", err)
	}

	// Timestamp
	timestamp := make([]byte, TIMESTAMP_LEN)
	n, err := connRead(conn, &timestamp, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading topic with error: %v", err)
	} else if n != int(TIMESTAMP_LEN) {
		return nil, nil, fmt.Errorf("failed reading topic: length is inadequate")
	}
	// CLIENT ONLY: write timestamp
	if _, err = tokenFile.Write(timestamp); err != nil {
		return nil, nil, fmt.Errorf("failed writing timestamp: %v", err)
	}

	// Random Bytes
	randomBytes := make([]byte, RANDOM_BYTES_LEN)
	firstRandomBytes := make([]byte, RANDOM_BYTES_LEN)
	var numTokensInt = int(req.NumTokens)
	for i := 0; i < numTokensInt; i++ {
		if _, err := connRead(conn, &randomBytes, time.Minute); err != nil {
			return nil, nil, fmt.Errorf("error reading tokens: %v", err)
		}

		if i > 0 {
			tokenFile.Write(randomBytes)
		} else {
			for j := 0; j < RANDOM_BYTES_LEN; j++ {
				firstRandomBytes[j] = randomBytes[j]
			}
		}
	}
	completed = true
	return timestamp, firstRandomBytes, nil
}

func popRandomBytesFromFile(tokenFilePath string) ([]byte, []byte, error) {
	return common.PopRandomBytesFromFileBase(tokenFilePath, TIMESTAMP_LEN, RANDOM_BYTES_LEN, true)
}

func GetToken(topic string, fetchReq FetchRequest) ([]byte, []byte, error) {
	if fetchReq.NumTokens < 4 || 0x3F*4 < fetchReq.NumTokens || fetchReq.NumTokens%4 != 0 {
		log.Fatalln("Invalid number of token generation. It must be between [4, 0x3F*4] and multiples of 4")
	}
	topic = strings.TrimSpace(topic)

	if err := os.MkdirAll(TOKENS_DIR, 0666); err != nil {
		log.Fatalf("Failed creating Tokens directory at %s: %v", TOKENS_DIR, err)
	}
	tokenFilePath := TOKENS_DIR + fetchReq.AccessType.String() + base64.RawURLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	timestamp, token, err := popRandomBytesFromFile(tokenFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error when popping random bytes from file: %v", err)
	}
	if timestamp == nil || token == nil {
		timestamp, token, err = fetchTokens(fetchReq, unsafe.Slice(unsafe.StringData(topic), len(topic)), tokenFilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("error when fetching random bytes from server: %v", err)
		}
		if timestamp == nil || token == nil {
			return nil, nil, fmt.Errorf("unexpectedly failed fetching tokens")
		}
	}
	return timestamp, token, nil
}
