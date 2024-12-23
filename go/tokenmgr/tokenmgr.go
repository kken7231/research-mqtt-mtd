package tokenmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"unicode/utf8"
	"unsafe"

	"mqttmtd/config"
	"mqttmtd/consts"
	"mqttmtd/funcs"
	"mqttmtd/types"
)

type FetchRequest struct {
	NumTokens       uint16
	AccessTypeIsPub bool
	PayloadAEADType types.PayloadAEADType
}

func saveTokenInfo(issuerRequest types.IssuerRequest, issuerResponse types.IssuerResponse, tokenFilePath string) (err error) {
	var (
		tokenFile *os.File
		completed bool = false
	)
	// Token File
	tokenFile, err = os.Create(tokenFilePath)
	if err != nil {
		err = fmt.Errorf("failed opening file to save tokens: %v", err)
		return
	}
	defer func() {
		tokenFile.Close()
		if !completed {
			fmt.Println("Ended token saving incomplete : ", err)
			if err = os.Remove(tokenFilePath); err != nil {
				fmt.Printf("failed removing file %s to recover from tokenFile creation failure: %v\n", tokenFilePath, err)
				return
			}
		}
	}()

	// Payload AEAD
	buf := make([]byte, 2)
	buf[0] = byte(issuerRequest.PayloadAEADType)
	if _, err = tokenFile.Write(buf[:1]); err != nil {
		return fmt.Errorf("failed writing aead type: %v", err)
	}
	if issuerRequest.PayloadAEADType.IsEncryptionEnabled() {
		// Encryption Key
		if _, err = tokenFile.Write(issuerResponse.EncryptionKey); err != nil {
			return fmt.Errorf("failed writing encryption key: %v", err)
		}

		// Token Index
		binary.BigEndian.PutUint16(buf, uint16(issuerRequest.NumberOfTokensDividedByMultiplier*consts.TOKEN_NUM_MULTIPLIER))
		if _, err = tokenFile.Write(buf); err != nil {
			return fmt.Errorf("failed writing token index: %v", err)
		}
	}

	// Timestamp
	if _, err = tokenFile.Write(issuerResponse.Timestamp); err != nil {
		return fmt.Errorf("failed writing timestamp: %v", err)
	}

	// Random Bytes
	if _, err := tokenFile.Write(issuerResponse.AllRandomBytes); err != nil {
		return fmt.Errorf("failed writing random bytes: %v", err)
	}
	completed = true
	return
}

func popTokenInfo(tokenFilePath string) (encKey []byte, tokenIndex uint16, token []byte, err error) {
	var (
		n               int
		tokenFile       *os.File
		tokenTempFile   *os.File
		completed       bool = false
		closeNotNeeded  bool = false
		tempFileRenamed bool = false

		aeadType        types.PayloadAEADType
		aeadTypeBytes   []byte
		tokenIndexBytes []byte
		randomBytes     []byte
	)
	// Token File
	tokenFile, err = os.Open(tokenFilePath)
	if err != nil {
		err = fmt.Errorf("failed opening file to read tokens: %v", err)
		return
	}
	defer func() {
		if !closeNotNeeded {
			tokenFile.Close()
		}
		if !completed {
			fmt.Println("Ended token popping incomplete : ", err)
			if err = os.Remove(tokenFilePath); err != nil {
				fmt.Printf("failed removing file %s to recover from tokenFile creation failure: %v\n", tokenFilePath, err)
				return
			}
		}
	}()
	// Payload AEAD
	aeadTypeBytes = make([]byte, 1)
	if n, err = tokenFile.Read(aeadTypeBytes); err != nil {
		err = fmt.Errorf("failed writing aead type: %v", err)
		goto popTokenInfoErr
	} else if n != 1 {
		err = fmt.Errorf("failed reading aead type, length too short")
		goto popTokenInfoErr
	}
	aeadType = types.PayloadAEADType(aeadTypeBytes[0])
	if aeadType.IsEncryptionEnabled() {
		// Encryption Key
		encKey = make([]byte, aeadType.GetKeyLen())
		if n, err = tokenFile.Read(encKey); err != nil {
			err = fmt.Errorf("failed reading encKey: %v", err)
			goto popTokenInfoErr
		} else if n != aeadType.GetKeyLen() {
			err = fmt.Errorf("failed reading encKey, length too short")
			goto popTokenInfoErr
		}

		// Token Index
		tokenIndexBytes = make([]byte, 2)
		if n, err = tokenFile.Read(tokenIndexBytes); err != nil {
			err = fmt.Errorf("failed reading tokenIndex: %v", err)
			goto popTokenInfoErr
		} else if n != 2 {
			err = fmt.Errorf("failed reading tokenIndex, length too short")
			goto popTokenInfoErr
		}
		tokenIndex = binary.BigEndian.Uint16(tokenIndexBytes)
	}

	// Token
	token = make([]byte, consts.TOKEN_SIZE)
	if n, err = tokenFile.Read(token); err != nil {
		err = fmt.Errorf("failed reading token: %v", err)
		goto popTokenInfoErr
	} else if n != consts.TOKEN_SIZE {
		err = fmt.Errorf("failed reading token, length too short")
		goto popTokenInfoErr
	}

	// Next Random Bytes?
	randomBytes = make([]byte, consts.RANDOM_BYTES_LEN)
	if n, err = tokenFile.Read(randomBytes); err != nil {
		// no remaining, remove file
		fmt.Printf("removing file %s since no token left\n", tokenFilePath)
		tokenFile.Close()
		if err = os.Remove(tokenFilePath); err != nil {
			fmt.Printf("failed removing file %s since no token left: %v\n", tokenFilePath, err)
			return
		}
		closeNotNeeded = true
		completed = true
		return
	} else if n != consts.RANDOM_BYTES_LEN {
		// illegal remaining, remove file
		fmt.Printf("removing file %s since token illegaly left\n", tokenFilePath)
		tokenFile.Close()
		if err = os.Remove(tokenFilePath); err != nil {
			fmt.Printf("failed removing file %s since token illegaly left: %v\n", tokenFilePath, err)
			return
		}
		closeNotNeeded = true
		completed = true
		return
	}

	// Token Temp File
	tokenTempFile, err = os.Create(tokenFilePath + ".tmp")
	if err != nil {
		err = fmt.Errorf("failed opening file to save tokens: %v", err)
		return
	}
	defer func() {
		if !closeNotNeeded {
			tokenTempFile.Close()
		}
		if !tempFileRenamed {
			fmt.Println("Ended token popping incomplete : ", err)
			if err = os.Remove(tokenFilePath + ".tmp"); err != nil {
				fmt.Printf("failed removing temp file %s to recover from tokenFile creation failure: %v\n", tokenFilePath, err)
				return
			}
		}
	}()

	// Payload AEAD
	if _, err = tokenTempFile.Write(aeadTypeBytes); err != nil {
		err = fmt.Errorf("failed writing aead to temp: %v", err)
		goto popTokenInfoErr
	}
	if aeadType.IsEncryptionEnabled() {
		// Encryption Key
		if _, err = tokenTempFile.Write(encKey); err != nil {
			err = fmt.Errorf("failed writing encryption key to temp: %v", err)
			goto popTokenInfoErr
		}

		// Token Index
		tokenIndex++
		binary.BigEndian.PutUint16(tokenIndexBytes, tokenIndex)
		if _, err = tokenTempFile.Write(tokenIndexBytes); err != nil {
			err = fmt.Errorf("failed writing token index to temp: %v", err)
			goto popTokenInfoErr
		}
	}

	// Timestamp
	if _, err = tokenTempFile.Write(token[:consts.TIMESTAMP_LEN]); err != nil {
		err = fmt.Errorf("failed writing timestamp to temp: %v", err)
		goto popTokenInfoErr
	}

	// Remaining Random Bytes
	n = consts.RANDOM_BYTES_LEN
	for err == nil && n == consts.RANDOM_BYTES_LEN {
		if _, err = tokenTempFile.Write(randomBytes); err != nil {
			err = fmt.Errorf("failed writing random bytes: %v", err)
			goto popTokenInfoErr
		}

		n, err = tokenFile.Read(randomBytes)
	}

	// Rename
	tokenFile.Close()
	tokenTempFile.Close()
	closeNotNeeded = true
	if err = os.Rename(tokenFilePath+".tmp", tokenFilePath); err != nil {
		err = fmt.Errorf("failed renaming tmp file: %v", err)
		goto popTokenInfoErr
	}
	tempFileRenamed = true
	completed = true
	return

popTokenInfoErr:
	encKey = nil
	token = nil
	return
}

func fetchTokens(req FetchRequest, topic []byte, tokenFilePath string) (err error) {
	if len(topic) > consts.MAX_UTF8_ENCODED_STRING_SIZE {
		err = fmt.Errorf("topic must be less than %d letters", consts.MAX_UTF8_ENCODED_STRING_SIZE)
		return
	}
	if !utf8.Valid(topic) {
		err = fmt.Errorf("failed fetching: topic is not aligned with utf-8")
		return
	}
	if req.NumTokens%consts.TOKEN_NUM_MULTIPLIER != 0 || req.NumTokens < consts.TOKEN_NUM_MULTIPLIER || req.NumTokens > 0x1F*consts.TOKEN_NUM_MULTIPLIER {
		err = fmt.Errorf("failed fetching: numTokens is inappropriate: %d", req.NumTokens)
		return
	}

	cert, err := tls.LoadX509KeyPair(config.Client.Certs.ClientCertFilePath, config.Client.Certs.ClientKeyFilePath)
	if err != nil {
		err = fmt.Errorf("failed to load client certificate: %v", err)
		return
	}

	caCert, err := os.ReadFile(config.Client.Certs.CaCertFilePath)
	if err != nil {
		err = fmt.Errorf("failed to load ca certificate: %v", err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   "server.local",
	}

	conn, err := tls.Dial("tcp", config.Client.IssuerAddr, tlsConf)
	if err != nil {
		err = fmt.Errorf("error connecting to mTLS server: %v", err)
		return
	}
	fmt.Println("Opened mTLS connection with ", conn.RemoteAddr().String())
	defer func() {
		conn.Close()
		fmt.Println("Closed mTLS connection with ", conn.RemoteAddr().String())
	}()

	// Send Issue Request
	request := types.IssuerRequest{
		AccessTypeIsPub:                   req.AccessTypeIsPub,
		PayloadAEADRequested:              req.PayloadAEADType.IsEncryptionEnabled(),
		NumberOfTokensDividedByMultiplier: byte(req.NumTokens / consts.TOKEN_NUM_MULTIPLIER),
		PayloadAEADType:                   req.PayloadAEADType,
		Topic:                             topic,
	}
	err = funcs.SendIssuerRequest(context.TODO(), conn, config.Client.SocketTimeout.External, request)
	if err != nil {
		return
	}

	// Receive Issuer Response
	var response types.IssuerResponse
	response, err = funcs.ParseIssuerResponse(context.TODO(), conn, config.Client.SocketTimeout.External, request)
	if err != nil {
		return
	}

	// Save Response
	err = saveTokenInfo(request, response, tokenFilePath)

	return
}

func GetToken(topic string, fetchReq FetchRequest) (encKey []byte, tokenIndex uint16, token []byte, err error) {
	if fetchReq.NumTokens < consts.TOKEN_NUM_MULTIPLIER || 0x1F*consts.TOKEN_NUM_MULTIPLIER < fetchReq.NumTokens || fetchReq.NumTokens%consts.TOKEN_NUM_MULTIPLIER != 0 {
		log.Fatalf("Invalid number of token generation. It must be between [%d, 0x1F*%d] and multiples of %d\n", consts.TOKEN_NUM_MULTIPLIER, consts.TOKEN_NUM_MULTIPLIER, consts.TOKEN_NUM_MULTIPLIER)
	}
	topic = strings.TrimSpace(topic)

	if err := os.MkdirAll(config.Client.FilePaths.TokensDirPath, 0666); err != nil {
		log.Fatalf("Failed creating Tokens directory at %s: %v", config.Client.FilePaths.TokensDirPath, err)
	}
	var accessTypeStr string
	if fetchReq.AccessTypeIsPub {
		accessTypeStr = "PUB"
	} else {
		accessTypeStr = "SUB"
	}
	tokenFilePath := config.Client.FilePaths.TokensDirPath + accessTypeStr + base64.URLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	if _, err = os.Stat(tokenFilePath); err != nil {
		// fetch needed
		err = fetchTokens(fetchReq, unsafe.Slice(unsafe.StringData(topic), len(topic)), tokenFilePath)
		if err != nil {
			err = fmt.Errorf("error when fetching random bytes from server: %v", err)
			return
		}
	}
	encKey, tokenIndex, token, err = popTokenInfo(tokenFilePath)
	if err != nil {
		err = fmt.Errorf("error when popping random bytes from file: %v", err)
		return
	}
	return
}
