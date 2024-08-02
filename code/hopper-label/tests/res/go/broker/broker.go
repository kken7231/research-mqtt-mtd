package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/kken7231/research-mqtt-mtd/code/hopper-label/common"
)

var (
	PUB_TOKENS        = make([][]byte, 0)
	PUB_TOPIC_NAMES   = make([][]byte, 0)
	SUB_TOKENS        = make([][]byte, 0)
	SUB_TOPIC_FILTERS = make([][]byte, 0)
	mu                sync.Mutex
)

func getPublishFilePath(topicName []byte, host string) (filePath string) {
	return fmt.Sprintf("%s/publish/%s-%s", common.BROKER_OUTPUT_DIRECTORY, common.BytesToB64EncodedString(topicName), host)
}

func getSubscribeFilePath(topicFilter []byte, host string) (filePath string) {
	return fmt.Sprintf("%s/subscribe/%s-%s", common.BROKER_OUTPUT_DIRECTORY, common.BytesToB64EncodedString(topicFilter), host)
}

func isTwoBytesEqual(a []byte, b []byte) (isEqual bool) {
	if len(a) != len(b) {
		return false
	}

	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func registerCurrentToken(topicSpecifiers *[][]byte, tokens *[][]byte, topicSpecifier []byte, token []byte) {
	*tokens = append(*tokens, token)
	*topicSpecifiers = append(*topicSpecifiers, topicSpecifier)
}

func updateCurrentToken(topicSpecifiers [][]byte, tokens *[][]byte, topicSpecifier []byte, newToken []byte) (isUpdateDone bool) {
	for i, s := range topicSpecifiers {
		if isTwoBytesEqual(s, topicSpecifier) {
			(*tokens)[i] = newToken
			return true
		}
	}
	return false
}

func revokeCurrentToken(topicSpecifiers *[][]byte, tokens *[][]byte, token []byte) (isRevocationDone bool) {
	for i, t := range *tokens {
		if isTwoBytesEqual(t, token) {
			(*tokens)[i] = (*tokens)[len(*tokens)-1]
			*tokens = (*tokens)[:len(*tokens)-1]
			(*topicSpecifiers)[i] = (*topicSpecifiers)[len(*topicSpecifiers)-1]
			*topicSpecifiers = (*topicSpecifiers)[:len(*topicSpecifiers)-1]
			return true
		}
	}
	return false
}

func getTopicSpecifierFromCurrentToken(topicSpecifiers [][]byte, tokens [][]byte, token []byte) (topicSpecifier []byte, ok bool) {
	for i, t := range tokens {
		if isTwoBytesEqual(t, token) {
			return topicSpecifiers[i], true
		}
	}
	return nil, false
}

func decodeTokenIfB64(token []byte) ([]byte, error) {
	var err error = nil
	if len(token) != common.TOKEN_LEN {
		converted, err := common.B64EncodedStringToBytes(unsafe.String(unsafe.SliceData(token), len(token)))
		if err != nil {
			return nil, err
		}
		return converted, err
	} else {
		return token, err
	}
}

func initTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(common.BROKER_CERT_FILE, common.BROKER_KEY_FILE)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(common.CA_CERT_FILE)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, err
}

func getMQTTVersion(packetData []byte, packetLen int, packetLenLen int) (uint8, error) {
	packetVarHeaderOffset := 1 + packetLenLen

	if packetLen < packetVarHeaderOffset+2 {
		return 0xFF, fmt.Errorf("not a valid CONNECT packet")
	}

	if !isTwoBytesEqual(packetData[packetVarHeaderOffset:packetVarHeaderOffset+6], []byte{0x00, 0x04, 0x4D, 0x51, 0x54, 0x54}) || packetLen < packetVarHeaderOffset+7 {
		return 0xFF, fmt.Errorf("protocol name is not MQTT")
	}

	fmt.Printf("MQTT Version Level is 0x%X\n", packetData[packetVarHeaderOffset+6])
	return packetData[packetVarHeaderOffset+6], nil
}

func replaceTokenWithTopicName(packetData []byte, packetLen int, packetLenLen int, host string) ([]byte, error) {
	packetVarHeaderOffset := 1 + packetLenLen

	tokenLen := int(binary.BigEndian.Uint16(packetData[packetVarHeaderOffset : packetVarHeaderOffset+2]))
	if packetLen < packetVarHeaderOffset+tokenLen {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, "illegal packet, probably topic name length is wrong")
	}

	token, err := decodeTokenIfB64(packetData[packetVarHeaderOffset+2 : packetVarHeaderOffset+2+tokenLen])
	if err != nil {
		return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, err)
	}
	if len(token) != common.TOKEN_LEN {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, fmt.Sprintf("illegal token: %d", len(token)))
	}

	topicName, ok := getTopicSpecifierFromCurrentToken(PUB_TOPIC_NAMES, PUB_TOKENS, token)
	if !ok {
		sb := strings.Builder{}
		sb.WriteByte('[')
		for _, token := range PUB_TOKENS {
			sb.WriteString(common.BytesToB64EncodedString(token))
			sb.WriteByte(',')
		}
		sb.WriteByte(']')
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, fmt.Sprintf("no topic name found: %s", sb.String()))
	}

	topicNameLen := len(topicName)
	if topicNameLen > 0xFF {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, "found a too long topic name")
	}

	filePath := getPublishFilePath(topicName, host)
	if _, err := os.Stat(filePath); err == nil {
		storedTokens, err := os.ReadFile(filePath)
		if err != nil {
			return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, err)
		}

		updateCurrentToken(PUB_TOPIC_NAMES, &PUB_TOKENS, topicName, storedTokens[:common.TOKEN_LEN])

		storedTokensLen := len(storedTokens)
		if storedTokensLen < common.TOKEN_LEN*2 || storedTokensLen%common.TOKEN_LEN != 0 {
			os.Remove(filePath)
		} else {
			err = os.WriteFile(filePath, storedTokens[common.TOKEN_LEN:], os.ModePerm)
			if err != nil {
				return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, err)
			}
		}
	} else {
		revokeCurrentToken(&PUB_TOPIC_NAMES, &PUB_TOKENS, token)
	}

	newPacketLen, err := common.ToVariableByteInteger(packetLen - tokenLen + topicNameLen)
	if err != nil {
		return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_NAME_INVALID, err)
	}
	newPacketData := bytes.NewBuffer([]byte{})
	newPacketData.WriteByte(packetData[0])
	newPacketData.Write(newPacketLen)
	newPacketData.WriteByte(byte((topicNameLen >> 8) & 0xFF))
	newPacketData.WriteByte(byte(topicNameLen & 0xFF))
	newPacketData.Write(topicName)
	newPacketData.Write(packetData[packetVarHeaderOffset+2+tokenLen:])

	return newPacketData.Bytes(), nil
}

func replaceTokenWithTopicFilter(packetData []byte, packetLen int, packetLenLen int, mqttVersion byte, host string) ([]byte, error) {
	packetVarHeaderOffset := 1 + packetLenLen
	var packetPayloadOffset int
	if mqttVersion == 5 {
		propertyLen, propertyLenLen, err := common.GetVariableByteInteger(packetData, packetVarHeaderOffset+2)
		if err != nil {
			return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, err)
		}
		packetPayloadOffset = packetVarHeaderOffset + 2 + propertyLenLen + propertyLen
	} else {
		packetPayloadOffset = packetVarHeaderOffset + 2
	}

	tokenLen := int(binary.BigEndian.Uint16(packetData[packetPayloadOffset : packetPayloadOffset+2]))
	if packetLen < packetPayloadOffset+tokenLen {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, "illegal packet, probably topic filter length is wrong")
	}

	token, err := decodeTokenIfB64(packetData[packetPayloadOffset+2 : packetPayloadOffset+2+tokenLen])
	if err != nil {
		return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, err)
	}
	if len(token) != common.TOKEN_LEN {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, fmt.Sprintf("illegal token: %d", len(token)))
	}

	topicFilter, ok := getTopicSpecifierFromCurrentToken(SUB_TOPIC_FILTERS, SUB_TOKENS, token)
	if !ok {
		sb := strings.Builder{}
		sb.WriteByte('[')
		for _, token := range PUB_TOKENS {
			sb.WriteString(common.BytesToB64EncodedString(token))
			sb.WriteByte(',')
		}
		sb.WriteByte(']')
		return []byte{}, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, fmt.Sprintf("no topic filter found: %s", sb.String()))
	}

	topicFilterLen := len(topicFilter)
	if topicFilterLen > 0xFF {
		return nil, common.NewMQTTMTDError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, "found a too long topic filter")
	}

	filePath := getSubscribeFilePath(topicFilter, host)
	if _, err := os.Stat(filePath); err == nil {
		storedTokens, err := os.ReadFile(filePath)
		if err != nil {
			return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, err)
		}

		updateCurrentToken(SUB_TOPIC_FILTERS, &SUB_TOKENS, topicFilter, storedTokens[:common.TOKEN_LEN])

		storedTokensLen := len(storedTokens)
		if storedTokensLen < common.TOKEN_LEN*2 || storedTokensLen%common.TOKEN_LEN != 0 {
			os.Remove(filePath)
		} else {
			err = os.WriteFile(filePath, storedTokens[common.TOKEN_LEN:], os.ModePerm)
			if err != nil {
				return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, err)
			}
		}
	} else {
		revokeCurrentToken(&SUB_TOPIC_FILTERS, &SUB_TOKENS, token)
	}

	newPacketLen, err := common.ToVariableByteInteger(packetLen - tokenLen + topicFilterLen)
	if err != nil {
		return nil, common.NewMQTTMTDErrorFromError(common.DISCON_REASON_CD_TOPIC_FILTER_INVALID, err)
	}
	newPacketData := bytes.NewBuffer([]byte{})
	newPacketData.WriteByte(packetData[0])
	newPacketData.Write(newPacketLen)
	newPacketData.Write(packetData[packetVarHeaderOffset:packetPayloadOffset])
	newPacketData.WriteByte(byte((topicFilterLen >> 8) & 0xFF))
	newPacketData.WriteByte(byte(topicFilterLen & 0xFF))
	newPacketData.Write(topicFilter)
	newPacketData.Write(packetData[packetPayloadOffset+2+tokenLen:])

	return newPacketData.Bytes(), nil
}

func issueTokens(dist *bytes.Buffer, packetType common.IssuablePacketType, topic []byte, host string, numOfTokens int) ([]byte, error) {
	if numOfTokens < 0 {
		return nil, fmt.Errorf("number of randoms must be positive")
	}

	// Open file
	var filePath string
	if packetType == common.CTRL_PACKET_TYPES_PUBLISH {
		filePath = getPublishFilePath(topic, host)
	} else {
		filePath = getSubscribeFilePath(topic, host)
	}
	output, err := os.Create(filePath)
	if err != nil {
		return nil, (err)
	}
	defer func() {
		if err := output.Close(); err != nil {
			fmt.Println("Closing a file failed")
		}
	}()

	// Lock mu to ban concurrent issue
	mu.Lock()
	defer mu.Unlock()

	// Generate
	timestamp := make([]byte, 8)
	randomPart := make([]byte, common.RANDOM_BYTES_LEN)

	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	timestamp = timestamp[1 : 1+common.TIMESTAMP_LEN]

	nRand, err := rand.Read(randomPart)
	if err != nil || nRand != common.RANDOM_BYTES_LEN {
		return nil, fmt.Errorf("generation of random bytes failed")
	}
	firstToken := append(timestamp, randomPart...)
	// output.Write(firstToken)
	dist.Write(firstToken)

	for i := 1; i < numOfTokens; i++ {
		nRand, err = rand.Read(randomPart)
		if err != nil || nRand != common.RANDOM_BYTES_LEN {
			return nil, fmt.Errorf("generation of random bytes failed")
		}
		output.Write(timestamp)
		output.Write(randomPart)
		dist.Write(timestamp)
		dist.Write(randomPart)
	}
	return firstToken, err
}

func generate(dist *bytes.Buffer, packetType common.IssuablePacketType, topic []byte, host string, numOfTokens int) error {
	var topicSpecifiers, tokens *[][]byte
	if packetType == common.CTRL_PACKET_TYPES_PUBLISH {
		topicSpecifiers = &PUB_TOPIC_NAMES
		tokens = &PUB_TOKENS
	} else {
		topicSpecifiers = &SUB_TOPIC_FILTERS
		tokens = &SUB_TOKENS
	}

	firstToken, err := issueTokens(dist, packetType, topic, host, numOfTokens)
	if err != nil {
		return err
	}

	updated := updateCurrentToken(*topicSpecifiers, tokens, topic, firstToken)
	if !updated {
		registerCurrentToken(topicSpecifiers, tokens, topic, firstToken)
	}
	return nil
}

func tokenIssuerHandler(conn *tls.Conn) {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Printf("Error handling host and port: %v\n", err)
		return
	}

	fmt.Printf("TLS connection established from %s\n", addr)
	defer func() {
		conn.Close()
		fmt.Printf("TLS connection closed from %s\n", addr)
	}()

	// Receive from the client
	data := make([]byte, 1024)
	packetDataLen, err := conn.Read(data)
	if err != nil && err != io.EOF {
		fmt.Printf("Error reading from %s: %v\n", addr, err)
		return
	}
	if packetDataLen == 0 {
		return
	}
	packetData := data[:packetDataLen]
	common.PrintPacket("incoming", conn, packetData, true)

	buf := bytes.NewBuffer([]byte{})

	// Generate tokens
	if packetDataLen > 5 {
		purposeAndNumMSB := packetData[0]
		numOfTokensGene := ((int(purposeAndNumMSB) & 0x7F) << 8) | int(packetData[1])
		if numOfTokensGene == 0 {
			numOfTokensGene = common.NUM_TOKENS_PER_GENE_DEFAULT
		}
		topicLen := int(packetData[2])<<8 | int(packetData[3])
		if topicLen > 0 {
			if packetDataLen == 4+topicLen {
				if purposeAndNumMSB&0x80 == common.FETCH_TOKEN_FOR_PUB {
					// publish
					topicName := packetData[4:]
					if len(topicName) > 0 && !bytes.ContainsAny(topicName, "+#") {
						generate(buf, common.CTRL_PACKET_TYPES_PUBLISH, topicName, host, numOfTokensGene)
					} else {
						fmt.Printf("[PUBLISH] invalid topic name \"%s\"\n", topicName)
					}
				} else {
					// subscribe
					topicFilter := packetData[4:]
					if len(topicFilter) > 0 {
						generate(buf, common.CTRL_PACKET_TYPES_SUBSCRIBE, topicFilter, host, numOfTokensGene)
					} else {
						fmt.Println("[SUBSCRIBE] topic filter has no content.")
					}
				}
			} else {
				fmt.Println("irrelevant topic name len")
			}
		} else {
			fmt.Println("no topic name")
		}
	} else {
		fmt.Println("length too short")
	}
	_, err = conn.Write(buf.Bytes())

	// Send the responce back
	if err != nil {
		fmt.Printf("Error sending to %s: %v\n", addr, err)
	} else {
		common.PrintPacket("outgoing", conn, buf.Bytes(), true)
	}
}

func tokenResolverHandler(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Printf("Error handling host and port: %v\n", err)
		return
	}

	fmt.Printf("Plain connection established from %s\n", addr)
	defer func() {
		conn.Close()
		fmt.Printf("Plain connection closed from %s\n", addr)
	}()

	brokerConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", common.PORT_BROKER))
	if err != nil {
		fmt.Printf("Error connecting to broker: %v\n", err)
		return
	}
	defer brokerConn.Close()

	var mqttVersion uint8 = 0x00

	for {
		// Receive from the client
		data := make([]byte, 1024)
		n, err := conn.Read(data)
		if err != nil && err != io.EOF {
			fmt.Printf("Error reading from %s: %v\n", addr, err)
			break
		}
		if n == 0 {
			break
		}
		packetData := data[:n]
		common.PrintPacket("incoming", conn, packetData, false, mqttVersion)

		// Replace the token & pass it to the broker
		packetType, _, packetLen, packetLenLen, err := common.GetMQTTControlHeader(packetData)
		if err == nil {
			if packetType == byte(common.CTRL_PACKET_TYPES_CONNECT) {
				mqttVersion, err = getMQTTVersion(packetData, packetLen, packetLenLen)
			} else if packetType == byte(common.CTRL_PACKET_TYPES_PUBLISH) {
				packetData, err = replaceTokenWithTopicName(packetData, packetLen, packetLenLen, host)
			} else if packetType == byte(common.CTRL_PACKET_TYPES_SUBSCRIBE) {
				packetData, err = replaceTokenWithTopicFilter(packetData, packetLen, packetLenLen, mqttVersion, host)
			}
		} else {
			err = common.NewMQTTMTDErrorFromError(0x81, err)
		}
		if err != nil {
			fmt.Printf("Error replacing a token: %v\n", err)
			var mqttmtderr *common.MQTTMTDError
			if errors.As(err, &mqttmtderr) {
				buf := []byte{common.CTRL_PACKET_TYPES_DISCONNECT, 0x01, mqttmtderr.ReasonCode}
				_, err = conn.Write(buf)
				if err != nil {
					fmt.Printf("Error sending DISCONNECT to %s: %v\n", addr, err)
				} else {
					common.PrintPacket("outgoing", conn, buf, false, mqttVersion)
				}
			}
			break
		}
		_, err = brokerConn.Write(packetData)
		if err != nil {
			fmt.Printf("Error sending to broker: %v\n", err)
			break
		}
		common.PrintPacket("outgoing", brokerConn, packetData, false, mqttVersion)

		// Receive the response from the broker
		response := make([]byte, 1024)
		n, err = brokerConn.Read(response)
		if err != nil && err != io.EOF {
			fmt.Printf("Error reading from broker: %v\n", err)
			break
		}
		response = response[:n]
		common.PrintPacket("incoming", brokerConn, response, false, mqttVersion)

		// Pass the responce down to the client
		_, err = conn.Write(response)
		if err != nil {
			fmt.Printf("Error sending to %s: %v\n", addr, err)
			break
		}
		common.PrintPacket("outgoing", conn, response, false, mqttVersion)
	}
}

func runServer(address string, isTokenIssuer bool) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Printf("Listening on %s (%s)\n", address, func() string {
		if isTokenIssuer {
			return "TLS"
		}
		return "Plain"
	}())

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		if isTokenIssuer {
			tlsConfig, err := initTLSConfig()
			if err != nil {
				fmt.Printf("Error accepting connection: %v\n", err)
				continue
			}
			tlsConn := tls.Server(conn, tlsConfig)
			go tokenIssuerHandler(tlsConn)
		} else {
			go tokenResolverHandler(conn)
		}
	}
}

func main() {
	common.EnsureOutputDir(common.BROKER_OUTPUT_DIRECTORY)
	common.EnsureOutputDir(common.BROKER_OUTPUT_DIRECTORY)
	common.EnsureOutputDir(common.BROKER_OUTPUT_DIRECTORY)

	go runServer(common.SERVER_ADDR_TOKEN_RESOLVER, true)
	go runServer(common.SERVER_ADDR_TOKEN_ISSUER, false)

	fmt.Println("TLS server and plain server are running in background threads.")

	select {} // keep the main function running
}
