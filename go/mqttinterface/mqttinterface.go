package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/authserver/types"
	"go/common"
	"go/mqttinterface/mqttparser"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	LADDR_MQTTINTERFACE string = ":1883"
	RADDR_VERIFIER      string = ":21883"
	RADDR_MQTTBROKER    string = ":11883"
	BUF_SIZE            int    = 1024

	NONCE_BASE int = 123456
)

type VerificationResponse struct {
	ResultCode           types.VerificationResponseCode
	NumRemainingTokens   uint16
	PayloadCipherType    types.PayloadCipherType
	PayloadEncryptionKey []byte
	TopicWithLen         []byte
}

func connCancellableReadByte(conn net.Conn, timeout time.Duration, done <-chan struct{}) (b byte, err error) {
	dst := make([]byte, 1)
	if _, err = common.ConnCancellableReadBase(conn, &dst, timeout, done); err != nil {
		return
	}
	b = dst[0]
	return
}

func connCancellableRead(conn net.Conn, dst *[]byte, timeout time.Duration, done <-chan struct{}) (n int, err error) {
	return common.ConnCancellableReadBase(conn, dst, timeout, done)
}

//	func debugConnWriteByte(conn net.Conn, b byte, timeout time.Duration) (err error) {
//		data := []byte{b}
//		_, err = common.DebugConnWriteBase(conn, data, timeout, DEBUG_ENABLED)
//		return
//	}
func connCancellableWrite(conn net.Conn, data []byte, timeout time.Duration, done <-chan struct{}) (n int, err error) {
	return common.ConnCancellableWriteBase(conn, data, timeout, done)
}

func sendPacketToVerifier(buf []byte, done <-chan struct{}) (response VerificationResponse, err error) {
	conn, err := net.Dial("tcp", RADDR_VERIFIER)
	if err != nil {
		fmt.Println("Error connecting To Verifier: ", err)
		return
	}
	defer conn.Close()

	if _, err = connCancellableWrite(conn, buf, time.Second, done); err != nil {
		return
	}

	resultCodeBuf := make([]byte, 1)
	if _, err = connCancellableRead(conn, &resultCodeBuf, time.Second, done); err != nil {
		return
	}
	resultCode := resultCodeBuf[0]

	if resultCode&0x80 == 0 {
		// success
		nTokensBuf := make([]byte, 2)
		if _, err = connCancellableRead(conn, &nTokensBuf, time.Second, done); err != nil {
			return
		}

		keyByteLen := 0
		var cipherType types.PayloadCipherType
		var encKey []byte
		if resultCode&0x20 != 0 {
			// with encryption
			cipherTypeBytes := make([]byte, 2)
			if _, err = connCancellableRead(conn, &cipherTypeBytes, time.Second, done); err != nil {
				return
			}
			cipherType = types.PayloadCipherType(binary.BigEndian.Uint16(cipherTypeBytes))
			switch cipherType {
			case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
				fallthrough
			case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
				keyByteLen = 16
			case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
				fallthrough
			case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
				keyByteLen = 32
			default:
				err = fmt.Errorf("Invalid Payload Cipher Type")
				return
			}

			encKey := make([]byte, keyByteLen)
			if _, err = connCancellableRead(conn, &encKey, time.Second, done); err != nil {
				return
			}
		}

		lenbuf := make([]byte, 2)
		if _, err = connCancellableRead(conn, &lenbuf, time.Second, done); err != nil {
			return
		}

		topicLen := int(binary.BigEndian.Uint16(lenbuf))
		topicWithLen := make([]byte, 2+topicLen)
		copy(topicWithLen[:2], lenbuf)
		topic := topicWithLen[2:]
		if _, err = connCancellableRead(conn, &topic, time.Second, done); err != nil {
			return
		}

		if resultCode&0x20 != 0 {
			response = VerificationResponse{
				ResultCode:           types.VerificationResponseCode(resultCode),
				NumRemainingTokens:   binary.BigEndian.Uint16(nTokensBuf),
				PayloadCipherType:    cipherType,
				PayloadEncryptionKey: encKey,
				TopicWithLen:         topicWithLen,
			}
		} else {
			response = VerificationResponse{
				ResultCode:         types.VerificationResponseCode(resultCode),
				NumRemainingTokens: binary.BigEndian.Uint16(nTokensBuf),
				PayloadCipherType:  types.PAYLOAD_CIPHER_NONE,
				TopicWithLen:       topicWithLen,
			}
		}
	} else {
		// fail
		response = VerificationResponse{
			ResultCode:         types.VerificationResponseCode(resultCode),
			NumRemainingTokens: 0,
			PayloadCipherType:  types.PAYLOAD_CIPHER_NONE,
		}
	}
	return
}

func decryptPayload(payload []byte, verfResponse VerificationResponse) (decrypted []byte, err error) {
	var (
		hash         []byte
		nonce        []byte
		encrypted    []byte
		hashComputed []byte
	)
	switch verfResponse.PayloadCipherType {
	case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		if len(payload) <= 32 {
			return
		}
		hash = payload[:32]
		encrypted = payload[32:]
	case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		if len(payload) <= 48 {
			return
		}
		hash = payload[:48]
		encrypted = payload[48:]
	}

	// Decryption
	switch verfResponse.PayloadCipherType {
	case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		var (
			block  cipher.Block
			aesGCM cipher.AEAD
		)
		block, err = aes.NewCipher(verfResponse.PayloadEncryptionKey)
		if err != nil {
			err = fmt.Errorf("failed to create AES cipher block: %w", err)
			return
		}
		aesGCM, err = cipher.NewGCM(block)
		if err != nil {
			err = fmt.Errorf("failed to create AES GCM mode: %w", err)
			return
		}
		nonce = make([]byte, aesGCM.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(NONCE_BASE)+uint64(verfResponse.NumRemainingTokens))
		decrypted, err = aesGCM.Open(nil, nonce, encrypted, nil)
		if err != nil {
			err = fmt.Errorf("failed to decrypt: %w", err)
			return
		}
	case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		var (
			c20p1305 cipher.AEAD
		)
		c20p1305, err = chacha20poly1305.New(verfResponse.PayloadEncryptionKey)
		if err != nil {
			err = fmt.Errorf("failed to create CHACHA20_POLY1305 cipher: %w", err)
			return
		}
		nonce = make([]byte, c20p1305.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(NONCE_BASE)+uint64(verfResponse.NumRemainingTokens))
		decrypted, err = c20p1305.Open(nil, nonce, encrypted, nil)
		if err != nil {
			err = fmt.Errorf("failed to decrypt: %w", err)
			return
		}
	}

	// Hash
	switch verfResponse.PayloadCipherType {
	case types.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case types.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		hash := sha256.New()
		hash.Write([]byte(decrypted))
		hashComputed = hash.Sum(nil)
	case types.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		hash := sha512.New384()
		hash.Write([]byte(decrypted))
		hashComputed = hash.Sum(nil)
	}

	if !bytes.Equal(hash, hashComputed) {
		err = fmt.Errorf("hash Compare failed")
	}
	return
}

func run() {
	fmt.Println("Starting mqtt interface server at ", LADDR_MQTTINTERFACE)
	listener, err := net.Listen("tcp", LADDR_MQTTINTERFACE)
	if err != nil {
		fmt.Println("Failed to start plain listener: ", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept plain connection:", err)
			continue
		}
		go mqttInterfaceHandler(conn)
	}
}

func clientToMqttHandler(buf []byte, incomingConn net.Conn, brokerConn net.Conn, done chan struct{}) (shouldCloseSock bool, err error) {
	shouldCloseSock = false
	incomingAddr := incomingConn.RemoteAddr()

	select {
	case <-done:
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	fixedHdr, err := getFixedHeader(incomingConn, time.Minute, done)
	if err != nil || fixedHdr.RemainingLength > BUF_SIZE {
		fmt.Printf("cli2Mqtt(%s): Failed getting fixed header: %v\n", incomingAddr, err)
		return
	}

	select {
	case <-done:
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	common.SetLen(&buf, fixedHdr.RemainingLength)
	if _, err = connCancellableRead(incomingConn, &buf, time.Minute, done); err != nil {
		fmt.Printf("cli2Mqtt(%s): Failed getting remaining part: %v\n", incomingAddr, err)
		return
	}

	if fixedHdr.ControlPacketType == MqttControlPUBLISH || fixedHdr.ControlPacketType == MqttControlSUBSCRIBE {
		// cyberdeception??
		bb := &bytes.Buffer{}

		decodeIfB64 := func(topic *[]byte, topicType string) (err error) {
			if len(*topic)%4 != 0 {
				// cyberdeception
				fmt.Printf("cli2Mqtt(%s): Seems not a b64 encoded\n", incomingAddr)
			} else {
				decodedTopic := make([]byte, len(*topic)/4*3)
				if _, err = base64.StdEncoding.Decode(decodedTopic, *topic); err != nil {
					fmt.Printf("cli2Mqtt(%s): Failed decoding the given %s: %v\n", incomingAddr, topicType, err)
					return
				}
				fmt.Printf("cli2Mqtt(%s): %s Bytes B64Decoded: %s\n", incomingAddr, topicType, hex.EncodeToString(decodedTopic))
				common.SetLen(topic, len(decodedTopic))
				copy(*topic, decodedTopic)
			}
			return
		}

		verifyToken := func(buf *[]byte, accessType types.AccessType, topic []byte) (response VerificationResponse, err error) {
			common.SetLen(buf, len(topic)+1)
			if accessType == types.AccessPub {
				(*buf)[0] = 0x80
			} else if accessType == types.AccessSub {
				(*buf)[0] = 0x00
			} else {
				err = fmt.Errorf("cli2Mqtt(%s): invalid access type 0x%02X", incomingAddr, accessType)
				return
			}
			copy((*buf)[1:], topic)
			select {
			case <-done:
				err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
				return
			default:
			}

			if response, err = sendPacketToVerifier(*buf, done); err != nil {
				return
			}
			if response.ResultCode&0x80 != 0 {
				// failed/suspiciousFail
				err = fmt.Errorf("cli2Mqtt(%s): verification failed", incomingAddr)
			}
			return
		}

		if fixedHdr.ControlPacketType == MqttControlPUBLISH {
			var (
				topicName      []byte
				contentBetween []byte
				verfResponse   VerificationResponse
				payload        []byte
			)
			topicName, contentBetween, payload, err = getTopicNameFromPublish(buf, (int(fixedHdr.Flags)>>1)&0x3)
			if err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed getting topicName: %v\n", incomingAddr, err)
				return
			}
			fmt.Printf("cli2Mqtt(%s): Topic Name Bytes: %s\n", incomingAddr, hex.EncodeToString(topicName))

			if err = decodeIfB64(&topicName, "Topic Name"); err != nil {
				return
			}

			if verfResponse, err = verifyToken(&buf, types.AccessPub, topicName); err != nil {
				return
			}

			bb.Write(verfResponse.TopicWithLen)
			bb.Write(contentBetween)
			if verfResponse.PayloadCipherType.IsValidCipherType() {
				var decrypted []byte
				if decrypted, err = decryptPayload(payload, verfResponse); err != nil {
					return
				}
				bb.Write(decrypted)
			} else {
				bb.Write(payload)
			}
		} else {
			var (
				topicFiltersWithOptions [][]byte
				verfResponse            VerificationResponse
				contentBefore           []byte
				contentAfter            []byte
			)
			contentBefore, topicFiltersWithOptions, contentAfter, err = getTopicFiltersFromSubscribe(buf)
			if err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed getting topicFilters: %v\n", incomingAddr, err)
				return
			}
			bb.Write(contentBefore)

			for _, filterWithOption := range topicFiltersWithOptions {
				topicFilter := filterWithOption[:len(filterWithOption)-1]
				topicFilterOption := filterWithOption[len(filterWithOption)-1]
				fmt.Printf("cli2Mqtt(%s): Topic Filter Bytes: %s, Option: 0x%02x\n", incomingAddr, hex.EncodeToString(topicFilter), topicFilterOption)

				if err = decodeIfB64(&topicFilter, "Topic Filter"); err != nil {
					return
				}

				if verfResponse, err = verifyToken(&buf, types.AccessSub, topicFilter); err != nil {
					return
				}
				bb.Write(verfResponse.TopicWithLen)
				bb.WriteByte(topicFilterOption)
			}

			bb.Write(contentAfter)
		}

		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(bb.Len()); err != nil {
			return
		}
		common.SetLen(&buf, 1+len(encodedRemainingLen)+bb.Len())
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
		copy(buf[1+len(encodedRemainingLen):], bb.Bytes())
	} else {
		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(fixedHdr.RemainingLength); err != nil {
			return
		}
		common.SetLen(&buf, 1+len(encodedRemainingLen)+len(buf))
		copy(buf[1+len(encodedRemainingLen):], buf)
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
	}

	select {
	case <-done:
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	if _, err = connCancellableWrite(brokerConn, buf, time.Minute, done); err != nil {
		fmt.Printf("cli2Mqtt(%s): Error sending out a packet to broker: %v\n", incomingAddr, err)
		return
	}

	// if fixedHdr.ControlPacketType == MqttControlPUBLISH {
	// 	shouldCloseSock = true
	// }

	return
}

func mqttToClientHandler(buf []byte, incomingConn net.Conn, brokerConn net.Conn, done <-chan struct{}) (err error) {
	incomingAddr := incomingConn.RemoteAddr()

	select {
	case <-done:
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	fixedHdr, err := getFixedHeader(brokerConn, time.Minute, done)
	if err != nil || fixedHdr.RemainingLength > BUF_SIZE {
		fmt.Printf("mqtt2Cli(%s): Failed getting fixed header: %v\n", incomingAddr, err)
		return
	}

	select {
	case <-done:
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	common.SetLen(&buf, fixedHdr.RemainingLength)
	if _, err = connCancellableRead(brokerConn, &buf, time.Minute, done); err != nil {
		fmt.Printf("mqtt2Cli(%s): Failed getting remaining part: %v\n", incomingAddr, err)
		return
	}

	var encodedRemainingLen []byte
	if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(fixedHdr.RemainingLength); err != nil {
		return
	}
	common.SetLen(&buf, 1+len(encodedRemainingLen)+len(buf))
	copy(buf[1+len(encodedRemainingLen):], buf)
	buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
	copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)

	select {
	case <-done:
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by chan", incomingAddr)
		return
	default:
	}
	if _, err = connCancellableWrite(incomingConn, buf, time.Minute, done); err != nil {
		fmt.Printf("mqtt2Cli(%s): Error sending out a packet to client: %v\n", incomingAddr, err)
		return
	}
	return
}

func mqttInterfaceHandler(incomingConn net.Conn) {
	defer func() {
		addr := incomingConn.RemoteAddr().String()
		incomingConn.Close()
		fmt.Printf("Closed connection with %s (client)\n", addr)
	}()

	brokerConn, err := net.Dial("tcp", RADDR_MQTTBROKER)
	if err != nil {
		fmt.Printf("Error connecting To MQTT Broker: %v\n", err)
		return
	}
	defer func() {
		addr := brokerConn.RemoteAddr().String()
		brokerConn.Close()
		fmt.Printf("Closed connection with %s (broker)\n", addr)
	}()

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, BUF_SIZE)
		for {
			select {
			case <-done:
				return
			default:
				if shouldCloseSock, err := clientToMqttHandler(buf, incomingConn, brokerConn, done); err != nil {
					fmt.Println("clientToMqttHandler failed: ", err)
					done <- struct{}{}
					return
				} else if shouldCloseSock {
					done <- struct{}{}
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, BUF_SIZE)
		for {
			select {
			case <-done:
				return
			default:
				if err := mqttToClientHandler(buf, incomingConn, brokerConn, done); err != nil {
					fmt.Println("mqttToClientHandler failed: ", err)
					done <- struct{}{}
					return
				}
			}
		}
	}()

	wg.Wait()
	fmt.Println("mqttInterfaceHandler ended")
}

func main() {
	go run()
	select {}
}
