package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"mqttmtd/config"
	"mqttmtd/funcs"
	"mqttmtd/mqttinterface/mqttparser"
	"mqttmtd/types"
	"net"
	"sync"
)

const (
	BUF_SIZE int = 1024
)

type MQTT_INTERFACE_CONTEXT_KEY string

type AEADInfo struct {
	AEADType  types.PayloadAEADType
	EncKey    []byte
	PubSeqNum uint64
}

func run() {
	fmt.Printf("Starting mqtt interface server on port %d\n", config.Server.Ports.MqttInterface)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", config.Server.Ports.MqttInterface))
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

func communicateWithVerifier(ctx context.Context, verifierRequest types.VerifierRequest) (response types.VerifierResponse, err error) {
	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", config.Server.Ports.Verifier))
	if err != nil {
		fmt.Println("Error connecting To Verifier: ", err)
		return
	}
	defer conn.Close()

	// Send Request
	if err = funcs.SendVerifierRequest(ctx, conn, config.Server.SocketTimeout.Local, verifierRequest); err != nil {
		return
	}

	// Receive Response
	return funcs.ParseVerifierResponse(ctx, conn, config.Server.SocketTimeout.Local, verifierRequest)
}

func clientToMqttHandler(ctx context.Context, buf []byte, incomingConn net.Conn, brokerConn net.Conn, cliMqttVersion *byte, aeadInfo *AEADInfo) (shouldCloseSock bool, err error) {
	shouldCloseSock = false
	incomingAddr := incomingConn.RemoteAddr()

	select {
	case <-ctx.Done():
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	fixedHdr, err := getFixedHeader(ctx, incomingConn, config.Server.SocketTimeout.External)
	if err != nil || fixedHdr.RemainingLength > BUF_SIZE {
		fmt.Printf("cli2Mqtt(%s): Failed getting fixed header: %v\n", incomingAddr, err)
		return
	}

	select {
	case <-ctx.Done():
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	funcs.SetLen(&buf, fixedHdr.RemainingLength)
	if _, err = funcs.ConnRead(ctx, incomingConn, buf, config.Server.SocketTimeout.External); err != nil {
		fmt.Printf("cli2Mqtt(%s): Failed getting remaining part: %v\n", incomingAddr, err)
		return
	}

	if fixedHdr.ControlPacketType == MqttControlPUBLISH || fixedHdr.ControlPacketType == MqttControlSUBSCRIBE {
		// When packet is PUBLISH/SUBSCRIBE
		// cyberdeception??
		bb := &bytes.Buffer{}

		decodeIfB64 := func(topic *[]byte, topicType string) (err error) {
			if len(*topic)%4 != 0 {
				// cyberdeception
				fmt.Printf("cli2Mqtt(%s): Seems not a b64 encoded\n", incomingAddr)
			} else {
				decodedTopic := make([]byte, len(*topic)/4*3)
				if _, err = base64.URLEncoding.Decode(decodedTopic, *topic); err != nil {
					fmt.Printf("cli2Mqtt(%s): Failed decoding the given %s: %v\n", incomingAddr, topicType, err)
					return
				}
				fmt.Printf("cli2Mqtt(%s): %s Bytes B64Decoded: %s\n", incomingAddr, topicType, hex.EncodeToString(decodedTopic))
				funcs.SetLen(topic, len(decodedTopic))
				copy(*topic, decodedTopic)
			}
			return
		}

		if fixedHdr.ControlPacketType == MqttControlPUBLISH {
			var (
				topicName      []byte
				contentBetween []byte
				verfRequest    types.VerifierRequest
				verfResponse   types.VerifierResponse
				payload        []byte
			)
			topicName, contentBetween, payload, err = getTopicNameFromPublish(*cliMqttVersion, buf, (int(fixedHdr.Flags)>>1)&0x3)
			if err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed getting topicName: %v\n", incomingAddr, err)
				return
			}
			fmt.Printf("cli2Mqtt(%s): Topic Name Bytes: %s\n", incomingAddr, hex.EncodeToString(topicName))

			if err = decodeIfB64(&topicName, "Topic Name"); err != nil {
				return
			}

			verfRequest = types.VerifierRequest{
				AccessTypeIsPub: true,
				Token:           topicName,
			}

			if verfResponse, err = communicateWithVerifier(ctx, verfRequest); err != nil {
				return
			}

			funcs.SetLen(&buf, 2)
			binary.BigEndian.PutUint16(buf, uint16(len(verfResponse.Topic)))
			bb.Write(buf)
			bb.Write(verfResponse.Topic)
			bb.Write(contentBetween)

			if verfResponse.PayloadAEADType.IsEncryptionEnabled() {
				var decrypted []byte
				if decrypted, err = verfResponse.PayloadAEADType.OpenMessage(payload, verfResponse.EncryptionKey, uint64(verfResponse.TokenIndex)); err != nil {
					return
				}
				bb.Write(decrypted)
			} else {
				bb.Write(payload)
			}
		} else {
			var (
				topicFiltersWithOptions [][]byte
				verfRequest             types.VerifierRequest
				verfResponse            types.VerifierResponse
				contentBefore           []byte
				contentAfter            []byte
			)
			contentBefore, topicFiltersWithOptions, contentAfter, err = getTopicFiltersFromSubscribe(*cliMqttVersion, buf)
			fmt.Printf("contentBefore: %s\n", hex.EncodeToString(contentBefore))
			fmt.Printf("contentAfter: %s\n", hex.EncodeToString(contentAfter))
			if err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed getting topicFilters: %v\n", incomingAddr, err)
				return
			}
			bb.Write(contentBefore)

			// TODO: disable z filters for now
			for _, filterWithOption := range topicFiltersWithOptions {
				topicFilter := filterWithOption[:len(filterWithOption)-1]
				topicFilterOption := filterWithOption[len(filterWithOption)-1]
				fmt.Printf("cli2Mqtt(%s): Topic Filter Bytes: %s, Option: 0x%02x\n", incomingAddr, hex.EncodeToString(topicFilter), topicFilterOption)

				if err = decodeIfB64(&topicFilter, "Topic Filter"); err != nil {
					return
				}

				verfRequest = types.VerifierRequest{
					AccessTypeIsPub: false,
					Token:           topicFilter,
				}

				if verfResponse, err = communicateWithVerifier(ctx, verfRequest); err != nil {
					return
				}
				if !verfResponse.ResultCode.IsSuccess() {
					fmt.Printf("cli2Mqtt(%s): Topic Filter Bytes %s: verification failed\n", incomingAddr, hex.EncodeToString(topicFilter))
					return
				}

				funcs.SetLen(&buf, 2)
				binary.BigEndian.PutUint16(buf, uint16(len(verfResponse.Topic)))
				bb.Write(buf)
				bb.Write(verfResponse.Topic)
				bb.WriteByte(topicFilterOption)
			}

			bb.Write(contentAfter)

			// Context settings for Server->Client Publish Encryption
			if verfResponse.PayloadAEADType.IsEncryptionEnabled() {
				var pubSeqNum uint64 = 0
				aeadInfo.AEADType = verfResponse.PayloadAEADType
				aeadInfo.EncKey = verfResponse.EncryptionKey
				aeadInfo.PubSeqNum = pubSeqNum
			}
		}

		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(bb.Len()); err != nil {
			return
		}
		funcs.SetLen(&buf, 1+len(encodedRemainingLen)+bb.Len())
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
		copy(buf[1+len(encodedRemainingLen):], bb.Bytes())
	} else {

		if fixedHdr.ControlPacketType == MqttControlCONNECT {
			if *cliMqttVersion, err = getMQTTVersionFromConnect(buf); err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed getting MQTT Version: %v\n", incomingAddr, err)
				return
			} else {
				fmt.Printf("cli2Mqtt(%s): Client MQTT Version: %d\n", incomingAddr, *cliMqttVersion)
			}
		}

		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(fixedHdr.RemainingLength); err != nil {
			return
		}
		funcs.SetLen(&buf, 1+len(encodedRemainingLen)+len(buf))
		copy(buf[1+len(encodedRemainingLen):], buf)
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
	}

	select {
	case <-ctx.Done():
		err = fmt.Errorf("cli2Mqtt(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	if _, err = funcs.ConnWrite(ctx, brokerConn, buf, config.Server.SocketTimeout.External); err != nil {
		fmt.Printf("cli2Mqtt(%s): Error sending out a packet to broker: %v\n", incomingAddr, err)
		return
	}
	return
}

func mqttToClientHandler(ctx context.Context, buf []byte, incomingConn net.Conn, brokerConn net.Conn, cliMqttVersion *byte, aeadInfo *AEADInfo) (err error) {
	incomingAddr := incomingConn.RemoteAddr()

	select {
	case <-ctx.Done():
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	fixedHdr, err := getFixedHeader(ctx, brokerConn, config.Server.SocketTimeout.External)
	if err != nil || fixedHdr.RemainingLength > BUF_SIZE {
		fmt.Printf("mqtt2Cli(%s): Failed getting fixed header: %v\n", incomingAddr, err)
		return
	}

	select {
	case <-ctx.Done():
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	funcs.SetLen(&buf, fixedHdr.RemainingLength)
	if _, err = funcs.ConnRead(ctx, brokerConn, buf, config.Server.SocketTimeout.External); err != nil {
		fmt.Printf("mqtt2Cli(%s): Failed getting remaining part: %v\n", incomingAddr, err)
		return
	}

	if fixedHdr.ControlPacketType == MqttControlPUBLISH {
		bb := &bytes.Buffer{}
		var (
			topicName      []byte
			contentBetween []byte
			payload        []byte
		)
		topicName, contentBetween, payload, err = getTopicNameFromPublish(*cliMqttVersion, buf, (int(fixedHdr.Flags)>>1)&0x3)
		if err != nil {
			fmt.Printf("mqtt2Cli(%s): Failed getting topicName: %v\n", incomingAddr, err)
			return
		}
		fmt.Printf("mqtt2Cli(%s): Topic Name Bytes: %s\n", incomingAddr, hex.EncodeToString(topicName))

		if aeadInfo.AEADType.IsEncryptionEnabled() {
			payload, err = aeadInfo.AEADType.SealMessage(payload, aeadInfo.EncKey, aeadInfo.PubSeqNum)
			if err != nil {
				fmt.Printf("mqtt2Cli(%s): Failed sealing payload: %v\n", incomingAddr, err)
				return
			}
		}

		// Topic Name
		funcs.SetLen(&buf, 2)
		binary.BigEndian.PutUint16(buf, 1)
		bb.Write(buf)
		bb.WriteByte('A')

		// Id and properties
		bb.Write(contentBetween)
		bb.Write(payload)

		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(bb.Len()); err != nil {
			return
		}
		funcs.SetLen(&buf, 1+len(encodedRemainingLen)+bb.Len())
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
		copy(buf[1+len(encodedRemainingLen):], bb.Bytes())
	} else {
		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(fixedHdr.RemainingLength); err != nil {
			return
		}
		funcs.SetLen(&buf, 1+len(encodedRemainingLen)+len(buf))
		copy(buf[1+len(encodedRemainingLen):], buf)
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
	}

	select {
	case <-ctx.Done():
		err = fmt.Errorf("mqtt2Cli(%s): interrupted by context cancel", incomingAddr)
		return
	default:
	}
	if _, err = funcs.ConnWrite(ctx, incomingConn, buf, config.Server.SocketTimeout.External); err != nil {
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

	brokerConn, err := net.Dial("tcp", fmt.Sprintf(":%d", config.Server.Ports.MqttServer))
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
	ctx, cancel := funcs.NewCancelableContext(true)
	var cliMqttVersion byte = 0xFF
	aeadInfo := AEADInfo{
		AEADType: types.PAYLOAD_AEAD_NONE,
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, BUF_SIZE)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if shouldCloseSock, err := clientToMqttHandler(ctx, buf, incomingConn, brokerConn, &cliMqttVersion, &aeadInfo); err != nil {
					fmt.Println("clientToMqttHandler failed: ", err)
					cancel()
					return
				} else if shouldCloseSock {
					cancel()
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
			case <-ctx.Done():
				return
			default:
				if err := mqttToClientHandler(ctx, buf, incomingConn, brokerConn, &cliMqttVersion, &aeadInfo); err != nil {
					fmt.Println("mqttToClientHandler failed: ", err)
					cancel()
					return
				}
			}
		}
	}()

	wg.Wait()
	fmt.Println("mqttInterfaceHandler ended")
}

func main() {
	configFilePath := flag.String("conf", "", "path to the server conf file")
	flag.Parse()

	if err := config.LoadServerConfig(*configFilePath); err != nil {
		log.Fatalf("Failed to load server config from %s: %v", *configFilePath, err)
	} else {
		log.Printf("Server Config Loaded from %s\n", *configFilePath)
	}

	go run()
	select {}
}
