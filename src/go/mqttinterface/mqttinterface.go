package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"go/common"
	"go/mqttinterface/mqttparser"
	"net"
	"sync"
	"time"
	"unsafe"
)

const (
	LADDR_MQTTINTERFACE string = ":1883"
	RADDR_VERIFIER      string = ":21883"
	RADDR_MQTTBROKER    string = ":11883"
	BUF_SIZE            int    = 1024
)

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

func sendPacketToVerifier(buf *[]byte, done <-chan struct{}) (err error) {
	conn, err := net.Dial("tcp", RADDR_VERIFIER)
	if err != nil {
		fmt.Println("Error connecting To Verifier: ", err)
		return
	}
	defer conn.Close()

	if _, err = connCancellableWrite(conn, *buf, time.Second, done); err != nil {
		return
	}
	common.SetLen(buf, 1)
	if _, err = connCancellableRead(conn, buf, time.Second, done); err != nil {
		return
	}
	resultCode := (*buf)[0]
	if resultCode == 0 || resultCode == 1 {
		lenbuf := make([]byte, 2)
		if _, err = connCancellableRead(conn, &lenbuf, time.Second, done); err != nil {
			return
		}

		topicLen := int(binary.BigEndian.Uint16(lenbuf))
		*buf = make([]byte, topicLen, 1+2+topicLen)
		if _, err = connCancellableRead(conn, buf, time.Second, done); err != nil {
			return
		}
		common.SetLen(buf, 3+topicLen)
		copy((*buf)[3:3+topicLen], (*buf)[:topicLen])
		copy((*buf)[1:3], lenbuf)
		(*buf)[0] = resultCode
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

	if fixedHdr.ControlPacketType == MqttControlPUBLISH {
		// cyberdeception??
		bb := bytes.Buffer{}
		topicName, others, puberr := getTopicNameFromPublish(buf)
		if puberr != nil {
			err = puberr
			fmt.Printf("cli2Mqtt(%s): Failed getting topicName: %v\n", incomingAddr, err)
			return
		}
		fmt.Printf("cli2Mqtt(%s): Topic Name Bytes: %s\n", incomingAddr, hex.EncodeToString(topicName))

		if len(topicName)%4 != 0 {
			// cyberdeception
			fmt.Printf("cli2Mqtt(%s): Seems not a b64 encoded\n", incomingAddr)
		} else {
			decodedTopicName := make([]byte, len(topicName)/4*3)
			if _, err = base64.StdEncoding.Decode(decodedTopicName, topicName); err != nil {
				fmt.Printf("cli2Mqtt(%s): Failed decoding the given topicname: %v\n", incomingAddr, err)
				return
			}
			fmt.Printf("cli2Mqtt(%s): Topic Name Bytes B64Decoded: %s\n", incomingAddr, hex.EncodeToString(decodedTopicName))
			common.SetLen(&topicName, len(decodedTopicName))
			copy(topicName, decodedTopicName)
		}

		common.SetLen(&buf, len(topicName)+1)
		buf[0] = 0x80
		copy(buf[1:], topicName)
		select {
		case <-done:
			err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
			return
		default:
		}
		if err = sendPacketToVerifier(&buf, done); err != nil {
			return
		}
		if buf[0] > 1 {
			// failed, cyberdeception
			err = fmt.Errorf("cli2Mqtt(%s): verification failed", incomingAddr)
			return
		}
		// success
		bb.Write(buf[1:])
		bb.Write(others)
		bb.WriteByte(0)

		var encodedRemainingLen []byte
		if encodedRemainingLen, err = mqttparser.EncodeToVariableByteInteger(bb.Len()); err != nil {
			return
		}
		common.SetLen(&buf, 1+len(encodedRemainingLen)+bb.Len())
		buf[0] = byte(fixedHdr.ControlPacketType)<<4 | (fixedHdr.Flags & 0xF)
		copy(buf[1:1+len(encodedRemainingLen)], encodedRemainingLen)
		copy(buf[1+len(encodedRemainingLen):], bb.Bytes())
	} else if fixedHdr.ControlPacketType == MqttControlSUBSCRIBE {
		// cyberdeception??
		bb := bytes.Buffer{}
		contentBefore, topicFiltersWithOptions, contentAfter, suberr := getTopicFiltersFromSubscribe(buf)
		bb.Write(contentBefore)
		if suberr != nil {
			err = suberr
			fmt.Printf("cli2Mqtt(%s): Failed getting topicFilters: %v\n", incomingAddr, err)
			return
		}

		for _, filterWithOption := range topicFiltersWithOptions {
			fmt.Printf("cli2Mqtt(%s): Topic Filter: %s, Option: 0x%02x\n", incomingAddr, unsafe.String(unsafe.SliceData(filterWithOption[:len(filterWithOption)-1]), len(filterWithOption)-1), filterWithOption[len(filterWithOption)-1])

			common.SetLen(&buf, len(filterWithOption))
			buf[0] = 0x00
			copy(buf[1:], filterWithOption[:len(filterWithOption)-1])
			select {
			case <-done:
				err = fmt.Errorf("cli2Mqtt(%s): interrupted by chan", incomingAddr)
				return
			default:
			}
			if err = sendPacketToVerifier(&buf, done); err != nil {
				return
			}
			if buf[0] > 1 {
				// failed, cyberdeception
				err = fmt.Errorf("cli2Mqtt(%s): verification failed", incomingAddr)
				return
			}
			// success
			bb.Write(buf[1:])
			bb.WriteByte(filterWithOption[len(filterWithOption)])
		}
		bb.Write(contentAfter)

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

	if fixedHdr.ControlPacketType == MqttControlPUBLISH || fixedHdr.ControlPacketType == MqttControlSUBSCRIBE {
		shouldCloseSock = true
	}

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
