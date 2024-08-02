package main

import (
	"encoding/binary"
	"fmt"
	"go/common"
	"net"
	"time"
)

func decodeVariableByteIntegerFromConn(conn net.Conn, timeout time.Duration, done <-chan struct{}) (value int, len int, err error) {
	ended := false
	var i int = 0
	buf := make([]byte, 1)
	for i < 4 {
		select {
		case <-done:
			err = fmt.Errorf("interrupted by chan")
			return
		default:
		}
		if _, err = common.ConnCancellableReadBase(conn, &buf, timeout, done); err != nil {
			return
		} else {
			encodedByte := int(buf[0])
			value += (encodedByte & 0x7F) << (7 * i)
			i++
			if encodedByte&0x80 == 0 {
				ended = true
				break
			}
		}
	}
	if !ended {
		err = fmt.Errorf("decoding of a variable byte integer ended unexpectedly. i=%d", i)
		value = 0
		i = 0
	}
	len = i
	return
}

type MQTTControlPacketType byte

const (
	MqttControlRESERVED MQTTControlPacketType = iota
	MqttControlCONNECT
	MqttControlCONNACK
	MqttControlPUBLISH
	MqttControlPUBACK
	MqttControlPUBREC
	MqttControlPUBREL
	MqttControlPUBCOMP
	MqttControlSUBSCRIBE
	MqttControlSUBACK
	MqttControlUNSUBSCRIBE
	MqttControlUNSUBACK
	MqttControlPINGREQ
	MqttControlPINGRESP
	MqttControlDISCONNECT
	MqttControlAUTH
)

func (ctrlType MQTTControlPacketType) String() string {
	switch ctrlType {
	case MqttControlRESERVED:
		return "RESERVED"
	case MqttControlCONNECT:
		return "CONNECT"
	case MqttControlCONNACK:
		return "CONNACK"
	case MqttControlPUBLISH:
		return "PUBLISH"
	case MqttControlPUBACK:
		return "PUBACK"
	case MqttControlPUBREC:
		return "PUBREC"
	case MqttControlPUBREL:
		return "PUBREL"
	case MqttControlPUBCOMP:
		return "PUBCOMP"
	case MqttControlSUBSCRIBE:
		return "SUBSCRIBE"
	case MqttControlSUBACK:
		return "SUBACK"
	case MqttControlUNSUBSCRIBE:
		return "UNSUBSCRIBE"
	case MqttControlUNSUBACK:
		return "UNSUBACK"
	case MqttControlPINGREQ:
		return "PINGREQ"
	case MqttControlPINGRESP:
		return "PINGRESP"
	case MqttControlDISCONNECT:
		return "DISCONNECT"
	case MqttControlAUTH:
		return "AUTH"
	default:
		return "UNKNOWN"
	}
}

type FixedHeader struct {
	Length            int
	ControlPacketType MQTTControlPacketType
	Flags             byte
	RemainingLength   int
}

func getFixedHeader(conn net.Conn, timeout time.Duration, done <-chan struct{}) (fixedHeader *FixedHeader, err error) {
	fixedHeader = &FixedHeader{}
	var firstByte byte
	if firstByte, err = connCancellableReadByte(conn, timeout, done); err != nil {
		return
	}
	fixedHeader.ControlPacketType = MQTTControlPacketType(firstByte >> 4)
	fixedHeader.Flags = firstByte & 0xF

	remainingLength, remainingLengthLen, err := decodeVariableByteIntegerFromConn(conn, timeout, done)
	if err != nil {
		return
	}
	fixedHeader.Length = 1 + remainingLengthLen
	fixedHeader.RemainingLength = remainingLength
	return
}

func getTopicNameFromPublish(varHdrAndPayload []byte) (topicName []byte, others []byte, err error) {
	length := int(binary.BigEndian.Uint16(varHdrAndPayload[:2]))
	if length > len(varHdrAndPayload)-2 {
		err = fmt.Errorf("length not inadequate")
		return
	}
	topicName = varHdrAndPayload[2 : 2+length]
	others = varHdrAndPayload[2+length:]
	return
}

func getTopicFiltersFromSubscribe(varHdrAndPayload []byte) (contentBefore []byte, topicFiltersWithOptions [][]byte, contentAfter []byte, err error) {
	if 4 > len(varHdrAndPayload) {
		err = fmt.Errorf("length not inadequate")
		return
	}
	propertiesLen := varHdrAndPayload[2]
	contentBefore = varHdrAndPayload[:3+int(propertiesLen)]
	offset := 3 + int(propertiesLen)
	for offset < len(varHdrAndPayload) {
		length := int(binary.BigEndian.Uint16(varHdrAndPayload[offset : offset+2]))
		if offset+2+length+1 > len(varHdrAndPayload) {
			return
		}
		topicFiltersWithOptions = append(topicFiltersWithOptions, varHdrAndPayload[offset+2:offset+2+length+1])
		offset += 2 + length + 1
	}
	contentAfter = varHdrAndPayload[offset:]
	return
}
