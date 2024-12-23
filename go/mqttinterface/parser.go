package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"mqttmtd/funcs"
	"net"
	"time"
	"unsafe"
)

func decodeVariableByteIntegerFromConn(ctx context.Context, conn net.Conn, timeout time.Duration) (value int, len int, err error) {
	ended := false
	var i int = 0
	buf := make([]byte, 1)
	for i < 4 {
		select {
		case <-ctx.Done():
			err = fmt.Errorf("decodeVariableByteIntegerFromConn interrupted by context cancel")
			goto decodeVariableByteIntegerFromConnError
		default:
		}
		if _, err = funcs.ConnRead(ctx, conn, buf, timeout); err != nil {
			goto decodeVariableByteIntegerFromConnError
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
		goto decodeVariableByteIntegerFromConnError
	}
	len = i
	return

decodeVariableByteIntegerFromConnError:
	value = 0
	len = 0
	return
}

func decodeVariableByteInteger(buf []byte) (value int, length int, err error) {
	ended := false
	var i int = 0
	for i < 4 {
		if i > len(buf)-1 {
			err = fmt.Errorf("decoding of a variable byte integer ended because buf len too short. i=%d", i)
			goto decodeVariableByteIntegerError
		}
		encodedByte := int(buf[i])
		value += (encodedByte & 0x7F) << (7 * i)
		i++
		if encodedByte&0x80 == 0 {
			ended = true
			break
		}
	}
	if !ended {
		err = fmt.Errorf("decoding of a variable byte integer ended unexpectedly. i=%d", i)
		goto decodeVariableByteIntegerError
	}
	length = i
	return

decodeVariableByteIntegerError:
	value = 0
	length = 0
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

func getFixedHeader(ctx context.Context, conn net.Conn, timeout time.Duration) (fixedHeader *FixedHeader, err error) {
	fixedHeader = &FixedHeader{}
	var (
		n   int
		buf []byte = make([]byte, 1)
	)
	if n, err = funcs.ConnRead(ctx, conn, buf, timeout); err != nil {
		return
	}
	if n != 1 {
		err = fmt.Errorf("fixedHeader read nothing")
		return
	}
	fixedHeader.ControlPacketType = MQTTControlPacketType(buf[0] >> 4)
	fixedHeader.Flags = buf[0] & 0xF

	remainingLength, remainingLengthLen, err := decodeVariableByteIntegerFromConn(ctx, conn, timeout)
	if err != nil {
		return
	}
	fixedHeader.Length = 1 + remainingLengthLen
	fixedHeader.RemainingLength = remainingLength
	return
}

func getMQTTVersionFromConnect(varHdrAndPayload []byte) (mqttVersion byte, err error) {
	if len(varHdrAndPayload) < 7 {
		err = fmt.Errorf("length inadequate")
		return
	}
	if unsafe.String(unsafe.SliceData(varHdrAndPayload[2:6]), 4) != "MQTT" {
		err = fmt.Errorf("protocol not mqtt")
		return
	}
	mqttVersion = varHdrAndPayload[6]
	return
}

func getTopicNameFromPublish(mqttVersion byte, varHdrAndPayload []byte, qos int) (topicName []byte, contentBetween []byte, payload []byte, err error) {
	if mqttVersion == 0xFF {
		err = fmt.Errorf("mqttVersion  invalid")
		return
	}
	length := int(binary.BigEndian.Uint16(varHdrAndPayload[:2]))
	if length > len(varHdrAndPayload)-2 {
		err = fmt.Errorf("length inadequate")
		return
	}
	topicName = varHdrAndPayload[2 : 2+length]
	identifierLen := 0
	if qos > 0 {
		identifierLen = 2
	}
	var (
		propertiesLen    int
		propertiesLenLen int
	)
	if mqttVersion >= 5 {
		propertiesLen, propertiesLenLen, err = decodeVariableByteInteger(varHdrAndPayload[2+length+identifierLen:])
	}
	contentBetween = varHdrAndPayload[2+length : 2+length+identifierLen+propertiesLenLen+propertiesLen]
	payload = varHdrAndPayload[2+length+identifierLen+propertiesLenLen+propertiesLen:]
	return
}

func getTopicFiltersFromSubscribe(mqttVersion byte, varHdrAndPayload []byte) (contentBefore []byte, topicFiltersWithOptions [][]byte, contentAfter []byte, err error) {
	if mqttVersion == 0xFF {
		err = fmt.Errorf("mqttVersion  invalid")
		return
	}
	if 4 > len(varHdrAndPayload) {
		err = fmt.Errorf("length inadequate")
		return
	}
	var (
		propertiesLen    int = 0
		propertiesLenLen int = 0
	)
	if mqttVersion >= 5 {
		propertiesLen, propertiesLenLen, err = decodeVariableByteInteger(varHdrAndPayload[2:])
	}
	contentBefore = varHdrAndPayload[:2+propertiesLenLen+propertiesLen]
	offset := 2 + propertiesLenLen + propertiesLen
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
