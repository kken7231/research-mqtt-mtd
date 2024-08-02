package common

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const (
	DEBUG                       = true
	PORT_BROKER                 = 11883
	NUM_TOKENS_PER_GENE_DEFAULT = 10
	NUM_TOKENS_PER_GENE_MAX     = 98
	TIMESTAMP_LEN               = 6
	TOKEN_LEN                   = 12
	RANDOM_BYTES_LEN            = TOKEN_LEN - TIMESTAMP_LEN
	SERVER_ADDR_TOKEN_RESOLVER  = "broker:8883"
	SERVER_ADDR_TOKEN_ISSUER    = "broker:1883"
	CA_CERT_FILE                = "/mosquitto/config/certs/ca/ca-sans.crt"
	BROKER_CERT_FILE            = "/mosquitto/config/certs/broker/broker-sans.crt"
	BROKER_KEY_FILE             = "/mosquitto/config/certs/broker/broker.key"
	CLIENT_CERT_FILE            = "/mosquitto/config/certs/client/client-sans.crt"
	CLIENT_KEY_FILE             = "/mosquitto/config/certs/client/client.key"
	BROKER_OUTPUT_DIRECTORY     = "/mosquitto/tokens/"
	CLIENT_OUTPUT_DIRECTORY     = "/mosquitto/tokens/"

	FETCH_TOKEN_FOR_PUB          byte               = 0x80
	FETCH_TOKEN_FOR_SUB          byte               = 0x00
	CTRL_PACKET_TYPES_CONNECT    IssuablePacketType = 0x10
	CTRL_PACKET_TYPES_PUBLISH    IssuablePacketType = 0x30
	CTRL_PACKET_TYPES_SUBSCRIBE  IssuablePacketType = 0x80
	CTRL_PACKET_TYPES_DISCONNECT byte               = 0xE0

	DISCON_REASON_CD_MALFORMED_PACKET     byte = 0x81
	DISCON_REASON_CD_TOPIC_FILTER_INVALID byte = 0x8F
	DISCON_REASON_CD_TOPIC_NAME_INVALID   byte = 0x90
)

var (
	CTRL_PACKET_TYPE_NAMES = [16]string{"RESRVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK_", "PUBREC_", "PUBREL_", "PUBCOMP", "SUBSCRB", "SUBACK_", "UNSUBSC", "UNSUBAC", "PINGREQ", "PINGRSP", "DISCNCT", "AUTH___"}
)

type MQTTMTDError struct {
	ReasonCode byte
	Message    string
}

func NewMQTTMTDError(reasonCode byte, message string) error {
	return &MQTTMTDError{
		ReasonCode: reasonCode,
		Message:    message,
	}
}

func NewMQTTMTDErrorFromError(reasonCode byte, err error) error {
	if err == nil {
		panic("error is nil")
	}
	return &MQTTMTDError{
		ReasonCode: reasonCode,
		Message:    err.Error(),
	}
}

func (e *MQTTMTDError) Error() string {
	return fmt.Sprintf("%s (reasonCode=0x%x)", e.Message, e.ReasonCode)
}

type IssuablePacketType byte

func EnsureOutputDir(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err = os.Mkdir(dirPath, os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(fmt.Sprintf("%s/publish/", dirPath), os.ModePerm)
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(fmt.Sprintf("%s/subscribe/", dirPath), os.ModePerm)
		if err != nil {
			panic(err)
		}
	}
}

/*
+----------+--------+--------+--------+--------+--------+--------+--------+--------+
|  Bit     |   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0    |
+----------+--------+--------+--------+--------+--------+--------+--------+--------+
| byte 1   |      MQTT Control Packet type     |          Reserved / Flags         |
+----------+--------+--------+--------+--------+--------+--------+--------+--------+
| byte 2 - |                           Remaining Length                            |
+----------+--------+--------+--------+--------+--------+--------+--------+--------+
*/

func GetMQTTControlHeader(packetData []byte) (controlType uint8, LSB4 uint8, packetLen int, packetLenLen int, _err error) {
	var err error = fmt.Errorf("failed fetchinng mqtt control header")
	if len(packetData) >= 2 {
		packetDataLen, packetDataLenLen, err := GetVariableByteInteger(packetData, 1)
		if err == nil && len(packetData)-packetDataLenLen-1 >= packetDataLen {
			return packetData[0] & 0xF0, packetData[0] & 0xF, packetDataLen, packetDataLenLen, err
		}
	}
	return 0xFF, 0xFF, -1, -1, err
}

func PrintPacket(inoutSpec string, conn net.Conn, content []byte, isTls bool, mqttVersion ...uint8) {
	if !DEBUG {
		return
	}

	if inoutSpec != "outgoing" && inoutSpec != "incoming" {
		fmt.Println("invalid inout_spec")
		return
	}

	var mqttVer uint8 = 0x5
	if len(mqttVersion) > 0 {
		mqttVer = mqttVersion[0]
	}

	message := fmt.Sprintf("len=%d", len(content))
	packetType, _, packetDataLen, packetDataLenLen, _ := GetMQTTControlHeader(content)
	packetVarHeaderOffset := 1 + packetDataLenLen
	if !isTls {
		if packetType == byte(CTRL_PACKET_TYPES_PUBLISH) {
			lenTopicName := int(binary.BigEndian.Uint16(content[packetVarHeaderOffset : packetVarHeaderOffset+2]))
			if packetDataLen < packetVarHeaderOffset+lenTopicName {
				fmt.Println("Error decoding topic name")
			} else if lenTopicName == TOKEN_LEN {
				message += fmt.Sprintf(", topic name: MAY BE TOKEN(%s)", hex.EncodeToString(content[packetVarHeaderOffset+2:packetVarHeaderOffset+2+lenTopicName]))
			} else {
				message += fmt.Sprintf(", topic name: \"%s\"", unsafe.String(unsafe.SliceData(content[packetVarHeaderOffset+2:packetVarHeaderOffset+2+lenTopicName]), lenTopicName))
			}
		} else if packetType == byte(CTRL_PACKET_TYPES_SUBSCRIBE) {
			propertyLen, propertyLenLen, err := GetVariableByteInteger(content, packetVarHeaderOffset+2)
			if err == nil {
				packetPayloadOffset := packetVarHeaderOffset + 2
				if mqttVer == 5 {
					packetPayloadOffset += propertyLenLen + propertyLen
				}

				lenTopicFilter := int(binary.BigEndian.Uint16(content[packetPayloadOffset : packetPayloadOffset+2]))
				if packetDataLen < packetPayloadOffset+lenTopicFilter {
					fmt.Println("Error decoding topic filter")
				} else if lenTopicFilter == TOKEN_LEN {
					message += fmt.Sprintf(", topic filter: MAY BE TOKEN(%s)", hex.EncodeToString(content[packetPayloadOffset+2:packetPayloadOffset+2+lenTopicFilter]))
				} else {
					message += fmt.Sprintf(", topic filter: \"%s\"", unsafe.String(unsafe.SliceData(content[packetPayloadOffset+2:packetPayloadOffset+2+lenTopicFilter]), lenTopicFilter))
				}
			} else {
				fmt.Println("Error decoding properties")
			}
		}
	}
	fmt.Printf("%s | %s%s:%s [%s] %s (%s)\n",
		time.Now().Format(time.RFC1123),
		conn.RemoteAddr(),
		func() string {
			if inoutSpec == "incoming" {
				return "=>"
			}
			return "<="
		}(),
		func() string {
			_, port, err := net.SplitHostPort(conn.LocalAddr().String())
			if err != nil {
				return "ERR"
			}
			return port
		}(),
		func() string {
			if isTls {
				return ""
			} else if packetType == 0xFF {
				return "UNDEFND"
			} else {
				return CTRL_PACKET_TYPE_NAMES[packetType>>4]
			}
		}(),
		hex.EncodeToString(content),
		message)
}

func BytesToEscapedString(bs []byte) (encoded string) {
	sb := strings.Builder{}
	for _, b := range bs {
		sb.WriteString("\\x")
		if b < 0x10 {
			sb.WriteByte('0')
		}
		sb.WriteString(strconv.FormatUint(uint64(b), 16))
	}
	return sb.String()
}

func BytesToB64EncodedString(bs []byte) (b64encoded string) {
	return base64.URLEncoding.EncodeToString(bs)
}

func B64EncodedStringToBytes(encoded string) (bs []byte, err error) {
	return base64.URLEncoding.DecodeString(encoded)
}

func GetVariableByteInteger(from []byte, offset int) (_value int, len int, _err error) {
	value := 0
	ended := false
	var err error = nil
	var i int = 0
	for i < 4 {
		encodedByte := int(from[offset+i])
		value += (encodedByte & 0x7F) << (7 * i)
		i++
		if encodedByte&0x80 == 0 {
			ended = true
			break
		}
	}
	if !ended {
		err = fmt.Errorf("decoding of a variable byte integer ended unexpectedly. i=%d", i)
		value = 0
		i = 0
	}
	return value, i, err
}

func ToVariableByteInteger(value int) (bs []byte, _err error) {
	encoded := make([]byte, 4)
	ended := false
	remainedValue := value
	var err error = nil
	var i int
	for i = 0; i < 4; i++ {
		encodedByte := remainedValue & 0x7F
		remainedValue >>= 7
		if remainedValue > 0 {
			encodedByte |= 0x80
		}
		encoded[i] = byte(encodedByte)
		if remainedValue == 0 {
			ended = true
			break
		}
	}
	if !ended {
		err = fmt.Errorf("encoding of a variable byte integer ended unexpectedly. i=%d", i)
		encoded = nil
	} else {
		encoded = encoded[:i+1]
	}
	return encoded, err
}
