// package mqttparser

// import (
// 	"encoding/binary"
// 	"fmt"
// 	"io"
// 	"unsafe"
// )

// type VariableHeaderConnect struct {
// 	ProtocolName    []byte
// 	ProtocolVersion byte
// 	ConnectFlags    byte
// 	CleanStart      bool
// 	WillFlag        bool
// 	WillQoS         byte
// 	WillRetain      bool
// 	UserNameFlag    bool
// 	PasswordFlag    bool
// 	KeepAlive       uint16
// 	Properties      []byte
// }

// func GetVariableHeaderConnect(reader io.Reader) (varHdr *VariableHeaderConnect, err error) {
// 	varHdr = &VariableHeaderConnect{}
// 	buf := make([]byte, 2, 2)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	if protocolNameLen := int(binary.BigEndian.Uint16(buf)); protocolNameLen != 4 {
// 		err = fmt.Errorf("protocol name length is not 4")
// 		return
// 	}

// 	varHdr.ProtocolName = make([]byte, 4)
// 	if _, err = reader.Read(varHdr.ProtocolName); err != nil {
// 		return
// 	}

// 	setLenOfASlice(&buf, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	varHdr.ProtocolVersion = buf[0]

// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	varHdr.ConnectFlags = buf[0]

// 	varHdr.CleanStart = varHdr.ConnectFlags&0x2 != 0
// 	varHdr.WillFlag = varHdr.ConnectFlags&0x4 != 0
// 	varHdr.WillQoS = (varHdr.ConnectFlags >> 3) & 0x3
// 	varHdr.WillRetain = varHdr.ConnectFlags&0x20 != 0
// 	varHdr.PasswordFlag = varHdr.ConnectFlags&0x40 != 0
// 	varHdr.UserNameFlag = varHdr.ConnectFlags&0x80 != 0

// 	setLenOfASlice(&buf, 2)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	varHdr.KeepAlive = binary.BigEndian.Uint16(buf)

// 	setLenOfASlice(&buf, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	propertiesLen := buf[0]

// 	varHdr.Properties = make([]byte, int(propertiesLen))
// 	if _, err = reader.Read(varHdr.Properties); err != nil {
// 		return
// 	}
// 	return
// }

// type VariableHeaderConnack struct {
// 	ConnectAcknowledgeFlags byte
// 	ConnectReasonCode       byte
// 	Properties              []byte
// }

// func GetVariableHeaderConnack(reader io.Reader) (varHdr *VariableHeaderConnack, err error) {
// 	varHdr = &VariableHeaderConnack{}

// 	buf := make([]byte, 1, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	varHdr.ConnectAcknowledgeFlags = buf[0]

// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	varHdr.ConnectReasonCode = buf[0]

// 	setLenOfASlice(&buf, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	propertiesLen := buf[0]

// 	varHdr.Properties = make([]byte, int(propertiesLen))
// 	if _, err = reader.Read(varHdr.Properties); err != nil {
// 		return
// 	}
// 	return
// }

// type VariableHeaderPublish struct {
// 	TopicName        string
// 	PacketIdentifier [2]byte
// 	Properties       []byte
// }

// func GetVariableHeaderPublish(reader io.Reader, qos byte) (varHdr *VariableHeaderPublish, err error) {
// 	varHdr = &VariableHeaderPublish{}

// 	topicNameBytes, err := decodeUTF8EncodedString(reader)
// 	if err != nil {
// 		return
// 	}
// 	varHdr.TopicName = unsafe.String(unsafe.SliceData(topicNameBytes), len(topicNameBytes))

// 	if qos > 0 {
// 		if _, err = reader.Read(varHdr.PacketIdentifier[:]); err != nil {
// 			return
// 		}
// 	}

// 	buf := make([]byte, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	propertiesLen := buf[0]

// 	varHdr.Properties = make([]byte, int(propertiesLen))
// 	if _, err = reader.Read(varHdr.Properties); err != nil {
// 		return
// 	}
// 	return
// }

// type VariableHeaderPuback struct {
// 	PacketIdentifier [2]byte
// 	ReasonCode       byte
// 	Properties       []byte
// }

// func GetVariableHeaderPuback(reader io.Reader, qos byte) (varHdr *VariableHeaderPuback, err error) {
// 	varHdr = &VariableHeaderPuback{}

// 	if _, err = reader.Read(varHdr.PacketIdentifier[:]); err != nil {
// 		return
// 	}

// 	buf := make([]byte, 1)
// 	if _, err = reader.Read(buf); err != nil {
// 		return
// 	}
// 	propertiesLen := buf[0]

// 	varHdr.Properties = make([]byte, int(propertiesLen))
// 	if _, err = reader.Read(varHdr.Properties); err != nil {
// 		return
// 	}
// 	return
// }

// type VariableHeaderPubrec struct {
// 	ReasonCode byte
// 	Properties []byte
// }

// type VariableHeaderPubrel struct {
// 	ReasonCode byte
// 	Properties []byte
// }

// type VariableHeaderPubcomp struct {
// 	ReasonCode byte
// 	Properties []byte
// }

// type VariableHeaderSubscribe struct {
// 	Properties []byte
// }

// type VariableHeaderSuback struct {
// 	Properties []byte
// }

// type VariableHeaderUnsubscribe struct {
// 	Properties []byte
// }

// type VariableHeaderUnsuback struct {
// 	Properties []byte
// }

// type VariableHeaderDisconnect struct {
// 	ReasonCode byte
// 	Properties []byte
// }
// type VariableHeaderAuth struct {
// 	ReasonCode byte
// 	Properties []byte
// }
