package mqttparser

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

func decodeVariableByteInteger(src []byte) (value int, len int, err error) {
	ended := false
	var i int = 0
	for i < 4 {
		encodedByte := int(src[i])
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
	len = i
	return
}

func EncodeToVariableByteInteger(value int) (encoded []byte, err error) {
	encoded = make([]byte, 4)
	ended := false
	remainedValue := value
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
	return
}

func decodeUTF8EncodedString(src []byte) (value string, err error) {
	length := int(binary.BigEndian.Uint16(src[:2]))
	if length > len(src)-2 {
		err = fmt.Errorf("length not inadequate")
		return
	}
	value = string(src[2 : 2+length])
	return
}

func encodeToUTF8EncodedString(value string) (encoded []byte, err error) {
	if len(value) > 0xFFFF {
		err = fmt.Errorf("length too long")
		return
	}
	encoded = make([]byte, 2+len(value))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(value)))
	copy(encoded[2:], unsafe.Slice(unsafe.StringData(value), len(value)))
	return
}
