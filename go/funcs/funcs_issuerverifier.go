package funcs

import (
	"context"
	"encoding/binary"
	"fmt"
	"mqttmtd/consts"
	"mqttmtd/types"
	"net"
	"time"
)

func SendIssuerRequest(ctx context.Context, conn net.Conn, timeout time.Duration, issuerRequest types.IssuerRequest) error {
	// Prepare the buffer for the entire message
	topicLen := len(issuerRequest.Topic)
	buf := make([]byte, 1+1+2+topicLen)

	// Set the flag
	buf[0] = 0
	if issuerRequest.AccessTypeIsPub {
		buf[0] |= consts.BIT_7
	}
	if issuerRequest.PayloadAEADRequested {
		buf[0] |= consts.BIT_6
	}
	if issuerRequest.NumberOfTokensDividedByMultiplier < 1 || issuerRequest.NumberOfTokensDividedByMultiplier > 0x1F {
		return fmt.Errorf("field NumberOfTokens is not in the range of [1, 0x1F]")
	}
	buf[0] |= issuerRequest.NumberOfTokensDividedByMultiplier

	offset := 1

	// Payload AEAD Type
	if issuerRequest.PayloadAEADRequested {
		buf[offset] = byte(issuerRequest.PayloadAEADType)
		offset += 1
	}

	// Topic
	binary.BigEndian.PutUint16(buf[offset:], uint16(topicLen))
	offset += 2
	copy(buf[offset:], issuerRequest.Topic)

	// Write the data to connection
	_, err := ConnWrite(ctx, conn, buf[:offset+len(issuerRequest.Topic)], timeout)
	return err
}

func ParseIssuerRequest(ctx context.Context, conn net.Conn, timeout time.Duration) (types.IssuerRequest, error) {
	buf := make([]byte, 2)

	// Read the flag
	if n, err := ConnRead(ctx, conn, buf[:1], timeout); err != nil || n != 1 {
		return types.IssuerRequest{}, fmt.Errorf("failed reading the flag field of an issuer request")
	}
	flag := buf[0]

	request := types.IssuerRequest{
		AccessTypeIsPub:                   (flag & consts.BIT_7) != 0,
		PayloadAEADRequested:              (flag & consts.BIT_6) != 0,
		NumberOfTokensDividedByMultiplier: flag & 0x1F,
	}

	// Read Payload AEAD Type if requested
	if request.PayloadAEADRequested {
		if n, err := ConnRead(ctx, conn, buf[:1], timeout); err != nil || n != 1 {
			return request, fmt.Errorf("failed reading payload AEAD type field of an issuer request")
		}
		request.PayloadAEADType = types.PayloadAEADType(buf[0])
	}

	// Read the topic length
	if n, err := ConnRead(ctx, conn, buf, timeout); err != nil || n != 2 {
		return request, fmt.Errorf("failed reading the length of Topic field of an issuer request")
	}
	topicLen := binary.BigEndian.Uint16(buf)

	// Validate and read the topic
	if topicLen > consts.MAX_UTF8_ENCODED_STRING_SIZE {
		return request, fmt.Errorf("invalid Topic length")
	}
	request.Topic = make([]byte, topicLen)
	if n, err := ConnRead(ctx, conn, request.Topic, timeout); err != nil || n != int(topicLen) {
		return request, fmt.Errorf("failed reading Topic field of an issuer request")
	}

	return request, nil
}

func SendIssuerResponse(ctx context.Context, conn net.Conn, timeout time.Duration, issuerResponse types.IssuerResponse) error {
	keyLen := len(issuerResponse.EncryptionKey)
	totalLen := keyLen + consts.TIMESTAMP_LEN + len(issuerResponse.AllRandomBytes)
	buf := make([]byte, totalLen)

	offset := 0

	// Encryption Key
	copy(buf[offset:], issuerResponse.EncryptionKey)
	offset += keyLen

	// Timestamp
	copy(buf[offset:], issuerResponse.Timestamp)
	offset += consts.TIMESTAMP_LEN

	// All Random Bytes
	copy(buf[offset:], issuerResponse.AllRandomBytes)

	// Write all the data to connection
	_, err := ConnWrite(ctx, conn, buf, timeout)
	return err
}

func ParseIssuerResponse(ctx context.Context, conn net.Conn, timeout time.Duration, request types.IssuerRequest) (types.IssuerResponse, error) {
	keyLen := 0
	if request.PayloadAEADRequested {
		keyLen = request.PayloadAEADType.GetKeyLen()
	}

	totalLen := keyLen + consts.TIMESTAMP_LEN + int(request.NumberOfTokensDividedByMultiplier)*consts.TOKEN_NUM_MULTIPLIER*consts.RANDOM_BYTES_LEN
	buf := make([]byte, totalLen)

	// Read all the data from the connection
	if n, err := ConnRead(ctx, conn, buf, timeout); err != nil || n != totalLen {
		return types.IssuerResponse{}, fmt.Errorf("failed reading the issuer response")
	}

	response := types.IssuerResponse{
		EncryptionKey:  buf[:keyLen],
		Timestamp:      buf[keyLen : keyLen+consts.TIMESTAMP_LEN],
		AllRandomBytes: buf[keyLen+consts.TIMESTAMP_LEN:],
	}

	return response, nil
}

func SendVerifierRequest(ctx context.Context, conn net.Conn, timeout time.Duration, verifierRequest types.VerifierRequest) error {
	// Prepare the buffer for the flag and token
	buf := make([]byte, 1+consts.TOKEN_SIZE)

	// Set the flag
	buf[0] = 0
	if verifierRequest.AccessTypeIsPub {
		buf[0] |= consts.BIT_7
	}

	// Token
	copy(buf[1:], verifierRequest.Token)

	// Write the data to connection
	_, err := ConnWrite(ctx, conn, buf, timeout)
	return err
}

func ParseVerifierRequest(ctx context.Context, conn net.Conn, timeout time.Duration) (types.VerifierRequest, error) {
	buf := make([]byte, 1+consts.TOKEN_SIZE)

	// Read the flag and token
	if n, err := ConnRead(ctx, conn, buf, timeout); err != nil || n != len(buf) {
		return types.VerifierRequest{}, fmt.Errorf("failed reading verifier request")
	}

	request := types.VerifierRequest{
		AccessTypeIsPub: (buf[0] & consts.BIT_7) != 0,
		Token:           buf[1:],
	}

	return request, nil
}

func SendVerifierResponse(ctx context.Context, conn net.Conn, timeout time.Duration, verifierResponse types.VerifierResponse) error {
	buf := []byte{byte(verifierResponse.ResultCode)}

	if verifierResponse.ResultCode.IsSuccessEncKey() {
		tmp := make([]byte, 2)

		// Token Index
		binary.BigEndian.PutUint16(tmp, verifierResponse.TokenIndex)
		buf = append(buf, tmp...)

		// Payload AEAD Type
		buf = append(buf, byte(verifierResponse.PayloadAEADType))

		// Encryption Key
		buf = append(buf, verifierResponse.EncryptionKey...)
	}

	if verifierResponse.ResultCode.IsSuccess() {
		// Topic Length and Topic
		topicLen := make([]byte, 2)
		binary.BigEndian.PutUint16(topicLen, uint16(len(verifierResponse.Topic)))
		buf = append(buf, topicLen...)
		buf = append(buf, verifierResponse.Topic...)
	}

	// Write all the data to connection
	_, err := ConnWrite(ctx, conn, buf, timeout)
	return err
}

func ParseVerifierResponse(ctx context.Context, conn net.Conn, timeout time.Duration, request types.VerifierRequest) (types.VerifierResponse, error) {
	buf := make([]byte, 2)
	var response types.VerifierResponse

	// Read the result code
	if n, err := ConnRead(ctx, conn, buf[:1], timeout); err != nil || n != 1 {
		return response, fmt.Errorf("failed reading the result code field of a verifier response")
	}
	response.ResultCode = types.VerificationResultCode(buf[0])

	if response.ResultCode.IsSuccessEncKey() {
		// Read Token Index and Payload AEAD Type
		if n, err := ConnRead(ctx, conn, buf, timeout); err != nil || n != 2 {
			return response, fmt.Errorf("failed reading Token Index field of a verifier response")
		}
		response.TokenIndex = binary.BigEndian.Uint16(buf)

		if n, err := ConnRead(ctx, conn, buf[:1], timeout); err != nil || n != 1 {
			return response, fmt.Errorf("failed reading Payload AEAD Type field of a verifier response")
		}
		response.PayloadAEADType = types.PayloadAEADType(buf[0])

		// Read Encryption Key
		keyLen := response.PayloadAEADType.GetKeyLen()
		response.EncryptionKey = make([]byte, keyLen)
		if n, err := ConnRead(ctx, conn, response.EncryptionKey, timeout); err != nil || n != keyLen {
			return response, fmt.Errorf("failed reading Encryption Key field of a verifier response")
		}
	}

	if response.ResultCode.IsSuccess() {
		// Read Topic Length
		if n, err := ConnRead(ctx, conn, buf, timeout); err != nil || n != 2 {
			return response, fmt.Errorf("failed reading Topic Length field of a verifier response")
		}
		topicLen := binary.BigEndian.Uint16(buf)

		// Validate and read the topic
		if topicLen > consts.MAX_UTF8_ENCODED_STRING_SIZE {
			return response, fmt.Errorf("invalid Topic length")
		}
		response.Topic = make([]byte, topicLen)
		if n, err := ConnRead(ctx, conn, response.Topic, timeout); err != nil || n != int(topicLen) {
			return response, fmt.Errorf("failed reading Topic field of a verifier response")
		}
	}

	return response, nil
}
