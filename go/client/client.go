package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"unsafe"

	"mqttmtd/consts"
	"mqttmtd/tokenmgr"
	"mqttmtd/types"
)

const (
	TOKENS_DIR = "/mqttmtd/tokens/"

	DEFAULT_CA_CRTFILE = "/mqttmtd/certs/ca/ca.crt"

	DEFAULT_CLIENT_CRTFILE = "/mqttmtd/certs/client/client.crt"
	DEFAULT_CLIENT_KEYFILE = "/mqttmtd/certs/client/client.key"

	TOKEN_NUM_MULTIPLIER = 16
)

func formatNibbleToCappedAscii(nib byte) byte {
	s_nib := nib & 0xF
	if s_nib < 0xA {
		return s_nib + '0'
	} else {
		return (s_nib - 0xA) + 'A'
	}
}

func formatByteToCappedAsciis(b byte, dst [2]byte) {
	dst[0] = formatNibbleToCappedAscii(b >> 4)
	dst[1] = formatNibbleToCappedAscii(b)
}

func main() {
	returnOnlyToken := *flag.Bool("tokenonly", false, "Prints only the token if true, otherwise prints all")
	b64 := *flag.Bool("b64", false, "Prints Base64-encoded token, otherwise hex")
	ntokens := *flag.Int("ntokens", -1, "Number of tokens to be generated")
	requestAccessType := *flag.String("reqtype", "", "PUB for pub, SUB for sub")
	topic := *flag.String("topic", "", "MQTT topic name")
	flag.Parse()

	// if returnOnlyToken {
	// 	tokenmgr.DebugEnabled = false
	// }
	if ntokens < TOKEN_NUM_MULTIPLIER || 0x1F*TOKEN_NUM_MULTIPLIER < ntokens || ntokens%TOKEN_NUM_MULTIPLIER != 0 {
		log.Fatalf("Invalid number of token generation. It must be between [%d, 0x1F*%d] and multiples of %d\n", TOKEN_NUM_MULTIPLIER, TOKEN_NUM_MULTIPLIER, TOKEN_NUM_MULTIPLIER)
	}
	var reqAccessType bool
	switch requestAccessType {
	case "PUB":
		reqAccessType = true
	case "SUB":
		reqAccessType = false
	default:
		log.Fatalln("Invalid access type requested. It must be either PUB, SUB or PUBSUB.")
	}
	if topic == "" {
		log.Fatalln("Invalid topic name. It must be an ASCII string with printable characters.")
	}

	fetchReq := &tokenmgr.FetchRequest{
		NumTokens:         uint16(ntokens),
		AccessTypeIsPub:   reqAccessType,
		PayloadCipherType: types.PAYLOAD_CIPHER_NONE,
	}
	_, _, token, err := tokenmgr.GetToken(topic, *fetchReq)
	if err != nil {
		log.Fatal(err)
	}

	var tokenStr string
	if b64 {
		tokenStr = base64.RawURLEncoding.EncodeToString(token)
	} else {
		tokenStrBytes := make([]byte, (consts.TIMESTAMP_LEN+consts.RANDOM_BYTES_LEN)*2)
		var buf [2]byte
		for i, b := range token {
			formatByteToCappedAsciis(b, buf)
			tokenStrBytes[2*i] = buf[0]
			tokenStrBytes[2*i+1] = buf[1]
		}
		tokenStr = unsafe.String(unsafe.SliceData(tokenStrBytes), len(tokenStrBytes))
	}
	if !returnOnlyToken {
		fmt.Print("Token: ")
	}
	fmt.Println(tokenStr)
}
