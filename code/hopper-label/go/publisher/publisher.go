package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/kken7231/research-mqtt-mtd/code/hopper-label/common"
)

var (
	TOKENS                     = make([][]byte, 0)
	TOPIC_NAMES                = make([][]byte, 0)
	OUTPUT_ONLY_TOKEN          = false
	OUTPUT_B64                 = false
	NUM_OF_FETCH_TOKENS uint16 = 1
)

func getFilePath(host string, port uint16, topicName string) string {
	return fmt.Sprintf("%s/publish/%s:%d:%s", common.CLIENT_OUTPUT_DIRECTORY, host, port, common.BytesToB64EncodedString(unsafe.Slice(unsafe.StringData(topicName), len(topicName))))
}

func printIfNotOnly(format string, a ...any) {
	if !OUTPUT_ONLY_TOKEN {
		fmt.Printf(format, a...)
	}
}

func printPacketIfNotOnly(inoutSpec string, conn net.Conn, content []byte) {
	if !OUTPUT_ONLY_TOKEN {
		common.PrintPacket(inoutSpec, conn, content, true)
	}
}

func isValidHostname(hostname string) bool {
	if len(hostname) > 255 || len(hostname) == 0 {
		return false
	}
	if hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) > 63 {
			return false
		}
		for _, char := range label {
			if !strings.Contains("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-", string(char)) {
				return false
			}
		}
	}
	return true
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

func isValidTopicName(topicName string) bool {
	if len(topicName) == 0 {
		return false
	}
	if !utf8.ValidString(topicName) {
		return false
	}

	for _, char := range topicName {
		if char < 32 || char > 126 || char == '+' || char == '#' {
			return false
		}
	}
	return true
}

func isValidNTokens(ntokens int) bool {
	return ntokens > 0 // && ntokens <= common.NUM_TOKENS_PER_GENE_MAX
}

func connectTLS(host string, port uint16, topicName string) ([]byte, error) {
	if len(topicName) > 0xFFFF {
		panic("Topic name too long")
	}
	defer func() {
		if r := recover(); r != nil {
			printIfNotOnly("Recovered in connectTLS: %v", r)
		}
	}()
	cert, err := tls.LoadX509KeyPair(common.CLIENT_CERT_FILE, common.CLIENT_KEY_FILE)
	if err != nil {
		panic(err)
	}

	caCert, err := os.ReadFile(common.CA_CERT_FILE)
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		fmt.Printf("Error connecting to TLS server: %v\n", err)
		return nil, err
	}
	defer conn.Close()

	var topicNameLen uint16 = uint16(len(topicName))
	data := make([]byte, 0, 4+topicNameLen)

	data = binary.BigEndian.AppendUint16(data, NUM_OF_FETCH_TOKENS)
	data[0] |= common.FETCH_TOKEN_FOR_PUB
	data = binary.BigEndian.AppendUint16(data, topicNameLen)
	data = append(data, unsafe.Slice(unsafe.StringData(topicName), int(topicNameLen))...)
	conn.Write(data)
	printPacketIfNotOnly("outgoing", conn, data)

	response := make([]byte, NUM_OF_FETCH_TOKENS*common.TOKEN_LEN)
	n, err := conn.Read(response)
	if err != nil {
		fmt.Printf("Error receiving from TLS server: %v\n", err)
		return nil, err
	}
	response = response[:n]
	printPacketIfNotOnly("incoming", conn, response)

	err = storeTokens(host, port, topicName, response[common.TOKEN_LEN:])
	return response[:common.TOKEN_LEN], err
}

func storeTokens(host string, port uint16, topicName string, tokensToBeSaved []byte) error {
	if len(tokensToBeSaved) == 0 {
		return nil
	}
	if len(tokensToBeSaved) < common.TOKEN_LEN {
		panic("No data as randomized topic names")
	}
	return os.WriteFile(getFilePath(host, port, topicName), tokensToBeSaved, os.ModePerm)
}

func popToken(filePath string) ([]byte, error) {
	tokens, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	if len(tokens)%common.TOKEN_LEN != 0 || len(tokens) == 0 {
		fmt.Printf("%d %d\n", len(tokens), common.TOKEN_LEN)
		panic(fmt.Sprintf("Invalid File: %s", filePath))
	}
	if len(tokens) < common.TOKEN_LEN*2 {
		err = os.Remove(filePath)
	} else {
		err = os.WriteFile(filePath, tokens[common.TOKEN_LEN:], os.ModePerm)
	}
	return tokens[:common.TOKEN_LEN], err
}

func getToken(host string, port uint16, topicName string) ([]byte, error) {
	filePath := getFilePath(host, port, topicName)
	if _, err := os.Stat(filePath); err == nil {
		return popToken(filePath)
	}
	return connectTLS(host, port, topicName)
}

func main() {
	common.EnsureOutputDir(common.CLIENT_OUTPUT_DIRECTORY)

	only := flag.Bool("only", false, "Prints only the token if true, otherwise prints all")
	b64 := flag.Bool("b64", false, "Prints the b64-encoded token if true, otherwise prints all")
	ntokens := flag.Int("ntokens", -1, "Number of tokens to be generated")
	host := flag.String("host", "", "Hostname of the MQTT server")
	port_int := flag.Int("port", 0, "Port number of the MQTT server")
	topic := flag.String("topic", "", "MQTT topic name")
	flag.Parse()

	// Validate inputs
	if !isValidHostname(*host) {
		fmt.Println("Invalid hostname")
	} else if !isValidPort(*port_int) {
		fmt.Println("Invalid port number")
	} else if !isValidTopicName(*topic) {
		fmt.Println("Invalid topic name. It must be an ASCII string with printable characters.")
	} else if !isValidNTokens(*ntokens) {
		fmt.Printf("Invalid number of token generation. It must be between 0 and %d.\n", common.NUM_TOKENS_PER_GENE_MAX)
	} else {
		OUTPUT_ONLY_TOKEN = *only
		OUTPUT_B64 = *b64
		NUM_OF_FETCH_TOKENS = uint16(*ntokens)
		// Proceed with connection and topic name fetching
		retrieved, err := getToken(*host, uint16(*port_int), *topic)
		if err != nil {
			fmt.Println("Error found")
			os.Exit(-1)
		} else if OUTPUT_ONLY_TOKEN {
			if OUTPUT_B64 {
				fmt.Print(common.BytesToB64EncodedString(retrieved))
			} else {
				fmt.Print(common.BytesToEscapedString(retrieved))
			}
		} else {
			if OUTPUT_B64 {
				fmt.Printf("First Token: %s\n", common.BytesToB64EncodedString(retrieved))
			} else {
				fmt.Printf("First Token: %s\n", common.BytesToEscapedString(retrieved))
			}
		}
	}
}
