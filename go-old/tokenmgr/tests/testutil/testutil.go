package testutil

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"go/common"
	"go/tokenmgr"
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"
	"unsafe"

	"github.com/eclipse/paho.golang/autopaho"
	"github.com/eclipse/paho.golang/paho"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SAMPLE_TOPIC_PUB    string = "/sample/topic/pub"
	SAMPLE_TOPIC_SUB    string = "/sample/topic/sub"
	SAMPLE_TOPIC_PUBSUB string = "/sample/topic/pubsub"

	// if server uses mDNS
	// ADDR_MQTT_INTERFACE string = "mqtt://server.local:1883"
	// else (like docker)
	ADDR_MQTT_INTERFACE string = "mqtt://server:1883"

	CA_CRT     string = "/mqttmtd/certs/ca/ca.pem"
	CLIENT_CRT string = "/mqttmtd/certs/client/client.pem"
	CLIENT_KEY string = "/mqttmtd/certs/client/client.key"

	// CA_CRT     string = "/Users/kentarou/git/research-mqtt-mtd/src/certs/ca/ca.crt"
	// CLIENT_CRT string = "/Users/kentarou/git/research-mqtt-mtd/src/certs/clients/client1.crt"
	// CLIENT_KEY string = "/Users/kentarou/git/research-mqtt-mtd/src/certs/clients/client1.key"
)

var (
	NumTokens uint16 = 0x10 * 16
)

func SetNumTokens(numTokens uint16) {
	NumTokens = numTokens
}

func ConnRead(conn net.Conn, dst *[]byte, timeout time.Duration) (n int, err error) {
	return common.ConnReadBase(conn, dst, timeout)
}

func ConnWrite(conn net.Conn, data []byte, timeout time.Duration) (n int, err error) {
	return common.ConnWriteBase(conn, data, timeout)
}

func Fatal(tb testing.TB, err error) {
	fmt.Printf("%v\n", err)
	tb.Fatal()
}

func RunBenchmarks(iter int, funcs ...func(*testing.B)) (results map[string]*testing.BenchmarkResult) {
	results = make(map[string]*testing.BenchmarkResult, len(funcs))

	for _, benchmarkFunc := range funcs {
		rv := reflect.ValueOf(benchmarkFunc)
		funcName := runtime.FuncForPC(rv.Pointer()).Name()
		results[funcName] = &testing.BenchmarkResult{}
		for j := 0; j < iter; j++ {
			res := testing.Benchmark(benchmarkFunc)
			results[funcName].N += res.N
			results[funcName].T += res.T
			results[funcName].Bytes += res.Bytes
			results[funcName].MemAllocs += res.MemAllocs
			results[funcName].MemBytes += res.MemBytes
		}
	}

	return
}

// PrintResults takes a map of benchmark results and prints them in a tabular format with headers.
func PrintResults(results map[string]*testing.BenchmarkResult) {
	// Determine the maximum length of each column
	maxFuncNameLen := len("FuncName")
	maxNLen := len("N")
	maxTLen := len("T(ns)")
	maxTPerIterLen := len("T/N(ns)")
	maxBytesLen := len("Bytes")
	maxMemAllocsLen := len("MemAllocs")
	maxMemBytesLen := len("MemBytes")

	for name, result := range results {
		if len(name) > maxFuncNameLen {
			maxFuncNameLen = len(name)
		}
		nLen := len(fmt.Sprintf("%d", result.N))
		tLen := len(fmt.Sprintf("%d", result.T.Nanoseconds()))
		tPerIterLen := len(fmt.Sprintf("%d", result.NsPerOp()))
		bytesLen := len(fmt.Sprintf("%d", result.Bytes))
		memAllocsLen := len(fmt.Sprintf("%d", result.MemAllocs))
		memBytesLen := len(fmt.Sprintf("%d", result.MemBytes))

		if nLen > maxNLen {
			maxNLen = nLen
		}
		if tLen > maxTLen {
			maxTLen = tLen
		}
		if tPerIterLen > maxTPerIterLen {
			maxTPerIterLen = tPerIterLen
		}
		if bytesLen > maxBytesLen {
			maxBytesLen = bytesLen
		}
		if memAllocsLen > maxMemAllocsLen {
			maxMemAllocsLen = memAllocsLen
		}
		if memBytesLen > maxMemBytesLen {
			maxMemBytesLen = memBytesLen
		}
	}

	// Print the header with dynamic width
	fmt.Printf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s\n", maxFuncNameLen, "FuncName", maxNLen, "N", maxTLen, "T(ns)", maxTPerIterLen, "T/N(ns)", maxBytesLen, "Bytes", maxMemAllocsLen, "MemAllocs", maxMemBytesLen, "MemBytes")

	// Print each benchmark result with dynamic width
	resKeys := make([]string, 0, len(results))
	for k := range results {
		resKeys = append(resKeys, k)
	}
	sort.Strings(resKeys)
	for _, name := range resKeys {
		result := results[name]
		fmt.Printf("%-*s %-*d %-*d %-*d %-*d %-*d %-*d\n",
			maxFuncNameLen, name,
			maxNLen, result.N,
			maxTLen, result.T.Nanoseconds(),
			maxTPerIterLen, result.NsPerOp(),
			maxBytesLen, result.Bytes,
			maxMemAllocsLen, result.MemAllocs,
			maxMemBytesLen, result.MemBytes)
	}
}

func PrepareFetchReq(accessType tokenmgr.AccessType, payloadEnc tokenmgr.PayloadCipherType) (fetchReq *tokenmgr.FetchRequest) {
	fetchReq = &tokenmgr.FetchRequest{
		NumTokens:         NumTokens,
		AccessType:        accessType,
		CaCrt:             CA_CRT,
		ClientCrt:         CLIENT_CRT,
		ClientKey:         CLIENT_KEY,
		PayloadCipherType: payloadEnc,
	}
	return
}

func SealMessage(tb testing.TB, cipherType tokenmgr.PayloadCipherType, encKey []byte, numTokensRemained uint16, msg []byte) (sealed []byte) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	var (
		hashComputed []byte
		nonce        []byte
		encrypted    []byte
	)
	// Hash
	switch cipherType {
	case tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case tokenmgr.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		fallthrough
	case tokenmgr.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		hash := sha256.New()
		hash.Write([]byte(msg))
		hashComputed = hash.Sum(nil)
	case tokenmgr.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		hash := sha512.New384()
		hash.Write([]byte(msg))
		hashComputed = hash.Sum(nil)
	}

	// Encryption
	switch cipherType {
	case tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256:
		fallthrough
	case tokenmgr.PAYLOAD_CIPHER_AES_128_CCM_SHA256:
		fallthrough
	case tokenmgr.PAYLOAD_CIPHER_AES_256_GCM_SHA384:
		var (
			block  cipher.Block
			aesGCM cipher.AEAD
		)
		block, err := aes.NewCipher(encKey)
		if err != nil {
			Fatal(tb, err)
		}
		aesGCM, err = cipher.NewGCM(block)
		if err != nil {
			Fatal(tb, err)
		}
		nonce = make([]byte, aesGCM.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(tokenmgr.NONCE_BASE)+uint64(numTokensRemained))
		encrypted = aesGCM.Seal(nil, nonce, msg, nil)
	case tokenmgr.PAYLOAD_CIPHER_CHACHA20_POLY1305_SHA256:
		var (
			c20p1305 cipher.AEAD
		)
		c20p1305, err := chacha20poly1305.New(encKey)
		if err != nil {
			Fatal(tb, err)
		}
		nonce = make([]byte, c20p1305.NonceSize())
		binary.BigEndian.PutUint64(nonce, uint64(tokenmgr.NONCE_BASE)+uint64(numTokensRemained))
		encrypted = c20p1305.Seal(nil, nonce, encrypted, nil)
	}

	sealed = make([]byte, len(hashComputed)+len(encrypted))
	copy(sealed[:len(hashComputed)], hashComputed)
	copy(sealed[len(hashComputed):], encrypted)
	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}
	return
}

func AutopahoPublish(tb testing.TB, timestamp []byte, randomBytes []byte, msg []byte) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	b64Encoded := make([]byte, tokenmgr.TOKEN_SIZE/3*4)
	base64.StdEncoding.Encode(b64Encoded, append(timestamp, randomBytes...))

	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}

	u, err := url.Parse(ADDR_MQTT_INTERFACE)
	if err != nil {
		Fatal(tb, err)
	}

	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	onClientErrorFunc := func(err error) {
		fmt.Printf("client error: %s\n", err)
	}
	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     20,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0xFFFFFFFF,
		OnConnectionUp:                func(cm *autopaho.ConnectionManager, connAck *paho.Connack) { fmt.Println("mqtt connection up") },
		OnConnectError:                func(err error) { fmt.Printf("error whilst attempting connection: %s\n", err) },
		ClientConfig: paho.ClientConfig{
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){},
			OnClientError:     onClientErrorFunc,
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					fmt.Printf("server requested disconnect: %s\n", d.Properties.ReasonString)
				} else {
					fmt.Printf("server requested disconnect; reason code: %d\n", d.ReasonCode)
				}
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()

		if b, ok := tb.(*testing.B); ok {
			b.StopTimer()
		}
	}()

	// Connect to the server - this will return immediately after initiating the connection process
	cm, err := autopaho.NewConnection(ctx, cliCfg) // starts process; will reconnect until context cancelled
	if err != nil {
		Fatal(tb, err)
		return
	}

	// AwaitConnection will return immediately if connection is up; adding this call stops publication whilst
	// connection is unavailable.
	err = cm.AwaitConnection(ctx)
	if err != nil { // Should only happen when context is cancelled
		fmt.Printf("publisher done (AwaitConnection: %s)\n", err)
		return
	}

	// Publish a test message (use PublishViaQueue if you don't want to wait for a response)
	if _, err = cm.Publish(ctx, &paho.Publish{
		QoS:     0,
		Topic:   string(b64Encoded),
		Payload: msg,
	}); err != nil {
		if ctx.Err() == nil {
			Fatal(tb, err)
		}
	}
	fmt.Println("mqtt publish made")

	cm.Disconnect(ctx)
	<-cm.Done() // Wait for clean shutdown (cancelling the context triggered the shutdown)
}

func AutopahoSubscribe(tb testing.TB, timestamp []byte, randomBytes []byte, isErrorExpected bool, subscribeChan chan struct{}, waitForPublish []byte) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	b64Encoded := make([]byte, tokenmgr.TOKEN_SIZE/3*4)
	base64.StdEncoding.Encode(b64Encoded, append(timestamp, randomBytes...))

	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}

	u, err := url.Parse(ADDR_MQTT_INTERFACE)
	if err != nil {
		Fatal(tb, err)
	}

	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	onClientErrorFunc := func(err error) {
		fmt.Printf("client error: %s\n", err)
		if !isErrorExpected {
			Fatal(tb, err)
		}
	}
	received := make(chan struct{})
	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     20,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0xFFFFFFFF,
		OnConnectionUp:                func(cm *autopaho.ConnectionManager, connAck *paho.Connack) { fmt.Println("mqtt connection up") },
		OnConnectError:                func(err error) { fmt.Printf("error whilst attempting connection: %s\n", err) },
		ClientConfig: paho.ClientConfig{
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					fmt.Printf("received message on topic %s; body: %s (retain: %t)\n", pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain)
					if bytes.Equal(pr.Packet.Payload, waitForPublish) {
						received <- struct{}{}
					}
					return true, nil
				}},
			OnClientError: onClientErrorFunc,
			OnServerDisconnect: func(d *paho.Disconnect) {
				if d.Properties != nil {
					fmt.Printf("server requested disconnect: %s\n", d.Properties.ReasonString)
				} else {
					fmt.Printf("server requested disconnect; reason code: %d\n", d.ReasonCode)
				}
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()

		if b, ok := tb.(*testing.B); ok {
			b.StopTimer()
		}
	}()

	// Connect to the server - this will return immediately after initiating the connection process
	cm, err := autopaho.NewConnection(ctx, cliCfg) // starts process; will reconnect until context cancelled
	if err != nil {
		Fatal(tb, err)
		return
	}

	// AwaitConnection will return immediately if connection is up; adding this call stops publication whilst
	// connection is unavailable.
	err = cm.AwaitConnection(ctx)
	if err != nil { // Should only happen when context is cancelled
		fmt.Printf("publisher done (AwaitConnection: %s)\n", err)
		return
	}

	// Subscribe to topic
	if _, err = cm.Subscribe(context.Background(), &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{
			QoS:   0,
			Topic: string(b64Encoded),
		}},
	}); err != nil {
		if ctx.Err() == nil && !isErrorExpected {
			Fatal(tb, err)
		}
	} else if isErrorExpected {
		Fatal(tb, err)
	}
	fmt.Println("mqtt subscription made")
	if subscribeChan != nil {
		subscribeChan <- struct{}{}
	}

	if len(waitForPublish) > 0 {
		select {
		case <-time.After(time.Second * 10):
			Fatal(tb, err)
		case <-received:
		}
	}
	cm.Disconnect(ctx)
	<-cm.Done() // Wait for clean shutdown (cancelling the context triggered the shutdown)
}

func RemoveTokenFile(topic string, fetchReq tokenmgr.FetchRequest) {
	tokenFilePath := tokenmgr.TOKENS_DIR + fetchReq.AccessType.String() + base64.URLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	os.Remove(tokenFilePath)
}

func GetTokenTest(tb testing.TB, topic string, fetchReq tokenmgr.FetchRequest, expectSuccess bool) (encKey []byte, numTokensRemained int, timestamp []byte, randomBytes []byte) {
	if _, err := os.Stat(fetchReq.CaCrt); err != nil {
		Fatal(tb, err)
	}
	if _, err := os.Stat(fetchReq.ClientCrt); err != nil {
		Fatal(tb, err)
	}
	if _, err := os.Stat(fetchReq.ClientKey); err != nil {
		Fatal(tb, err)
	}

	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	encKey, numTokensRemained, timestamp, randomBytes, err := tokenmgr.GetToken(topic, fetchReq)
	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}
	if expectSuccess {
		if err != nil {
			Fatal(tb, err)
		}
		if len(timestamp) != tokenmgr.TIMESTAMP_LEN || len(randomBytes) != tokenmgr.RANDOM_BYTES_LEN {
			Fatal(tb, fmt.Errorf("length invalid"))
		}
		if (fetchReq.PayloadCipherType.IsValidCipherType() && encKey == nil) || (!fetchReq.PayloadCipherType.IsValidCipherType() && encKey != nil) {
			Fatal(tb, fmt.Errorf("enc invalid"))
		}
		return
	} else {
		if err == nil && len(timestamp) == tokenmgr.TIMESTAMP_LEN &&
			len(randomBytes) == tokenmgr.RANDOM_BYTES_LEN &&
			((fetchReq.PayloadCipherType.IsValidCipherType() && encKey != nil) || (!fetchReq.PayloadCipherType.IsValidCipherType() && encKey == nil)) {
			Fatal(tb, fmt.Errorf("no error observed"))
		}
		return
	}
}
