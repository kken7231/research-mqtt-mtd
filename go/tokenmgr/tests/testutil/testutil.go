package testutil

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"mqttmtd/config"
	"mqttmtd/consts"
	"mqttmtd/tokenmgr"
	"mqttmtd/types"
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
)

const (
	SAMPLE_TOPIC_PUB    string = "/sample/topic/pub"
	SAMPLE_TOPIC_SUB    string = "/sample/topic/sub"
	SAMPLE_TOPIC_PUBSUB string = "/sample/topic/pubsub"

	// if server uses mDNS
	// ADDR_MQTT_INTERFACE string = "mqtt://server.local:1883"
	// else (like docker)
	ADDR_MQTT_INTERFACE string = "mqtt://server:1883"

	// CONFIG_FILEPATH string = "/Users/kentarou/git/research-mqtt-mtd/go/config/client_conf.yml"
	// CONFIG_FILEPATH string = "/Users/kentarou/git/research-mqtt-mtd/go/config/client_conf.yml"
	CONFIG_FILEPATH string = "/mqttmtd/config/client_conf.yml"
)

var (
	NumTokens uint16 = 0x10 * 16
)

func SetNumTokens(numTokens uint16) {
	NumTokens = numTokens
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

func PrepareFetchReq(accessTypeIsPub bool, aeadType types.PayloadAEADType) (fetchReq *tokenmgr.FetchRequest) {
	fetchReq = &tokenmgr.FetchRequest{
		NumTokens:       NumTokens,
		AccessTypeIsPub: accessTypeIsPub,
		PayloadAEADType: aeadType,
	}
	return
}

func sealMessage(tb testing.TB, aeadType types.PayloadAEADType, encKey []byte, tokenIndex uint16, msg []byte) (sealed []byte) {
	var err error
	if sealed, err = aeadType.SealMessage(msg, encKey, uint64(tokenIndex)); err != nil {
		Fatal(tb, err)
	}
	return
}

func openMessage(tb testing.TB, aeadType types.PayloadAEADType, encKey []byte, pubSeqNum uint64, sealedMsg []byte) (opened []byte) {
	var err error
	if opened, err = aeadType.OpenMessage(sealedMsg, encKey, pubSeqNum); err != nil {
		Fatal(tb, err)
	}
	return
}

func AutopahoPublish(tb testing.TB, token []byte, msg []byte, aeadType types.PayloadAEADType, encKey []byte, tokenIndex uint16) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	b64Encoded := make([]byte, consts.TOKEN_SIZE/3*4)
	base64.URLEncoding.Encode(b64Encoded, token)

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

	// Publish a test message
	if aeadType.IsEncryptionEnabled() {
		// Payload AEAD Encryption Enabled
		if _, err = cm.Publish(ctx, &paho.Publish{
			QoS:     0,
			Topic:   string(b64Encoded),
			Payload: sealMessage(tb, aeadType, encKey, tokenIndex, msg),
		}); err != nil {
			if ctx.Err() == nil {
				Fatal(tb, err)
			}
		}
	} else {
		// Payload AEAD Encryption Disabled
		if _, err = cm.Publish(ctx, &paho.Publish{
			QoS:     0,
			Topic:   string(b64Encoded),
			Payload: msg,
		}); err != nil {
			if ctx.Err() == nil {
				Fatal(tb, err)
			}
		}
	}
	fmt.Println("mqtt publish made")

	cm.Disconnect(ctx)
	<-cm.Done() // Wait for clean shutdown (cancelling the context triggered the shutdown)
}

func AutopahoSubscribe(tb testing.TB, token []byte, isErrorExpected bool, subscribeChan chan struct{}, waitForPublish []byte, aeadType types.PayloadAEADType, encKey []byte) {
	var pubSeqNum uint64 = 0

	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	b64Encoded := make([]byte, consts.TOKEN_SIZE/3*4)
	base64.URLEncoding.Encode(b64Encoded, token)

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
	onPublishReceivedFunc := func(pr paho.PublishReceived) (bool, error) {
		if aeadType.IsEncryptionEnabled() {
			opened := openMessage(tb, aeadType, encKey, pubSeqNum, pr.Packet.Payload)
			fmt.Printf("received sealed message on topic \"%s\"; body: %s (retain: %t)\n", pr.Packet.Topic, opened, pr.Packet.Retain)
			if bytes.Equal(opened, waitForPublish) {
				received <- struct{}{}
			}
		} else {
			fmt.Printf("received message on topic \"%s\"; body: %s (retain: %t)\n", pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain)
			if bytes.Equal(pr.Packet.Payload, waitForPublish) {
				received <- struct{}{}
			}
		}
		return true, nil
	}
	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     20,
		CleanStartOnInitialConnection: true,
		SessionExpiryInterval:         0xFFFFFFFF,
		OnConnectionUp:                func(cm *autopaho.ConnectionManager, connAck *paho.Connack) { fmt.Println("mqtt connection up") },
		OnConnectError:                func(err error) { fmt.Printf("error whilst attempting connection: %s\n", err) },
		ClientConfig: paho.ClientConfig{
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){onPublishReceivedFunc},
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

	// Subscribe to topic
	if _, err = cm.Subscribe(ctx, &paho.Subscribe{
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
	} else {
		fmt.Println("mqtt subscription made")
	}
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

func LoadClientConfig(tb testing.TB) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	if err := config.LoadClientConfig(CONFIG_FILEPATH); err != nil {
		Fatal(tb, err)
	}
	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}
}

func RemoveTokenFile(topic string, fetchReq tokenmgr.FetchRequest) {
	var accessTypeStr string
	if fetchReq.AccessTypeIsPub {
		accessTypeStr = "PUB"
	} else {
		accessTypeStr = "SUB"
	}
	tokenFilePath := config.Client.FilePaths.TokensDirPath + accessTypeStr + base64.URLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	os.Remove(tokenFilePath)
}

func GetTokenTest(tb testing.TB, topic string, fetchReq tokenmgr.FetchRequest, expectSuccess bool) (encKey []byte, tokenIndex uint16, token []byte) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	var err error
	encKey, tokenIndex, token, err = tokenmgr.GetToken(topic, fetchReq)
	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}
	if expectSuccess {
		if err != nil {
			Fatal(tb, err)
		}
		if len(token) != consts.TOKEN_SIZE {
			Fatal(tb, fmt.Errorf("length invalid"))
		}
		if (fetchReq.PayloadAEADType.IsEncryptionEnabled() && encKey == nil) || (!fetchReq.PayloadAEADType.IsEncryptionEnabled() && encKey != nil) {
			Fatal(tb, fmt.Errorf("enc invalid"))
		}
		return
	} else {
		if err == nil && len(token) == consts.TOKEN_SIZE &&
			((fetchReq.PayloadAEADType.IsEncryptionEnabled() && encKey != nil) || (!fetchReq.PayloadAEADType.IsEncryptionEnabled() && encKey == nil)) {
			Fatal(tb, fmt.Errorf("no error observed"))
		}
		return
	}
}
