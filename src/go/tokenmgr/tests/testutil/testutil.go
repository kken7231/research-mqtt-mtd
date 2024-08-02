package testutil

import (
	"context"
	"encoding/base64"
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
)

const (
	SAMPLE_TOPIC_PUB    string = "/sample/topic/pub"
	SAMPLE_TOPIC_SUB    string = "/sample/topic/sub"
	SAMPLE_TOPIC_PUBSUB string = "/sample/topic/pubsub"
)

var (
	NumTokens byte = 0x10 * 4
)

func SetNumTokens(numTokens byte) {
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

func PrepareFetchReq(accessType tokenmgr.AccessType) (fetchReq *tokenmgr.FetchRequest) {
	fetchReq = &tokenmgr.FetchRequest{
		NumTokens:  NumTokens,
		AccessType: accessType,
		CaCrt:      "/mqttmtd/certs/ca/ca.crt",
		ClientCrt:  "/mqttmtd/certs/client/client1.crt",
		ClientKey:  "/mqttmtd/certs/client/client1.key",
	}
	return
}

func AutopahoPublish(tb testing.TB, timestamp []byte, randomBytes []byte, msg string) {
	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	b64Encoded := make([]byte, tokenmgr.TOKEN_SIZE/3*4)
	base64.StdEncoding.Encode(b64Encoded, append(timestamp, randomBytes...))

	if b, ok := tb.(*testing.B); ok {
		b.StopTimer()
	}

	u, err := url.Parse("mqtt://server:1883")
	if err != nil {
		Fatal(tb, err)
	}

	if b, ok := tb.(*testing.B); ok {
		b.StartTimer()
	}
	cliCfg := autopaho.ClientConfig{
		ServerUrls: []*url.URL{u},
		KeepAlive:  20, // Keepalive message should be sent every 20 seconds
		// CleanStartOnInitialConnection defaults to false. Setting this to true will clear the session on the first connection.
		CleanStartOnInitialConnection: false,
		// SessionExpiryInterval - Seconds that a session will survive after disconnection.
		// It is important to set this because otherwise, any queued messages will be lost if the connection drops and
		// the server will not queue messages while it is down. The specific setting will depend upon your needs
		// (60 = 1 minute, 3600 = 1 hour, 86400 = one day, 0xFFFFFFFE = 136 years, 0xFFFFFFFF = don't expire)
		SessionExpiryInterval: 60,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			fmt.Println("mqtt connection up")
			// Subscribing in the OnConnectionUp callback is recommended (ensures the subscription is reestablished if
			// the connection drops)
			// if _, err := cm.Subscribe(context.Background(), &paho.Subscribe{
			// 	Subscriptions: []paho.SubscribeOptions{
			// 		{Topic: topic, QoS: 1},
			// 	},
			// }); err != nil {
			// 	fmt.Printf("failed to subscribe (%s). This is likely to mean no messages will be received.", err)
			// }
			// fmt.Println("mqtt subscription made")
		},
		OnConnectError: func(err error) { fmt.Printf("error whilst attempting connection: %s\n", err) },
		// eclipse/paho.golang/paho provides base mqtt functionality, the below config will be passed in for each connection
		ClientConfig: paho.ClientConfig{
			// If you are using QOS 1/2, then it's important to specify a client id (which must be unique)
			// ClientID: clientID,
			// OnPublishReceived is a slice of functions that will be called when a message is received.
			// You can write the function(s) yourself or use the supplied Router
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(pr paho.PublishReceived) (bool, error) {
					fmt.Printf("received message on topic %s; body: %s (retain: %t)\n", pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain)
					return true, nil
				}},
			OnClientError: func(err error) { fmt.Printf("client error: %s\n", err) },
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
		Payload: []byte(msg),
	}); err != nil {
		if ctx.Err() == nil {
			Fatal(tb, err)
		}
	}
	cm.Disconnect(ctx)
	<-cm.Done() // Wait for clean shutdown (cancelling the context triggered the shutdown)
}

func RemoveTokenFile(topic string, fetchReq tokenmgr.FetchRequest) {
	tokenFilePath := tokenmgr.TOKENS_DIR + fetchReq.AccessType.String() + base64.URLEncoding.EncodeToString(unsafe.Slice(unsafe.StringData(topic), len(topic)))
	os.Remove(tokenFilePath)
}

func GetTokenTest(tb testing.TB, topic string, fetchReq tokenmgr.FetchRequest, expectSuccess bool) (timestamp []byte, randomBytes []byte) {
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
	timestamp, randomBytes, err := tokenmgr.GetToken(topic, fetchReq)
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
		return
	} else {
		if err == nil {
			Fatal(tb, fmt.Errorf("no error observed"))
		}
		return
	}
}
