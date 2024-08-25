package t03subscribe

import (
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"testing"
)

var Benchmarks = []func(*testing.B){
	BenchmarkSubscribe_Single,
	BenchmarkSubscribe_PubToken_Single,
	BenchmarkSubscribe_Cycle,
}

func BenchmarkSubscribe_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(b, token, false, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
}

func BenchmarkSubscribe_PubToken_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(b, token, true, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
}

func BenchmarkSubscribe_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
		testutil.AutopahoSubscribe(b, token, false, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
