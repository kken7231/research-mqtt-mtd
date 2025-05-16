package t02publish

import (
	"fmt"
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"testing"
)

var Benchmarks = []func(*testing.B){
	BenchmarkPublish_Single,
	BenchmarkPublish_SubToken_Single,
	BenchmarkPublish_Cycle,
}

func BenchmarkPublish_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	b.StopTimer()
	_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoPublish(b, token, []byte("BenchmarkPublish_Single"), types.PAYLOAD_AEAD_NONE, nil, 0)
}

func BenchmarkPublish_SubToken_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	b.StopTimer()
	_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoPublish(b, token, []byte("BenchmarkPublish_SubToken_Single"), types.PAYLOAD_AEAD_NONE, nil, 0)
}

func BenchmarkPublish_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(b)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	b.StopTimer()
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(b, topic, *fetchReq, true)
		testutil.AutopahoPublish(b, token, []byte(fmt.Sprintf("BenchmarkPublish_Cycle%d", i)), types.PAYLOAD_AEAD_NONE, nil, 0)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
