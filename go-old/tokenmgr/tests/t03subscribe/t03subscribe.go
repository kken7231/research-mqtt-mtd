package t03subscribe

import (
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

var Benchmarks = []func(*testing.B){
	BenchmarkSubscribe_Single,
	BenchmarkSubscribe_PubToken_Single,
	BenchmarkSubscribe_Cycle,
}

func BenchmarkSubscribe_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	_, _, timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(b, timestamp, randomBytes, false, nil, []byte{})
}

func BenchmarkSubscribe_PubToken_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	_, _, timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(b, timestamp, randomBytes, true, nil, []byte{})
}

func BenchmarkSubscribe_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
		testutil.AutopahoSubscribe(b, timestamp, randomBytes, false, nil, []byte{})
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
