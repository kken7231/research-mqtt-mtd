package t01gettoken

import (
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

var Benchmarks = []func(*testing.B){
	BenchmarkGetToken_Pub_Single,
	BenchmarkGetToken_PubonSubTopic_Single,
	BenchmarkGetToken_Pub_Cycle,
	BenchmarkGetToken_Sub_Single,
	BenchmarkGetToken_SubonPubTopic_Single,
	BenchmarkGetToken_Sub_Cycle,
}

func BenchmarkGetToken_Pub_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.GetTokenTest(b, topic, *fetchReq, true)
}

func BenchmarkGetToken_PubonSubTopic_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.GetTokenTest(b, topic, *fetchReq, false)
}

func BenchmarkGetToken_Pub_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		testutil.GetTokenTest(b, topic, *fetchReq, true)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}

func BenchmarkGetToken_Sub_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.GetTokenTest(b, topic, *fetchReq, true)
}

func BenchmarkGetToken_SubonPubTopic_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	testutil.GetTokenTest(b, topic, *fetchReq, false)
}

func BenchmarkGetToken_Sub_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	b.StopTimer()
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		testutil.GetTokenTest(b, topic, *fetchReq, true)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
