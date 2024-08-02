package t02publish

import (
	"fmt"
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

var Benchmarks = []func(*testing.B){
	BenchmarkPublish_Single,
	BenchmarkPublish_SubToken_Single,
	BenchmarkPublish_Cycle,
}

func BenchmarkPublish_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
	b.StopTimer()
	timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoPublish(b, timestamp, randomBytes, "BenchmarkPublish_Single")
}

func BenchmarkPublish_SubToken_Single(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub)
	b.StopTimer()
	timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
	testutil.AutopahoPublish(b, timestamp, randomBytes, "BenchmarkPublish_SubToken_Single")
}

func BenchmarkPublish_Cycle(b *testing.B) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
	b.StopTimer()
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		timestamp, randomBytes := testutil.GetTokenTest(b, topic, *fetchReq, true)
		testutil.AutopahoPublish(b, timestamp, randomBytes, fmt.Sprintf("BenchmarkPublish_Cycle%d", i))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
