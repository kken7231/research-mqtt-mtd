package t02publish

import (
	"fmt"
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// go test -x -v
func TestPublish_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoPublish(t, timestamp, randomBytes, []byte("TestPublish_Single"))
}

func TestPublish_SubToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoPublish(t, timestamp, randomBytes, []byte("TestPublish_SubToken_Single"))
}

func TestPublish_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
		testutil.AutopahoPublish(t, timestamp, randomBytes, []byte(fmt.Sprintf("TestPublish_Cycle%d", i)))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
