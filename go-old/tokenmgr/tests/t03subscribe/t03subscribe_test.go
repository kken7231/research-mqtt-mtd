package t03subscribe

import (
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// // go test -x -v
func TestSubscribe_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, nil, []byte{})
}

func TestSubscribe_PubToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
	_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(t, timestamp, randomBytes, true, nil, []byte{})
}

func TestSubscribe_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
		testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, nil, []byte{})
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
