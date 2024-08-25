package t03subscribe

import (
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// // go test -x -v
func TestSubscribe_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_CIPHER_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(t, token, false, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
}

func TestSubscribe_PubToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_CIPHER_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoSubscribe(t, token, true, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
}

func TestSubscribe_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_CIPHER_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
		testutil.AutopahoSubscribe(t, token, false, nil, []byte{}, types.PAYLOAD_CIPHER_NONE, nil)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
