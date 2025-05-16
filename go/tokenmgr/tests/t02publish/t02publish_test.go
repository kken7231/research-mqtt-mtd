package t02publish

import (
	"fmt"
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// go test -x -v
func TestPublish_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoPublish(t, token, []byte("TestPublish_Single"), types.PAYLOAD_AEAD_NONE, nil, 0)
}

func TestPublish_SubToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	testutil.AutopahoPublish(t, token, []byte("TestPublish_SubToken_Single"), types.PAYLOAD_AEAD_NONE, nil, 0)
}

func TestPublish_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
		testutil.AutopahoPublish(t, token, []byte(fmt.Sprintf("TestPublish_Cycle%d", i)), types.PAYLOAD_AEAD_NONE, nil, 0)
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
