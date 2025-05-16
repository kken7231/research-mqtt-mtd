package t01gettoken

import (
	"encoding/hex"
	"fmt"
	"mqttmtd/consts"
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// go test -x -v
func TestGetToken_Pub_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(token[:consts.TIMESTAMP_LEN]), hex.EncodeToString(token[consts.TIMESTAMP_LEN:]))
}

func TestGetToken_PubonSubTopic_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	testutil.GetTokenTest(t, topic, *fetchReq, false)
}

func TestGetToken_Pub_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
		fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(token[:consts.TIMESTAMP_LEN]), hex.EncodeToString(token[consts.TIMESTAMP_LEN:]))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}

func TestGetToken_Sub_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
	fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(token[:consts.TIMESTAMP_LEN]), hex.EncodeToString(token[consts.TIMESTAMP_LEN:]))
}

func TestGetToken_SubonPubTopic_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	testutil.GetTokenTest(t, topic, *fetchReq, false)
}

func TestGetToken_Sub_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	testutil.LoadClientConfig(t)
	fetchReq := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		_, _, token := testutil.GetTokenTest(t, topic, *fetchReq, true)
		fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(token[:consts.TIMESTAMP_LEN]), hex.EncodeToString(token[consts.TIMESTAMP_LEN:]))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
