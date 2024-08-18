package t01gettoken

import (
	"encoding/hex"
	"fmt"
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
	"testing"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// go test -x -v
func TestGetToken_Pub_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
	timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(timestamp), hex.EncodeToString(randomBytes))
}

func TestGetToken_PubonSubTopic_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
	testutil.GetTokenTest(t, topic, *fetchReq, false)
}

func TestGetToken_Pub_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
		fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(timestamp), hex.EncodeToString(randomBytes))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}

func TestGetToken_Sub_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub)
	timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
	fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(timestamp), hex.EncodeToString(randomBytes))
}
func TestGetToken_SubonPubTopic_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub)
	testutil.GetTokenTest(t, topic, *fetchReq, false)
}

func TestGetToken_Sub_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_SUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
		fmt.Printf("TIMESTAMP[%s], RANDOM_BYTES[%s]\n", hex.EncodeToString(timestamp), hex.EncodeToString(randomBytes))
	}
	testutil.RemoveTokenFile(topic, *fetchReq)
}
