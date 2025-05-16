package t04pubsub

import (
	"fmt"
	"mqttmtd/tokenmgr/tests/testutil"
	"mqttmtd/types"
	"sync"
	"testing"
	"time"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// // go test -x -v
func TestPubSubAEAD_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	aeadType := types.PAYLOAD_AEAD_AES_128_GCM
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, aeadType)
	fetchReqPub := testutil.PrepareFetchReq(true, aeadType)
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			encKey, _, token := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
			testutil.AutopahoSubscribe(t, token, false, subDone, []byte("TestPubSubAEAD_Single"), aeadType, encKey)
			wg.Done()
		}()
		go func() {
			<-subDone
			encKey, tokenIndex, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
			testutil.AutopahoPublish(t, token, []byte("TestPubSubAEAD_Single"), aeadType, encKey, tokenIndex)
			wg.Done()
		}()
		wg.Wait()
		done <- struct{}{}
	}()
	go func() {
		time.Sleep(time.Second * 10)
		expired <- struct{}{}
	}()
	select {
	case <-expired:
		t.Fatal()
	case <-done:
	}
}

func TestPubSubAEAD_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	aeadType := types.PAYLOAD_AEAD_AES_128_GCM
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, aeadType)
	fetchReqPub := testutil.PrepareFetchReq(true, aeadType)
	testutil.RemoveTokenFile(topic, *fetchReqSub)
	testutil.RemoveTokenFile(topic, *fetchReqPub)
	for i := 0; i < int(fetchReqSub.NumTokens); i++ {
		expired := make(chan struct{})
		subDone := make(chan struct{})
		done := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				encKey, _, token := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
				testutil.AutopahoSubscribe(t, token, false, subDone, []byte(fmt.Sprintf("TestPubSubAEAD_Cycle%d", i)), aeadType, encKey)
				wg.Done()
			}()
			go func() {
				<-subDone
				encKey, tokenIndex, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				testutil.AutopahoPublish(t, token, []byte(fmt.Sprintf("TestPubSubAEAD_Cycle%d", i)), aeadType, encKey, tokenIndex)
				wg.Done()
			}()
			wg.Wait()
			done <- struct{}{}
		}()
		go func() {
			time.Sleep(time.Second * 10)
			expired <- struct{}{}
		}()
		select {
		case <-expired:
			t.Fatal()
		case <-done:
		}
	}
	testutil.RemoveTokenFile(topic, *fetchReqSub)
	testutil.RemoveTokenFile(topic, *fetchReqPub)
}
