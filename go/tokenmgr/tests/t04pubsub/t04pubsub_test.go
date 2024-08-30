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
func TestPubSub_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	fetchReqPub := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, _, token := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
			testutil.AutopahoSubscribe(t, token, false, subDone, []byte("TestPubSub_Single"), types.PAYLOAD_AEAD_NONE, nil)
			wg.Done()
		}()
		go func() {
			<-subDone
			_, _, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
			testutil.AutopahoPublish(t, token, []byte("TestPubSub_Single"), types.PAYLOAD_AEAD_NONE, nil, 0)
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

func TestPubSub_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, types.PAYLOAD_AEAD_NONE)
	fetchReqPub := testutil.PrepareFetchReq(true, types.PAYLOAD_AEAD_NONE)
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
				_, _, token := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
				testutil.AutopahoSubscribe(t, token, false, subDone, []byte(fmt.Sprintf("TestPubSub_Cycle%d", i)), types.PAYLOAD_AEAD_NONE, nil)
				wg.Done()
			}()
			go func() {
				<-subDone
				_, _, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				testutil.AutopahoPublish(t, token, []byte(fmt.Sprintf("TestPubSub_Cycle%d", i)), types.PAYLOAD_AEAD_NONE, nil, 0)
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
