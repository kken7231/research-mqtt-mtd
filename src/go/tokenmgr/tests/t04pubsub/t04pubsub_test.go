package t04pubsub

import (
	"fmt"
	"go/tokenmgr"
	"go/tokenmgr/tests/testutil"
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
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub)
			timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte("TestPubSub_Single"))
			wg.Done()
		}()
		go func() {
			<-subDone
			fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub)
			timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoPublish(t, timestamp, randomBytes, "TestPubSub_Single")
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
	fetchReqSub := testutil.PrepareFetchReq(tokenmgr.AccessSub)
	fetchReqPub := testutil.PrepareFetchReq(tokenmgr.AccessPub)
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
				timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
				testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte(fmt.Sprintf("TestPubSub_Cycle%d", i)))
				wg.Done()
			}()
			go func() {
				<-subDone
				timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				testutil.AutopahoPublish(t, timestamp, randomBytes, fmt.Sprintf("TestPubSub_Cycle%d", i))
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
