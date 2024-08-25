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
			fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte("TestPubSub_Single"))
			wg.Done()
		}()
		go func() {
			<-subDone
			fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoPublish(t, timestamp, randomBytes, []byte("TestPubSub_Single"))
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
	fetchReqSub := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	fetchReqPub := testutil.PrepareFetchReq(tokenmgr.AccessPub, tokenmgr.PAYLOAD_CIPHER_NONE)
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
				_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
				testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte(fmt.Sprintf("TestPubSub_Cycle%d", i)))
				wg.Done()
			}()
			go func() {
				<-subDone
				_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				testutil.AutopahoPublish(t, timestamp, randomBytes, []byte(fmt.Sprintf("TestPubSub_Cycle%d", i)))
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

func TestPubSub_OneToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPubSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte("TestPubSub_OneToken_Single"))
			wg.Done()
		}()
		go func() {
			<-subDone
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoPublish(t, timestamp, randomBytes, []byte("TestPubSub_OneToken_Single"))
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

func TestPubSub_OneToken_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPubSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	testutil.RemoveTokenFile(topic, *fetchReq)
	for i := 0; i < int(fetchReq.NumTokens); i++ {
		expired := make(chan struct{})
		subDone := make(chan struct{})
		done := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
				testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte(fmt.Sprintf("TestPubSub_OneToken_Cycle%d", i)))
				wg.Done()
			}()
			go func() {
				<-subDone
				_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
				testutil.AutopahoPublish(t, timestamp, randomBytes, []byte(fmt.Sprintf("TestPubSub_OneToken_Cycle%d", i)))
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
	testutil.RemoveTokenFile(topic, *fetchReq)
}
