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
func TestPubSubCipher_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	cipherType := types.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, cipherType)
	fetchReqPub := testutil.PrepareFetchReq(true, cipherType)
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			encKey, _, token := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
			testutil.AutopahoSubscribe(t, token, false, subDone, []byte("TestPubSubCipher_Single"), cipherType, encKey)
			wg.Done()
		}()
		go func() {
			<-subDone
			encKey, tokenIndex, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
			testutil.AutopahoPublish(t, token, []byte("TestPubSubCipher_Single"), cipherType, encKey, tokenIndex)
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

func TestPubSubCipher_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	cipherType := types.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	testutil.LoadClientConfig(t)
	fetchReqSub := testutil.PrepareFetchReq(false, cipherType)
	fetchReqPub := testutil.PrepareFetchReq(true, cipherType)
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
				testutil.AutopahoSubscribe(t, token, false, subDone, []byte(fmt.Sprintf("TestPubSubCipher_Cycle%d", i)), cipherType, encKey)
				wg.Done()
			}()
			go func() {
				<-subDone
				encKey, tokenIndex, token := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				testutil.AutopahoPublish(t, token, []byte(fmt.Sprintf("TestPubSubCipher_Cycle%d", i)), cipherType, encKey, tokenIndex)
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
