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
func TestPubSubCipher_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	cipherType := tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	fetchReqSub := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	fetchReqPub := testutil.PrepareFetchReq(tokenmgr.AccessPub, cipherType)
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqSub, true)
			testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte("TestPubSubCipher_Single"))
			wg.Done()
		}()
		go func() {
			<-subDone
			encKey, numTokensRemained, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
			encryptedMsg := testutil.SealMessage(t, cipherType, encKey, uint16(numTokensRemained), []byte("TestPubSubCipher_Single"))
			testutil.AutopahoPublish(t, timestamp, randomBytes, encryptedMsg)
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
	cipherType := tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	fetchReqSub := testutil.PrepareFetchReq(tokenmgr.AccessSub, tokenmgr.PAYLOAD_CIPHER_NONE)
	fetchReqPub := testutil.PrepareFetchReq(tokenmgr.AccessPub, cipherType)
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
				testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte(fmt.Sprintf("TestPubSubCipher_Cycle%d", i)))
				wg.Done()
			}()
			go func() {
				<-subDone
				encKey, numTokensRemained, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReqPub, true)
				encryptedMsg := testutil.SealMessage(t, cipherType, encKey, uint16(numTokensRemained), []byte(fmt.Sprintf("TestPubSubCipher_Cycle%d", i)))
				testutil.AutopahoPublish(t, timestamp, randomBytes, encryptedMsg)
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

func TestPubSubCipher_OneToken_Single(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	cipherType := tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	expired := make(chan struct{})
	subDone := make(chan struct{})
	done := make(chan struct{})
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPubSub, cipherType)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, _, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte("TestPubSubCipher_OneToken_Single"))
			wg.Done()
		}()
		go func() {
			<-subDone
			encKey, numTokensRemained, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
			encryptedMsg := testutil.SealMessage(t, cipherType, encKey, uint16(numTokensRemained), []byte("TestPubSubCipher_OneToken_Single"))
			testutil.AutopahoPublish(t, timestamp, randomBytes, encryptedMsg)
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

func TestPubSubCipher_OneToken_Cycle(t *testing.T) {
	topic := testutil.SAMPLE_TOPIC_PUBSUB
	cipherType := tokenmgr.PAYLOAD_CIPHER_AES_128_GCM_SHA256
	fetchReq := testutil.PrepareFetchReq(tokenmgr.AccessPubSub, cipherType)
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
				testutil.AutopahoSubscribe(t, timestamp, randomBytes, false, subDone, []byte(fmt.Sprintf("TestPubSubCipher_OneToken_Cycle%d", i)))
				wg.Done()
			}()
			go func() {
				<-subDone
				encKey, numTokensRemained, timestamp, randomBytes := testutil.GetTokenTest(t, topic, *fetchReq, true)
				encryptedMsg := testutil.SealMessage(t, cipherType, encKey, uint16(numTokensRemained), []byte(fmt.Sprintf("TestPubSubCipher_OneToken_Cycle%d", i)))
				testutil.AutopahoPublish(t, timestamp, randomBytes, encryptedMsg)
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
