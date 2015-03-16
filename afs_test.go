package afs

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"testing"

	. "afs/server"
	. "afs/client"
	. "afs/lib"
)

var servers []*Server = nil
var clients []*Client = nil

var ServerAddrs []string = []string{"127.0.0.1:8000", "127.0.0.1:80001"}
const NumClients = 3
const NumServers = 2

func TestAES(t *testing.T) {
	testData := make([][]byte, NumClients)
	for j := range testData {
		data := make([]byte, BlockSize)
		rand.Read(data)
		//data[j] = 1
		testData[j] = data
	}

	key := make([]byte, SecretSize)
	rand.Read(key)
	for i := range testData {
		enc := CounterAES(key, testData[i])
		dec := CounterAES(key, enc)
		for j := range testData[i] {
			if testData[i][j] != dec[j] {
				panic("AES Failed!")
			}
		}
	}

}

func TestRounds(t *testing.T) {
	b := 10

	testData := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		for j := range testData[i] {
			data := make([]byte, BlockSize)
			rand.Read(data)
			//data[j] = 1
			// if i == 0 {
			// 	fmt.Println("block:", data)
			// }
			testData[i][j] = data
		}

		registerBlocks(testData[i])
	}

	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func(c int) { //a client
			defer wg.Done()
			var wg2 sync.WaitGroup
			wg2.Add(1)
			go func(c int) {
				defer wg2.Done()
				for i := 0; i < b; i++ {
					if clients[c].Id() == 0 {
						fmt.Println("Round: ", i)
					}
					k := (i + c) % NumClients
					h := Suite.Hash()
					h.Write(testData[i][k])
					hash := h.Sum(nil)
					clients[c].RequestBlock(c, hash)
					// if clients[c].Id() == 0 {
					// 	fmt.Println("requested: ", i)
					// }
				}
			} (c)

			wg2.Add(1)
			go func(c int) {
				defer wg2.Done()
				for i := 0; i < b; i++ {
					clients[c].UploadPieces()
					// if clients[c].Id() == 0 {
					// 	fmt.Println("uploaded: ", i)
					// }
				}
			} (c)


			wg2.Add(1)
			go func(c int) {
				defer wg2.Done()
				for i := 0; i < b; i++ {
					res := clients[c].Download()
					if Membership(res, testData[i]) == -1 {
						fmt.Println("Round", i)
						fmt.Println("res: ", res)
						fmt.Println("test: ", testData[i])
						log.Fatal("Didn't get all data back")
					}
				}
			} (c)

			wg2.Wait()
		} (c)
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	runtime.GOMAXPROCS(runtime.NumCPU())
	servers, clients = setup(NumServers, NumClients)
	time.Sleep(1000*time.Millisecond)

	os.Exit(m.Run())
}
