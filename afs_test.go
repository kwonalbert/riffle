package afs

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
	"sync"

	"testing"

	. "afs/server"
	. "afs/client"
	. "afs/lib"
)

var servers []*Server = nil
var clients []*Client = nil

func TestRounds(t *testing.T) {
	b := 10

	testData := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		for j := range testData[i] {
			data := make([]byte, BlockSize)
			rand.Read(data)
			//data[j] = 1
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
					k := (i + c) % NumClients
					hash := Suite.Hash().Sum(testData[i][k])
					clients[c].RequestBlock(c, hash)
					if clients[c].Id() == 0 {
						fmt.Println("requested: ", i)
					}
				}
			} (c)

			wg2.Add(1)
			go func(c int) {
				defer wg2.Done()
				for i := 0; i < b; i++ {
					clients[c].UploadPieces()
					if clients[c].Id() == 0 {
						fmt.Println("uploaded: ", i)
					}
				}
			} (c)


			wg2.Add(1)
			go func(c int) {
				defer wg2.Done()
				for i := 0; i < b; i++ {
					res := clients[c].Download()
					membership(res, testData[i])
				}
			} (c)

			wg2.Wait()
		} (c)
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	servers, clients = setup(NumServers, NumClients)
	time.Sleep(500*time.Millisecond)

	os.Exit(m.Run())
}
