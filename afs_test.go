package afs

import (
	"crypto/rand"
	"fmt"
	"os"
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
			testData[i][j] = data
		}

		registerBlocks(testData[i])
	}

	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func(c int) { //a client
			defer wg.Done()
	  		for i := 0; i < b; i++ {
				if c == 0 {
					fmt.Println("Round ", i)
				}
				k := (i + c) % NumClients
				go clients[c].RequestBlock(c, Suite.Hash().Sum(testData[i][k]))
				go clients[c].Upload()
				res := clients[c].Download()
				membership(res, testData[i])
			}
		} (c)
	}
	wg.Wait()
}

func TestMain(m *testing.M) {
	if servers == nil {
		servers, clients = setup(NumServers, NumClients)
	}

	for _, c := range clients {
		c.ShareSecret()
	}

	for i, s := range servers {
		masks := s.Masks()
		secrets := s.Secrets()
		cmasks := make([][]byte, NumClients)
		csecrets := make([][]byte, NumClients)
		for _, c := range clients {
			cmasks[c.Id()] = c.Masks()[i]
			csecrets[c.Id()] = c.Secrets()[i]
		}
		compareSecrets(masks, cmasks)
		compareSecrets(secrets, csecrets)
	}

	os.Exit(m.Run())
}
