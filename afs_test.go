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
	servers, clients = setup(NumServers, NumClients)

	os.Exit(m.Run())
}

func TestFiles(t *testing.T) {
	b := NumClients
	testData := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		for j := range testData[i] {
			data := make([]byte, BlockSize)
			rand.Read(data)
			testData[i][j] = data
		}
	}

	for i := range testData {
		hashes := make([][]byte, len(testData[i]))
		for j := range testData[i] {
			hashes[j] = Suite.Hash().Sum(testData[i][j])
		}
		file := File{
			Name: fmt.Sprintf("%d", i),
			Hashes: hashes,
			Blocks: testData[i],
		}
		fmt.Println(file)
	}
}
