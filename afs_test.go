package afs

import (
	"crypto/rand"
	"fmt"
	"net/rpc"
	"log"
	"os"
	"sync"

	"testing"

	. "afs/server"
	. "afs/client"
	. "afs/lib"
)

var servers []*Server = nil
var clients []*Client = nil

func TestRequest(t *testing.T) {
	testData := make([][]byte, NumClients)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		testData[i] = make([]byte, HashSize)
		rand.Read(testData[i])
		go func(i int, c *Client) {
			defer wg.Done()
			c.RequestBlock(i, Suite.Hash().Sum(testData[i]))
		} (i, c)
	}
	wg.Wait()

	for _, c := range clients {
		hashes := c.DownloadReqHash()
		for i := range testData {
			dataHash := Suite.Hash().Sum(testData[i])
			found := false
			for j := range hashes {
				same := true
				for k := range hashes {
					same = same && (hashes[j][k] == dataHash[k])
				}
				if same {
					found = true
					break
				}
			}
			if !found {
				panic("Didn't get all the hashes")
			}
		}
	}
}

func TestPIR(t *testing.T) {
	//create test data
	testData := make([]Block, NumClients)
	for i := 0; i < NumClients; i++ {
		data := make([]byte, BlockSize)
		rand.Read(data)
		testData[i] = Block {
			Block: data,
			Round: 0,
		}
	}

	rpcServers := clients[0].RpcServers()
	//put some blocks in server for testing
	for _, rpcServer := range rpcServers {
		go func(rpcServer *rpc.Client) {
			err := rpcServer.Call("Server.PutUploadedBlocks", testData, nil)
			if err != nil {
				log.Fatal("Couldn't share uploaded blocks", err)
			}
		} (rpcServer)
	}

	//do pir from client
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			res := c.DownloadSlot(i)
			if len(res) != BlockSize {
				panic("PIR failed! None matching size")
			}
			for j := range res {
				if res[j] != testData[i].Block[j] {
					panic("PIR failed!")
				}
			}
			c.ClearHashes()
		} (i, c)
	}
	wg.Wait()

}

func TestUploadDownload(t *testing.T) {
	testData := make([][]byte, NumClients)
	for i := range testData {
		data := make([]byte, BlockSize)
		rand.Read(data)
		testData[i] = data
	}
	uploadBlock(testData)
	downloadBlock(testData)
}

func TestRounds(t *testing.T) {
	b := 5

	testData := make([][][]byte, b)
	for i := 0; i < b; i++ {
		testData[i] = make([][]byte, NumClients)
		for j := range testData {
			data := make([]byte, BlockSize)
			rand.Read(data)
			testData[i][j] = data
		}

		registerBlocks(testData[i])
	}

	var wg sync.WaitGroup
	for i := 0; i < b; i++ {
		go func(i int) {
			request(testData[i], i)
			fmt.Println("Round :", i)
		} (i)
		go upload()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			download(testData[i])
			fmt.Println("Round ", i, "Done")
		} (i)
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
