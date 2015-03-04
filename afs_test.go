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

func setup(numServers int, numClients int) ([]*Server, []*Client) {
	fmt.Println(fmt.Sprintf("Setting up for %d servers and %d clients", numServers, numClients))
	ss := make([]string, numServers)
	cs := make([]string, numClients)
	for i := range ss {
		ss[i] = fmt.Sprintf("127.0.0.1:%d", 8000+i)
	}
	for i := range cs {
		cs[i] = fmt.Sprintf("127.0.0.1:%d", 9000+i)
	}

	servers := make([]*Server, numServers)
	clients := make([]*Client, numClients)

	fmt.Println("Starting servers")
	var wg sync.WaitGroup
	for i := range ss {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := NewServer(ss[i], i, ss)
			servers[i] = s
			s.MainLoop()
		}(i)
	}
	wg.Wait()

	for _, s := range servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			s.ConnectServers()
		}(s)
	}
	wg.Wait()

	fmt.Println("Registering Clients")
	for i := range cs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := NewClient(fmt.Sprintf("127.0.0.1:%d", 9000+i), ss, "127.0.0.1:8000")
			clients[i] = c
			c.Register(0)
		} (i)
	}
	wg.Wait()

	fmt.Println("Done Registration")

	servers[0].RegisterDone()

	fmt.Println("Done Setup")

	return servers, clients
}

func compareSecrets(secerets1 [][]byte, secerets2 [][]byte) {
	for i := range secerets1 {
		for j := range secerets1[i] {
			if secerets1[i][j] != secerets2[i][j] {
				fmt.Println(secerets1)
				fmt.Println(secerets2)
				panic("Sharing secrets didn't work!")
			}
		}
	}
}

func TestShareSecret(t *testing.T) {
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
}

func TestPIR(t *testing.T) {
	for _, c := range clients {
		c.ShareSecret()
	}

	//create test data
	testData := make([]Block, NumClients)
	for i := 0; i < NumClients; i++ {
		data := make([]byte, BlockSize)
		rand.Read(data)
		testData[i] = Block {
			Hash: nil,
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
			for j := range res {
				if res[j] != testData[i].Block[j] {
					panic("PIR failed!")
				}
			}
		} (i, c)
	}
	wg.Wait()

}

func TestUpload(t *testing.T) {
	//upload blocks
	testData := make([][]byte, NumClients)
	for i, c := range clients {
		go func(i int, c *Client) {
			data := make([]byte, BlockSize)
			rand.Read(data)
			testData[i] = data
			upblock := Block {
				Hash: nil,
				Block: data,
				Round: 0,
			}
			c.UploadBlock(upblock)
		} (i, c)
	}

	//do pir from client
	res := make([][]byte, NumClients)
	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Add(1)
		go func(i int, c *Client) {
			defer wg.Done()
			res[i] = c.DownloadSlot(i)
		} (i, c)
	}
	wg.Wait()

	found := make([]bool, NumClients)
	for i := range found {
		found[i] = false
	}

	for i := range testData {
		if found[i] {
			fmt.Println(testData)
			fmt.Println(res)
			panic("Duplicate blocks!")
		}
		found[i] = false
		for j := range res {
			same := true
			for k := range res[j] {
				same = same && (testData[i][k] == res[j][k])
			}
			if same {
				found[i] = true
				break
			}
		}
		if !found[i] {
			panic("Didn't get all the data back")
		}
	}

}

func TestMain(m *testing.M) {
	if servers == nil {
		servers, clients = setup(NumServers, NumClients)
	}

	os.Exit(m.Run())
}
