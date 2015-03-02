package afs

import (
	"crypto/rand"
	"fmt"
	"log"

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
	for i := range ss {
		s := NewServer(ss[i], i, ss)
		servers[i] = s
		s.MainLoop()
	}

	for _, s := range servers {
		s.ConnectServers()
	}

	fmt.Println("Registering Clients")
	for i := range cs {
		c := NewClient(fmt.Sprintf("127.0.0.1:%d", 9000+i), ss, "127.0.0.1:8000")
		clients[i] = c
		c.Register("127.0.0.1:8000")
	}

	servers[0].RegisterDone()

	fmt.Println("Done Registration")

	return servers, clients
}

func compareSecrets(smasks [][]byte, cmasks [][]byte) {
	for i := range smasks {
		for j := range smasks[i] {
			if smasks[i][j] != cmasks[i][j] {
				panic("Sharing masks didn't work!")
			}
		}
	}
}

func TestShareSecret(t *testing.T) {
	numS := NumServers
	numC := NumClients

	if servers == nil {
		servers, clients = setup(numS, numC)
	}

	for _, c := range clients {
		c.ShareSecret()
	}

	for i, s := range servers {
		masks := s.Masks()
		secrets := s.Secrets()
		cmasks := make([][]byte, numC)
		csecrets := make([][]byte, numC)
		for j, c := range clients {
			cmasks[j] = c.Masks()[i]
			csecrets[j] = c.Secrets()[i]
		}
		compareSecrets(masks, cmasks)
		compareSecrets(secrets, csecrets)
	}
}

func TestPIR(t *testing.T) {
	numS := NumServers
	numC := NumClients

	if servers == nil {
		_, clients = setup(numS, numC)
	}

	for _, c := range clients {
		c.ShareSecret()
	}

	//create test data
	testData := make([]Block, numC)
	for i := 0; i < numC; i++ {
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
		err := rpcServer.Call("Server.PutUploadedBlocks", testData, nil)
		if err != nil {
			log.Fatal("Couldn't share uploaded blocks", err)
		}
	}

	//do pir from client
	for i, c := range clients {
		res := c.GetResponse(i)
		for j := range res {
			if res[j] != testData[i].Block[j] {
				panic("PIR failed!")
			}
		}
	}

}
