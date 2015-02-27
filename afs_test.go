package afs

import (
	"fmt"
	"net"
	"net/rpc"

	"testing"

	. "afs/server"
	. "afs/client"
	. "afs/lib"
)

var rpcServers []*rpc.Server

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
	rpcServers := make([]*rpc.Server, numServers)
	for i := range ss {
		s := NewServer(ss[i], ss)
		servers[i] = s
		rpcServer := rpc.NewServer()
		rpcServer.Register(s)
		l, err := net.Listen("tcp", ss[i])
		if err != nil {
			panic("Cannot starting listening to the port")
		}
		rpcServers[i] = rpcServer
		go rpcServer.Accept(l)
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

	servers, clients := setup(numS, numC)

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

}
