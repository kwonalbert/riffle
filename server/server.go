package server

import (
	// "flag"
	"fmt"
	"log"
	// "net"
	"net/rpc"
	"sync"
	// "time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

type Server struct {
	addr            string //this server
	servers         []string //other servers

	regLock         sync.Mutex //registration mutex

	//crypto
	g               abstract.Group
	rand            cipher.Stream

	//clients
	clients         []string //clients connected here
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)

	//downloading
	blocks          []Block
	masks           [][]byte //clients' masks for PIR
	secrets         [][]byte //shared secret used to xor
	otherResps      [][]byte //other servers responding to this
}


///////////////////////////////
//Initial Setup
//////////////////////////////

func NewServer(addr string, servers []string) *Server {
	s := Server{
		addr:           addr,
		servers:        servers,

		g:              Suite,
		rand:           Suite.Cipher(abstract.RandomKey),

		clients:        []string{},
		numClients:     0,
		totalClients:   0,

		masks:          nil,
		secrets:        nil,
	}

	return &s
}

//register the client here, and notify the server it will be talking to
func (s *Server) Register(client ClientRegistration, clientId *int) error {
	s.regLock.Lock()
	*clientId = s.totalClients
	s.totalClients++
	if s.addr == client.Server {
		s.numClients++
		s.clients = append(s.clients, client.Addr)
	} else {
		server, err := rpc.Dial("tcp", client.Server)
		if err != nil {
			log.Fatal(fmt.Sprintf("Server %s cannot connect to %s: ", s.addr, client.Server), err)
		}
		err = server.Call("Server.Register2", client, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Cannot connect to %s: ", client.Server), err)
		}
	}
	s.regLock.Unlock()
	return nil
}

//called to increment total number of clients
func (s *Server) Register2(client ClientRegistration, _ *int) error {
	s.regLock.Lock()
	s.numClients++
	s.clients = append(s.clients, client.Addr)
	s.regLock.Unlock()
	return nil
}

func (s *Server) RegisterDone() {
	rpcServers := make([]*rpc.Client, len(s.servers))
	for i := range rpcServers {
		rpcServer, err := rpc.Dial("tcp", s.servers[i])
		if err != nil {
			log.Fatal("Cannot establish connection")
		}
		err = rpcServer.Call("Server.RegisterDone2", s.totalClients, nil)
		if err != nil {
			log.Fatal("Cannot update num clients")
		}
	}

}

func (s *Server) RegisterDone2(numClients int, _ *int) error {
	s.totalClients = numClients
	s.masks = make([][]byte, numClients)
	s.secrets = make([][]byte, numClients)
	return nil
}

//DH exchange
func (s *Server) shareSecret(clientPublic abstract.Point) (abstract.Point, abstract.Point) {
	gen := s.g.Point().Base()
	secret := s.g.Secret().Pick(s.rand)
	public := s.g.Point().Mul(gen, secret)
	sharedSecret := s.g.Point().Mul(clientPublic, secret)
	return public, sharedSecret
}

func (s *Server) ShareMask(clientDH ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(clientDH.Public))
	s.masks[clientDH.Id] = MarshalPoint(shared)
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) ShareSecret(clientDH ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(clientDH.Public))
	s.secrets[clientDH.Id] = MarshalPoint(shared)
	*serverPub = MarshalPoint(pub)
	return nil
}



/////////////////////////////////
//Download
////////////////////////////////

func (s *Server) computeResponse(cid int, mask []byte) []byte {
	response := make([]byte, BlockSize)
        i := 0
L:
        for _, b := range mask {
                for j := 0; j < 8; j++ {
                        if b&1 == 1 {
                                Xor(s.blocks[i].Block, response)
                        }
                        b >>= 1
                        i++
                        if i >= s.totalClients {
                                break L
                        }
                }
        }
	Xor(s.secrets[cid], response)
        return response
}






/////////////////////////////////
//Misc (mostly for testing)
////////////////////////////////

func (s *Server) Masks() [][]byte {
	return s.masks
}

func (s *Server) Secrets() [][]byte {
	return s.secrets
}
