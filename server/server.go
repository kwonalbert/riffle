package server

import (
	// "flag"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"sync"
	// "time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

type clientBlock struct {
	cid             int //client id for the block
	sid             int //sending server's id
	block           Block
}

type Server struct {
	addr            string //this server
	id              int
	servers         []string //other servers
	rpcServers      []*rpc.Client
	regLock         []*sync.Mutex //registration mutex
	//crypto
	g               abstract.Group
	rand            cipher.Stream

	allBlocks       []Block //all blocks store on this server

	//clients
	clients         []string //clients connected here
	clientMap       map[int]int //maps clients to dedicated server
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)

	//downloading
	blocksChan      chan []Block
	blocks          map[int][]Block //only keep track of relevant blocks
	xorsChan        []map[int](chan Block)
	maskChan        chan []byte
	masks           [][]byte //clients' masks for PIR
	secrets         [][]byte //shared secret used to xor
	otherResps      [][]byte //other servers responding to this
}


///////////////////////////////
//Initial Setup
//////////////////////////////

func NewServer(addr string, id int, servers []string) *Server {
	s := Server{
		addr:           addr,
		servers:        servers,
		regLock:        []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},

		g:              Suite,
		rand:           Suite.Cipher(abstract.RandomKey),

		clients:        []string{},
		clientMap:      make(map[int]int),
		numClients:     0,
		totalClients:   0,

		blocksChan:     make(chan []Block),
		blocks:         make(map[int][]Block),
		xorsChan:       make([]map[int](chan Block), len(servers)),
		masks:          nil,
		secrets:        nil,
	}

	return &s
}


/////////////////////////////////
//Helpers
////////////////////////////////
func (s *Server) MainLoop() {
	rpcServer := rpc.NewServer()
	rpcServer.Register(s)
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		panic("Cannot starting listening to the port")
	}
	go rpcServer.Accept(l)

	for {
		go s.handleResponse()
	}
}

func (s *Server) ConnectServers() {
	rpcServers := make([]*rpc.Client, len(s.servers))
	for i := range rpcServers {
		rpcServer, err := rpc.Dial("tcp", s.servers[i])
		if err != nil {
			log.Fatal("Cannot establish connection")
		}
		rpcServers[i] = rpcServer
	}
	s.rpcServers = rpcServers
}

func (s *Server) handleResponse() {
	allBlocks := <-s.blocksChan
	for i := 0; i < s.totalClients; i++ {
		if s.clientMap[i] == s.id {
			continue
		}
		//if it doesnt belong to me, xor things and send it over
		go func(i int, sid int) {
			res := ComputeResponse(allBlocks, s.masks[i], s.secrets[i])
			cb := clientBlock {
				cid: i,
				sid: s.id,
				block: Block {
					Hash: nil,
					Block: res,
					Round: 0,
				},
			}
			err := s.rpcServers[sid].Call("Server.PutClientBlock", cb, nil)
			if err != nil {
				log.Fatal("Couldn't register: ", err)
			}
		} (i, s.clientMap[i])
	}
	//store it on this server as well
	s.allBlocks = allBlocks
}



/////////////////////////////////
//Registration
////////////////////////////////

//register the client here, and notify the server it will be talking to
//TODO: should check for duplicate clients, just in case..
func (s *Server) Register(client ClientRegistration, clientId *int) error {
	s.regLock[0].Lock()
	*clientId = s.totalClients
	s.totalClients++
	for _, rpcServer := range s.rpcServers {
		err := rpcServer.Call("Server.Register2", client, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Cannot connect to %d: ", client.ServerId), err)
		}
	}
	s.regLock[0].Unlock()
	return nil
}

//called to increment total number of clients
func (s *Server) Register2(client ClientRegistration, _ *int) error {
	s.regLock[1].Lock()
	s.clients = append(s.clients, client.Addr)
	s.clientMap[client.Id] = client.ServerId
	s.regLock[1].Unlock()
	return nil
}

func (s *Server) RegisterDone() {
	for _, rpcServer := range s.rpcServers {
		err := rpcServer.Call("Server.RegisterDone2", s.totalClients, nil)
		if err != nil {
			log.Fatal("Cannot update num clients")
		}
	}

}

func (s *Server) RegisterDone2(numClients int, _ *int) error {
	s.totalClients = numClients
	for i := 0; i < len(s.servers); i++ {
		for j := 0; j < numClients; j++ {
			s.xorsChan[i][j] = make(chan Block)
		}
	}
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

func (s *Server) GetResponse(cmask ClientMask, response *[]byte) error {
	allBlocks := make([]Block, len(s.servers))
	for i := range allBlocks {
		allBlocks[i] = <-s.xorsChan[i][cmask.Id]
	}
	r := ComputeResponse(allBlocks, cmask.Mask, s.secrets[cmask.Id])
	*response = r
	return nil
}

//used to push response for particular client
func (s *Server) PutClientBlock(cBlock clientBlock, _ *int) error {
	s.xorsChan[cBlock.sid][cBlock.cid] <- cBlock.block
	return nil
}

//used to push the uploaded blocks from the final shuffle server
func (s *Server) PutUploadedBlocks(blocks []Block, _ *int) error {
	s.blocksChan <- blocks
	return nil
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
