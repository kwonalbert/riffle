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
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/shuffle"
)

//any variable/func with 2: similar object as s-c but only s-s
type Server struct {
	addr            string //this server
	id              int
	servers         []string //other servers
	rpcServers      []*rpc.Client
	regLock         []*sync.Mutex //registration mutex
	regDone         bool

	//crypto
	g               abstract.Group
	rand            cipher.Stream
	sk              abstract.Secret //secret and public elgamal key
	pk              abstract.Point
	pks             []abstract.Point //all servers pks
	nextPk          abstract.Point

	allBlocks       []Block //all blocks store on this server

	//clients
	clients         []string //clients connected here
	clientMap       map[int]int //maps clients to dedicated server
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)

	//uploading
	ublockChan      chan UpBlock
	ublockChan2     chan UpBlock
	shuffleChan     chan []UpBlock //collect all uploads together

	//downloading
	dblocksChan     chan []Block
	blocksRdy       []chan bool
	blocks          map[int][]Block //keep track of blocks mapped to this server
	xorsChan        []map[int](chan Block)
	maskChan        chan []byte
	masks           [][]byte //clients' masks for PIR
	secrets         [][]byte //shared secret used to xor
}


///////////////////////////////
//Initial Setup
//////////////////////////////

func NewServer(addr string, id int, servers []string) *Server {
	rand := Suite.Cipher(abstract.RandomKey)
	sk := Suite.Secret().Pick(rand)
	pk := Suite.Point().Mul(nil, sk)

	s := Server{
		addr:           addr,
		id:             id,
		servers:        servers,
		regLock:        []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},
		regDone:        false,

		g:              Suite,
		rand:           rand,
		sk:             sk,
		pk:             pk,
		pks:            make([]abstract.Point, len(servers)),

		allBlocks:      nil,

		clients:        []string{},
		clientMap:      make(map[int]int),
		numClients:     0,
		totalClients:   0,

		ublockChan:     make(chan UpBlock),
		ublockChan2:    make(chan UpBlock),
		shuffleChan:    make(chan []UpBlock),

		dblocksChan:    make(chan []Block),
		blocksRdy:      nil,
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

func runFunc(f func()) {
	go func () {
		for {
			f()
		}
	} ()
}

func (s *Server) MainLoop() {
	rpcServer := rpc.NewServer()
	rpcServer.Register(s)
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		panic("Cannot starting listening to the port")
	}
	go rpcServer.Accept(l)

	runFunc(s.handleResponse)
	runFunc(s.handleUpload)
	runFunc(s.gatherUploads)
	runFunc(s.shuffleUploads)
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

	var wg sync.WaitGroup
	for i, rpcServer := range rpcServers {
		wg.Add(1)
		go func (i int, rpcServer *rpc.Client) {
			defer wg.Done()
			pk := make([]byte, SecretSize)
			err := rpcServer.Call("Server.GetPK", 0, &pk)
			if err != nil {
				log.Fatal("Couldn't get server's pk: ", err)
			}
			s.pks[i] = UnmarshalPoint(pk)
		} (i, rpcServer)
	}
	wg.Wait()
	if s.id != len(s.servers)-1 {
		s.nextPk = s.pks[s.id]
		for i := s.id+1; i < len(s.servers); i++ {
			s.nextPk = s.g.Point().Add(s.nextPk, s.pks[i])
		}
	} else {
		s.nextPk = s.pk
	}
	s.rpcServers = rpcServers
}

func (s *Server) handleResponse() {
	if !s.regDone {
		return
	}

	allBlocks := <-s.dblocksChan
	for i := 0; i < s.totalClients; i++ {
		if s.clientMap[i] == s.id {
			continue
		}
		//if it doesnt belong to me, xor things and send it over
		go func(i int, sid int) {
			res := ComputeResponse(allBlocks, s.masks[i], s.secrets[i])
			cb := ClientBlock {
				CId: i,
				SId: s.id,
				Block: Block {
					Hash: nil,
					Block: res,
					Round: 0,
				},
			}
			err := s.rpcServers[sid].Call("Server.PutClientBlock", cb, nil)
			if err != nil {
				log.Fatal("Couldn't put block: ", err)
			}
		} (i, s.clientMap[i])
	}
	//store it on this server as well
	s.allBlocks = allBlocks

	for i := range s.blocksRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int) {s.blocksRdy[i] <- true}(i)
	}
}

func (s *Server) handleUpload() {
	if !s.regDone {
		return
	}

	upBlock := <-s.ublockChan
	if s.id != 0 {
		err := s.rpcServers[0].Call("Server.UploadBlock2", upBlock, nil)
		if err != nil {
			log.Fatal("Couldn't send block to first server: ", err)
		}
	} else {
		s.ublockChan2 <- upBlock
	}
}

func (s *Server) gatherUploads() {
	if !s.regDone {
		return
	}

	allUploads := make([]UpBlock, s.totalClients)
	for i := 0; i < s.totalClients; i++ {
		allUploads[i] = <-s.ublockChan2
	}
	s.shuffleChan <- allUploads
}

func (s *Server) shuffleUploads() {
	if !s.regDone {
		return
	}

	allUploads := <-s.shuffleChan
	//shuffle and reblind

	numChunks := len(allUploads[0].C1)
	for _, upload := range allUploads {
		if numChunks != len(upload.C1)  {
			panic("Different chunk lengths")
		}
	}

	Xs := make([][]abstract.Point, numChunks)
	Ys := make([][]abstract.Point, numChunks)

	for i := range Xs {
		Xs[i] = make([]abstract.Point, s.totalClients)
		Ys[i] = make([]abstract.Point, s.totalClients)
		for j := 0; j < s.totalClients; j++ {
			Xs[i][j] = UnmarshalPoint(allUploads[j].C1[i])
			Ys[i][j] = UnmarshalPoint(allUploads[j].C2[i])
		}
	}

	// Pick a random permutation
	pi := make([]int, s.totalClients)
	for i := 0; i < s.totalClients; i++ {	// Initialize a trivial permutation
		pi[i] = i
	}
	for i := s.totalClients-1; i > 0; i-- {	// Shuffle by random swaps
		j := int(random.Uint64(s.rand) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}

	Xbars := make([][]abstract.Point, numChunks)
	Ybars := make([][]abstract.Point, numChunks)
	decs := make([][]abstract.Point, numChunks)
	provers := make([] proof.Prover, numChunks)

	//do the shuffle, and blind using next server's keys
	//everyone shares the same group
	var wg sync.WaitGroup
	for i := range decs {
		decs[i] = make([]abstract.Point, s.totalClients)
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			pk := s.nextPk
			Xbars[i], Ybars[i], provers[i] = shuffle.Shuffle2(pi, s.g, nil, pk, Xs[i], Ys[i], s.rand)
			//decrypt a layer
			var decWG sync.WaitGroup
			for j := 0; j < s.totalClients; j++ {
				decWG.Add(1)
				go func (i int, j int) {
					defer decWG.Done()
					c1 := Xbars[i][j]
					c2 := Ybars[i][j]
					decs[i][j] = Decrypt(s.g, c1, c2, s.sk)
				} (i, j)
			}
			decWG.Wait()
		} (i)
	}
	wg.Wait()

	if s.id == len(s.servers) - 1 {
		//last server to shuffle, then broadcast
		blocks := make([]Block, s.totalClients)
		for i := range blocks {
			block := []byte{}
			for j := range decs {
				msg, err := decs[j][i].Data()
				if err != nil {
					log.Fatal("Could not decrypt: ", err)
				}
				block = append(block, msg...)
			}
			blocks[i] = Block {
				Hash: nil,
				Block: block,
				Round: 0,
			}
		}

		for _, rpcServer := range s.rpcServers {
			wg.Add(1)
			go func(rpcServer *rpc.Client) {
				defer wg.Done()
				err := rpcServer.Call("Server.PutUploadedBlocks", blocks, nil)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
				}
			} (rpcServer)
		}
		wg.Wait()
	} else {
		for i := range allUploads {
			for j := range allUploads[i].C1 {
				allUploads[i].C1[j] = MarshalPoint(Xbars[j][i])
				allUploads[i].C2[j] = MarshalPoint(decs[j][i])
			}
		}
		err := s.rpcServers[s.id+1].Call("Server.ShuffleBlocks", allUploads, nil)
		if err != nil {
			log.Fatal("Failed requesting shuffle: ", err)
		}
	}
}

/////////////////////////////////
//Registration
////////////////////////////////

//register the client here, and notify the server it will be talking to
//TODO: should check for duplicate clients, just in case..
func (s *Server) Register(client *ClientRegistration, clientId *int) error {
	s.regLock[0].Lock()
	*clientId = s.totalClients
	s.totalClients++
	s.regLock[0].Unlock()
	for _, rpcServer := range s.rpcServers {
		err := rpcServer.Call("Server.Register2", client, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Cannot connect to %d: ", client.ServerId), err)
		}
	}
	return nil
}

//called to increment total number of clients
func (s *Server) Register2(client *ClientRegistration, _ *int) error {
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
		s.xorsChan[i] = make(map[int](chan Block))
		for j := 0; j < numClients; j++ {
			s.xorsChan[i][j] = make(chan Block)
		}
	}
	s.masks = make([][]byte, numClients)
	s.secrets = make([][]byte, numClients)

	for i := range s.masks {
		s.masks[i] = make([]byte, SecretSize)
		s.secrets[i] = make([]byte, SecretSize)
	}

	s.blocksRdy = make([]chan bool, numClients)
	for i := range s.blocksRdy {
		s.blocksRdy[i] = make(chan bool)
	}
	s.regDone = true

	return nil
}

func (s *Server) GetPK(_ int, pk *[]byte) error {
	*pk = MarshalPoint(s.pk)
	return nil
}

func (s *Server) shareSecret(clientPublic abstract.Point) (abstract.Point, abstract.Point) {
	gen := s.g.Point().Base()
	secret := s.g.Secret().Pick(s.rand)
	public := s.g.Point().Mul(gen, secret)
	sharedSecret := s.g.Point().Mul(clientPublic, secret)
	return public, sharedSecret
}

func (s *Server) ShareMask(clientDH *ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(clientDH.Public))
	s.masks[clientDH.Id] = MarshalPoint(shared)
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) ShareSecret(clientDH *ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(clientDH.Public))
	s.secrets[clientDH.Id] = MarshalPoint(shared)
	*serverPub = MarshalPoint(pub)
	return nil
}

/////////////////////////////////
//Upload
////////////////////////////////
func (s *Server) UploadBlock(block *UpBlock, _ *int) error {
	s.ublockChan <- *block
	return nil
}

func (s *Server) UploadBlock2(block *UpBlock, _*int) error {
	s.ublockChan2 <- *block
	return nil
}

func (s *Server) ShuffleBlocks(blocks *[]UpBlock, _*int) error {
	s.shuffleChan <- *blocks
	return nil
}


/////////////////////////////////
//Download
////////////////////////////////

func (s *Server) GetResponse(cmask ClientMask, response *[]byte) error {
	otherBlocks := make([][]byte, len(s.servers))
	for i := range otherBlocks {
		if i == s.id {
			otherBlocks[i] = make([]byte, BlockSize)
		} else {
			curBlock := <-s.xorsChan[i][cmask.Id]
			otherBlocks[i] = curBlock.Block
		}
	}
	<-s.blocksRdy[cmask.Id]
	r := ComputeResponse(s.allBlocks, cmask.Mask, s.secrets[cmask.Id])
	Xor(Xors(otherBlocks), r)
	*response = r
	return nil
}

//used to push response for particular client
func (s *Server) PutClientBlock(cblock ClientBlock, _ *int) error {
	block := cblock.Block
	s.xorsChan[cblock.SId][cblock.CId] <- block
	return nil
}

//used to push the uploaded blocks from the final shuffle server
func (s *Server) PutUploadedBlocks(blocks []Block, _ *int) error {
	s.dblocksChan <- blocks
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
