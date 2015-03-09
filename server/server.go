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
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
)

//any variable/func with 2: similar object as s-c but only s-s
type Server struct {
	addr            string //this server
	port            int
	id              int
	servers         []string //other servers
	rpcServers      []*rpc.Client
	regLock         []*sync.Mutex //registration mutex
	regDone         bool

	//crypto
	g               abstract.Group
	rand            abstract.Cipher
	sk              abstract.Secret //secret and public elgamal key
	pk              abstract.Point
	pks             []abstract.Point //all servers pks
	nextPk          abstract.Point

	//clients
	clients         []string //clients connected here
	clientMap       map[int]int //maps clients to dedicated server
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)
	masks           [][]byte //clients' masks for PIR
	secrets         [][]byte //shared secret used to xor

	reqRound        int
	gatherRound     int
	shuffleRound    int
	downRound       int
	rounds          []*Round
}

//per round variables
type Round struct {
	allBlocks       []Block //all blocks store on this server

	//requesting
	requestsChan    []chan Request
	reqHashes       [][]byte
	reqHashesRdy    []chan bool

	//uploading
	ublockChan      chan UpBlock
	ublockChan2     chan UpBlock
	shuffleChan     chan []UpBlock //collect all uploads together

	//downloading
	upHashes        [][]byte
	dblocksChan     chan []Block
	blocksRdy       []chan bool
	upHashesRdy     []chan bool
	blocks          [](map[int][]Block) //keep track of blocks mapped to this server
	xorsChan        []map[int](chan Block)
	maskChan        chan []byte
}

///////////////////////////////
//Initial Setup
//////////////////////////////

func NewServer(addr string, port int, id int, servers []string) *Server {
	rand := Suite.Cipher(abstract.RandomKey)
	sk := Suite.Secret().Pick(rand)
	pk := Suite.Point().Mul(nil, sk)

	rounds := make([]*Round, MaxRounds)

	for i := range rounds {
		r := Round{
			allBlocks:      nil,

			requestsChan:   nil,
			reqHashes:      nil,
			reqHashesRdy:   nil,

			ublockChan:     make(chan UpBlock),
			ublockChan2:    make(chan UpBlock),
			shuffleChan:    make(chan []UpBlock),

			upHashes:       nil,
			dblocksChan:    make(chan []Block),
			blocksRdy:      nil,
			upHashesRdy:    nil,
			xorsChan:       make([]map[int](chan Block), len(servers)),
		}
		rounds[i] = &r
	}

	s := Server{
		addr:           addr,
		port:           port,
		id:             id,
		servers:        servers,
		regLock:        []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},
		regDone:        false,

		g:              Suite,
		rand:           rand,
		sk:             sk,
		pk:             pk,
		pks:            make([]abstract.Point, len(servers)),

		clients:        []string{},
		clientMap:      make(map[int]int),
		numClients:     0,
		totalClients:   0,
		masks:          nil,
		secrets:        nil,

		reqRound:       0,
		gatherRound:    0,
		shuffleRound:   0,
		downRound:      0,
		rounds:         rounds,
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

	RunFunc(s.handleRequests)
	for r := 0; r < MaxRounds; r++ {
		go func(r int){
			for{
				s.handleUpload(r)
			}
		} (r)
	}
	RunFunc(s.gatherUploads)
	RunFunc(s.shuffleUploads)
	RunFunc(s.handleResponses)
}

func (s *Server) ConnectServers() {
	rpcServers := make([]*rpc.Client, len(s.servers))
	for i := range rpcServers {
		var rpcServer *rpc.Client
		var err error
		if i == s.id {
			//make a local rpc
			addr := fmt.Sprintf("127.0.0.1:%d", s.port)
			rpcServer, err = rpc.Dial("tcp", addr)
		} else {
			rpcServer, err = rpc.Dial("tcp", s.servers[i])
		}
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

func (s *Server) handleRequests() {
	if !s.regDone {
		return
	}

	round := s.reqRound % MaxRounds
	allRequests := make([][][]byte, s.totalClients)

	var wg sync.WaitGroup
	for i := range allRequests {
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			req := <-s.rounds[round].requestsChan[i]
			allRequests[i] = req.Hash
		} (i)
	}
	wg.Wait()

	s.rounds[round].reqHashes = XorsDC(allRequests)
	for i := range s.rounds[round].reqHashesRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int, rount int) {
			s.rounds[round].reqHashesRdy[i] <- true
		} (i, round)
	}
	s.reqRound++
}

func (s *Server) handleResponses() {
	if !s.regDone {
		return
	}

	round := s.downRound % MaxRounds
	allBlocks := <-s.rounds[round].dblocksChan
	for i := 0; i < s.totalClients; i++ {
		if s.clientMap[i] == s.id {
			continue
		}
		//if it doesnt belong to me, xor things and send it over
		go func(i int, sid int) {
			res := ComputeResponse(allBlocks, s.masks[i], s.secrets[i])
			rand := Suite.Cipher(s.secrets[i])
			rand.Read(s.secrets[i])
			rand = Suite.Cipher(s.masks[i])
			rand.Read(s.masks[i])
			cb := ClientBlock {
				CId: i,
				SId: s.id,
				Block: Block {
					Block: res,
					Round: round,
				},
			}
			err := s.rpcServers[sid].Call("Server.PutClientBlock", cb, nil)
			if err != nil {
				log.Fatal("Couldn't put block: ", err)
			}
		} (i, s.clientMap[i])
	}

	//store it on this server as well
	s.rounds[round].allBlocks = allBlocks

	for i := range s.rounds[round].blocksRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int, round int) {
			s.rounds[round].blocksRdy[i] <- true
		} (i, round)
	}
	s.downRound++
}

func (s *Server) handleUpload(round int) {
	if !s.regDone {
		return
	}

	upBlock := <-s.rounds[round].ublockChan
	err := s.rpcServers[0].Call("Server.UploadBlock2", upBlock, nil)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
}

func (s *Server) gatherUploads() {
	if !s.regDone {
		return
	}

	round := s.gatherRound % MaxRounds
	allUploads := make([]UpBlock, s.totalClients)
	for i := 0; i < s.totalClients; i++ {
		allUploads[i] = <-s.rounds[round].ublockChan2
	}
	s.rounds[round].shuffleChan <- allUploads
	s.gatherRound++
}

func (s *Server) shuffleUploads() {
	if !s.regDone {
		return
	}

	round := s.shuffleRound % MaxRounds
	allUploads := <-s.rounds[round].shuffleChan
	//shuffle and reblind

	numBlockChunks := len(allUploads[0].BC1)
	for _, upload := range allUploads {
		if numBlockChunks != len(upload.BC1)  {
			panic("Different chunk lengths")
		}
	}

	// numHashChunks := len(allUploads[0].HC1)
	// for _, upload := range allUploads {
	// 	if numBlockChunks != len(upload.HC1)  {
	// 		panic("Different chunk lengths")
	// 	}
	// }

	BXs := make([][]abstract.Point, numBlockChunks)
	BYs := make([][]abstract.Point, numBlockChunks)
	//HXs := make([][]abstract.Point, numHashChunks)
	//HYs := make([][]abstract.Point, numHashChunks)

	for i := range BXs {
		BXs[i] = make([]abstract.Point, s.totalClients)
		BYs[i] = make([]abstract.Point, s.totalClients)
		for j := 0; j < s.totalClients; j++ {
			BXs[i][j] = UnmarshalPoint(allUploads[j].BC1[i])
			BYs[i][j] = UnmarshalPoint(allUploads[j].BC2[i])
		}
	}

	//TODO: need to send ybar and proofs out out eventually
	Xbars, _, decs, _ := s.shuffle(BXs, BYs, numBlockChunks)

	if s.id == len(s.servers) - 1 {
		//last server to shuffle, broadcast
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
				Block: block,
				Round: round,
			}
		}
		var wg sync.WaitGroup
		for _, rpcServer := range s.rpcServers {
			wg.Add(1)
			go func(rpcServer *rpc.Client) {
				defer wg.Done()
				err := rpcServer.Call("Server.PutUploadedBlocks", &blocks, nil)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
				}
			} (rpcServer)
		}
		wg.Wait()
	} else {
		for i := range allUploads {
			for j := range allUploads[i].BC1 {
				allUploads[i].BC1[j] = MarshalPoint(Xbars[j][i])
				allUploads[i].BC2[j] = MarshalPoint(decs[j][i])
			}
		}
		err := s.rpcServers[s.id+1].Call("Server.ShuffleBlocks", allUploads, nil)
		if err != nil {
			log.Fatal("Failed requesting shuffle: ", err)
		}
	}
	s.shuffleRound++
}

func (s *Server) shuffle(Xs [][]abstract.Point, Ys [][]abstract.Point, numChunks int) ([][]abstract.Point,
	[][]abstract.Point, [][]abstract.Point, [][]byte) {
	pi := GeneratePI(s.totalClients, s.rand)
	Xbars := make([][]abstract.Point, numChunks)
	Ybars := make([][]abstract.Point, numChunks)
	decs := make([][]abstract.Point, numChunks)
	provers := make([] proof.Prover, numChunks)
	prfs := make([][]byte, numChunks)
	pk := s.nextPk

	//do the shuffle, and blind using next server's keys
	//everyone shares the same group
	var wg sync.WaitGroup
	for i := range decs {
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			Xbars[i], Ybars[i], provers[i] = shuffle.Shuffle2(pi, s.g, nil, pk, Xs[i], Ys[i], s.rand)
			prf, err := proof.HashProve(Suite, "PairShuffle", s.rand, provers[i])
			if err != nil {
				panic("Shuffle proof failed: " + err.Error())
			}
			prfs[i] = prf

			//decrypt a layer
			var decWG sync.WaitGroup
			decs[i] = make([]abstract.Point, s.totalClients)
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

	return Xbars, Ybars, decs, prfs
}

/////////////////////////////////
//Registration and Setup
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
	if s.totalClients == NumClients {
		s.RegisterDone()
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

	s.masks = make([][]byte, numClients)
	s.secrets = make([][]byte, numClients)

	for i := range s.masks {
		s.masks[i] = make([]byte, SecretSize)
		s.secrets[i] = make([]byte, SecretSize)
	}

	for r := range s.rounds {

		for i := 0; i < len(s.servers); i++ {
			s.rounds[r].xorsChan[i] = make(map[int](chan Block))
			for j := 0; j < numClients; j++ {
				s.rounds[r].xorsChan[i][j] = make(chan Block)
			}
		}

		s.rounds[r].requestsChan = make([]chan Request, numClients)

		for i := range s.rounds[r].requestsChan {
			s.rounds[r].requestsChan[i] = make(chan Request)
		}

		s.rounds[r].upHashes = make([][]byte, numClients)

		s.rounds[r].blocksRdy = make([]chan bool, numClients)
		s.rounds[r].upHashesRdy = make([]chan bool, numClients)
		s.rounds[r].reqHashesRdy = make([]chan bool, numClients)
		for i := range s.rounds[r].blocksRdy {
			s.rounds[r].blocksRdy[i] = make(chan bool)
			s.rounds[r].upHashesRdy[i] = make(chan bool)
			s.rounds[r].reqHashesRdy[i] = make(chan bool)
		}
	}
	s.regDone = true
	return nil
}

func (s *Server) GetNumClients(_ int, num *int) error {
	*num = s.totalClients
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
	s.secrets[clientDH.Id] = make([]byte, SecretSize)
	*serverPub = MarshalPoint(pub)
	return nil
}

/////////////////////////////////
//Request
////////////////////////////////
func (s *Server) RequestBlock(cr *ClientRequest, _ *int) error {
	var wg sync.WaitGroup
	for i, rpcServer := range s.rpcServers {
		wg.Add(1)
		go func (i int, rpcServer *rpc.Client) {
			defer wg.Done()
			err := rpcServer.Call("Server.ShareRequest", cr, nil)
			if err != nil {
				log.Fatal("Couldn't share request: ", err)
			}
		} (i, rpcServer)
	}
	wg.Wait()
	return nil
}

func (s *Server) ShareRequest(cr *ClientRequest, _ *int) error {
	round := cr.Request.Round % MaxRounds
	s.rounds[round].requestsChan[cr.Id] <- cr.Request
	return nil
}

func (s *Server) GetReqHashes(args *RequestArg, hashes *[][]byte) error {
	round := args.Round % MaxRounds
	<-s.rounds[round].reqHashesRdy[args.Id]
	*hashes = s.rounds[round].reqHashes
	return nil
}

/////////////////////////////////
//Upload
////////////////////////////////
func (s *Server) UploadBlock(block *UpBlock, _ *int) error {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan <- *block
	return nil
}

func (s *Server) UploadBlock2(block *UpBlock, _*int) error {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2 <- *block
	return nil
}

func (s *Server) ShuffleBlocks(blocks *[]UpBlock, _*int) error {
	round := (*blocks)[0].Round % MaxRounds
	s.rounds[round].shuffleChan <- *blocks
	return nil
}


/////////////////////////////////
//Download
////////////////////////////////
func (s *Server) GetUpHashes(args *RequestArg, hashes *[][]byte) error {
	round := args.Round % MaxRounds
	<-s.rounds[round].upHashesRdy[args.Id]
	*hashes = s.rounds[round].upHashes
	return nil
}

func (s *Server) GetResponse(cmask ClientMask, response *[]byte) error {
	otherBlocks := make([][]byte, len(s.servers))
	var wg sync.WaitGroup
	round := cmask.Round % MaxRounds
	for i := range otherBlocks {
		if i == s.id {
			otherBlocks[i] = make([]byte, BlockSize)
		} else {
			wg.Add(1)
			go func(i int, cmask ClientMask) {
				defer wg.Done()
				curBlock := <-s.rounds[round].xorsChan[i][cmask.Id]
				otherBlocks[i] = curBlock.Block
			} (i, cmask)
		}
	}
	wg.Wait()
	<-s.rounds[round].blocksRdy[cmask.Id]
	r := ComputeResponse(s.rounds[round].allBlocks, cmask.Mask, s.secrets[cmask.Id])
	rand := Suite.Cipher(s.secrets[cmask.Id])
	rand.Read(s.secrets[cmask.Id])
	Xor(Xors(otherBlocks), r)
	*response = r
	return nil
}

//used to push response for particular client
func (s *Server) PutClientBlock(cblock ClientBlock, _ *int) error {
	block := cblock.Block
	round := block.Round % MaxRounds
	s.rounds[round].xorsChan[cblock.SId][cblock.CId] <- block
	return nil
}

//used to push the uploaded blocks from the final shuffle server
func (s *Server) PutUploadedBlocks(blocks *[]Block, _ *int) error {
	//V1: hash here
	round := (*blocks)[0].Round % MaxRounds
	for i := range *blocks {
		s.rounds[round].upHashes[i] = Suite.Hash().Sum((*blocks)[i].Block)
	}

	for i := range s.rounds[round].upHashesRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int, round int) {
			s.rounds[round].upHashesRdy[i] <- true
		} (i, round)
	}

	s.rounds[round].dblocksChan <- *blocks
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

/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	// var addr *string = flag.String("a", "addr", "addr [address]")
	// var id *int = flag.Int("i", "id", "id [num]")
	// var port *int = flag.Int("p", "port", "port [num]")
	// var servers *string = flag.Strin("s", "servers", "servers [servers list]")

	// var ss []string

	// s := NewServer(*addr, *port, *id, ss)
	// //s.ConnectServers()
}
