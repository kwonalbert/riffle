//package server
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"

	"time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var TotalClients = 0
var profile = false
var debug = false

//any variable/func with 2: similar object as s-c but only s-s
type Server struct {
	port1           int //client facing
	port2           int //server facing
	id              int
	serverAddrs     []string //other servers
	conns           []*grpc.ClientConn
	servers         []RiffleInternalClient
	regLock         []*sync.Mutex //registration mutex
	regChan         chan bool
	regDone         chan bool
	connectDone     chan bool
	running         chan bool
	secretLock      *sync.Mutex

	FSMode          bool //true for microblogging, false for file sharing

	//crypto
	suite           abstract.Suite
	g               abstract.Group
	sk              abstract.Secret //secret and public elgamal key
	pk              abstract.Point
	pkBin           []byte
	pks             []abstract.Point //all servers pks
	pksBin          [][]byte
	nextPks         []abstract.Point
	nextPksBin      [][]byte
	ephSecret       abstract.Secret

	//used during key shuffle
	pi              []int
	keys            [][]byte
	keysRdy         chan bool
	auxProofChan    []chan AuxKeyProof
	keyUploadChan   chan UpKey
	keyShuffleChan  chan InternalKey //collect all uploads together

	//clients
	clientMap       map[int]int //maps clients to dedicated server
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)
	maskss          [][][]byte //clients' masks for PIR
	secretss        [][][]byte //shared secret used to xor

	//all rounds
	rounds          []*Round

	memProf         *os.File
}

//per round variables
type Round struct {
	allBlocks       []Block //all blocks store on this server

	//requesting
	reqChan2        []chan Request
	requestsChan    chan []*Request
	reqHashes       [][]byte
	reqHashesRdy    []chan bool

	//uploading
	ublockChan2     []chan Block
	shuffleChan     chan []Block
	upHashesRdy     []chan bool

	//downloading
	upHashes        [][]byte
	dblocksChan     chan []Block
	blocksRdy       []chan bool
	xorsChan        []map[int](chan Block)
}

///////////////////////////////
//Initial Setup
//////////////////////////////

func NewServer(port1 int, port2 int, id int, servers []string, FSMode bool) *Server {
	suite := edwards.NewAES128SHA256Ed25519(false)
	rand := suite.Cipher(abstract.RandomKey)
	sk := suite.Secret().Pick(rand)
	pk := suite.Point().Mul(nil, sk)
	pkBin := MarshalPoint(pk)
	ephSecret := suite.Secret().Pick(rand)

	rounds := make([]*Round, MaxRounds)

	for i := range rounds {
		r := Round{
			allBlocks:      nil,

			reqChan2:       nil,
			requestsChan:   nil,
			reqHashes:      nil,
			reqHashesRdy:   nil,

			ublockChan2:    nil,
			shuffleChan:    make(chan []Block), //collect all uploads together
			upHashesRdy:    nil,

			upHashes:       nil,
			dblocksChan:    make(chan []Block),
			blocksRdy:      nil,
			xorsChan:       make([]map[int](chan Block), len(servers)),
		}
		rounds[i] = &r
	}

	s := Server{
		port1:          port1,
		port2:          port2,
		id:             id,
		serverAddrs:    servers,
		conns:          make([]*grpc.ClientConn, len(servers)),
		servers:        make([]RiffleInternalClient, len(servers)),

		regLock:        []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},
		regChan:        make(chan bool, TotalClients),
		regDone:        make(chan bool),
		connectDone:    make(chan bool),
		running:        make(chan bool),
		secretLock:     new(sync.Mutex),

		suite:          suite,
		g:              suite,
		sk:             sk,
		pk:             pk,
		pkBin:          pkBin,
		pks:            make([]abstract.Point, len(servers)),
		pksBin:         make([][]byte, len(servers)),
		nextPks:        make([]abstract.Point, len(servers)),
		nextPksBin:     make([][]byte, len(servers)),
		ephSecret:      ephSecret,

		pi:             nil,
		keys:           nil,
		keysRdy:        nil,
		auxProofChan:   make([]chan AuxKeyProof, len(servers)),
		keyUploadChan:  nil,
		keyShuffleChan: make(chan InternalKey),

		clientMap:      make(map[int]int),
		numClients:     0,
		totalClients:   0,
		maskss:         nil,
		secretss:       nil,

		rounds:         rounds,

		FSMode:         FSMode,

		memProf:        nil,
	}

	for i := range s.auxProofChan {
		s.auxProofChan[i] = make(chan AuxKeyProof, len(servers))
	}

	return &s
}


/////////////////////////////////
//Helpers
////////////////////////////////

func (s *Server) runHandlers() {
	//<-s.connectDone
	<-s.regDone

	runHandler(s.gatherKeys, 1)
	runHandler(s.shuffleKeys, 1)

	runHandler(s.gatherRequests, MaxRounds)
	runHandler(s.shuffleRequests, MaxRounds)
	runHandler(s.gatherUploads, MaxRounds)
	runHandler(s.shuffleUploads, MaxRounds)
	runHandler(s.handleResponses, MaxRounds)

	s.running <- true
}

func (s *Server) gatherRequests(round uint64) {
	rnd := round % MaxRounds
	allReqs := make([]*Request, s.totalClients)
	var wg sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			req := <-s.rounds[rnd].reqChan2[i]
			req.Id = 0
			allReqs[i] = &req
		} (i)
	}
	wg.Wait()

	s.rounds[rnd].requestsChan <- allReqs
}

func (s *Server) shuffleRequests(round uint64) {
	rnd := round % MaxRounds
	allReqs := <-s.rounds[rnd].requestsChan

	//construct permuted blocks
	input := make([][]byte, s.totalClients)
	for i := range input {
		input[i] = allReqs[s.pi[i]].Hash
	}

	s.shuffle(input, round)

	reqs := make([]*Request, s.totalClients)
	for i := range reqs {
		reqs[i] = &Request{Hash: input[i], Round: round, Id: 0}
	}
	requests := &Requests{Requests: reqs}

	t := time.Now()
	if s.id == len(s.servers) - 1 {
		var wg sync.WaitGroup
		for i := range s.servers {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := s.servers[i].PutPlainRequests(context.TODO(), requests)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded reqs: ", err)
				}
			} (i)
		}
		wg.Wait()
	} else {
		_, err := s.servers[s.id+1].ShareServerRequests(context.TODO(), requests)
		if err != nil {
			log.Fatal("Couldn't hand off the requests to next server", s.id+1, err)
		}
	}

	if profile {
		fmt.Println("round", round, ". ", s.id, "server shuffle req: ", time.Since(t))
	}
}

func (s *Server) handleResponses(round uint64) {
	rnd := round % MaxRounds
	allBlocks := <-s.rounds[rnd].dblocksChan
	//store it on this server as well
	s.rounds[rnd].allBlocks = allBlocks

	if s.FSMode {
		t := time.Now()

		var wg sync.WaitGroup
		for i := 0; i < s.totalClients; i++ {
			if s.clientMap[i] == s.id {
				continue
			}
			//if it doesnt belong to me, xor things and send it over
			wg.Add(1)
			go func(i int, r uint64) {
				defer wg.Done()
				res := ComputeResponse(allBlocks, s.maskss[r][i], s.secretss[r][i])
				sha3.ShakeSum256(s.secretss[r][i], s.secretss[r][i])
				sha3.ShakeSum256(s.maskss[r][i], s.maskss[r][i])
				//fmt.Println(s.id, round, "mask", i, s.maskss[i])
				cb := &ClientBlock {
					Cid: uint64(i),
					Sid: uint64(s.id),
					Block: &Block {
						Block: res,
						Round: round,
					},
				}
				_, err := s.servers[s.clientMap[i]].PutClientBlock(context.TODO(), cb)
				if err != nil {
					log.Fatal("Couldn't put block: ", err)
				}
			} (i, rnd)
		}
		wg.Wait()

		if profile {
			fmt.Println(s.id, "handling_resp:", time.Since(t))
		}
	}
	for i := range s.rounds[rnd].blocksRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int, round uint64) {
			s.rounds[rnd].blocksRdy[i] <- true
		} (i, round)
	}
}

func (s *Server) gatherUploads(round uint64) {
	rnd := round % MaxRounds
	allBlocks := make([]Block, s.totalClients)
	var wg sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			block := <-s.rounds[rnd].ublockChan2[i]
			block.Id = 0
			allBlocks[i] = block
		} (i)
	}
	wg.Wait()

	s.rounds[rnd].shuffleChan <- allBlocks
}

func (s *Server) shuffleUploads(round uint64) {
	rnd := round % MaxRounds
	allBlocks := <-s.rounds[rnd].shuffleChan

	//construct permuted blocks
	input := make([][]byte, s.totalClients)
	for i := range input {
		input[i] = allBlocks[s.pi[i]].Block
	}

	s.shuffle(input, round)

	uploads := make([]*Block, s.totalClients)
	for i := range uploads {
		uploads[i] = &Block{Block: input[i], Round: round, Id: 0}
	}
	blocks := &Blocks{Blocks: uploads}

	t := time.Now()

	if s.id == len(s.servers) - 1 {
		var wg sync.WaitGroup
		for i := range s.servers {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := s.servers[i].PutPlainBlocks(context.TODO(), blocks)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
				}
			} (i)
		}
		wg.Wait()
	} else {
		_, err := s.servers[s.id+1].ShareServerBlocks(context.TODO(), blocks)
		if err != nil {
			log.Fatal("Couldn't hand off the blocks to next server", s.id+1, err)
		}
	}
	if profile {
		fmt.Println("round", round, ". ", s.id, "server shuffle: ", time.Since(t))
	}

	sum := 0
	for i := range blocks.Blocks {
		sum += len(blocks.Blocks[i].Block)
	}
	//fmt.Println(round, s.id, "sent: ", sum)
}

func (s *Server) gatherKeys(_ uint64) {
	allKeys := make([]UpKey, s.totalClients)
	for i := 0; i < s.totalClients; i++ {
		key := <-s.keyUploadChan
		allKeys[key.Id] = key
	}

	serversLeft := len(s.servers)-s.id

	Xss := make([]*Points, serversLeft)
	Yss := make([]*Points, serversLeft)

	for i := range Xss {
		Xs := make([][]byte, s.totalClients)
		Ys := make([][]byte, s.totalClients)
		for j := range Xs {
			Xs[j] = allKeys[j].C1S[i].X
			Ys[j] = allKeys[j].C2S[i].X
		}
		Xss[i] = &Points{Xs: Xs}
		Yss[i] = &Points{Xs: Ys}
	}

	ik := InternalKey {
		Xss: append([]*Points{nil}, Xss ...),
		Yss: append([]*Points{nil}, Yss ...),
		Sid: uint64(s.id),
	}

	aux := &AuxKeyProof {
		OrigXss: Xss,
		OrigYss: Yss,
		Sid:     uint64(s.id),
	}

	var wg sync.WaitGroup
	for i := range s.servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.servers[i].PutAuxProof(context.TODO(), aux)
			if err != nil {
				log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
			}
		} (i)
	}
	wg.Wait()

	s.keyShuffleChan <- ik
}

func (s *Server) shuffleKeys(_ uint64) {
	keys := <-s.keyShuffleChan

	serversLeft := len(s.servers)-s.id

	Xss := make([][]abstract.Point, serversLeft)
	Yss := make([][]abstract.Point, serversLeft)
	for i := range Xss {
		Xss[i] = make([]abstract.Point, s.totalClients)
		Yss[i] = make([]abstract.Point, s.totalClients)
		for j := range Xss[i] {
			Xss[i][j] = UnmarshalPoint(s.suite, keys.Xss[i+1].Xs[j])
			Yss[i][j] = UnmarshalPoint(s.suite, keys.Yss[i+1].Xs[j])
		}
	}

	Xbarss := make([][]abstract.Point, serversLeft)
	Ybarss := make([][]abstract.Point, serversLeft)
	decss := make([][]abstract.Point, serversLeft)
	prfs := make([][]byte, serversLeft)

	var shuffleWG sync.WaitGroup
	for i := 0; i < serversLeft; i++ {
		shuffleWG.Add(1)
		go func(i int, pk abstract.Point) {
			defer shuffleWG.Done()
			//only one chunk
			rand := s.suite.Cipher(abstract.RandomKey)
			var prover proof.Prover
			var err error
			Xbarss[i], Ybarss[i], prover = shuffle.Shuffle2(s.pi, s.g, nil, pk, Xss[i], Yss[i], rand)
			prfs[i], err = proof.HashProve(s.suite, "PairShuffle", rand, prover)
			if err != nil {
				log.Fatal("Shuffle proof failed: " + err.Error())
			}
			var decWG sync.WaitGroup
			decss[i] = make([]abstract.Point, s.totalClients)
			for j := range decss[i] {
				decWG.Add(1)
				go func (i int, j int) {
					defer decWG.Done()
					decss[i][j] = Decrypt(s.g, Xbarss[i][j], Ybarss[i][j], s.sk)
				} (i, j)
			}
			decWG.Wait()

		} (i, s.nextPks[i])
	}
	shuffleWG.Wait()

	//whatever is at index 0 belongs to me
	for i := range decss[0] {
		s.keys[i] = MarshalPoint(decss[0][i])
	}

	ik := InternalKey {
		Xss: make([]*Points, serversLeft),
		Yss: make([]*Points, serversLeft),
		Sid: uint64(s.id),

		Ybarss:  make([]*Points, serversLeft),
		Proofs:  prfs,
		Keys:    make([][]byte, serversLeft),
	}

	for i := range ik.Xss {
		ik.Xss[i] = &Points{Xs: make([][]byte, s.totalClients)}
		ik.Yss[i] = &Points{Xs: make([][]byte, s.totalClients)}
		ik.Ybarss[i] = &Points{Xs:make([][]byte, s.totalClients)}
		for j := range ik.Xss[i].Xs {
			ik.Xss[i].Xs[j] = MarshalPoint(Xbarss[i][j])
			if i == 0 {
				//i == 0 is my point, so don't pass it to next person
				ik.Yss[i].Xs[j] = MarshalPoint(s.g.Point().Base())
			} else {
				ik.Yss[i].Xs[j] = MarshalPoint(decss[i][j])
			}
			ik.Ybarss[i].Xs[j] = MarshalPoint(Ybarss[i][j])
		}
		ik.Keys[i] = s.nextPksBin[i]
	}

	var wg sync.WaitGroup
	for i := range s.servers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.servers[i].ShareServerKeys(context.TODO(), &ik)
			if err != nil {
				log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
			}
		} (i)
	}
	wg.Wait()
}

/////////////////////////////////
//Registration and Setup
////////////////////////////////
//register the client here, and notify the server it will be talking to
//TODO: should check for duplicate clients, just in case..
func (s *Server) Register(cxt context.Context, sid *UInt) (*RegisterReply, error) {
	s.regLock[0].Lock()
	clientId := uint64(s.totalClients)
	client := &ClientRegistration{
		ServerId: sid.Val,
		Id: clientId,
	}
	s.totalClients++
	for _, server := range s.servers {
		_, err := server.Register2(context.TODO(), client)
		if err != nil {
			log.Fatal(fmt.Sprintf("Cannot connect to %d: ", sid.Val), err)
		}
	}
	if s.totalClients == TotalClients {
		s.registerDone()
	}
	fmt.Println("Registered", clientId)
	s.regLock[0].Unlock()
	<-s.regChan
	reply := &RegisterReply{
		Id: clientId,
		NumClients: uint64(s.totalClients),
		Pks: s.pksBin}
	return reply, nil
}

//called to increment total number of clients
func (s *Server) Register2(cxt context.Context, client *ClientRegistration) (*Empty, error) {
	s.regLock[1].Lock()
	s.clientMap[int(client.Id)] = int(client.ServerId)
	s.regLock[1].Unlock()
	return &Empty{}, nil
}

func (s *Server) registerDone() {
	for _, server := range s.servers {
		_, err := server.RegisterDone2(context.TODO(), &UInt{Val: uint64(s.totalClients)})
		if err != nil {
			log.Fatal("Cannot update num clients")
		}
	}

	for i := 0; i < s.totalClients; i++ {
		s.regChan <- true
	}
}

func (s *Server) RegisterDone2(cxt context.Context, nc *UInt) (*Empty, error) {
	numClients := int(nc.Val)
	s.totalClients = numClients

	size := (numClients/SecretSize)*SecretSize + SecretSize
	s.maskss = make([][][]byte, MaxRounds)
	s.secretss = make([][][]byte, MaxRounds)
	for r := range s.maskss {
		s.maskss[r] = make([][]byte, numClients)
		s.secretss[r] = make([][]byte, numClients)
		for i := range s.maskss[r] {
			s.maskss[r][i] = make([]byte, size)
			s.secretss[r][i] = make([]byte, BlockSize)
		}
	}

	s.pi = GeneratePI(numClients)

	s.keys = make([][]byte, numClients)
	s.keysRdy = make(chan bool, numClients)

	s.keyUploadChan = make(chan UpKey, numClients)

	for r := range s.rounds {
		for i := 0; i < len(s.servers); i++ {
			s.rounds[r].xorsChan[i] = make(map[int](chan Block))
			for j := 0; j < numClients; j++ {
				s.rounds[r].xorsChan[i][j] = make(chan Block)
			}
		}

		s.rounds[r].requestsChan = make(chan []*Request)
		s.rounds[r].reqHashes = make([][]byte, numClients)

		s.rounds[r].reqChan2 = make([]chan Request, numClients)
		s.rounds[r].upHashes = make([][]byte, numClients)
		s.rounds[r].blocksRdy = make([]chan bool, numClients)
		s.rounds[r].upHashesRdy = make([]chan bool, numClients)
		s.rounds[r].reqHashesRdy = make([]chan bool, numClients)
		s.rounds[r].ublockChan2 = make([]chan Block, numClients)
		for i := range s.rounds[r].blocksRdy {
			s.rounds[r].reqChan2[i] = make(chan Request)
			s.rounds[r].blocksRdy[i] = make(chan bool)
			s.rounds[r].upHashesRdy[i] = make(chan bool)
			s.rounds[r].reqHashesRdy[i] = make(chan bool)
			s.rounds[r].ublockChan2[i] = make(chan Block)
		}
	}
	s.regDone <- true
	fmt.Println(s.id, "Register done")
	<-s.running
	return &Empty{}, nil
}

func (s *Server) connectServers() {
	for i := range s.conns {
		var conn *grpc.ClientConn
		var err error = errors.New("")
		for ; err != nil ; {
			if i == s.id { //make a local rpc
				addr := fmt.Sprintf("127.0.0.1:%d", s.port2)
				conn, err = grpc.Dial(addr)
			} else {
				conn, err = grpc.Dial(s.serverAddrs[i])
			}
		}
		s.conns[i] = conn
		s.servers[i] = NewRiffleInternalClient(conn)
	}
	var wg sync.WaitGroup
	for i := range s.servers {
		wg.Add(1)
		go func (i int) {
			defer wg.Done()
			pk, err := s.servers[i].GetPK(context.TODO(), &Empty{})
			if err != nil {
				log.Fatal("Couldn't get server's pk: ", err)
			}
			s.pks[i] = UnmarshalPoint(s.suite, pk.X)
			s.pksBin[i] = pk.X
		} (i)
	}
	wg.Wait()
	for i := 0; i < len(s.servers)-s.id; i++ {
		pk := s.pk
		for j := 1; j <= i; j++ {
			pk = s.g.Point().Add(pk, s.pks[s.id + j])
		}
		s.nextPks[i] = pk
		s.nextPksBin[i] = MarshalPoint(pk)
	}
}

func (s *Server) GetPK(ctx context.Context, _ *Empty) (*Point, error) {
	pt := Point{X: s.pkBin}
	return &pt, nil
}

func (s *Server) UploadKeys(ctx context.Context, key *UpKey) (*Empty, error) {
	s.keyUploadChan <- *key
	<-s.keysRdy
	return &Empty{}, nil
}

func (s *Server) shareSecret(clientPublic abstract.Point) (abstract.Point, abstract.Point) {
	s.secretLock.Lock()
	rand := s.suite.Cipher(abstract.RandomKey)
	gen := s.g.Point().Base()
	secret := s.g.Secret().Pick(rand)
	public := s.g.Point().Mul(gen, secret)
	sharedSecret := s.g.Point().Mul(clientPublic, secret)
	s.secretLock.Unlock()
	return public, sharedSecret
}

func (s *Server) ShareSecrets(ctx context.Context, clientDH *ClientDH) (*Points, error) {
	pub1, shared1 := s.shareSecret(UnmarshalPoint(s.suite, clientDH.Public))
	pub2, shared2 := s.shareSecret(UnmarshalPoint(s.suite, clientDH.Public))
	mask := MarshalPoint(shared1)
	secret := MarshalPoint(shared2)
	for r := 0; r < MaxRounds; r++ {
		if r == 0 {
			sha3.ShakeSum256(s.maskss[r][clientDH.Id], mask)
			sha3.ShakeSum256(s.secretss[r][clientDH.Id], secret)
		} else {
			sha3.ShakeSum256(s.maskss[r][clientDH.Id], s.maskss[r-1][clientDH.Id])
			sha3.ShakeSum256(s.secretss[r][clientDH.Id], s.secretss[r-1][clientDH.Id])
		}
	}
	pts := Points{Xs: [][]byte{MarshalPoint(pub1), MarshalPoint(pub2)}}
	return &pts, nil
}

func (s *Server) PutAuxProof(ctx context.Context, aux *AuxKeyProof) (*Empty, error) {
	s.auxProofChan[aux.Sid] <- *aux
	return &Empty{}, nil
}

func (s *Server) ShareServerKeys(ctx context.Context, ik *InternalKey) (*Bool, error) {
	aux := <-s.auxProofChan[ik.Sid]
	good := s.verifyShuffle(*ik, aux)

	if int(ik.Sid) != len(s.servers) - 1 {
		aux = AuxKeyProof {
			OrigXss: ik.Xss[1:],
			OrigYss: ik.Yss[1:],
			Sid:     ik.Sid + 1,
		}
		s.auxProofChan[aux.Sid] <- aux
	}

	if int(ik.Sid) == len(s.servers) - 1 && s.id == 0 {
		for i := 0; i < s.totalClients; i++ {
			go func () {
				s.keysRdy <- true
			} ()
		}
	} else if int(ik.Sid) == s.id - 1 {
		ik.Ybarss = nil
		ik.Proofs = nil
		ik.Keys = nil
		s.keyShuffleChan <- *ik
	}
	correct := Bool{Val: good}
	return &correct, nil
}

/////////////////////////////////
//Request
////////////////////////////////
func (s *Server) RequestBlock(ctx context.Context, req *Request) (*Hashes, error) {
	round := req.Round % MaxRounds
	_, err := s.servers[0].RequestBlock2(ctx, req)
	if err != nil {
		log.Fatal("Couldn't send request block: ", err)
	}
	<-s.rounds[round].reqHashesRdy[req.Id]
	hashes := &Hashes{Hashes: s.rounds[round].reqHashes}
	return hashes, err
}

func (s *Server) RequestBlock2(ctx context.Context, req *Request) (*Empty, error) {
	round := req.Round % MaxRounds
	s.rounds[round].reqChan2[req.Id] <- *req
	return &Empty{}, nil
}

func (s *Server) PutPlainRequests(ctx context.Context, rs *Requests) (*Empty, error) {
	reqs := rs.Requests
	round := reqs[0].Round % MaxRounds
	for i := range reqs {
		s.rounds[round].reqHashes[i] = reqs[i].Hash
	}

	for i := range s.rounds[round].reqHashesRdy {
		if s.clientMap[i] != s.id {
			continue
		}
		go func(i int, round uint64) {
			s.rounds[round].reqHashesRdy[i] <- true
		} (i, round)
	}

	return &Empty{}, nil
}

func (s *Server) ShareServerRequests(ctx context.Context, rs *Requests) (*Empty, error) {
	reqs := rs.Requests
	round := reqs[0].Round % MaxRounds
	s.rounds[round].requestsChan <- rs.Requests
	return &Empty{}, nil
}

/////////////////////////////////
//Upload
////////////////////////////////
func (s *Server) UploadBlock(ctx context.Context, block *Block) (*Hashes, error) {
	round := block.Round % MaxRounds
	_, err := s.servers[0].UploadBlock2(ctx, block)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
	<-s.rounds[round].upHashesRdy[block.Id]
	hashes := &Hashes{Hashes: s.rounds[round].upHashes}
	return hashes, nil
}

func (s *Server) UploadBlock2(ctx context.Context, block *Block) (*Empty, error) {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2[block.Id] <- *block
	return &Empty{}, nil
}

func (s *Server) UploadSmall(ctx context.Context, block *Block) (*Empty, error) {
	_, err := s.servers[0].UploadBlock2(ctx, block)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
	return &Empty{}, nil
}

func (s *Server) UploadSmall2(ctx context.Context, block *Block) (*Empty, error) {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2[block.Id] <- *block
	return &Empty{}, nil
}

func (s *Server) PutPlainBlocks(ctx context.Context, bs *Blocks) (*Empty, error) {
	blocks := make([]Block, len(bs.Blocks))
	for i := range bs.Blocks {
		blocks[i] = *(bs.Blocks[i])
	}
	round := blocks[0].Round % MaxRounds

	for i := range blocks {
		h := s.suite.Hash()
		h.Write(blocks[i].Block)
		s.rounds[round].upHashes[i] = h.Sum(nil)
	}

	if s.FSMode {
		for i := range s.rounds[round].upHashesRdy {
			if s.clientMap[i] != s.id {
				continue
			}
			go func(i int, round uint64) {
				s.rounds[round].upHashesRdy[i] <- true
			} (i, round)
		}
	}

	s.rounds[round].dblocksChan <- blocks
	return &Empty{}, nil
}

func (s *Server) ShareServerBlocks(ctx context.Context, bs *Blocks) (*Empty, error) {
	blocks := make([]Block, len(bs.Blocks))
	for i := range bs.Blocks {
		blocks[i] = *(bs.Blocks[i])
	}
	round := blocks[0].Round % MaxRounds
	s.rounds[round].shuffleChan <- blocks
	return &Empty{}, nil
}


/////////////////////////////////
//Download
////////////////////////////////
func (s *Server) GetResponse(ctx context.Context, cmask *ClientMask) (*Datum, error) {
	t := time.Now()
	round := cmask.Round % MaxRounds
	otherBlocks := make([][]byte, len(s.servers))
	var wg sync.WaitGroup
	for i := range otherBlocks {
		if i == s.id {
			otherBlocks[i] = make([]byte, BlockSize)
		} else {
			wg.Add(1)
			go func(i int, cmask ClientMask) {
				defer wg.Done()
				curBlock := <-s.rounds[round].xorsChan[i][int(cmask.Id)]
				otherBlocks[i] = curBlock.Block
			} (i, *cmask)
		}
	}
	wg.Wait()
	<-s.rounds[round].blocksRdy[cmask.Id]
	if cmask.Id == 0 && profile {
		fmt.Println(cmask.Id, "down_network:", time.Since(t))
	}
	r := ComputeResponse(s.rounds[round].allBlocks, cmask.Mask, s.secretss[round][cmask.Id])
	sha3.ShakeSum256(s.secretss[round][cmask.Id], s.secretss[round][cmask.Id])
	Xor(Xors(otherBlocks), r)
	resp := &Datum{Datum: r}
	return resp, nil
}

func (s *Server) GetAllResponses(ctx context.Context, args *RequestArg) (*Data, error) {
	round := args.Round % MaxRounds
	<-s.rounds[round].blocksRdy[args.Id]
	resps := make([][]byte, s.totalClients)
	for i := range s.rounds[round].allBlocks {
		resps[i] = s.rounds[round].allBlocks[i].Block
	}
	resp := &Data{Data: resps}
	return resp, nil
}

//used to push response for particular client
func (s *Server) PutClientBlock(ctx context.Context, cblock *ClientBlock) (*Empty, error) {
	block := *cblock.Block
	round := block.Round % MaxRounds
	s.rounds[round].xorsChan[cblock.Sid][int(cblock.Cid)] <- block
	return &Empty{}, nil
}

/////////////////////////////////
//Misc
////////////////////////////////
//used for the local test function to start the server
func (s *Server) MainLoop() error {
	l1, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port1))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", s.port1)
	}
	l2, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port2))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", s.port2)
	}
	rpcServer1 := grpc.NewServer()
	rpcServer2 := grpc.NewServer()
	RegisterRiffleServer(rpcServer1, s)
	RegisterRiffleInternalServer(rpcServer2, s)
	go rpcServer1.Serve(l1)
	go rpcServer2.Serve(l2)
	s.connectServers()
	go s.runHandlers()
	return nil
}


func (s *Server) verifyShuffle(ik InternalKey, aux AuxKeyProof) bool {
	Xss := aux.OrigXss
	Yss := aux.OrigYss
	Xbarss := ik.Xss
	Ybarss := ik.Ybarss
	prfss := ik.Proofs

	for i := range Xss {
		pk := UnmarshalPoint(s.suite, ik.Keys[i])
		Xs := make([]abstract.Point, len(Xss[i].Xs))
		Ys := make([]abstract.Point, len(Yss[i].Xs))
		Xbars := make([]abstract.Point, len(Xbarss[i].Xs))
		Ybars := make([]abstract.Point, len(Ybarss[i].Xs))
		for j := range Xss[i].Xs {
			Xs[j] = UnmarshalPoint(s.suite, Xss[i].Xs[j])
			Ys[j] = UnmarshalPoint(s.suite, Yss[i].Xs[j])
			Xbars[j] = UnmarshalPoint(s.suite, Xbarss[i].Xs[j])
			Ybars[j] = UnmarshalPoint(s.suite, Ybarss[i].Xs[j])
		}
		v := shuffle.Verifier(s.suite, nil, pk, Xs, Ys, Xbars, Ybars)
		err := proof.HashVerify(s.suite, "PairShuffle", v, prfss[i])
		if err != nil {
			log.Println("Shuffle verify failed: ", err)
			return false
		}
	}
	return true
}

func (s *Server) shuffle(input [][]byte, round uint64) {
	tmp := make([]byte, 24)
	nonce := [24]byte{}
	binary.PutUvarint(tmp, round)
	copy(nonce[:], tmp[:])
	var aesWG sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		aesWG.Add(1)
		go func(i int) {
			defer aesWG.Done()
			key := [32]byte{}
			copy(key[:], s.keys[i][:])
			var good bool
			input[i], good = secretbox.Open(nil, input[i], &nonce, &key)
			if !good {
				log.Fatal(round, " check failed:", s.id, i)
			}
		} (i)
	}
	aesWG.Wait()
}

func (s *Server) Masks() [][][]byte {
	return s.maskss
}

func (s *Server) Secrets() [][][]byte {
	return s.secretss
}

func (s *Server) Keys() [][]byte {
	return s.keys
}

func runHandler(f func(uint64), rounds uint64) {
	var r uint64 = 0
	for ; r < rounds; r++ {
		go func (r uint64) {
			for {
				f(r)
				r += rounds
			}
		} (r)
	}
}

func SetTotalClients(n int) {
	TotalClients = n
}

/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var memprofile = flag.String("memprofile", "", "write memory profile to this file")
	var id *int = flag.Int("i", 0, "id [num]")
	var port1 *int = flag.Int("p1", 8000, "port1 [num]")
	var port2 *int = flag.Int("p2", 8001, "port2 [num]")
	var servers *string = flag.String("s", "", "servers [file]")
	var numClients *int = flag.Int("n", 0, "num clients [num]")
	var mode *string = flag.String("m", "", "mode [m for microblogging|f for file sharing]")
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	ss := ParseServerList(*servers)

	SetTotalClients(*numClients)

	s := NewServer(*port1, *port2, *id, ss, *mode == "f")

	if *memprofile != "" {
                f, err := os.Create(*memprofile)
                if err != nil {
                        log.Fatal(err)
                }
                s.memProf = f
        }
	l1, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port1))
	if err != nil {
		panic("Cannot starting listening to the port")
	}
	l2, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port2))
	if err != nil {
		panic("Cannot starting listening to the port")
	}
	rpcServer1 := grpc.NewServer()
	rpcServer2 := grpc.NewServer()
	RegisterRiffleServer(rpcServer1, s)
	RegisterRiffleInternalServer(rpcServer2, s)
	go rpcServer1.Serve(l1)
	go rpcServer2.Serve(l2)

	s.connectServers()
	fmt.Println("Starting server", *id)
	s.runHandlers()
	fmt.Println("Handler running", *id)

	Wait()
}
