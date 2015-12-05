//package server
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"

	"time"

	. "github.com/kwonalbert/riffle/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

var TotalClients = 0
var profile = false
var debug = false

//any variable/func with 2: similar object as s-c but only s-s
type Server struct {
	port1       int
	port2       int
	id          int
	servers     []string //other servers
	rpcServers  []*rpc.Client
	regLock     []*sync.Mutex //registration mutex
	regChan     chan bool
	regDone     chan bool
	connectDone chan bool
	running     chan bool
	secretLock  *sync.Mutex

	FSMode bool //true for microblogging, false for file sharing

	//crypto
	suite      abstract.Suite
	g          abstract.Group
	sk         abstract.Secret //secret and public elgamal key
	pk         abstract.Point
	pkBin      []byte
	pks        []abstract.Point //all servers pks
	nextPks    []abstract.Point
	nextPksBin [][]byte
	ephSecret  abstract.Secret

	//used during key shuffle
	pi             []int
	keys           [][]byte
	keysRdy        chan bool
	auxProofChan   []chan AuxKeyProof
	keyUploadChan  chan UpKey
	keyShuffleChan chan InternalKey //collect all uploads together

	//clients
	clientMap    map[int]int //maps clients to dedicated server
	numClients   int         //#clients connect here
	totalClients int         //total number of clients (sum of all servers)
	maskss       [][][]byte  //clients' masks for PIR
	secretss     [][][]byte  //shared secret used to xor

	//all rounds
	rounds []*Round

	memProf *os.File
}

//per round variables
type Round struct {
	allBlocks []Block //all blocks store on this server

	//requesting
	reqChan2     []chan Request
	requestsChan chan []Request
	reqHashes    [][]byte
	reqHashesRdy []chan bool

	//uploading
	ublockChan2 []chan Block
	shuffleChan chan []Block
	upHashesRdy []chan bool

	//downloading
	upHashes    [][]byte
	dblocksChan chan []Block
	blocksRdy   []chan bool
	xorsChan    []map[int](chan Block)
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
			allBlocks: nil,

			reqChan2:     nil,
			requestsChan: nil,
			reqHashes:    nil,
			reqHashesRdy: nil,

			ublockChan2: nil,
			shuffleChan: make(chan []Block), //collect all uploads together
			upHashesRdy: nil,

			upHashes:    nil,
			dblocksChan: make(chan []Block),
			blocksRdy:   nil,
			xorsChan:    make([]map[int](chan Block), len(servers)),
		}
		rounds[i] = &r
	}

	s := Server{
		port1:       port1,
		port2:       port2,
		id:          id,
		servers:     servers,
		regLock:     []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},
		regChan:     make(chan bool, TotalClients),
		regDone:     make(chan bool),
		connectDone: make(chan bool),
		running:     make(chan bool),
		secretLock:  new(sync.Mutex),

		suite:      suite,
		g:          suite,
		sk:         sk,
		pk:         pk,
		pkBin:      pkBin,
		pks:        make([]abstract.Point, len(servers)),
		nextPks:    make([]abstract.Point, len(servers)),
		nextPksBin: make([][]byte, len(servers)),
		ephSecret:  ephSecret,

		pi:             nil,
		keys:           nil,
		keysRdy:        nil,
		auxProofChan:   make([]chan AuxKeyProof, len(servers)),
		keyUploadChan:  nil,
		keyShuffleChan: make(chan InternalKey),

		clientMap:    make(map[int]int),
		numClients:   0,
		totalClients: 0,
		maskss:       nil,
		secretss:     nil,

		rounds: rounds,

		FSMode: FSMode,

		memProf: nil,
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
	allReqs := make([]Request, s.totalClients)
	var wg sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := <-s.rounds[rnd].reqChan2[i]
			req.Id = 0
			allReqs[i] = req
		}(i)
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

	reqs := make([]Request, s.totalClients)
	for i := range reqs {
		reqs[i] = Request{Hash: input[i], Round: round, Id: 0}
	}

	t := time.Now()
	if s.id == len(s.servers)-1 {
		if len(input[0]) != (BlockSize + HashSize) {
			log.Fatal("size mismatch!")
		}
		var wg sync.WaitGroup
		for _, rpcServer := range s.rpcServers {
			wg.Add(1)
			go func(rpcServer *rpc.Client) {
				defer wg.Done()
				err := rpcServer.Call("Server.PutPlainRequests", &reqs, nil)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded reqs: ", err)
				}
			}(rpcServer)
		}
		wg.Wait()
	} else {
		err := s.rpcServers[s.id+1].Call("Server.ShareServerRequests", &reqs, nil)
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

		for i := range allBlocks {
			s.rounds[rnd].upHashes[i] = allBlocks[i].Block[BlockSize:]
		}

		for i := range s.rounds[rnd].upHashesRdy {
			if s.clientMap[i] != s.id {
				continue
			}
			go func(i int) {
				s.rounds[rnd].upHashesRdy[i] <- true
			}(i)
		}

		var wg sync.WaitGroup
		for i := 0; i < s.totalClients; i++ {
			if s.clientMap[i] == s.id {
				continue
			}
			//if it doesnt belong to me, xor things and send it over
			wg.Add(1)
			go func(i int, rpcServer *rpc.Client, r uint64) {
				defer wg.Done()
				res := ComputeResponse(allBlocks, s.maskss[r][i], s.secretss[r][i])
				sha3.ShakeSum256(s.secretss[r][i], s.secretss[r][i])
				sha3.ShakeSum256(s.maskss[r][i], s.maskss[r][i])
				//fmt.Println(s.id, round, "mask", i, s.maskss[i])
				cb := ClientBlock{
					CId: i,
					SId: s.id,
					Block: Block{
						Block: res,
						Round: round,
					},
				}
				err := rpcServer.Call("Server.PutClientBlock", cb, nil)
				if err != nil {
					log.Fatal("Couldn't put block: ", err)
				}
			}(i, s.rpcServers[s.clientMap[i]], rnd)
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
		}(i, round)
	}
}

func (s *Server) gatherUploads(round uint64) {
	rnd := round % MaxRounds
	allBlocks := make([]Block, s.totalClients)
	var wg sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			block := <-s.rounds[rnd].ublockChan2[i]
			block.Id = 0
			allBlocks[i] = block
		}(i)
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

	uploads := make([]Block, s.totalClients)
	for i := range uploads {
		uploads[i] = Block{Block: input[i], Round: round, Id: 0}
	}

	t := time.Now()

	if s.id == len(s.servers)-1 {
		var wg sync.WaitGroup
		for _, rpcServer := range s.rpcServers {
			wg.Add(1)
			go func(rpcServer *rpc.Client) {
				defer wg.Done()
				err := rpcServer.Call("Server.PutPlainBlocks", &uploads, nil)
				if err != nil {
					log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
				}
			}(rpcServer)
		}
		wg.Wait()
	} else {
		err := s.rpcServers[s.id+1].Call("Server.ShareServerBlocks", &uploads, nil)
		if err != nil {
			log.Fatal("Couldn't hand off the blocks to next server", s.id+1, err)
		}
	}
	if profile {
		fmt.Println("round", round, ". ", s.id, "server shuffle: ", time.Since(t))
	}
}

func (s *Server) gatherKeys(_ uint64) {
	allKeys := make([]UpKey, s.totalClients)
	for i := 0; i < s.totalClients; i++ {
		key := <-s.keyUploadChan
		allKeys[key.Id] = key
	}

	serversLeft := len(s.servers) - s.id

	Xss := make([][][]byte, serversLeft)
	Yss := make([][][]byte, serversLeft)

	for i := range Xss {
		Xss[i] = make([][]byte, s.totalClients)
		Yss[i] = make([][]byte, s.totalClients)
		for j := range Xss[i] {
			Xss[i][j] = allKeys[j].C1s[i]
			Yss[i][j] = allKeys[j].C2s[i]
		}
	}

	ik := InternalKey{
		Xss: append([][][]byte{nil}, Xss...),
		Yss: append([][][]byte{nil}, Yss...),
		SId: s.id,
	}

	aux := AuxKeyProof{
		OrigXss: Xss,
		OrigYss: Yss,
		SId:     s.id,
	}

	var wg sync.WaitGroup
	for _, rpcServer := range s.rpcServers {
		wg.Add(1)
		go func(rpcServer *rpc.Client) {
			defer wg.Done()
			err := rpcServer.Call("Server.PutAuxProof", &aux, nil)
			if err != nil {
				log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
			}
		}(rpcServer)
	}
	wg.Wait()

	s.keyShuffleChan <- ik
}

func (s *Server) shuffleKeys(_ uint64) {
	keys := <-s.keyShuffleChan

	serversLeft := len(s.servers) - s.id

	Xss := make([][]abstract.Point, serversLeft)
	Yss := make([][]abstract.Point, serversLeft)
	for i := range Xss {
		Xss[i] = make([]abstract.Point, s.totalClients)
		Yss[i] = make([]abstract.Point, s.totalClients)
		for j := range Xss[i] {
			Xss[i][j] = UnmarshalPoint(s.suite, keys.Xss[i+1][j])
			Yss[i][j] = UnmarshalPoint(s.suite, keys.Yss[i+1][j])
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
				go func(i int, j int) {
					defer decWG.Done()
					decss[i][j] = Decrypt(s.g, Xbarss[i][j], Ybarss[i][j], s.sk)
				}(i, j)
			}
			decWG.Wait()

		}(i, s.nextPks[i])
	}
	shuffleWG.Wait()

	//whatever is at index 0 belongs to me
	for i := range decss[0] {
		s.keys[i] = MarshalPoint(decss[0][i])
	}

	ik := InternalKey{
		Xss: make([][][]byte, serversLeft),
		Yss: make([][][]byte, serversLeft),
		SId: s.id,

		Ybarss: make([][][]byte, serversLeft),
		Proofs: prfs,
		Keys:   make([][]byte, serversLeft),
	}

	for i := range ik.Xss {
		ik.Xss[i] = make([][]byte, s.totalClients)
		ik.Yss[i] = make([][]byte, s.totalClients)
		ik.Ybarss[i] = make([][]byte, s.totalClients)
		for j := range ik.Xss[i] {
			ik.Xss[i][j] = MarshalPoint(Xbarss[i][j])
			if i == 0 {
				//i == 0 is my point, so don't pass it to next person
				ik.Yss[i][j] = MarshalPoint(s.g.Point().Base())
			} else {
				ik.Yss[i][j] = MarshalPoint(decss[i][j])
			}
			ik.Ybarss[i][j] = MarshalPoint(Ybarss[i][j])
		}
		ik.Keys[i] = s.nextPksBin[i]
	}

	var wg sync.WaitGroup
	for _, rpcServer := range s.rpcServers {
		wg.Add(1)
		go func(rpcServer *rpc.Client) {
			defer wg.Done()
			err := rpcServer.Call("Server.ShareServerKeys", &ik, nil)
			if err != nil {
				log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
			}
		}(rpcServer)
	}
	wg.Wait()
}

/////////////////////////////////
//Registration and Setup
////////////////////////////////
//register the client here, and notify the server it will be talking to
//TODO: should check for duplicate clients, just in case..
func (s *Server) Register(serverId int, clientId *int) error {
	s.regLock[0].Lock()
	*clientId = s.totalClients
	client := &ClientRegistration{
		ServerId: serverId,
		Id:       *clientId,
	}
	s.totalClients++
	for _, rpcServer := range s.rpcServers {
		err := rpcServer.Call("Server.Register2", client, nil)
		if err != nil {
			log.Fatal(fmt.Sprintf("Cannot connect to %d: ", serverId), err)
		}
	}
	if s.totalClients == TotalClients {
		s.registerDone()
	}
	fmt.Println("Registered", *clientId)
	s.regLock[0].Unlock()
	return nil
}

//called to increment total number of clients
func (s *Server) Register2(client *ClientRegistration, _ *int) error {
	s.regLock[1].Lock()
	s.clientMap[client.Id] = client.ServerId
	s.regLock[1].Unlock()
	return nil
}

func (s *Server) registerDone() {
	for _, rpcServer := range s.rpcServers {
		err := rpcServer.Call("Server.RegisterDone2", s.totalClients, nil)
		if err != nil {
			log.Fatal("Cannot update num clients")
		}
	}

	for i := 0; i < s.totalClients; i++ {
		s.regChan <- true
	}
}

func (s *Server) RegisterDone2(numClients int, _ *int) error {
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

		s.rounds[r].requestsChan = make(chan []Request)
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
	return nil
}

func (s *Server) connectServers() {
	rpcServers := make([]*rpc.Client, len(s.servers))
	for i := range rpcServers {
		var rpcServer *rpc.Client
		var err error = errors.New("")
		for err != nil {
			if i == s.id { //make a local rpc
				addr := fmt.Sprintf("127.0.0.1:%d", s.port2)
				rpcServer, err = rpc.Dial("tcp", addr)
			} else {
				rpcServer, err = rpc.Dial("tcp", s.servers[i])
			}
		}
		rpcServers[i] = rpcServer
	}

	var wg sync.WaitGroup
	for i, rpcServer := range rpcServers {
		wg.Add(1)
		go func(i int, rpcServer *rpc.Client) {
			defer wg.Done()
			pk := make([]byte, SecretSize)
			err := rpcServer.Call("Server.GetPK", 0, &pk)
			if err != nil {
				log.Fatal("Couldn't get server's pk: ", err)
			}
			s.pks[i] = UnmarshalPoint(s.suite, pk)
		}(i, rpcServer)
	}
	wg.Wait()
	for i := 0; i < len(s.servers)-s.id; i++ {
		pk := s.pk
		for j := 1; j <= i; j++ {
			pk = s.g.Point().Add(pk, s.pks[s.id+j])
		}
		s.nextPks[i] = pk
		s.nextPksBin[i] = MarshalPoint(pk)
	}
	s.rpcServers = rpcServers
	//s.connectDone <- true
}

func (s *Server) GetNumClients(_ int, num *int) error {
	<-s.regChan
	*num = s.totalClients
	return nil
}

func (s *Server) GetPK(_ int, pk *[]byte) error {
	*pk = s.pkBin
	return nil
}

func (s *Server) UploadKeys(key *UpKey, _ *int) error {
	s.keyUploadChan <- *key
	return nil
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

func (s *Server) ShareMask(clientDH *ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(s.suite, clientDH.Public))
	mask := MarshalPoint(shared)
	for r := 0; r < MaxRounds; r++ {
		if r == 0 {
			sha3.ShakeSum256(s.maskss[r][clientDH.Id], mask)
		} else {
			sha3.ShakeSum256(s.maskss[r][clientDH.Id], s.maskss[r-1][clientDH.Id])
		}
	}
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) ShareSecret(clientDH *ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(s.suite, clientDH.Public))
	secret := MarshalPoint(shared)
	for r := 0; r < MaxRounds; r++ {
		if r == 0 {
			sha3.ShakeSum256(s.secretss[r][clientDH.Id], secret)
		} else {
			sha3.ShakeSum256(s.secretss[r][clientDH.Id], s.secretss[r-1][clientDH.Id])
		}
	}
	//s.secretss[clientDH.Id] = make([]byte, len(MarshalPoint(shared)))
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) GetEphKey(_ int, serverPub *[]byte) error {
	pub := s.g.Point().Mul(s.g.Point().Base(), s.ephSecret)
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) PutAuxProof(aux *AuxKeyProof, _ *int) error {
	s.auxProofChan[aux.SId] <- *aux
	return nil
}

func (s *Server) ShareServerKeys(ik *InternalKey, correct *bool) error {
	aux := <-s.auxProofChan[ik.SId]
	good := s.verifyShuffle(*ik, aux)

	if ik.SId != len(s.servers)-1 {
		aux = AuxKeyProof{
			OrigXss: ik.Xss[1:],
			OrigYss: ik.Yss[1:],
			SId:     ik.SId + 1,
		}
		s.auxProofChan[aux.SId] <- aux
	}

	if ik.SId == len(s.servers)-1 && s.id == 0 {
		for i := 0; i < s.totalClients; i++ {
			go func() {
				s.keysRdy <- true
			}()
		}
	} else if ik.SId == s.id-1 {
		ik.Ybarss = nil
		ik.Proofs = nil
		ik.Keys = nil
		s.keyShuffleChan <- *ik
	}
	*correct = good
	return nil
}

func (s *Server) KeyReady(id int, _ *int) error {
	<-s.keysRdy
	return nil
}

/////////////////////////////////
//Request
////////////////////////////////
func (s *Server) RequestBlock(req *Request, hashes *[][]byte) error {
	round := req.Round % MaxRounds
	err := s.rpcServers[0].Call("Server.RequestBlock2", req, nil)
	<-s.rounds[round].reqHashesRdy[req.Id]
	*hashes = s.rounds[round].reqHashes
	return err
}

func (s *Server) RequestBlock2(req *Request, _ *int) error {
	round := req.Round % MaxRounds
	s.rounds[round].reqChan2[req.Id] <- *req
	return nil
}

func (s *Server) PutPlainRequests(rs *[]Request, _ *int) error {
	reqs := *rs
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
		}(i, round)
	}

	return nil
}

func (s *Server) ShareServerRequests(reqs *[]Request, _ *int) error {
	round := (*reqs)[0].Round % MaxRounds
	s.rounds[round].requestsChan <- *reqs
	return nil
}

/////////////////////////////////
//Upload
////////////////////////////////
func (s *Server) UploadBlock(block *Block, hashes *[][]byte) error {
	round := block.Round % MaxRounds
	err := s.rpcServers[0].Call("Server.UploadBlock2", block, nil)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
	<-s.rounds[round].upHashesRdy[block.Id]
	*hashes = s.rounds[round].upHashes
	return nil
}

func (s *Server) UploadBlock2(block *Block, _ *int) error {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2[block.Id] <- *block
	return nil
}

func (s *Server) UploadSmall(block *Block, _ *int) error {
	err := s.rpcServers[0].Call("Server.UploadBlock2", block, nil)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
	return nil
}

func (s *Server) UploadSmall2(block *Block, _ *int) error {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2[block.Id] <- *block
	return nil
}

func (s *Server) PutPlainBlocks(bs *[]Block, _ *int) error {
	blocks := *bs
	round := blocks[0].Round % MaxRounds

	s.rounds[round].dblocksChan <- blocks

	return nil
}

func (s *Server) ShareServerBlocks(blocks *[]Block, _ *int) error {
	round := (*blocks)[0].Round % MaxRounds
	s.rounds[round].shuffleChan <- *blocks
	return nil
}

/////////////////////////////////
//Download
////////////////////////////////
func (s *Server) GetResponse(cmask ClientMask, response *[]byte) error {
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
				curBlock := <-s.rounds[round].xorsChan[i][cmask.Id]
				otherBlocks[i] = curBlock.Block
			}(i, cmask)
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
	*response = r
	return nil
}

func (s *Server) GetAllResponses(args *RequestArg, responses *[][]byte) error {
	round := args.Round % MaxRounds
	<-s.rounds[round].blocksRdy[args.Id]
	resps := make([][]byte, s.totalClients)
	for i := range s.rounds[round].allBlocks {
		resps[i] = s.rounds[round].allBlocks[i].Block
	}
	*responses = resps
	return nil
}

//used to push response for particular client
func (s *Server) PutClientBlock(cblock ClientBlock, _ *int) error {
	block := cblock.Block
	round := block.Round % MaxRounds
	s.rounds[round].xorsChan[cblock.SId][cblock.CId] <- block
	return nil
}

/////////////////////////////////
//Misc
////////////////////////////////
//used for the local test function to start the server
func (s *Server) MainLoop() error {
	rpcServer1 := rpc.NewServer()
	rpcServer2 := rpc.NewServer()
	rpcServer1.Register(s)
	rpcServer2.Register(s)
	l1, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port1))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", err)
	}
	l2, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port2))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", err)
	}
	go rpcServer1.Accept(l1)
	go rpcServer2.Accept(l2)
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
		Xs := make([]abstract.Point, len(Xss[i]))
		Ys := make([]abstract.Point, len(Yss[i]))
		Xbars := make([]abstract.Point, len(Xbarss[i]))
		Ybars := make([]abstract.Point, len(Ybarss[i]))
		for j := range Xss[i] {
			Xs[j] = UnmarshalPoint(s.suite, Xss[i][j])
			Ys[j] = UnmarshalPoint(s.suite, Yss[i][j])
			Xbars[j] = UnmarshalPoint(s.suite, Xbarss[i][j])
			Ybars[j] = UnmarshalPoint(s.suite, Ybarss[i][j])
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
		}(i)
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
		go func(r uint64) {
			for {
				f(r)
				r += rounds
			}
		}(r)
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

	rpcServer1 := rpc.NewServer()
	rpcServer2 := rpc.NewServer()
	rpcServer1.Register(s)
	rpcServer2.Register(s)
	l1, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port1))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", err)
	}
	l2, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port2))
	if err != nil {
		log.Fatal("Cannot starting listening to the port: ", err)
	}
	go rpcServer1.Accept(l1)
	go rpcServer2.Accept(l2)
	s.connectServers()
	fmt.Println("Starting server", *id)
	s.runHandlers()
	fmt.Println("Handler running", *id)

	Wait()
}
