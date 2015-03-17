//package server
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"runtime"
	"sync"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/shuffle"
)

var TotalClients = 0

//any variable/func with 2: similar object as s-c but only s-s
type Server struct {
	addr            string //this server
	port            int
	id              int
	servers         []string //other servers
	rpcServers      []*rpc.Client
	regLock         []*sync.Mutex //registration mutex
	regChan         chan bool
	regDone         chan bool
	connectDone     chan bool
	running         chan bool
	secretLock      *sync.Mutex
	pkLock          *sync.Mutex //avoid data race in go

	//crypto
	suite           abstract.Suite
	g               abstract.Group
	sk              abstract.Secret //secret and public elgamal key
	pk              abstract.Point
	pks             []abstract.Point //all servers pks
	nextPks         []abstract.Point
	nextPksBin      [][]byte
	ephSecret       abstract.Secret

	//clients
	clientMap       map[int]int //maps clients to dedicated server
	numClients      int //#clients connect here
	totalClients    int //total number of clients (sum of all servers)
	masks           [][]byte //clients' masks for PIR
	secrets         [][]byte //shared secret used to xor

	//all rounds
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
	ublockChan2     chan UpBlock
	shuffleChan     chan InternalUpload //collect all uploads together
	auxProofChan    []chan AuxProof

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
	suite := edwards.NewAES128SHA256Ed25519(false)
	rand := suite.Cipher(abstract.RandomKey)
	sk := suite.Secret().Pick(rand)
	pk := suite.Point().Mul(nil, sk)
	ephSecret := suite.Secret().Pick(rand)

	rounds := make([]*Round, MaxRounds)

	for i := range rounds {
		r := Round{
			allBlocks:      nil,

			requestsChan:   nil,
			reqHashes:      nil,
			reqHashesRdy:   nil,

			ublockChan2:    nil,
			shuffleChan:    make(chan InternalUpload),
			auxProofChan:   make([]chan AuxProof, len(servers)),

			upHashes:       nil,
			dblocksChan:    make(chan []Block),
			blocksRdy:      nil,
			upHashesRdy:    nil,
			xorsChan:       make([]map[int](chan Block), len(servers)),
		}
		for i := range r.auxProofChan {
			r.auxProofChan[i] = make(chan AuxProof, len(servers))
		}
		rounds[i] = &r
	}

	s := Server{
		addr:           addr,
		port:           port,
		id:             id,
		servers:        servers,
		regLock:        []*sync.Mutex{new(sync.Mutex), new(sync.Mutex)},
		regChan:        make(chan bool, TotalClients),
		regDone:        make(chan bool),
		connectDone:    make(chan bool),
		running:        make(chan bool),
		secretLock:     new(sync.Mutex),
		pkLock:         new(sync.Mutex),

		suite:          suite,
		g:              suite,
		sk:             sk,
		pk:             pk,
		pks:            make([]abstract.Point, len(servers)),
		nextPks:        make([]abstract.Point, len(servers)),
		nextPksBin:     make([][]byte, len(servers)),
		ephSecret:      ephSecret,

		clientMap:      make(map[int]int),
		numClients:     0,
		totalClients:   0,
		masks:          nil,
		secrets:        nil,

		rounds:         rounds,
	}

	return &s
}


/////////////////////////////////
//Helpers
////////////////////////////////

func (s *Server) runHandlers() {
	//<-s.connectDone
	<-s.regDone
	runHandler(s.handleRequests)
	runHandler(s.gatherUploads)
	runHandler(s.shuffleUploads)
	runHandler(s.handleResponses)
	s.running <- true
}

func (s *Server) handleRequests(round int) {
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
}

func (s *Server) handleResponses(round int) {
	allBlocks := <-s.rounds[round].dblocksChan
	var wg sync.WaitGroup
	for i := 0; i < s.totalClients; i++ {
		if s.clientMap[i] == s.id {
			continue
		}
		//if it doesnt belong to me, xor things and send it over
		wg.Add(1)
		go func(i int, rpcServer *rpc.Client) {
			defer wg.Done()
			res := ComputeResponse(allBlocks, s.masks[i], s.secrets[i])
			rand := s.suite.Cipher(s.secrets[i])
			rand.Read(s.secrets[i])
			rand = s.suite.Cipher(s.masks[i])
			rand.Read(s.masks[i])
			//fmt.Println(s.id, round, "mask", i, s.masks[i])
			cb := ClientBlock {
				CId: i,
				SId: s.id,
				Block: Block {
					Block: res,
					Round: round,
				},
			}
			err := rpcServer.Call("Server.PutClientBlock", cb, nil)
			if err != nil {
				log.Fatal("Couldn't put block: ", err)
			}
		} (i, s.rpcServers[s.clientMap[i]])
	}
	wg.Wait()

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
}

func (s *Server) gatherUploads(round int) {
	allUploads := make([]UpBlock, s.totalClients)
	for i := 0; i < s.totalClients; i++ {
		allUploads[i] = <-s.rounds[round].ublockChan2
	}

	hashChunks := len(allUploads[0].HC1[0])
	serversLeft := len(s.servers)-s.id

	Xsss := make([][][][]byte, serversLeft)
	Ysss := make([][][][]byte, serversLeft)

	for i := range Xsss {
		Xsss[i] = make([][][]byte, hashChunks)
		Ysss[i] = make([][][]byte, hashChunks)
		for j := range Xsss[i] {
			Xsss[i][j] = make([][]byte, s.totalClients)
			Ysss[i][j] = make([][]byte, s.totalClients)
			for k := range Xsss[i][j] {
				Xsss[i][j][k] = allUploads[k].HC1[i][j]
				Ysss[i][j][k] = allUploads[k].HC2[i][j]
			}
		}
	}

	DXs := make([][]byte, s.totalClients)
	DYs := make([][]byte, s.totalClients)
	BCs := make([][]byte, s.totalClients)
	for i := range DXs {
		DXs[i] = allUploads[i].DH1
		DYs[i] = allUploads[i].DH2
		BCs[i] = allUploads[i].BC
	}

	iu := InternalUpload {
		Xsss: Xsss,
		Ysss: Ysss,
		DXs:  DXs,
		DYs:  DYs,
		BCs:  BCs,
		Round: allUploads[0].Round,
	}

	iu.Xsss = append([][][][]byte{nil}, iu.Xsss ...)
	iu.Ysss = append([][][][]byte{nil}, iu.Ysss ...)

	aux := AuxProof {
		OrigXsss: Xsss,
		OrigYsss: Ysss,
		OrigDXs:  DXs,
		OrigDYs:  DYs,
		SId:      s.id,
		Round:    allUploads[0].Round,
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
		} (rpcServer)
	}
	wg.Wait()

	//fmt.Println(s.id, "done gathering", round)
	s.rounds[round].shuffleChan <- iu
}

func (s *Server) shuffleUploads(round int) {
	uploads := <-s.rounds[round].shuffleChan

	//fmt.Println(s.id, "shuffle start: ", round)

	//shuffle and reblind

	hashChunks := len(uploads.Xsss[1])
	serversLeft := len(s.servers)-s.id
	// for _, upload := range allUploads {
	// 	if hashChunks != len(upload.HC1[0])  {
	// 		panic("Different chunk lengths")
	// 	}
	// }

	Xsss := make([][][]abstract.Point, serversLeft)
	Ysss := make([][][]abstract.Point, serversLeft)
	for i := range Xsss {
		Xsss[i] = make([][]abstract.Point, hashChunks)
		Ysss[i] = make([][]abstract.Point, hashChunks)
		for j := range Xsss[i] {
			Xsss[i][j] = make([]abstract.Point, s.totalClients)
			Ysss[i][j] = make([]abstract.Point, s.totalClients)
			for k := range Xsss[i][j] {
				Xsss[i][j][k] = UnmarshalPoint(s.suite, uploads.Xsss[i+1][j][k])
				Ysss[i][j][k] = UnmarshalPoint(s.suite, uploads.Ysss[i+1][j][k])
			}
		}
	}
	DXs := make([]abstract.Point, s.totalClients)
	DYs := make([]abstract.Point, s.totalClients)
	for i := range DXs {
		DXs[i] = UnmarshalPoint(s.suite, uploads.DXs[i])
		DYs[i] = UnmarshalPoint(s.suite, uploads.DYs[i])
	}

	//TODO: need to send ybar and proofs out out eventually
	rand := s.suite.Cipher(abstract.RandomKey)
	pi := GeneratePI(s.totalClients, rand)

	Xbarsss := make([][][]abstract.Point, serversLeft)
	Ybarsss := make([][][]abstract.Point, serversLeft)
	Hdecss := make([][][]abstract.Point, serversLeft)
	prfss := make([][][]byte, serversLeft)

	ephKeys := make([]abstract.Point, s.totalClients)
	decBlocks := make([][]byte, s.totalClients)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var shuffleWG sync.WaitGroup
		for i := 0; i < serversLeft; i++ {
			shuffleWG.Add(1)
			go func(i int, pk abstract.Point) {
				defer shuffleWG.Done()
				Xbarsss[i], Ybarsss[i], Hdecss[i], prfss[i] = s.shuffle(pi, Xsss[i], Ysss[i], hashChunks, pk)
			} (i, s.nextPks[i])
		}
		shuffleWG.Wait()
	} ()
	go func() {
		defer wg.Done()
		var aesWG sync.WaitGroup
		for j := 0; j < s.totalClients; j++ {
			aesWG.Add(1)
			go func(j int) {
				defer aesWG.Done()
				ephKey := Decrypt(s.g, DXs[pi[j]], DYs[pi[j]], s.sk)
				key := MarshalPoint(s.g.Point().Mul(ephKey, s.ephSecret))
				//shuffle using pi
				decBlocks[j] = CounterAES(key, uploads.BCs[pi[j]])
				//fmt.Println(s.id, round, "server key", key)
				//fmt.Println(s.id, round, "server bs", decBlocks[j])
				ephKeys[j] = ephKey
			} (j)
		}
		aesWG.Wait()
	} ()
	wg.Wait()

	hashes := make([][]byte, s.totalClients)

	for i := range hashes {
		hash := []byte{}
		for j := range Hdecss[0] {
			msg, err := Hdecss[0][j][i].Data()
			if err != nil {
				log.Fatal(s.id, " could not decrypt ", round, ": ", err)
			}
			hash = append(hash, msg...)
		}
		hashes[i] = hash
	}

	iu := InternalUpload {
		Xsss: make([][][][]byte, serversLeft),
		Ysss: make([][][][]byte, serversLeft),
		DXs:  nil,
		DYs:  nil,
		BCs:  decBlocks,
		Hs:   hashes,
		SId:  s.id,
		Round: round,

		Ybarsss:  make([][][][]byte, serversLeft),
		Proofss:  prfss,
		Keys:     make([][]byte, serversLeft),
	}

	for i := range iu.Xsss {
		iu.Xsss[i] = make([][][]byte, hashChunks)
		iu.Ysss[i] = make([][][]byte, hashChunks)
		iu.Ybarsss[i] = make([][][]byte, hashChunks)
		for j := range iu.Xsss[i] {
			iu.Xsss[i][j] = make([][]byte, s.totalClients)
			iu.Ysss[i][j] = make([][]byte, s.totalClients)
			iu.Ybarsss[i][j] = make([][]byte, s.totalClients)
			for k := range iu.Xsss[i][j] {
				iu.Xsss[i][j][k] = MarshalPoint(Xbarsss[i][j][k])
				iu.Ysss[i][j][k] = MarshalPoint(Hdecss[i][j][k])
				iu.Ybarsss[i][j][k] = MarshalPoint(Ybarsss[i][j][k])
			}
		}
		iu.Keys[i] = s.nextPksBin[i]
	}

	if s.id != len(s.servers) - 1 {
		iu.DXs = make([][]byte, s.totalClients)
		iu.DYs =  make([][]byte, s.totalClients)
		for i := range iu.DXs {
			dh1, dh2 := EncryptPoint(s.g, ephKeys[i], s.pks[s.id+1])
			iu.DXs[i] = MarshalPoint(dh1)
			iu.DYs[i] = MarshalPoint(dh2)
		}
	}

	for _, rpcServer := range s.rpcServers {
		wg.Add(1)
		go func(rpcServer *rpc.Client) {
			defer wg.Done()
			err := rpcServer.Call("Server.ShareServerBlocks", &iu, nil)
			if err != nil {
				log.Fatal("Failed uploading shuffled and decoded blocks: ", err)
			}
		} (rpcServer)
	}
	wg.Wait()

	//fmt.Println(s.id, "shuffle done: ", round)
}

func (s *Server) shuffle(pi []int, Xs [][]abstract.Point, Ys [][]abstract.Point, numChunks int, pk abstract.Point) ([][]abstract.Point,
	[][]abstract.Point, [][]abstract.Point, [][]byte) {
	Xbars := make([][]abstract.Point, numChunks)
	Ybars := make([][]abstract.Point, numChunks)
	decs := make([][]abstract.Point, numChunks)
	provers := make([] proof.Prover, numChunks)
	prfs := make([][]byte, numChunks)


	//do the shuffle, and blind using the next server's keys
	//everyone shares the same group
	var wg sync.WaitGroup
	for i := range decs {
		wg.Add(1)
		go func (i int, suite abstract.Suite, g abstract.Group, sk abstract.Secret) {
			defer wg.Done()
			rand := suite.Cipher(abstract.RandomKey)
			Xbars[i], Ybars[i], provers[i] = shuffle.Shuffle2(pi, g, nil, pk, Xs[i], Ys[i], rand)
			prf, err := proof.HashProve(suite, "PairShuffle", rand, provers[i])
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
					decs[i][j] = Decrypt(g, c1, c2, sk)
				} (i, j)
			}
			decWG.Wait()
		} (i, s.suite, s.g, s.sk)
	}
	wg.Wait()

	return Xbars, Ybars, decs, prfs
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
		Id: *clientId,
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

		s.rounds[r].ublockChan2 = make(chan UpBlock, numClients-1)
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
		for ; err != nil ; {
			if i == s.id { //make a local rpc
				addr := fmt.Sprintf("127.0.0.1:%d", s.port)
				rpcServer, err = rpc.Dial("tcp", addr)
			} else {
				rpcServer, err = rpc.Dial("tcp", s.servers[i])
			}
			rpcServers[i] = rpcServer
		}
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
			s.pks[i] = UnmarshalPoint(s.suite, pk)
		} (i, rpcServer)
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
	s.rpcServers = rpcServers
	//s.connectDone <- true
}

func (s *Server) GetNumClients(_ int, num *int) error {
	<-s.regChan
	*num = s.totalClients
	return nil
}

func (s *Server) GetPK(_ int, pk *[]byte) error {
	s.pkLock.Lock()
	//tmp := s.pk //avoid data race
	*pk = MarshalPoint(s.pk)
	s.pkLock.Unlock()
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
	s.masks[clientDH.Id] = MarshalPoint(shared)
	//fmt.Println(s.id, "mask", clientDH.Id, MarshalPoint(shared))
	// s.masks[clientDH.Id] = make([]byte, len(MarshalPoint(shared)))
	// s.masks[clientDH.Id][clientDH.Id] = 1
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) ShareSecret(clientDH *ClientDH, serverPub *[]byte) error {
	pub, shared := s.shareSecret(UnmarshalPoint(s.suite, clientDH.Public))
	//s.secrets[clientDH.Id] = MarshalPoint(shared)
	s.secrets[clientDH.Id] = make([]byte, len(MarshalPoint(shared)))
	*serverPub = MarshalPoint(pub)
	return nil
}

func (s *Server) GetEphKey(_ int, serverPub *[]byte) error {
	pub := s.g.Point().Mul(s.g.Point().Base(), s.ephSecret)
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
	err := s.rpcServers[0].Call("Server.UploadBlock2", block, nil)
	if err != nil {
		log.Fatal("Couldn't send block to first server: ", err)
	}
	return nil
}

func (s *Server) UploadBlock2(block *UpBlock, _*int) error {
	round := block.Round % MaxRounds
	s.rounds[round].ublockChan2 <- *block
	//fmt.Println("put ublockchan2", round)
	return nil
}

func (s *Server) PutAuxProof(aux *AuxProof, _ *int) error {
	round := aux.Round % MaxRounds
	s.rounds[round].auxProofChan[aux.SId] <- *aux
	return nil
}

func (s *Server) verifyShuffle(iu InternalUpload, aux AuxProof) bool {
	Xsss := aux.OrigXsss
	Ysss := aux.OrigYsss
	Xbarsss := iu.Xsss
	Ybarsss := iu.Ybarsss
	prfss := iu.Proofss

	for i := range Xsss {
		pk := UnmarshalPoint(s.suite, iu.Keys[i])
		for j := range Xsss[i] {
			Xs := make([]abstract.Point, len(Xsss[i][j]))
			Ys := make([]abstract.Point, len(Ysss[i][j]))
			Xbars := make([]abstract.Point, len(Xbarsss[i][j]))
			Ybars := make([]abstract.Point, len(Ybarsss[i][j]))
			for k := range Xsss[i][j] {
				Xs[k] = UnmarshalPoint(s.suite, Xsss[i][j][k])
				Ys[k] = UnmarshalPoint(s.suite, Ysss[i][j][k])
				Xbars[k] = UnmarshalPoint(s.suite, Xbarsss[i][j][k])
				Ybars[k] = UnmarshalPoint(s.suite, Ybarsss[i][j][k])
			}
			v := shuffle.Verifier(s.suite, nil, pk, Xs, Ys, Xbars, Ybars)
			err := proof.HashVerify(s.suite, "PairShuffle", v, prfss[i][j])
			if err != nil {
				log.Println("Shuffle verify failed: ", err)
				return false
			}
		}
	}
	return true
}

func (s *Server) ShareServerBlocks(iu *InternalUpload, correct *bool) error {
	round := iu.Round % MaxRounds
	blocks := make([]Block, s.totalClients)
	for i := range blocks {
		blocks[i] = Block {
			Hash:  iu.Hs[i],
			Block: iu.BCs[i],
			Round: round,
		}
	}

	aux := <-s.rounds[round].auxProofChan[iu.SId]
	//fmt.Println(s.id, round, "aux:", aux.OrigXsss[0][0][0])
	good := s.verifyShuffle(*iu, aux)
	for i := range blocks {
		h := s.suite.Hash()
		h.Write(blocks[i].Block)
		hash := h.Sum(nil)
		good = good && SliceEquals(hash, blocks[i].Hash)
	}
	if !good {
		log.Fatal(s.id, round, " Proving failed!")
	}
	if iu.SId != len(s.servers) - 1 {
		aux = AuxProof {
			OrigXsss: iu.Xsss[1:],
			OrigYsss: iu.Ysss[1:],
			OrigDXs:  iu.DXs,
			OrigDYs:  iu.DYs,
			SId:      iu.SId + 1,
			Round:    round,
		}
		s.rounds[round].auxProofChan[aux.SId] <- aux
	}

	if iu.SId == len(s.servers) - 1 {
		for i := range blocks {
			s.rounds[round].upHashes[i] = blocks[i].Hash
		}
		for i := range s.rounds[round].upHashesRdy {
			if s.clientMap[i] != s.id {
				continue
			}
			go func(i int, round int) {
				s.rounds[round].upHashesRdy[i] <- true
			} (i, round)
		}
		s.rounds[round].dblocksChan <- blocks
	} else if iu.SId == s.id - 1 {
		iu.Ybarsss = nil
		iu.Proofss = nil
		iu.Keys = nil
		s.rounds[round].shuffleChan <- *iu
	}
	*correct = good
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
				//fmt.Println(s.id, "mask for", cmask.Id, cmask.Mask)
				otherBlocks[i] = curBlock.Block
			} (i, cmask)
		}
	}
	wg.Wait()
	<-s.rounds[round].blocksRdy[cmask.Id]
	r := ComputeResponse(s.rounds[round].allBlocks, cmask.Mask, s.secrets[cmask.Id])
	rand := s.suite.Cipher(s.secrets[cmask.Id])
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

/////////////////////////////////
//Misc
////////////////////////////////
//used for the local test function to start the server
func (s *Server) MainLoop(_ int, _ *int) error {
	rpcServer := rpc.NewServer()
	rpcServer.Register(s)
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		panic("Cannot starting listening to the port")
	}
	go rpcServer.Accept(l)
	s.connectServers()
	go s.runHandlers()

	return nil
}

func (s *Server) Masks() [][]byte {
	return s.masks
}

func (s *Server) Secrets() [][]byte {
	return s.secrets
}

func runHandler(f func(int)) {
	for r := 0; r < MaxRounds; r++ {
		go func (r int) {
			for {
				f(r)
			}
		} (r)
	}
}

func SetTotalClients(n int) {
	TotalClients = n
}

// func invIndex() {
//		nextUploads := make([]UpBlock, s.totalClients)
// 		for i := range nextUploads {
// 			dh1, dh2 := EncryptPoint(s.g, ephKeys[i], s.pks[s.id+1])
// 			upblock := UpBlock {
// 				HC1: make([][][]byte, serversLeft-1),
// 				HC2: make([][][]byte, serversLeft-1),
// 				DH1: MarshalPoint(dh1),
// 				DH2: MarshalPoint(dh2),
// 				BC:  decBlocks[i],
// 				Round: allUploads[i].Round,
// 			}
// 			for j := 0; j < serversLeft-1; j++ {
// 				upblock.HC1[j] = make([][]byte, hashChunks)
// 				upblock.HC2[j] = make([][]byte, hashChunks)
// 				for k := 0; k < hashChunks; k++ {
// 					upblock.HC1[j][k] = MarshalPoint(HXbarss[j+1][k][i])
// 					upblock.HC2[j][k] = MarshalPoint(Hdecss[j+1][k][i])
// 				}
// 			}
// 			nextUploads[i] = upblock
// 		}
// }

/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var id *int = flag.Int("i", 0, "id [num]")
	var servers *string = flag.String("s", "", "servers [file]")
	var numClients *int = flag.Int("n", 0, "num clients [num]")
	flag.Parse()

	ss := ParseServerList(*servers)

	SetTotalClients(*numClients)

	s := NewServer(ss[*id], ServerPort + *id, *id, ss)

	rpcServer := rpc.NewServer()
	rpcServer.Register(s)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		panic("Cannot starting listening to the port")
	}

	go rpcServer.Accept(l)
	s.connectServers()
	fmt.Println("Starting server", *id)
	s.runHandlers()
	fmt.Println("Handler running", *id)

	Wait()
}

