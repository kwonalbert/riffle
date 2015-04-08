//package client
package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"log"
	"net/rpc"
	"sync"
	"time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

var profile = false
var debug = false

//assumes RPC model of communication
type Client struct {
	id              int //client id
	servers         []string //all servers
	rpcServers      []*rpc.Client
	myServer        int //server downloading from (using PIR)
	totalClients    int

	FSMode          bool //true for microblogging, false for file sharing

	files           map[string]*File //files in hand; filename to hashes
	osFiles         map[string]*os.File

	testPieces      map[string][]byte //used only for testing

	//crypto
	suite           abstract.Suite
	g               abstract.Group
	pks             []abstract.Point //server public keys

	keys            [][]byte
	ephKeys         []abstract.Point

	//downloading
	dhashes         chan []byte //hash to download (per round)
	maskss          [][][]byte //masks used
	secretss        [][][]byte //secret for data

	rounds          []*Round
}

type Round struct {
	reqLock         *sync.Mutex
	upLock          *sync.Mutex
	downLock        *sync.Mutex

	reqHashesChan   chan [][]byte
	dhashChan       chan []byte
	upHashesChan    chan [][]byte
}

func NewClient(servers []string, myServer string, FSMode bool) *Client {
	suite := edwards.NewAES128SHA256Ed25519(false)

	myServerIdx := -1
	rpcServers := make([]*rpc.Client, len(servers))
	for i := range rpcServers {
		if servers[i] == myServer {
			myServerIdx = i
		}
		rpcServer, err := rpc.Dial("tcp", servers[i])
		if err != nil {
			log.Fatal("Cannot establish connection:", err)
		}
		rpcServers[i] = rpcServer
	}

	pks := make([]abstract.Point, len(servers))
	var wg sync.WaitGroup
	for i, rpcServer := range rpcServers {
		wg.Add(1)
		go func(i int, rpcServer *rpc.Client) {
			defer wg.Done()
			pk := make([]byte, SecretSize)
			err := rpcServer.Call("Server.GetPK", 0, &pk)
			if err != nil {
				log.Fatal("Couldn't get server's pk:", err)
			}
			pks[i] = UnmarshalPoint(suite, pk)
		} (i, rpcServer)
	}
	wg.Wait()

	rounds := make([]*Round, MaxRounds)

	for i := range rounds {
		r := Round{
			reqLock:        new(sync.Mutex),
			upLock:         new(sync.Mutex),
			downLock:       new(sync.Mutex),

			reqHashesChan:  make(chan [][]byte),
			dhashChan:      make(chan []byte),
			upHashesChan:   make(chan [][]byte),
		}
		rounds[i] = &r
	}

	//id comes from servers
	c := Client {
		id:             -1,
		servers:        servers,
		rpcServers:     rpcServers,
		myServer:       myServerIdx,
		totalClients:   -1,

		FSMode:         FSMode,

		files:          make(map[string]*File),
		osFiles:        make(map[string]*os.File),

		testPieces:     make(map[string][]byte),

		suite:          suite,
		g:              suite,
		pks:            pks,

		keys:           make([][]byte, len(servers)),
		ephKeys:        make([]abstract.Point, len(servers)),

		dhashes:        make(chan []byte, MaxRounds),
		maskss:         nil,
		secretss:       nil,

		rounds:         rounds,
	}

	return &c
}

/////////////////////////////////
//Registration and Setup
////////////////////////////////
func (c *Client) Register(idx int) {
	var id int
	err := c.rpcServers[idx].Call("Server.Register", c.myServer, &id)
	if err != nil {
		log.Fatal("Couldn't register: ", err)
	}
	c.id = id
}

func (c *Client) RegisterDone(idx int) {
	var totalClients int
	err := c.rpcServers[idx].Call("Server.GetNumClients", 0, &totalClients)
	if err != nil {
		log.Fatal("Couldn't get number of clients")
	}
	c.totalClients = totalClients

	size := (totalClients/SecretSize)*SecretSize + SecretSize
	c.maskss = make([][][]byte, MaxRounds)
	c.secretss = make([][][]byte, MaxRounds)
	for r := range c.maskss {
		c.maskss[r] = make([][]byte, len(c.servers))
		c.secretss[r] = make([][]byte, len(c.servers))
		for i := range c.maskss[r] {
			c.maskss[r][i] = make([]byte, size)
			c.secretss[r][i] = make([]byte, BlockSize)
		}
	}
}

func (c *Client) UploadKeys(idx int) {
	if c.id == 0 {
		defer TimeTrack(time.Now(), "sharing keys")
	}
	c1s := make([]abstract.Point, len(c.servers))
	c2s := make([]abstract.Point, len(c.servers))

	gen := c.g.Point().Base()
	rand := c.suite.Cipher(abstract.RandomKey)
	keyPts := make([]abstract.Point, len(c.servers))
	for i := range keyPts {
		secret := c.g.Secret().Pick(rand)
		public := c.g.Point().Mul(gen, secret)
		keyPts[i] = public
		c.keys[i] = MarshalPoint(public)
	}

	for i := range c.servers {
		c1s[i], c2s[i] = EncryptKey(c.g, keyPts[i], c.pks[:i+1])
	}

	upkey := UpKey {
		C1s: make([][]byte, len(c1s)),
		C2s: make([][]byte, len(c1s)),
		Id: c.id,
	}

	for i := range c1s {
		upkey.C1s[i] = MarshalPoint(c1s[i])
		upkey.C2s[i] = MarshalPoint(c2s[i])
	}

	err := c.rpcServers[idx].Call("Server.UploadKeys", &upkey, nil)
	if err != nil {
		log.Fatal("Couldn't upload a key: ", err)
	}

	err = c.rpcServers[idx].Call("Server.KeyReady", c.id, nil)
	if err != nil {
		log.Fatal("Couldn't determine key ready", err)
	}
}

//share one time secret with the server
func (c *Client) ShareSecret() {
	gen := c.g.Point().Base()
	rand := c.suite.Cipher(abstract.RandomKey)
	secret1 := c.g.Secret().Pick(rand)
	secret2 := c.g.Secret().Pick(rand)
	public1 := c.g.Point().Mul(gen, secret1)
	public2 := c.g.Point().Mul(gen, secret2)

	//generate share secrets via Diffie-Hellman w/ all servers
	//one used for masks, one used for one-time pad
	cs1 := ClientDH {
		Public: MarshalPoint(public1),
		Id: c.id,
	}
	cs2 := ClientDH {
		Public: MarshalPoint(public2),
		Id: c.id,
	}

	masks := make([][]byte, len(c.servers))
	secrets := make([][]byte, len(c.servers))

	var wg sync.WaitGroup
	for i, rpcServer := range c.rpcServers {
		wg.Add(1)
		go func(i int, rpcServer *rpc.Client, cs1 ClientDH, cs2 ClientDH) {
			defer wg.Done()
			servPub1 := make([]byte, SecretSize)
			servPub2 := make([]byte, SecretSize)
			servPub3 := make([]byte, SecretSize)
			call1 := rpcServer.Go("Server.ShareMask", &cs1, &servPub1, nil)
			call2 := rpcServer.Go("Server.ShareSecret", &cs2, &servPub2, nil)
			call3 := rpcServer.Go("Server.GetEphKey", 0, &servPub3, nil)
			<-call1.Done
			<-call2.Done
			<-call3.Done
			masks[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(c.suite, servPub1), secret1))
			// c.masks[i] = make([]byte, SecretSize)
			// c.masks[i][c.id] = 1
			secrets[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(c.suite, servPub2), secret2))
			//secrets[i] = make([]byte, SecretSize)
			c.ephKeys[i] = UnmarshalPoint(c.suite, servPub3)
		} (i, rpcServer, cs1, cs2)
	}
	wg.Wait()

	for r := range c.secretss {
		for i := range c.secretss[r] {
			if r == 0 {
				sha3.ShakeSum256(c.secretss[r][i], secrets[i])
			} else {
				sha3.ShakeSum256(c.secretss[r][i], c.secretss[r-1][i])
			}
		}
	}

	for r := range c.maskss {
		for i := range c.maskss[r] {
			if r == 0 {
				sha3.ShakeSum256(c.maskss[r][i], masks[i])
			} else {
				sha3.ShakeSum256(c.maskss[r][i], c.maskss[r-1][i])
			}
		}
	}

}

/////////////////////////////////
//Request
////////////////////////////////
func (c *Client) RequestBlock(hash []byte, rnd uint64) ([]byte, [][]byte) {
	t := time.Now()

	req := Request{Hash: c.seal(hash, rnd), Round: rnd, Id: c.id}

	if rnd == 0 && debug {
		fmt.Println(c.id, rnd, "requesting", req.Hash)
	}

	t = time.Now()
	var hashes [][]byte
	err := c.rpcServers[c.myServer].Call("Server.RequestBlock", &req, &hashes)
	if err != nil {
		log.Fatal("Couldn't request a block: ", err)
	}
	if c.id == 0 && profile {
		fmt.Println(c.id, "req_network:", time.Since(t))
	}
	return hash, hashes
}

/////////////////////////////////
//Upload
////////////////////////////////
func (c *Client) Upload(hashes [][]byte, rnd uint64) [][]byte {
	var name string
	var offset int64 = -1
	var hash []byte

	t := time.Now()
	//TODO: probably replace with hash map mapping hashes to file names
	for n, f := range c.files {
		fhashes := f.Hashes
		for _, h := range hashes {
			o, ok := fhashes[string(h)]
			if ok {
				offset = o
				hash = h
			}
		}
		//for now, just do the first one you find
		if offset != -1 {
			name = n
			break
		}
	}

	match := make([]byte, BlockSize)
	if offset != -1 {
		f := c.osFiles[name]
		_, err := f.ReadAt(match, offset)
		if err != nil {
			log.Fatal("Failed reading file", name, ":", err)
		}
	}
	if c.id == 0 && profile {
		fmt.Println(c.id, "file_read:", time.Since(t))
	}
	return c.UploadBlock(Block{Block: append(match, hash...), Round: rnd, Id: c.id})
}

func (c *Client) UploadBlock(block Block) [][]byte {
	block.Block = c.seal(block.Block, block.Round)

	var hashes [][]byte
	t := time.Now()
	err := c.rpcServers[c.myServer].Call("Server.UploadBlock", &block, &hashes)
	if err != nil {
		log.Fatal("Couldn't upload a block: ", err)
	}
	if c.id == 0 && profile {
		fmt.Println(c.id, "up_network:", time.Since(t))
	}
	return hashes
}

func (c *Client) UploadSmall(block Block) {
	block.Block = c.seal(block.Block, block.Round)
	err := c.rpcServers[c.myServer].Call("Server.UploadSmall", &block, nil)
	if err != nil {
		log.Fatal("Couldn't upload a block: ", err)
	}
}


/////////////////////////////////
//Download
////////////////////////////////
func (c *Client) Download(hash []byte, hashes [][]byte, rnd uint64) []byte {
	round := rnd % MaxRounds
	c.rounds[round].downLock.Lock()
	block := c.DownloadBlock(hash, hashes, rnd)
	c.rounds[round].downLock.Unlock()
	return block
}

func (c *Client) DownloadAll(rnd uint64) [][]byte {
	round := rnd % MaxRounds
	c.rounds[round].downLock.Lock()
	args := RequestArg{Id: c.id, Round: rnd}
	resps := make([][]byte, c.totalClients)
	err := c.rpcServers[c.myServer].Call("Server.GetAllResponses", &args, &resps)
	if err != nil {
		log.Fatal("Couldn't download up hashes: ", err)
	}
	c.rounds[round].downLock.Unlock()
	return resps
}

func (c *Client) DownloadBlock(hash []byte, hashes [][]byte, rnd uint64) []byte {
	idx := Membership(hash, hashes)

	if idx == -1 {
		return c.DownloadSlot(0, rnd)
	} else {
		return c.DownloadSlot(idx, rnd)
	}
}

func (c *Client) DownloadSlot(slot int, rnd uint64) []byte {
	//all but one server uses the prng technique
	round := rnd % MaxRounds
	maskSize := len(c.maskss[round][0])
	finalMask := make([]byte, maskSize)
	SetBit(slot, true, finalMask)
	mask := Xors(c.maskss[round])
	Xor(c.maskss[round][c.myServer], mask)
	Xor(finalMask, mask)

	//one response includes all the secrets
	response := make([]byte, BlockSize)
	secretsXor := Xors(c.secretss[round])
	cMask := ClientMask {Mask: mask, Id: c.id, Round: rnd}

	t := time.Now()
	err := c.rpcServers[c.myServer].Call("Server.GetResponse", cMask, &response)
	if err != nil {
		log.Fatal("Could not get response: ", err)
	}

	if c.id == 0 && profile {
		fmt.Println(c.id, "down_network_total:", time.Since(t))
	}


	Xor(secretsXor, response)

	for i := range c.secretss[round] {
		sha3.ShakeSum256(c.secretss[round][i], c.secretss[round][i])
	}

	for i := range c.maskss[round] {
		sha3.ShakeSum256(c.maskss[round][i], c.maskss[round][i])
	}

	return response
}

/////////////////////////////////
//Misc (mostly for testing)
////////////////////////////////
func (c *Client) seal(input []byte, round uint64) []byte {
	msg := input
	rnd := make([]byte, 24)
	binary.PutUvarint(rnd, round)
	nonce := [24]byte{}
	copy(nonce[:], rnd[:])
	for i := range c.servers {
		idx := len(c.servers) - i - 1
		key := [32]byte{}
		copy(key[:], c.keys[idx][:])
		msg = secretbox.Seal(nil, msg, &nonce, &key)
	}
	return msg
}

func (c *Client) RegisterBlock(block []byte) {
	h := c.suite.Hash()
	h.Write(block)
	hash := h.Sum(nil)
	c.testPieces[string(hash)] = block
}

func (c *Client) UploadPieces(hashes [][]byte, rnd uint64) {
	round := rnd % MaxRounds
	c.rounds[round].upLock.Lock()
	match := []byte{}
	for _, h := range hashes {
		if len(c.testPieces[string(h)]) == 0 {
			continue
		}
		match = c.testPieces[string(h)]
		break
	}

	h := c.suite.Hash()
	h.Write(match)
	match = h.Sum(match)
	if rnd == 0 && debug {
		fmt.Println(c.id, "uploading", match)
	}

	//TODO: handle unfound hash..
	if match == nil {
		match = make([]byte, BlockSize)
		fmt.Println(c.id, "unfound", hashes)
	}

	c.UploadBlock(Block{Block: match, Round: rnd, Id: c.id})
	c.rounds[round].upLock.Unlock()
}

func (c *Client) Id() int {
	return c.id
}

func (c *Client) Masks() [][][]byte {
	return c.maskss
}

func (c *Client) Secrets() [][][]byte {
	return c.secretss
}

func (c *Client) Keys() [][]byte {
	return c.keys
}

/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	var wf *string = flag.String("w", "", "wanted [file]") //torrent file
	var f *string = flag.String("f", "", "file [file]") //file in possession
	var s *int = flag.Int("i", 0, "server [id]") //my server id
	var servers *string = flag.String("s", "", "servers [file]")
	var mode *string = flag.String("m", "", "mode [m for microblogging|f for file sharing]")
	flag.Parse()

	ss := ParseServerList(*servers)

	c := NewClient(ss, ss[*s], *mode == "f")
	c.Register(0)
	c.RegisterDone(0)
	c.ShareSecret()
	//c.UploadKeys(0)

	fmt.Println("Started client", c.id)

	if c.id == 0 {
		defer TimeTrack(time.Now(), "total time:")
	}

	var wg sync.WaitGroup
	if c.FSMode {
		file, err := NewFile(c.suite, *f)
		if err != nil {
			log.Fatal("Failed reading the file in hand", err)
		}
		c.files[*f] = file
		c.osFiles[*f], _ = os.Open(*f)

		wanted, err := NewDesc(*wf)
		if err != nil {
			log.Fatal("Failed reading the torrent file", err)
		}

		// newFile := fmt.Sprintf("%s.file", *wf)
		// nf, err := os.Create(newFile)
		// if err != nil {
		// 	log.Fatal("Failed creating dest file", err)
		// }

		wantedArr := make([][]byte, len(wanted) + (len(wanted) % MaxRounds))
		i := 0
		for k, _ := range wanted {
			wantedArr[i] = []byte(k)
			i++
		}

		// block := make([]byte, BlockSize)
		// rand.Read(block)
		// h := c.suite.Hash()
		// h.Write(block)
		// block = h.Sum(block)
		// fmt.Println(block[BlockSize:])

		var r uint64 = 0
		for ; r < MaxRounds; r++ {
			wg.Add(1)
			go func (r uint64) {
				defer wg.Done()
				for ; r < uint64(len(wantedArr)); {
					hash, hashes := c.RequestBlock(wantedArr[r], r)
					hashes = c.Upload(hashes, r)
					c.Download(hash, hashes, r)
					t := time.Now()
					//hashes := c.UploadBlock(Block{Block: block, Round: r, Id: c.id})
					if c.id == 0 {
						fmt.Printf("Round %d: %s\n", r, time.Since(t))
					}
					r += MaxRounds
				}
			} (r)
		}
		wg.Wait()
	} else {
		var r uint64 = 0
		for ; r < MaxRounds; r++ {
			wg.Add(1)
			go func (r uint64) {
				defer wg.Done()
				for ; r < MaxRounds*3; {
					block := make([]byte, BlockSize)
					rand.Read(block)
					c.UploadSmall(Block{Block: block, Round: r, Id: c.id})
					c.DownloadAll(r)
					r += MaxRounds
				}
			} (r)
		}
		wg.Wait()
	}
}
