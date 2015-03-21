package client
//package main

import (
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
)

//assumes RPC model of communication

type Client struct {
	id              int //client id
	servers         []string //all servers
	rpcServers      []*rpc.Client
	myServer        int //server downloading from (using PIR)
	totalClients    int

	files           map[string]*File //files in hand; filename to hashes
	osFiles         map[string]*os.File

	testPieces      map[string][]byte //used only for testing

	//crypto
	suite           abstract.Suite
	g               abstract.Group
	pks             []abstract.Point //server public keys

	reqRound        uint64
	reqHashRound    uint64
	upRound         uint64
	downRound       uint64

	reqLock         *sync.Mutex
	reqHashLock     *sync.Mutex
	upLock          *sync.Mutex
	downLock        *sync.Mutex

	keys            [][]byte
	ephKeys         []abstract.Point

	//downloading
	dhashes         chan []byte //hash to download (per round)
	maskss          [][][]byte //masks used
	secretss        [][][]byte //secret for data
}

func NewClient(servers []string, myServer string) *Client {
	suite := edwards.NewAES128SHA256Ed25519(false)

	myServerIdx := -1
	rpcServers := make([]*rpc.Client, len(servers))
	for i := range rpcServers {
		fmt.Println("client connecting to", servers[i])
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

	//id comes from servers
	c := Client {
		id:             -1,
		servers:        servers,
		rpcServers:     rpcServers,
		myServer:       myServerIdx,
		totalClients:   -1,

		files:          make(map[string]*File),
		osFiles:        make(map[string]*os.File),

		testPieces:     make(map[string][]byte),

		suite:          suite,
		g:              suite,
		pks:            pks,

		reqRound:       0,
		reqHashRound:   0,
		upRound:        0,
		downRound:      0,

		reqLock:        new(sync.Mutex),
		reqHashLock:    new(sync.Mutex),
		upLock:         new(sync.Mutex),
		downLock:       new(sync.Mutex),

		keys:           make([][]byte, len(servers)),
		ephKeys:        make([]abstract.Point, len(servers)),

		dhashes:        make(chan []byte, MaxRounds),
		maskss:         nil,
		secretss:       nil,
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

	//fmt.Println(c.id, "client pt", c.upRound, MarshalPoint(public))
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

	//fmt.Println(c.id, "masks", c.masks)
	for r := range c.secretss {
		for i := range c.secretss[r] {
			if r == 0 {
				rand = c.suite.Cipher(secrets[i])
			} else {
				rand = c.suite.Cipher(c.secretss[r-1][i])
			}
			rand.Read(c.secretss[r][i])
		}
	}

	for r := range c.maskss {
		for i := range c.maskss[r] {
			if r == 0 {
				rand = c.suite.Cipher(masks[i])
			} else {
				rand = c.suite.Cipher(c.maskss[r-1][i])
			}
			rand.Read(c.maskss[r][i])
		}
	}

}

/////////////////////////////////
//Request
////////////////////////////////
func (c *Client) RequestBlock(slot int, hash []byte) {
	c.reqLock.Lock()
	round := c.reqRound % MaxRounds
	reqs := make([][]byte, c.totalClients)
	for i := range reqs {
		if i == slot {
			reqs[i] = hash
		} else {
			reqs[i] = make([]byte, len(hash))
		}
	}
	req := Request{Hash: reqs, Round: round}
	cr := ClientRequest{Request: req, Id: c.id}
	c.dhashes <- hash

	// if c.id == 0 {
	// 	fmt.Println(c.id, c.reqRound, "requesting", hash)
	// }

	//TODO: xor in some secrets
	err := c.rpcServers[c.myServer].Call("Server.RequestBlock", &cr, nil)
	if err != nil {
		log.Fatal("Couldn't request a block: ", err)
	}
	c.reqRound++
	c.reqLock.Unlock()
}

/////////////////////////////////
//Upload
////////////////////////////////
func (c *Client) DownloadReqHash() [][]byte {
	c.reqHashLock.Lock()
	var hashes [][]byte
	args := RequestArg{Id: c.id, Round: c.reqHashRound}
	err := c.rpcServers[c.myServer].Call("Server.GetReqHashes", &args, &hashes)
	if err != nil {
		log.Fatal("Couldn't download req hashes: ", err)
	}

	// if c.id == 0 && c.reqRound == 0 {
	// 	fmt.Println(c.reqHashRound, "all reqs", hashes)
	// }

	c.reqHashRound++
	c.reqHashLock.Unlock()
	return hashes
}

func (c *Client) Upload() {
	//okay to lock; bandwidth is still near maximized
	c.upLock.Lock()
	hashes := c.DownloadReqHash()
	match := []byte{}
	var name string
	var offset int64 = -1

	//TODO: probably replace with hash map mapping hashes to file names
	for n, f := range c.files {
		fhashes := f.Hashes
		for _, h := range hashes {
			o, ok := fhashes[string(h)]
			if ok {
				offset = o
			}
		}
		//for now, just do the first one you find
		if offset != -1 {
			name = n
			break
		}
	}

	match = make([]byte, BlockSize)
	if offset != -1 {
		f := c.osFiles[name]
		_, err := f.ReadAt(match, offset)
		if err != nil {
			log.Fatal("Failed reading file", name, ":", err)
		}
	}

	c.UploadBlock(Block{Block: match, Round: c.upRound, Id: c.id})
	c.upRound++
	c.upLock.Unlock()
}

func (c *Client) UploadBlock(block Block) {
	msg := block.Block

	round := make([]byte, 24)
	binary.PutUvarint(round, c.upRound)
	nonce := [24]byte{}
	copy(nonce[:], round[:])
	for i := range c.servers {
		idx := len(c.servers) - i - 1
		key := [32]byte{}
		copy(key[:], c.keys[idx][:])
		msg = secretbox.Seal(nil, msg, &nonce, &key)
	}
	block.Block = msg

	err := c.rpcServers[c.myServer].Call("Server.UploadBlock", &block, nil)
	if err != nil {
		log.Fatal("Couldn't upload a block: ", err)
	}
}


/////////////////////////////////
//Download
////////////////////////////////
func (c *Client) Download() []byte {
	c.downLock.Lock()
	hash := <-c.dhashes
 	// if c.id == 0 {
	// 	fmt.Println(c.id, "hash", hash)
	// }
	block := c.DownloadBlock(hash)
	c.downRound++
	c.downLock.Unlock()
	return block
}

func (c *Client) DownloadBlock(hash []byte) []byte {
	var hashes [][]byte
	args := RequestArg{Id: c.id, Round: c.downRound}
	err := c.rpcServers[c.myServer].Call("Server.GetUpHashes", &args, &hashes)
	if err != nil {
		log.Fatal("Couldn't download up hashes: ", err)
	}

	// if c.id == 0 {
	// 	fmt.Println(c.id, c.downRound, "down hashes", hashes)
	// }

	idx := Membership(hash, hashes)

	if idx == -1 {
		return c.DownloadSlot(0)
	} else {
		return c.DownloadSlot(idx)
	}
}

func (c *Client) DownloadSlot(slot int) []byte {
	//all but one server uses the prng technique
	round := c.downRound % MaxRounds
	maskSize := len(c.maskss[round][0])
	finalMask := make([]byte, SecretSize)
	SetBit(slot, true, finalMask)
	mask := make([]byte, maskSize)
	Xors(mask, c.maskss[round])
	XorWords(mask, c.maskss[round][c.myServer], mask)
	XorWords(finalMask, finalMask, mask)

	//one response includes all the secrets
	response := make([]byte, BlockSize)
	secretsXor := make([]byte, BlockSize)
	Xors(secretsXor, c.secretss[round])
	cMask := ClientMask {Mask: mask, Id: c.id, Round: c.downRound}
	err := c.rpcServers[c.myServer].Call("Server.GetResponse", cMask, &response)
	if err != nil {
		log.Fatal("Could not get response: ", err)
	}

	XorWords(response, secretsXor, response)

	for i := range c.secretss[round] {
		rand := c.suite.Cipher(c.secretss[round][i])
		rand.Read(c.secretss[round][i])
	}

	for i := range c.maskss[round] {
		rand := c.suite.Cipher(c.maskss[round][i])
		rand.Read(c.maskss[round][i])
	}

	//fmt.Println(c.id, c.downRound, "update masks", c.masks)

	return response
}

/////////////////////////////////
//Misc (mostly for testing)
////////////////////////////////
func (c *Client) RegisterBlock(block []byte) {
	h := c.suite.Hash()
	h.Write(block)
	hash := h.Sum(nil)
	c.testPieces[string(hash)] = block
	//fmt.Println(c.id, "registering", hash)
}

func (c *Client) UploadPieces() {
	c.upLock.Lock()
	hashes := c.DownloadReqHash()
	match := []byte{}
	for _, h := range hashes {
		if len(c.testPieces[string(h)]) == 0 {
			continue
		}
		match = c.testPieces[string(h)]
		break
	}

	// h := c.suite.Hash()
	// h.Write(match)
	// if c.upRound == 0 {
	// 	fmt.Println(c.id, "uploading", match, h.Sum(nil))
	// }

	//TODO: handle unfound hash..
	if match == nil {
		match = make([]byte, BlockSize)
		fmt.Println(c.id, "unfound", hashes)
	}

	c.UploadBlock(Block{Block: match, Round: c.upRound, Id: c.id})
	c.upRound++
	c.upLock.Unlock()
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

func (c *Client) ClearHashes() {
	c.rpcServers[c.myServer].Call("Server.GetUpHashes", c.id, nil)
}


/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	var wf *string = flag.String("w", "", "wanted [file]") //torrent file
	var f *string = flag.String("f", "", "file [file]") //file in possession
	var s *int = flag.Int("i", 0, "server [id]") //my server id
	var servers *string = flag.String("s", "", "servers [file]")
	flag.Parse()

	ss := ParseServerList(*servers)

	c := NewClient(ss, ss[*s])
	c.Register(0)
	c.RegisterDone(0)
	fmt.Println(c.id, "Sharing secret...")
	c.ShareSecret()
	c.UploadKeys(0)

	fmt.Println("Started client", c.id)

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
	if c.id == 0 {
		defer TimeTrack(time.Now(), fmt.Sprintf("sharing %d chunks", len(wanted)))
	}

	var wg sync.WaitGroup
	//for {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k, _ := range wanted {
				c.RequestBlock(c.id, []byte(k))
				//fmt.Println(c.id, "Requested", c.reqRound)
			}
		} ()

		//wg.Add(1)
		go func() {
			//defer wg.Done()
			for {
				c.Upload()
				//fmt.Println(c.id, "Uploaded", c.upRound)
			}
		} ()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, _ = range wanted {
				res := c.Download()
				h := c.suite.Hash()
				h.Write(res)
				hash := h.Sum(nil)
				_ = wanted[string(hash)]
				//nf.WriteAt(res, offset)
				if c.id == 0 {
					fmt.Println(c.id, "Downloaded", c.downRound)
				}
			}
		}()

		wg.Wait()
	//}

}
