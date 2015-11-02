//package client
package main

import (
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"sync"

	. "riffle/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

//assumes RPC model of communication

type Client struct {
	id           int      //client id
	servers      []string //all servers
	rpcServers   []*rpc.Client
	myServer     int //server downloading from (using PIR)
	totalClients int

	files   map[string]*File //files in hand; filename to hashes
	osFiles map[string]*os.File

	testPieces map[string][]byte //used only for testing

	//crypto
	g    abstract.Group
	rand cipher.Stream
	pks  []abstract.Point //server public keys

	reqRound     int
	reqHashRound int
	upRound      int
	downRound    int

	reqLock     *sync.Mutex
	reqHashLock *sync.Mutex
	upLock      *sync.Mutex
	downLock    *sync.Mutex

	ephKeys []abstract.Point

	//downloading
	dhashes chan []byte //hash to download (per round)
	masks   [][]byte    //masks used
	secrets [][]byte    //secret for data
}

func NewClient(servers []string, myServer string) *Client {
	myServerIdx := 0
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
			pks[i] = UnmarshalPoint(pk)
		}(i, rpcServer)
	}
	wg.Wait()

	masks := make([][]byte, len(servers))
	secrets := make([][]byte, len(servers))
	for i := 0; i < len(servers); i++ {
		masks[i] = make([]byte, SecretSize)
		secrets[i] = make([]byte, SecretSize)
	}

	//id comes from servers
	c := Client{
		id:           -1,
		servers:      servers,
		rpcServers:   rpcServers,
		myServer:     myServerIdx,
		totalClients: -1,

		files:   make(map[string]*File),
		osFiles: make(map[string]*os.File),

		testPieces: make(map[string][]byte),

		g:    Suite,
		rand: Suite.Cipher(abstract.RandomKey),
		pks:  pks,

		reqRound:     0,
		reqHashRound: 0,
		upRound:      0,
		downRound:    0,

		reqLock:     new(sync.Mutex),
		reqHashLock: new(sync.Mutex),
		upLock:      new(sync.Mutex),
		downLock:    new(sync.Mutex),

		ephKeys: make([]abstract.Point, len(servers)),

		dhashes: make(chan []byte, MaxRounds),
		masks:   masks,
		secrets: secrets,
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

func (c *Client) RegisterDone() {
	var totalClients int
	err := c.rpcServers[c.myServer].Call("Server.GetNumClients", 0, &totalClients)
	if err != nil {
		log.Fatal("Couldn't get number of clients")
	}
	c.totalClients = totalClients
}

//share one time secret with the server
func (c *Client) ShareSecret() {
	gen := c.g.Point().Base()
	secret1 := c.g.Secret().Pick(c.rand)
	secret2 := c.g.Secret().Pick(c.rand)
	public1 := c.g.Point().Mul(gen, secret1)
	public2 := c.g.Point().Mul(gen, secret2)

	//generate share secrets via Diffie-Hellman w/ all servers
	//one used for masks, one used for one-time pad
	var wg sync.WaitGroup
	for i, rpcServer := range c.rpcServers {
		wg.Add(1)
		go func(i int, rpcServer *rpc.Client) {
			defer wg.Done()

			cs1 := ClientDH{
				Public: MarshalPoint(public1),
				Id:     c.id,
			}
			cs2 := ClientDH{
				Public: MarshalPoint(public2),
				Id:     c.id,
			}

			servPub1 := make([]byte, SecretSize)
			servPub2 := make([]byte, SecretSize)
			servPub3 := make([]byte, SecretSize)
			call1 := rpcServer.Go("Server.ShareMask", &cs1, &servPub1, nil)
			call2 := rpcServer.Go("Server.ShareSecret", &cs2, &servPub2, nil)
			call3 := rpcServer.Go("Server.GetEphKey", 0, &servPub3, nil)
			_ = <-call1.Done
			_ = <-call2.Done
			_ = <-call3.Done
			c.masks[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(servPub1), secret1))
			c.secrets[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(servPub2), secret2))
			c.ephKeys[i] = UnmarshalPoint(servPub3)
		}(i, rpcServer)
	}
	wg.Wait()
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

	// if c.reqRound == 0 {
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
	var match []byte
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
	// h := Suite.Hash()
	// h.Write(match)
	// if c.upRound == 0 {
	// 	fmt.Println(c.id, "uploading", match, h.Sum(nil))
	// }

	c.UploadBlock(Block{Block: match, Round: c.upRound})
	c.upRound++
	c.upLock.Unlock()
}

func (c *Client) UploadBlock(block Block) {
	h := Suite.Hash()
	h.Write(block.Block)
	hash := h.Sum(nil)
	hc1s, hc2s := Encrypt(c.g, hash, c.pks)

	gen := c.g.Point().Base()
	secret := c.g.Secret().Pick(c.rand)
	public := c.g.Point().Mul(gen, secret)
	bs := block.Block
	for i := range c.servers {
		key := MarshalPoint(c.g.Point().Mul(c.ephKeys[i], secret))
		//fmt.Println(c.id, "client key", c.upRound, i, key)
		bs = CounterAES(key, bs)
	}

	dh1, dh2 := EncryptPoint(c.g, public, c.pks[0])
	//fmt.Println(c.id, "client pt", c.upRound, MarshalPoint(public))
	upblock := UpBlock{
		HC1:   make([][]byte, len(hc1s)),
		HC2:   make([][]byte, len(hc2s)),
		DH1:   MarshalPoint(dh1),
		DH2:   MarshalPoint(dh2),
		BC:    bs,
		Round: block.Round,
	}

	for i := range hc1s {
		upblock.HC1[i] = MarshalPoint(hc1s[i])
		upblock.HC2[i] = MarshalPoint(hc2s[i])
	}

	err := c.rpcServers[c.myServer].Call("Server.UploadBlock", &upblock, nil)
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

	//fmt.Println(c.id, c.downRound, "down hashes", hashes)

	idx := Membership(hash, hashes)

	if idx == -1 {
		//TODO: handle unfound hash..
		return make([]byte, 0)
	} else {
		return c.DownloadSlot(idx)
	}
}

func (c *Client) DownloadSlot(slot int) []byte {
	//all but one server uses the prng technique
	finalMask := make([]byte, SecretSize)
	SetBit(slot, true, finalMask)
	mask := Xors(c.masks)
	Xor(c.masks[c.myServer], mask)
	Xor(finalMask, mask)

	//one response includes all the secrets
	response := make([]byte, BlockSize)
	secretsXor := Xors(c.secrets)
	cMask := ClientMask{Mask: mask, Id: c.id, Round: c.downRound}
	err := c.rpcServers[c.myServer].Call("Server.GetResponse", cMask, &response)
	if err != nil {
		log.Fatal("Could not get response: ", err)
	}

	Xor(secretsXor, response)

	for i := range c.secrets {
		rand := Suite.Cipher(c.secrets[i])
		rand.Read(c.secrets[i])
	}

	for i := range c.masks {
		rand := Suite.Cipher(c.masks[i])
		rand.Read(c.masks[i])
	}

	return response
}

/////////////////////////////////
//Misc (mostly for testing)
////////////////////////////////
func (c *Client) RegisterBlock(block []byte) {
	h := Suite.Hash()
	h.Write(block)
	hash := h.Sum(nil)
	c.testPieces[string(hash)] = block
	//fmt.Println(c.id, "registering", hash)
}

func (c *Client) UploadPieces() {
	c.upLock.Lock()
	hashes := c.DownloadReqHash()
	var match []byte = nil
	for _, h := range hashes {
		if len(c.testPieces[string(h)]) == 0 {
			continue
		}
		match = c.testPieces[string(h)]
		break
	}

	// h := Suite.Hash()
	// h.Write(match)
	// if c.upRound == 0 {
	// 	fmt.Println(c.id, "uploading", match, h.Sum(nil))
	// }

	//TODO: handle unfound hash..
	if match == nil {
		match = make([]byte, BlockSize)
		fmt.Println(c.id, "unfound", hashes)
	}

	c.UploadBlock(Block{Block: match, Round: c.upRound})
	c.upRound++
	c.upLock.Unlock()
}

func (c *Client) Id() int {
	return c.id
}

func (c *Client) Masks() [][]byte {
	return c.masks
}

func (c *Client) Secrets() [][]byte {
	return c.secrets
}
func (c *Client) RpcServers() []*rpc.Client {
	return c.rpcServers
}

func (c *Client) ClearHashes() {
	c.rpcServers[c.myServer].Call("Server.GetUpHashes", c.id, nil)
}

/////////////////////////////////
//MAIN
/////////////////////////////////
func main() {
	var wf *string = flag.String("w", "", "wanted [file]") //torrent file
	var f *string = flag.String("f", "", "file [file]")    //file in possession
	var s *int = flag.Int("i", 0, "server [id]")           //my server id
	var servers *string = flag.String("s", "", "servers [file]")
	flag.Parse()

	ss := ParseServerList(*servers)

	c := NewClient(ss, ss[*s])
	c.Register(0)
	c.RegisterDone()
	c.ShareSecret()

	fmt.Println("Started client", c.id)

	file, err := NewFile(*f)
	if err != nil {
		log.Fatal("Failed reading the file in hand", err)
	}
	c.files[*f] = file
	c.osFiles[*f], _ = os.Open(*f)

	wanted, err := NewDesc(*wf)
	if err != nil {
		log.Fatal("Failed reading the torrent file", err)
	}

	newFile := fmt.Sprintf("%s.file", *wf)
	nf, err := os.Create(newFile)
	if err != nil {
		log.Fatal("Failed creating dest file", err)
	}

	var wg sync.WaitGroup
	//for {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for k, _ := range wanted {
			c.RequestBlock(c.id, []byte(k))
			fmt.Println(c.id, "Requested", c.reqRound)
		}
	}()

	//wg.Add(1)
	go func() {
		//defer wg.Done()
		for {
			c.Upload()
			fmt.Println(c.id, "Uploaded", c.upRound)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, _ = range wanted {
			res := c.Download()
			h := Suite.Hash()
			h.Write(res)
			hash := h.Sum(nil)
			offset := wanted[string(hash)]
			nf.WriteAt(res, offset)
			fmt.Println(c.id, "Downloaded", c.downRound)
		}
	}()

	wg.Wait()
	//}

}
