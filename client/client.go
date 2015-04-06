package client
//package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"log"
	"sync"
	"time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var profile = false
var debug = false

//assumes RPC model of communication
type Client struct {
	id              uint64 //client id
	conns           []*grpc.ClientConn
	servers         []RiffleClient //all servers
	myServer        *UInt //server downloading from (using PIR)
	totalClients    uint64

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

	myServerIdx := &UInt{}
	conns := make([]*grpc.ClientConn, len(servers))
	rpcServers := make([]RiffleClient, len(servers))
	for i, server := range servers {
		if server == myServer {
			myServerIdx.Val = uint64(i)
		}
		conn, err := grpc.Dial(server)
		if err != nil {
			log.Fatal("Cannot establish connection:", err)
		}
		conns[i] = conn
		rpcServers[i] = NewRiffleClient(conn)
	}

	pks := make([]abstract.Point, len(servers))

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
		id:             0,
		servers:        rpcServers,
		myServer:       myServerIdx,
		totalClients:   0,

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
	reply, err := c.servers[idx].Register(context.TODO(), c.myServer)
	if err != nil {
		log.Fatal("Couldn't register: ", err)
	}
	c.id = reply.Id
	c.totalClients = reply.NumClients
	for i, pk := range reply.Pks {
		c.pks[i] = UnmarshalPoint(c.suite, pk)
	}
	size := (c.totalClients/SecretSize)*SecretSize + SecretSize
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
		C1S: make([]*Point, len(c1s)),
		C2S: make([]*Point, len(c1s)),
		Id: c.id,
	}

	for i := range c1s {
		upkey.C1S[i] = &Point{X: MarshalPoint(c1s[i])}
		upkey.C2S[i] = &Point{X: MarshalPoint(c2s[i])}
	}

	_, err := c.servers[idx].UploadKeys(context.TODO(), &upkey)
	if err != nil {
		log.Fatal("Couldn't upload a key: ", err)
	}
}

//share one time secret with the server
func (c *Client) ShareSecret() {
	gen := c.g.Point().Base()
	rand := c.suite.Cipher(abstract.RandomKey)
	secret := c.g.Secret().Pick(rand)
	public := c.g.Point().Mul(gen, secret)

	//generate share secrets via Diffie-Hellman w/ all servers
	//one used for masks, one used for one-time pad
	cs := ClientDH {
		Public: MarshalPoint(public),
		Id: c.id,
	}

	masks := make([][]byte, len(c.servers))
	secrets := make([][]byte, len(c.servers))

	var wg sync.WaitGroup
	for i := range c.servers {
		wg.Add(1)
		go func(i int, cs ClientDH) {
			defer wg.Done()
			pts, err := c.servers[i].ShareSecrets(context.TODO(), &cs)
			if err != nil {
				log.Fatal("Could not share secret: ", err)
			}
			serv0 := UnmarshalPoint(c.suite, pts.Xs[0])
			serv1 := UnmarshalPoint(c.suite, pts.Xs[1])
			masks[i] = MarshalPoint(c.g.Point().Mul(serv0, secret))
			// c.masks[i] = make([]byte, SecretSize)
			// c.masks[i][c.id] = 1
			secrets[i] = MarshalPoint(c.g.Point().Mul(serv1, secret))
			//secrets[i] = make([]byte, SecretSize)
		} (i, cs)
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
	hashes, err := c.servers[c.myServer.Val].RequestBlock(context.TODO(), &req)
	if err != nil {
		log.Fatal("Couldn't request a block: ", err)
	}
	if c.id == 0 && profile {
		fmt.Println(c.id, "req_network:", time.Since(t))
	}
	return hash, hashes.Hashes
}

/////////////////////////////////
//Upload
////////////////////////////////
func (c *Client) Upload(hashes [][]byte, rnd uint64) [][]byte {
	match := []byte{}
	var name string
	var offset int64 = -1

	t := time.Now()
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
	if c.id == 0 && profile {
		fmt.Println(c.id, "file_read:", time.Since(t))
	}
	return c.UploadBlock(Block{Block: match, Round: rnd, Id: c.id})
}

func (c *Client) UploadBlock(block Block) [][]byte {
	block.Block = c.seal(block.Block, block.Round)

	t := time.Now()
	hashes, err := c.servers[c.myServer.Val].UploadBlock(context.TODO(), &block)
	if err != nil {
		log.Fatal("Couldn't upload a block: ", err)
	}
	if c.id == 0 && profile {
		fmt.Println(c.id, "up_network:", time.Since(t))
	}
	return hashes.Hashes
}

func (c *Client) UploadSmall(block Block) {
	block.Block = c.seal(block.Block, block.Round)
	_, err := c.servers[c.myServer.Val].UploadSmall(context.TODO(), &block)
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
	data, err := c.servers[c.myServer.Val].GetAllResponses(context.TODO(), &args)
	if err != nil {
		log.Fatal("Couldn't download up hashes: ", err)
	}
	c.rounds[round].downLock.Unlock()
	return data.Data
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
	Xor(c.maskss[round][c.myServer.Val], mask)
	Xor(finalMask, mask)

	//one response includes all the secrets
	secretsXor := Xors(c.secretss[round])
	cMask := ClientMask {Mask: mask, Id: c.id, Round: rnd}

	t := time.Now()
	datum, err := c.servers[c.myServer.Val].GetResponse(context.TODO(), &cMask)
	if err != nil {
		log.Fatal("Could not get response: ", err)
	}
	response := datum.Datum

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
	if rnd == 0 && debug {
		fmt.Println(c.id, "uploading", match, h.Sum(nil))
	}

	//TODO: handle unfound hash..
	if match == nil {
		match = make([]byte, BlockSize)
		fmt.Println(c.id, "unfound", hashes)
	}

	c.UploadBlock(Block{Block: match, Round: rnd, Id: c.id})
	c.rounds[round].upLock.Unlock()
}

func (c *Client) Id() uint64 {
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

		var r uint64 = 0
		for ; r < MaxRounds; r++ {
			wg.Add(1)
			go func (r uint64) {
				defer wg.Done()
				for ; r < uint64(len(wantedArr)); {
					hash, hashes := c.RequestBlock(wantedArr[r], r)
					hashes = c.Upload(hashes, r)
					c.Download(hash, hashes, r)
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
