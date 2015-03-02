package client

import (
	//"flag"
	//"fmt"
	"log"
	//"net"
	"net/rpc"
	"sync"
	//"time"

	. "afs/lib" //types and utils

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
)

//assumes RPC model of communication

type Client struct {
	addr           string //client addr
	id             int //client id
	servers        []string //all servers
	rpcServers     []*rpc.Client
	myServer       int //server downloading from (using PIR)

	//crypto
	g              abstract.Group
	rand           cipher.Stream
	pks            []abstract.Point //server public keys

	//downloading
	masks          [][]byte //masks used
	secrets        [][]byte //secret for data
}

func NewClient(addr string, servers []string, myServer string) *Client {
	myServerIdx := 0
	rpcServers := make([]*rpc.Client, len(servers))
	for i := range rpcServers {
		if servers[i] == myServer {
			myServerIdx = i
		}
		rpcServer, err := rpc.Dial("tcp", servers[i])
		if err != nil {
			log.Fatal("Cannot establish connection")
		}
		rpcServers[i] = rpcServer
	}

	pks := make([]abstract.Point, len(servers))
	for i, rpcServer := range rpcServers {
		pk := make([]byte, SecretSize)
		err := rpcServer.Call("Server.GetPK", 0, &pk)
		if err != nil {
			log.Fatal("Couldn't get server's pk: ", err)
		}
		pks[i] = UnmarshalPoint(pk)
	}

	masks := make([][]byte, len(servers))
	secrets := make([][]byte, len(servers))
	for i := 0; i < len(servers); i++ {
		masks[i] = make([]byte, SecretSize)
		secrets[i] = make([]byte, SecretSize)
	}


	//id comes from servers
	c := Client {
		addr:           addr,
		servers:        servers,
		rpcServers:     rpcServers,
		myServer:       myServerIdx,

		g:              Suite,
		rand:           Suite.Cipher(abstract.RandomKey),
		pks:            pks,

		masks:          masks,
		secrets:        secrets,
	}

	return &c
}
/////////////////////////////////
//Registration and Setup
////////////////////////////////

func (c *Client) Register(server string) {
	cr := ClientRegistration {
		Addr: c.addr,
		ServerId: c.myServer,
		Id: c.id,
	}
	var id int
	s, err := rpc.Dial("tcp", server)
	if err != nil {
		log.Fatal("Couldn't connect to a server: ", err)
	}
	err = s.Call("Server.Register", cr, &id)
	if err != nil {
		log.Fatal("Couldn't register: ", err)
	}
	c.id = id
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

			cs1 := ClientDH {
				Public: MarshalPoint(public1),
				Id: c.id,
			}
			cs2 := ClientDH {
				Public: MarshalPoint(public2),
				Id: c.id,
			}

			servPub1 := make([]byte, SecretSize)
			servPub2 := make([]byte, SecretSize)
			call1 := rpcServer.Go("Server.ShareMask", &cs1, &servPub1, nil)
			call2 := rpcServer.Go("Server.ShareSecret", &cs2, &servPub2, nil)
			_ = <-call1.Done
			_ = <-call2.Done
			c.masks[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(servPub1), secret1))
			c.secrets[i] = MarshalPoint(c.g.Point().Mul(UnmarshalPoint(servPub2), secret2))
		} (i, rpcServer)
	}
	wg.Wait()
}

/////////////////////////////////
//Upload
////////////////////////////////
func (c *Client) UploadBlock(block Block) {
	c1s, c2s := Encrypt(c.g, block.Block, c.pks)
	upblock := UpBlock {
		C1: make([][]byte, len(c1s)),
		C2: make([][]byte, len(c2s)),
		Round: 0,
	}
	for i := range c1s {
		upblock.C1[i] = MarshalPoint(c1s[i])
		upblock.C2[i] = MarshalPoint(c2s[i])
	}

	err := c.rpcServers[c.myServer].Call("Server.UploadBlock", &upblock, nil)
	if err != nil {
		log.Fatal("Couldn't uploda a block: ", err)
	}
}


/////////////////////////////////
//Download
////////////////////////////////

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
	cMask := ClientMask {Mask: mask, Id: c.id}
	c.rpcServers[c.myServer].Call("Server.GetResponse", cMask, &response)
	Xor(secretsXor, response)

	//TODO: call PRNG to update all secrets

	return response
}

/////////////////////////////////
//Misc (mostly for testing)
////////////////////////////////

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
