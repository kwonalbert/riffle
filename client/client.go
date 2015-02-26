package client

import (
	"bytes"
	// "flag"
	// "fmt"
	"log"
	//"net"
	"net/rpc"
	"sync"
	// "time"

	. "afs/lib" //types and utils

	//"github.com/dedis/crypto"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
	//"github.com/dedis/crypto/random"
)

//assumes RPC model of communication

type Client struct {
	addr           string //client addr
	id             int //client id
	servers        []*rpc.Client //all servers
	client         *rpc.Client

	//downloading
	myServerIdx    int //server downloading from (using PIR)
	masks          [][]byte //masks used
	secrets        [][]byte //secret for data
	msgChan        chan []byte //received messages
}

func NewClient(addr string, servers []*rpc.Client, client *rpc.Client) *Client {
	secrets := make([][]byte, len(servers))
	for i := range secrets {
		//TODO: should derive the length 256 the pt length..
		secrets[i] = make([]byte, 256)
	}

	c := Client {
		addr: addr,
		servers: servers,
		client: client,

		secrets: secrets,
		msgChan: make(chan []byte),
	}

	return &c
}

func (c *Client) shareSecret(g abstract.Group, rand cipher.Stream) {
	gen := g.Point().Base()
	secret1 := g.Point().Mul(gen, g.Secret().Pick(rand))
	secret2 := g.Point().Mul(gen, g.Secret().Pick(rand))

	//generate share secrets via Diffie-Hellman w/ all servers
	//one used for masks, one used for one-time pad
	var wg sync.WaitGroup
	for i, server := range c.servers {
		wg.Add(1)
		go func(i int, server *rpc.Client) {
			var serverSecret1 abstract.Secret
			var serverSecret2 abstract.Secret
			defer wg.Done()
			err1 := server.Call("Server.ShareSecret", secret1, &serverSecret1)
			err2 := server.Call("Server.ShareSecret", secret2, &serverSecret2)
			if err1 != nil {
				log.Fatal("Failed getting secret: ", err1)
			} else if err2 != nil  {
				log.Fatal("Failed getting secret: ", err2)
			}
			sharedSecret1 := g.Point().Mul(secret1, serverSecret1)
			sharedSecret2 := g.Point().Mul(secret2, serverSecret2)
			var buf bytes.Buffer
			sharedSecret1.MarshalTo(&buf)
			buf.Read(c.masks[i])
			sharedSecret2.MarshalTo(&buf)
			buf.Read(c.secrets[i])
		} (i, server)
	}
	wg.Wait()
}

func (c *Client) getResponse(slot int) []byte {
	//all but one server uses the prng technique
	mask := make([]byte, SecretSize)
	SetBit(slot, true, mask)
	mask = Xors(c.masks)
	Xor(c.masks[c.myServerIdx], mask)


	//one response includes all the secrets
	response := make([]byte, BlockSize)
	responseXor := Xors(c.secrets)
	c.servers[c.myServerIdx].Call("Server.GetResponse", mask, &response)
	Xor(responseXor, response)

	//TODO: call PRNG to update all secrets

	return response
}
