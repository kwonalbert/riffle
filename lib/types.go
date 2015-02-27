package lib

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
)

const NumClients = 3
const NumServers = 2

//sizes in bytes
const HashSize = 160/8
const BlockSize = 1024 //1KB for testing;
//const BlockSize = 1024*1024 //1MB
const SecretSize = 256/8

var Suite abstract.Suite = edwards.NewAES128SHA256Ed25519(false)

type File struct {
	Name            string
}

type Block struct {
	Hash            []byte
	Block           []byte
	Round           int
}

type Request struct {
	Hash            []byte
	Round           int
}

/////////////////////////////////
//convenience types
////////////////////////////////

type ClientDH struct {
	Public          []byte
	Id              int
}

type ClientRegistration struct {
	Addr            string
	Server          string //server client is connected to
}
