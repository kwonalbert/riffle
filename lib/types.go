package lib

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
)

const NumClients = 10
const NumServers = 2

var Suite abstract.Suite = edwards.NewAES128SHA256Ed25519(false)

//sizes in bytes
const HashSize = 32
const BlockSize = 32 //1KB for testing;
//const BlockSize = 1024*1024 //1MB
const SecretSize = 256/8

type File struct {
	Name            string
	Hashes          [][]byte
	Blocks          [][]byte
}

type Block struct {
	Block           []byte
	Round           int
}

//encrypted version of the block
//first version elgamals everything
type UpBlock struct {
	BC1             [][]byte
	BC2             [][]byte
	HC1             [][]byte
	HC2             [][]byte
	Round           int
}

// //second version elgamals only hashs
// type UpBlock struct {
// 	Hash            []ElGamal
// 	Block           [][]byte //broken into AES sized chunks
// 	Round           int
// }

// type Request struct {
// 	Hash            []byte
// 	Round           int
// }

//Dissent model request
type Request struct {
	Hash            [][]byte
	Round           int
}

/////////////////////////////////
//convenience types
////////////////////////////////

type ClientDH struct {
	Public          []byte
	Id              int
}

type ClientMask struct {
	Mask            []byte
	Id              int
}

type ClientRegistration struct {
	Addr            string
	ServerId        int //the dedicated server
	Id              int
}

type ClientRequest struct {
	Request        Request
	Id             int
}

type ClientBlock struct {
	CId             int //client id for the block
	SId             int //sending server's id
	Block           Block
}
