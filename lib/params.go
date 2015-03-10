package lib

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
)

var Suite abstract.Suite = edwards.NewAES128SHA256Ed25519(false)
const NumClients = 10
const NumServers = 3

const MaxRounds = 3

//sizes in bytes
const HashSize = 32
const BlockSize = 22 //1KB for testing;
//const BlockSize = 1024*1024 //1MB
const SecretSize = 256/8


var ServerAddrs []string = []string{"localhost:8000", "localhost:8001"}
const ServerPort = 8000

const ClientPort = 9000
