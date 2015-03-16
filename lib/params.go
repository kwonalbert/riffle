package lib

import (
	"github.com/dedis/crypto/abstract"
	//"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/edwards"
)

var Suite abstract.Suite = edwards.NewAES128SHA256Ed25519(false)
//var Suite abstract.Suite = openssl.NewAES128SHA256P256()

//sizes in bytes
const HashSize = 28
const BlockSize = 1024 //1KB for testing; 1MB for production
const SecretSize = 256/8

const MaxRounds = 5

const ServerPort = 8000
