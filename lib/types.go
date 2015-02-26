package lib

//sizes in bytes
const HashSize = 160/8
const BlockSize = 1024*1024 //1MB
const SecretSize = 256

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
