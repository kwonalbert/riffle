package lib

const HashSize = 160/8
const BlockSize = 1048576

type Block struct {
	Hash  []byte
	Block []byte
	Round int
}

type Request struct {
	Hash  []byte
	Round int
}
