package lib

type File struct {
	Name            string
	Hashes          map[string]int64 //maps hash to offset
}

type Block struct {
	Hash            []byte
	Block           []byte
	Round           int
}

// type UpBlock struct {
// 	HC1             [][]byte //hashes
// 	HC2             [][]byte
// 	BC1             [][]byte //aes encrypted block
// 	BC2             [][]byte
// 	Round           int
// }

//encrypted version of the block
type UpBlock struct {
	HC1             [][]byte //hashes
	HC2             [][]byte
	DH1             []byte //diffie-hellman ephemeral
	DH2             []byte
	BC              []byte //aes encrypted block
	Round           int
}

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
	Round           int
}

type ClientRegistration struct {
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

type RequestArg struct {
	Id              int
	Round           int
}
