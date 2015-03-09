package lib

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
	Round           int
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

type RequestArg struct {
	Id              int
	Round           int
}
