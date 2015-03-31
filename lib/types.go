package lib

type File struct {
	Name            string
	Hashes          map[string]int64 //maps hash to offset
}

//NOTE: could be encrypted version of the block
type Block struct {
	Block           []byte
	Round           uint64

	Id              int //id is only attached in the first submit
}

type Request struct {
	Hash            []byte
	Round           uint64

	Id              int
}

type UpKey struct {
	C1s             [][]byte
	C2s             [][]byte
	Id              int
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
	Round           uint64
}

type ClientRegistration struct {
	ServerId        int //the dedicated server
	Id              int
}

type ClientBlock struct {
	CId             int //client id for the block
	SId             int //sending server's id
	Block           Block
}

type RequestArg struct {
	Id              int
	Round           uint64
}

type InternalKey struct {
	Xss             [][][]byte
	Yss             [][][]byte
	SId             int

	Ybarss          [][][]byte
	Proofs          [][]byte
	Keys            [][]byte
}

type AuxKeyProof struct {
	OrigXss         [][][]byte
	OrigYss         [][][]byte
	SId             int
}

type InternalUpload struct {
	Blocks          []Block
	SId             int
}
