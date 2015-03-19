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

//encrypted version of the block
type UpBlock struct {
	HC1             [][][]byte //hashes
	HC2             [][][]byte
	DH1             []byte //diffie-hellman ephemeral
	DH2             []byte
	BC              []byte //aes encrypted block
	Round           int
}

type UpKey struct {
	C1s             [][]byte
	C2s             [][]byte
	Id              int
}

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
	Xsss            [][][][]byte
	Ysss            [][][][]byte
	DXs             [][]byte
	DYs             [][]byte
	BCs             [][]byte
	Hs              [][]byte
	SId             int
	Round           int

	Ybarsss         [][][][]byte
	Proofss         [][][]byte
	Keys            [][]byte
}

type AuxProof struct {
	OrigXsss        [][][][]byte
	OrigYsss        [][][][]byte
	OrigDXs         [][]byte
	OrigDYs         [][]byte
	SId             int
	Round           int
}
