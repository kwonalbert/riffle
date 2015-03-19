package lib

import (
	"bufio"
	"bytes"
	"errors"
	//"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"
	"os"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/cipher"
	"github.com/dedis/crypto/random"
)

func SetBit(n_int int, b bool, bs []byte) {
	n := uint(n_int)
	if b {
		bs[n/8] |= 1 << (n % 8)
	} else {
		bs[n/8] &= ^(1 << (n % 8))
	}
}

func Xor(r []byte, w []byte) {
	for j := 0; j < len(w)/len(r); j+=len(r) {
		for i, b := range r {
			w[i] ^= b
		}
	}
}

func Xors(bss [][]byte) []byte {
	n := len(bss[0])
	x := make([]byte, n)
	for _, bs := range bss {
		for i, b := range bs {
			x[i] ^= b
		}
	}
	return x
}

func XorsDC(bsss [][][]byte) [][]byte {
	n := len(bsss)
	m := len(bsss[0])
	x := make([][]byte, n)
	for i, _ := range bsss {
		y := make([][]byte, m)
		for j := 0; j < m; j++ {
			y[j] = bsss[j][i]
		}
		x[i] = Xors(y)
	}
	return x
}

func AllZero(xs []byte) bool {
	for _, x := range xs {
		if x != 0 {
			return false
		}
	}
	return true
}

func ComputeResponse(allBlocks []Block, mask []byte, secret []byte) []byte {
	response := make([]byte, BlockSize)
        i := 0
L:
        for _, b := range mask {
                for j := 0; j < 8; j++ {
                        if b&1 == 1 {
                                Xor(allBlocks[i].Block, response)
                        }
                        b >>= 1
                        i++
                        if i >= len(allBlocks) {
                                break L
                        }
                }
        }
	Xor(secret, response)
        return response
}

func ReverseMap(m map[int]int) map[int][]int {
	res := make(map[int][]int)
	for k, v := range m {
		if res[v] == nil {
			res[v] = []int{k}
		} else {
			res[v] = append(res[v], k)
		}
	}
	return res
}

func GeneratePI(size int, rand cipher.Stream) []int {
	// Pick a random permutation
	pi := make([]int, size)
	for i := 0; i < size; i++ {	// Initialize a trivial permutation
		pi[i] = i
	}
	for i := size-1; i > 0; i-- {	// Shuffle by random swaps
		j := int(random.Uint64(rand) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}
	return pi
}

func Encrypt(g abstract.Group, msg []byte, pks []abstract.Point) ([]abstract.Point, []abstract.Point) {
	c1s := []abstract.Point{}
	c2s := []abstract.Point{}
	var msgPt abstract.Point
	remainder := msg
	for ; len(remainder) != 0 ;  {
		msgPt, remainder = g.Point().Pick(remainder, random.Stream)
		k := g.Secret().Pick(random.Stream)
		c1 := g.Point().Mul(nil, k)
		var c2 abstract.Point = nil
		for _, pk := range pks {
			if c2 == nil {
				c2 = g.Point().Mul(pk, k)
			} else {
				c2 = c2.Add(c2, g.Point().Mul(pk, k))
			}
		}
		c2 = c2.Add(c2, msgPt)
		c1s = append(c1s, c1)
		c2s = append(c2s, c2)
	}
	return c1s, c2s
}

func EncryptKey(g abstract.Group, msgPt abstract.Point, pks []abstract.Point) (abstract.Point, abstract.Point) {
	k := g.Secret().Pick(random.Stream)
	c1 := g.Point().Mul(nil, k)
	var c2 abstract.Point = nil
	for _, pk := range pks {
		if c2 == nil {
			c2 = g.Point().Mul(pk, k)
		} else {
			c2 = c2.Add(c2, g.Point().Mul(pk, k))
		}
	}
	c2 = c2.Add(c2, msgPt)
	return c1, c2
}

func EncryptPoint(g abstract.Group, msgPt abstract.Point, pk abstract.Point) (abstract.Point, abstract.Point) {
	k := g.Secret().Pick(random.Stream)
	c1 := g.Point().Mul(nil, k)
	c2 := g.Point().Mul(pk, k)
	c2 = c2.Add(c2, msgPt)
	return c1, c2
}

func Decrypt(g abstract.Group, c1 abstract.Point, c2 abstract.Point, sk abstract.Secret) abstract.Point {
	return g.Point().Sub(c2, g.Point().Mul(c1, sk))
}

func Membership(res []byte, set [][]byte) int {
	for i := range set {
		same := true
		same = same && (len(res) == len(set[i]))
		for k := range res {
			same = same && (set[i][k] == res[k])
		}
		if same {
			return i
		}
	}
	return -1
}

func MarshalPoint(pt abstract.Point) []byte {
	buf := new(bytes.Buffer)
	ptByte := make([]byte, SecretSize)
	pt.MarshalTo(buf)
	buf.Read(ptByte)
	return ptByte
}

func UnmarshalPoint(suite abstract.Suite, ptByte []byte) abstract.Point {
	buf := bytes.NewBuffer(ptByte)
	pt := suite.Point()
	pt.UnmarshalFrom(buf)
	return pt
}

func Wait() {
	var w sync.WaitGroup
	w.Add(1)
	w.Wait()
}

func SliceEquals(X, Y []byte) bool {
	if len(X) != len(Y) {
		return false
	}
	for i := range X {
		if X[i] != Y[i] {
			return false
		}
	}
	return true
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s took %s", name, elapsed)
}

func NewDesc(path string) (map[string]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal("Failed opening file", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() % HashSize != 0 {
		return nil, errors.New(" Misformatted file")
	}
	numHashes := fi.Size() / HashSize

	hashes := make(map[string]int64)

	for i := 0; int64(i) < numHashes; i++ {
		hash := make([]byte, HashSize)
		_, err := f.Read(hash)
		if err != nil {
			log.Fatal("Failed reading file", err)
		}
		//fmt.Println("hash", hash, "to", i * BlockSize)
		hashes[string(hash)] = int64(i * BlockSize)
	}

	return hashes, nil
}

func NewFile(suite abstract.Suite, path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal("Failed opening file", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	blocks := (fi.Size() + BlockSize - 1) / BlockSize

	x := &File{
		Name: path,
		Hashes: make(map[string]int64, blocks),
	}

	for i := 0; int64(i) < blocks; i++ {
		tmp := make([]byte, BlockSize)
		_, err := f.Read(tmp)
		if err != nil {
			log.Fatal("Failed reading file", err)
		}
		h := suite.Hash()
		h.Write(tmp)
		x.Hashes[string(h.Sum(nil))] = int64((i * BlockSize))
	}

	return x, nil
}

func ParseServerList(path string) []string {
	servers, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("Failed reading servers file:", err)
	}
	scan := bufio.NewScanner(bytes.NewReader(servers))
	ss := []string{}
	for ; scan.Scan(); {
		ss = append(ss, string(scan.Bytes()))
	}
	return ss
}
