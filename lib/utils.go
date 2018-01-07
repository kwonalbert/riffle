package lib

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

func SetBit(n_int int, b bool, bs []byte) {
	n := uint(n_int)
	if b {
		bs[n/8] |= 1 << (n % 8)
	} else {
		bs[n/8] &= ^(1 << (n % 8))
	}
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
				XorWords(response, allBlocks[i].Block[:BlockSize], response)
			}
			b >>= 1
			i++
			if i >= len(allBlocks) {
				break L
			}
		}
	}
	XorWords(response, secret, response)
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

func GeneratePI(size int) []int {
	// Pick a random permutation
	pi := make([]int, size)
	for i := 0; i < size; i++ { // Initialize a trivial permutation
		pi[i] = i
	}
	for i := size - 1; i > 0; i-- { // Shuffle by random swaps
		max := big.NewInt(int64(i + 1))
		jBig, _ := rand.Int(rand.Reader, max)
		j := jBig.Int64()
		if j != int64(i) {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}
	return pi
}

func Encrypt(g kyber.Group, msg []byte, pks []kyber.Point) ([]kyber.Point, []kyber.Point) {
	c1s := []kyber.Point{}
	c2s := []kyber.Point{}
	msgPt := g.Point()
	done := false
	i := 0
	l := msgPt.EmbedLen()
	for !done {
		start := i * l
		end := (i + 1) * l
		if end > len(msg) {
			end = len(msg)
		}
		msgPt = g.Point().Embed(msg[start:end], random.Stream)
		i++

		k := g.Scalar().Pick(random.Stream)
		c1 := g.Point().Mul(k, nil)
		var c2 kyber.Point = nil
		for _, pk := range pks {
			if c2 == nil {
				c2 = g.Point().Mul(k, pk)
			} else {
				c2 = c2.Add(c2, g.Point().Mul(k, pk))
			}
		}
		c2 = c2.Add(c2, msgPt)
		c1s = append(c1s, c1)
		c2s = append(c2s, c2)
	}
	return c1s, c2s
}

func EncryptKey(g kyber.Group, msgPt kyber.Point, pks []kyber.Point) (kyber.Point, kyber.Point) {
	k := g.Scalar().Pick(random.Stream)
	c1 := g.Point().Mul(k, nil)
	var c2 kyber.Point = nil
	for _, pk := range pks {
		if c2 == nil {
			c2 = g.Point().Mul(k, pk)
		} else {
			c2 = c2.Add(c2, g.Point().Mul(k, pk))
		}
	}
	c2 = c2.Add(c2, msgPt)
	return c1, c2
}

func EncryptPoint(g kyber.Group, msgPt kyber.Point, pk kyber.Point) (kyber.Point, kyber.Point) {
	k := g.Scalar().Pick(random.Stream)
	c1 := g.Point().Mul(k, nil)
	c2 := g.Point().Mul(k, pk)
	c2 = c2.Add(c2, msgPt)
	return c1, c2
}

func Decrypt(g kyber.Group, c1 kyber.Point, c2 kyber.Point, sk kyber.Scalar) kyber.Point {
	return g.Point().Sub(c2, g.Point().Mul(sk, c1))
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

func MarshalPoint(pt kyber.Point) []byte {
	buf := new(bytes.Buffer)
	ptByte := make([]byte, SecretSize)
	pt.MarshalTo(buf)
	buf.Read(ptByte)
	return ptByte
}

func UnmarshalPoint(suite kyber.Group, ptByte []byte) kyber.Point {
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
	fmt.Println(name, " took ", elapsed)
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
	if fi.Size()%HashSize != 0 {
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

func NewFile(suite kyber.Group, path string) (*File, error) {
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
		Name:   path,
		Hashes: make(map[string]int64, blocks),
	}

	for i := 0; int64(i) < blocks; i++ {
		tmp := make([]byte, BlockSize)
		_, err := f.Read(tmp)
		if err != nil {
			log.Fatal("Failed reading file", err)
		}
		h := sha256.New()
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
	for scan.Scan() {
		ss = append(ss, string(scan.Bytes()))
	}
	return ss
}
