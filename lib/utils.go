package lib

import (
	"bytes"

	"github.com/dedis/crypto/abstract"
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


func Decrypt(g abstract.Group, c1 abstract.Point, c2 abstract.Point, sk abstract.Secret) abstract.Point {
	return g.Point().Sub(c2, g.Point().Mul(c1, sk))
}

func MarshalPoint(pt abstract.Point) []byte {
	buf := new(bytes.Buffer)
	ptByte := make([]byte, SecretSize)
	pt.MarshalTo(buf)
	buf.Read(ptByte)
	return ptByte
}

func UnmarshalPoint(ptByte []byte) abstract.Point {
	buf := bytes.NewBuffer(ptByte)
	pt := Suite.Point()
	pt.UnmarshalFrom(buf)
	return pt
}
