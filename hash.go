// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/stephenfire/go-rtl"
	"golang.org/x/crypto/ripemd160"
)

// Interface type that can calculate hash values
type Hasher interface {
	HashValue() ([]byte, error)
}

// Since 16 bit counting is used in serialization, the maximum supported proof height cannot exceed 65535
type MerkleProofs struct {
	Hashs []Hash   `json:"hashs"` // Use ToBeProof to alculate the Hash list of Hash with index starting from 0 in order
	Paths *big.Int `json:"paths"` // Bit operands. The bit corresponding to the index of hashs
	//                            // indicates that the corresponding hash value is placed left (1)
	//                            // or right (0) during hash operation, and the order is exactly
	//                            // the binary value of the proved object
}

func NewMerkleProofs() *MerkleProofs {
	return &MerkleProofs{
		Paths: new(big.Int),
	}
}

func (p *MerkleProofs) Clone() *MerkleProofs {
	if p == nil {
		return nil
	}
	ret := new(MerkleProofs)
	if p.Hashs != nil {
		ret.Hashs = make([]Hash, len(p.Hashs))
		for i := 0; i < len(p.Hashs); i++ {
			ret.Hashs[i] = p.Hashs[i]
		}
	}
	if p.Paths != nil {
		ret.Paths = new(big.Int).Set(p.Paths)
	}
	return ret
}

func (p *MerkleProofs) Len() int {
	if p == nil {
		return 0
	}
	return len(p.Hashs)
}

// The key of the current proof value, OK is false when overflowing
func (p *MerkleProofs) Key() (key uint64, ok bool) {
	if p.Paths == nil || !p.Paths.IsUint64() {
		return 0, false
	}
	return p.Paths.Uint64(), true
}

func (p *MerkleProofs) BigKey(bigKey *big.Int, startAt int) int {
	if bigKey == nil || startAt < 0 {
		return startAt
	}
	if p == nil || len(p.Hashs) == 0 {
		return startAt
	}
	i := 0
	for ; i < len(p.Hashs); i++ {
		pos := startAt + i
		bigKey.SetBit(bigKey, pos, p.Paths.Bit(i))
	}
	return i + startAt
}

// h: a point on the proofing path
// order: Is this point on the left side (true) or the right side (false) of the proof path
func (p *MerkleProofs) Append(h Hash, order bool) {
	p.Hashs = append(p.Hashs, h)
	b := uint(1)
	if !order {
		b = 0
	}
	p.Paths.SetBit(p.Paths, len(p.Hashs)-1, b)
	// fmt.Printf("merkle proof append: %x, left:%t\n", h[:5], order)
}

// Whether the corresponding hash value should be placed left (true) or right (false) when
// calculating the upper level hash
func (p *MerkleProofs) Order(i int) bool {
	if p.Paths == nil {
		return false
	}
	if p.Paths.Bit(i) == 1 {
		return true
	} else {
		return false
	}
}

func (p *MerkleProofs) Iterate(hashCallback func(val []byte, order bool) error) error {
	if p == nil {
		return nil
	}
	for i := 0; i < len(p.Hashs); i++ {
		if err := hashCallback(p.Hashs[i][:], p.Order(i)); err != nil {
			return err
		}
	}
	return nil
}

// According to the input, calculate the hash according to the proof, and return the result.
// If the proof is empty, the input is returned
func (p *MerkleProofs) Proof(toBeProof Hash) ([]byte, error) {
	h := toBeProof[:]
	callback := func(val []byte, order bool) error {
		var err error
		h, err = HashPairOrder(order, val, h)
		return err
	}
	if errr := p.Iterate(callback); errr != nil {
		return nil, errr
	}
	// if p != nil {
	// 	for i := 0; i < len(p.Hashs); i++ {
	// 		if p.Order(i) {
	// 			h = HashPair(p.Hashs[i][:], h)
	// 		} else {
	// 			h = HashPair(h, p.Hashs[i][:])
	// 		}
	// 	}
	// }
	return h, nil
}

// Gets the hash value corresponding with index (starting from 0) on the proof path and its order.
// If order is true, the hash value returned should be placed in the left, otherwise, right
func (p *MerkleProofs) Get(index int) (h Hash, order bool, err error) {
	if index < 0 || index >= len(p.Hashs) {
		return Hash{}, false, ErrIllegalParams
	}
	h = p.Hashs[index]
	if p.Paths.Bit(index) == 1 {
		order = true
	} else {
		order = false
	}
	return
}

func writeArray(array []byte, buf []byte, w io.Writer) error {
	l := len(array)
	binary.BigEndian.PutUint16(buf, uint16(l))
	// Because the interface requires that if the return length is less than the length of
	// inputting buffer, it must return non-nil error, so it is no longer necessary to check
	// whether the length is correct
	_, err := w.Write(buf)
	if err != nil {
		return err
	}
	if l > 0 {
		_, err = w.Write(array)
		if err != nil {
			return err
		}
	}
	return nil
}

func readArray(sizeBuf []byte, r io.Reader) ([]byte, error) {
	_, err := r.Read(sizeBuf)
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(sizeBuf)
	array := make([]byte, size)
	if size > 0 {
		_, err = r.Read(array)
		if err != nil {
			return array, err
		}
	}
	return array, nil
}

// 1 byte flag of whether it's nil (common.NilOrFalse/common.NotNilOrTrue)
// + binary.BigEndian.PutUint16(len(Hashs))
// + binary.BigEndian.PutUint16(len(Hashs[0])) + Hashs[0]
// + ...
// + binary.BigEndian.PutUint16(len(Hashs[len(Hashs)-1])) + Hashs[len(Hashs)-1]
// + binary.BigEndian.PutUint16(len(Paths.Bytes())) + Paths.Bytes()
func (p *MerkleProofs) Serialization(w io.Writer) error {
	if p == nil {
		w.Write([]byte{rtl.NilOrFalse})
		return nil
	} else {
		w.Write([]byte{rtl.NotNilOrTrue})
	}
	l := make([]byte, 2)
	size := len(p.Hashs)
	binary.BigEndian.PutUint16(l, uint16(size))
	_, err := w.Write(l)
	if err != nil {
		return err
	}
	for i := 0; i < size; i++ {
		_, err = w.Write(p.Hashs[i][:])
		if err != nil {
			return err
		}
	}

	var path []byte
	if p.Paths != nil {
		path = p.Paths.Bytes()
	}
	err = writeArray(path, l, w)
	if err != nil {
		return err
	}

	return nil
}

func (p *MerkleProofs) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	flag := make([]byte, 1)
	_, err = r.Read(flag)
	if err != nil {
		return
	}
	if flag[0] == rtl.NilOrFalse {
		return true, nil
	}

	sizebuf := make([]byte, 2)

	var array []byte
	_, err = r.Read(sizebuf)
	if err != nil {
		return
	}
	hashSize := int(binary.BigEndian.Uint16(sizebuf))
	p.Hashs = make([]Hash, hashSize)
	for i := 0; i < hashSize; i++ {
		_, err = r.Read(p.Hashs[i][:])
		if err != nil {
			return
		}
	}

	array, err = readArray(sizebuf, r)
	if err != nil {
		return
	}
	p.Paths = new(big.Int)
	p.Paths.SetBytes(array)

	return
}

func (p MerkleProofs) String() string {
	buf := BytesBufferPool.Get().(*bytes.Buffer)
	defer BytesBufferPool.Put(buf)
	buf.Reset()

	buf.WriteString("Proof{")
	buf.WriteString(fmt.Sprintf("(%x),", p.Paths.Uint64()))
	if len(p.Hashs) > 0 {
		for i := 0; i < len(p.Hashs); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			if p.Paths.Bit(i) == 0 {
				buf.WriteByte('-')
			}
			buf.WriteString(fmt.Sprintf("%x", p.Hashs[i][:]))
			if p.Paths.Bit(i) == 1 {
				buf.WriteByte('-')
			}
		}
	}
	buf.WriteByte('}')

	return buf.String()
}

func (p *MerkleProofs) InfoString(level IndentLevel) string {
	if p == nil {
		return "MerkleProofs<nil>"
	}
	buf := BytesBufferPool.Get().(*bytes.Buffer)
	defer BytesBufferPool.Put(buf)
	buf.Reset()

	base := level.IndentString()
	buf.WriteString("MerkleProofs{")
	buf.WriteString(fmt.Sprintf("\n%s\tPath: %x", base, p.Paths.Uint64()))
	for i, h := range p.Hashs {
		buf.WriteString(fmt.Sprintf("\n%s\t%d: (%d)%x", base, i, p.Paths.Bit(i), h[:]))
	}
	buf.WriteString("\n")
	buf.WriteString(base)
	buf.WriteByte('}')
	return buf.String()
}

func Hash256(v ...[]byte) Hash {
	return BytesToHash(SystemHash256(v...))
}

func Hash256p(v ...[]byte) *Hash {
	h := SystemHash256(v...)
	hh := BytesToHash(h)
	return &hh
}

func Hash256WithError(v ...[]byte) (Hash, error) {
	h := SystemHash256(v...)
	hh := BytesToHash(h)
	return hh, nil
}

func Hash256s(in ...[]byte) ([]byte, error) {
	return SystemHash256(in...), nil
}

func Hash256NoError(in ...[]byte) []byte {
	return SystemHash256(in...)
}

func SystemHash256(in ...[]byte) []byte {
	return CipherHash256(RealCipher, in...)
}

func CipherHash256(cipher cipher.Cipher, in ...[]byte) []byte {
	hasher := cipher.Hasher()
	for _, b := range in {
		hasher.Write(b)
	}
	return hasher.Sum(nil)
}

func HashRipemd160(data []byte) []byte {
	md := ripemd160.New()
	return md.Sum(data)
}

func ValuesMerkleTreeHash(values interface{}, toBeProof int, proofs *MerkleProofs) (rootHash []byte, err error) {
	val := reflect.ValueOf(values)
	typ := val.Type()
	if typ.Kind() != reflect.Slice {
		return nil, ErrUnsupported
	}
	var hashList [][]byte
	for i := 0; i < val.Len(); i++ {
		h, err := HashObject(val.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		hashList = append(hashList, h)
	}
	return MerkleHashComplete(hashList, toBeProof, proofs)
}

// MerkleHash Calculate merkle tree root hash with hashlist parameter according to fixed algorithm.
// If proofs is not nil, put the merkle tree proof of the value of hashList[tobeproof] into proofs in order
// Return error is not nil if there's an error, []byte is meaningless. Proofs DOES NOT GUARANTEE no change at this time
// toBeProof is the index of the object to be proved in the hashlist array
func MerkleHashComplete(hashList [][]byte, toBeProof int, proofs *MerkleProofs) ([]byte, error) {
	if len(hashList) == 0 {
		return CopyBytes(NilHashSlice), nil
	}

	// Find the smallest power value of 2 greater than the length of hashList and fill it with
	// NilHash value, which is used as the leaf node of balanced binary tree
	max := 2
	for max < len(hashList) {
		max <<= 1
	}
	for i := len(hashList); i < max; i++ {
		hashList = append(hashList, CopyBytes(NilHashSlice))
	}

	var hh []byte

	// if proofs != nil {
	// 	fmt.Printf("making proof: %x, index:%d\n", hashList, toBeProof)
	// 	defer fmt.Printf("MerkelProofs: %s\n", proofs)
	// }

	for max > 1 {
		// Calculate the value of each layer of the balanced binary tree from bottom to top
		max >>= 1
		b := make([][]byte, max)
		for i := 0; i < max; i++ {
			p1 := 2 * i
			p2 := p1 + 1
			// Calculate hashes adjacent to each other
			hh = HashPair(hashList[p1], hashList[p2])
			b[i] = hh

			if proofs != nil && toBeProof >= 0 {
				if toBeProof == p1 {
					proofs.Append(BytesToHash(hashList[p2]), false)
				} else if toBeProof == p2 {
					proofs.Append(BytesToHash(hashList[p1]), true)
				}
			}
		}
		hashList = b
		if toBeProof >= 0 {
			// Because toBeProof is a signed integer, arithmetic shift is performed, and the
			// negative sign will not be lost, so there will be no situation where the negative
			// shift becomes 0
			toBeProof >>= 1
		}
	}

	if proofs != nil && toBeProof < 0 {
		// When proof is needed, and the index is less than 0, it means that only the root Hash
		// needs to be saved, and the sequence value is useless at this time
		// Used to prove the value of a node with children
		proofs.Append(BytesToHash(hashList[0]), false)
	}
	return hashList[0], nil
}

// depth: If it is a positive number, it is the depth of the specified merkle tree. At this time,
// if the number of leaves of the complete binary tree specified by the depth is greater than
// len(hashList), at most one NilHashSlice is supplemented per layer
func MerkleHash(hashList [][]byte, toBeProof int, proofs *MerkleProofs) (root []byte, err error) {
	if len(hashList) == 0 {
		return CopyBytes(NilHashSlice), nil
	}

	// Find the smallest power of 2 greater than the length of hashList, and get the height of
	// the complete binary tree (the number from top to bottom)
	depth := 1
	max := 2
	for max < len(hashList) {
		max <<= 1
		depth++
	}

	list := make([][]byte, len(hashList))
	copy(list, hashList)

	var hh []byte

	// Calculate Merkle hash according to the height of binary tree, and fill in NilHashSlice when it is needed
	for d := 0; d < depth; d++ {
		length := len(list)
		next := list[0 : (length+1)/2]
		for i := 0; i < length; i += 2 {
			j := i + 1
			right := NilHashSlice
			if j < length {
				right = list[j]
			}
			hh = HashPair(list[i], right)
			if proofs != nil && toBeProof >= 0 {
				if toBeProof == i {
					proofs.Append(BytesToHash(right), false)
				} else if toBeProof == j {
					proofs.Append(BytesToHash(list[i]), true)
				}
			}
			next[i>>1] = hh
			if j >= length {
				break
			}
		}
		list = next
		if toBeProof >= 0 {
			toBeProof >>= 1
		}
	}

	return list[0], nil
}

func HashPair(a []byte, b []byte) []byte {
	result, err := Hash256s(a, b)
	if err != nil {
		panic(NewDvppError("hash pair error", err))
	}
	// fmt.Printf("Hash(%x, %x) = %x\n", a[:5], b[:5], result[:5])
	return result
}

func HashPairOrder(order bool, a, b []byte) ([]byte, error) {
	if order {
		return Hash256s(a, b)
	} else {
		return Hash256s(b, a)
	}
}

func IsNilHash(bs []byte) bool {
	if len(bs) == 0 {
		return true
	}
	return bytes.Equal(bs, NilHashSlice)
}

func HashSliceEquals(h1, h2 []byte) bool {
	nh1, nh2 := IsNilHash(h1), IsNilHash(h2)
	if nh1 && nh2 {
		return true
	}
	if nh1 || nh2 {
		return false
	}
	return bytes.Equal(h1, h2)
}

func HashEquals(h1, h2 *Hash) bool {
	if (h1 == nil || h1.IsNil()) && (h2 == nil || h2.IsNil()) {
		return true
	}
	if h1.Equals(h2) {
		return true
	}
	return false
}

func ToHeaderPosHashBuffer(id ChainID, height Height) [13]byte {
	var buf [13]byte
	idbytes := id.Bytes()
	copy(buf[0:], idbytes)
	heightbytes := height.Bytes()
	copy(buf[4:], heightbytes)
	return buf
}

func HeaderIndexHash(posBuffer [13]byte, index byte) []byte {
	posBuffer[12] = index
	indexHash, _ := Hash256s(posBuffer[:])
	return indexHash
}
