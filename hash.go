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
	"sort"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common/math"
	"github.com/stephenfire/go-rtl"
	"golang.org/x/crypto/ripemd160"
)

// Interface type that can calculate hash values
type Hasher interface {
	HashValue() ([]byte, error)
}

type (
	MoreTime struct {
		Index int `json:"i"`     // the index of MerkleProofs.Hashs
		Times int `json:"times"` // how many more times the Hash repeats (one time in Hashs not included)
	}

	MoreTimes []MoreTime

	// an index range described by two values, containing both sides
	// a = fullBorder[0], b = fullBorder[1]
	// indexes: [a, b]
	fullBorder [2]int

	HashItem struct {
		Val   Hash
		Order bool // true for Item.Val on the left side, false for right side
	}
)

func (f fullBorder) isValid() bool {
	return f[0] >= 0 && f[1] >= f[0]
}

func (f fullBorder) a() int {
	return f[0]
}

func (f fullBorder) b() int {
	return f[1]
}

// f = [a,b]
// -1: fullIndex < a
// 0: a <= fullIndex <= b
// 1: a > b
func (f fullBorder) compared(fullIndex int) int {
	if fullIndex < f[0] {
		return -1
	}
	if fullIndex >= f[0] && fullIndex <= f[1] {
		return 0
	}
	return 1
}

func (f fullBorder) String() string {
	return fmt.Sprintf("[%d, %d]", f[0], f[1])
}

func (m MoreTime) IsValid() bool {
	return m.Index >= 0 && m.Times > 0
}

func (m MoreTime) Equal(o MoreTime) bool {
	return m == o
}

func (m MoreTime) _border(prev MoreTime, prevBorder fullBorder) fullBorder {
	if !prev.IsValid() {
		// prev is invalid means current MoreTime is the first
		return fullBorder{m.Index, m.Index + m.Times}
	} else {
		// m.Index-prev.Index is the number of hashes with no duplicates between m and prev
		s := prevBorder.b() + m.Index - prev.Index
		return fullBorder{s, s + m.Times}
	}
}

func (m MoreTime) String() string {
	return fmt.Sprintf("{Idx:%d Times:%d}", m.Index, m.Times)
}

func (ms MoreTimes) Clone() MoreTimes {
	if ms == nil {
		return nil
	}
	rs := make(MoreTimes, len(ms), len(ms))
	copy(rs, ms)
	return rs
}

func (ms MoreTimes) IsValid() bool {
	if ms == nil {
		return true
	}
	if len(ms) == 0 {
		return false
	}
	lastIndex := 0
	for _, m := range ms {
		if !m.IsValid() {
			return false
		}
		if lastIndex >= m.Index {
			return false
		}
		lastIndex = m.Index
	}
	return true
}

func (ms MoreTimes) Equal(os MoreTimes) bool {
	if len(ms) != len(os) {
		return false
	}
	if ms == nil && os == nil {
		return true
	}
	if ms == nil || os == nil {
		return false
	}
	for i, m := range ms {
		if m != os[i] {
			return false
		}
	}
	return true
}

func (ms MoreTimes) Find(index int) (times int, exist bool) {
	i := sort.Search(len(ms), func(j int) bool {
		return ms[j].Index >= index
	})
	if i >= len(ms) {
		return 0, false
	}
	if ms[i].Index == index {
		return ms[i].Times, true
	}
	return 0, false
}

func (ms MoreTimes) Append(index int) MoreTimes {
	if index < 0 {
		return ms
	}
	if len(ms) == 0 {
		return append(ms, MoreTime{
			Index: index,
			Times: 1,
		})
	}
	last := len(ms) - 1
	if ms[last].Index == index {
		ms[last].Times++
		return ms
	} else if ms[last].Index < index {
		return append(ms, MoreTime{
			Index: index,
			Times: 1,
		})
	} else {
		return ms
	}
}

func (ms MoreTimes) Count() int {
	if len(ms) == 0 {
		return 0
	}
	count := 0
	for _, m := range ms {
		if m.Times > 0 {
			count += m.Times
		}
	}
	return count
}

// get index of MerkleProofs.Hashs by the index of the expanded full hash list
func (ms MoreTimes) GetHashsIndex(fullIndex int) int {
	if len(ms) == 0 || fullIndex <= 0 {
		return fullIndex
	}
	lastMt := MoreTime{Index: 0, Times: 0}
	lastBorder := fullBorder{0, 0}
	for _, m := range ms {
		border := m._border(lastMt, lastBorder)
		compared := border.compared(fullIndex)
		if compared < 0 {
			return fullIndex - lastBorder.b() + lastMt.Index
		} else if compared == 0 {
			return m.Index
		}
		// compared>0
		lastMt = m
		lastBorder = border
	}
	return fullIndex - lastBorder.b() + lastMt.Index
}

type moreTimesIterator struct {
	i  int
	ms MoreTimes
}

func newMoreTimesIterator(ms MoreTimes) *moreTimesIterator {
	return &moreTimesIterator{
		i:  -1,
		ms: ms,
	}
}

func (it *moreTimesIterator) hasMore() bool {
	return it.i < (len(it.ms) - 1)
}

func (it *moreTimesIterator) next() (MoreTime, bool) {
	if it.hasMore() {
		it.i++
		return it.ms[it.i], true
	}
	return MoreTime{}, false
}

// Since 16 bit counting is used in serialization, the maximum supported proof height cannot exceed 65535
type MerkleProofs struct {
	// Use ToBeProof to alculate the Hash list of Hash with index starting from 0 in order
	Hashs []Hash `json:"hashs"`
	// Bit operands. The bit corresponding to the index of hashs indicates that the corresponding
	// hash value is placed left (1) or right (0) during hash operation, and the order is exactly
	// the binary value of the proved object
	Paths *big.Int `json:"paths"`
	// To save storage it is used to shrink consecutive identical hash values. Each MoreTime means
	// MerkleProofs.Hashs[MoreTime.Index] repeats MoreTime.Times times more than itself
	Repeats MoreTimes `json:"repeats"`
}

func NewMerkleProofs() *MerkleProofs {
	return &MerkleProofs{
		Paths: new(big.Int),
	}
}

func (p *MerkleProofs) Equal(o *MerkleProofs) bool {
	if p == o {
		return true
	}
	if p == nil || o == nil {
		return false
	}
	if len(p.Hashs) != len(o.Hashs) {
		return false
	}
	for i := 0; i < len(p.Hashs); i++ {
		if p.Hashs[i] != o.Hashs[i] {
			return false
		}
	}
	if math.CompareBigInt(p.Paths, o.Paths) != 0 {
		return false
	}
	return p.Repeats.Equal(o.Repeats)
}

func (p *MerkleProofs) Clone() *MerkleProofs {
	if p == nil {
		return nil
	}
	var hs []Hash
	if p.Hashs != nil {
		hs = make([]Hash, len(p.Hashs), len(p.Hashs))
		copy(hs, p.Hashs)
	}
	return &MerkleProofs{
		Hashs:   hs,
		Paths:   math.CopyBigInt(p.Paths),
		Repeats: p.Repeats.Clone(),
	}
}

func (p *MerkleProofs) Len() int {
	if p == nil {
		return 0
	}
	return len(p.Hashs) + p.Repeats.Count()
}

func (p *MerkleProofs) BigKey(bigKey *big.Int, startAt int) int {
	if bigKey == nil || startAt < 0 {
		return startAt
	}
	if p == nil || len(p.Hashs) == 0 {
		return startAt
	}

	l := p.Len()
	for i := 0; i < l; i++ {
		bigKey.SetBit(bigKey, i+startAt, p.Paths.Bit(i))
	}
	return l + startAt
}

// h: a point on the proofing path
// order: Is this point on the left side (true) or the right side (false) of the proof path
func (p *MerkleProofs) Append(h Hash, order bool) {
	if len(p.Hashs) > 0 && p.Hashs[len(p.Hashs)-1] == h {
		p.Repeats = p.Repeats.Append(len(p.Hashs) - 1)
	} else {
		p.Hashs = append(p.Hashs, h)
	}
	b := uint(1)
	if !order {
		b = 0
	}
	if b == 1 {
		p.Paths.SetBit(p.Paths, len(p.Hashs)+p.Repeats.Count()-1, b)
	}
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

func (p *MerkleProofs) _hashsIterate(callback func(h Hash, index, startFullIndex int, times int) error) error {
	if p == nil || len(p.Hashs) == 0 {
		return nil
	}
	cursor := MoreTime{Index: -1, Times: 0}
	it := newMoreTimesIterator(p.Repeats)
	fullIndex := 0
	for i, val := range p.Hashs {
		for it.hasMore() && i > cursor.Index {
			n, exist := it.next()
			if !exist || !n.IsValid() {
				return fmt.Errorf("%s at %d invalid or exist=%t", n, i, exist)
			}
			cursor = n
		}
		if cursor.Index == i {
			if err := callback(val, i, fullIndex, cursor.Times+1); err != nil {
				return fmt.Errorf("callback failed at fullIdx:%d i:%d==%s: %v", fullIndex, i, cursor, err)
			}
			fullIndex += cursor.Times + 1
		} else {
			// 1. it.hasMore()==false && i>cursor.Index
			// 2. i<cursor.Index and i>lastCursor.Index
			if err := callback(val, i, fullIndex, 1); err != nil {
				return fmt.Errorf("callback failed at fullIdx:%d i:%d<>%s: %v", fullIndex, i, cursor, err)
			}
			fullIndex++
		}
	}
	return nil
}

func (p *MerkleProofs) Iterate(hashCallback func(val []byte, order bool) error) error {
	if p == nil || len(p.Hashs) == 0 {
		return nil
	}
	return p._hashsIterate(func(h Hash, index, startFullIndex int, times int) error {
		for i := 0; i < times; i++ {
			fullIndex := startFullIndex + i
			order := p.Order(fullIndex)
			if err := hashCallback(h[:], order); err != nil {
				return fmt.Errorf("hashCallback(Idx:%d FullIdx:%d Order:%t) failed: %v", index, fullIndex, order, err)
			}
		}
		return nil
	})
}

func (p *MerkleProofs) ToItems() ([]HashItem, error) {
	if p == nil || len(p.Hashs) == 0 {
		return nil, nil
	}
	ret := make([]HashItem, 0, p.Len())
	err := p.Iterate(func(val []byte, order bool) error {
		ret = append(ret, HashItem{Val: BytesToHash(val), Order: order})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
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
	return h, nil
}

// Gets the hash value corresponding with index (starting from 0) on the proof path and its order.
// If order is true, the hash value returned should be placed in the left, otherwise, right
func (p *MerkleProofs) Get(fullIndex int) (h Hash, order bool, err error) {
	if fullIndex < 0 {
		return Hash{}, false, ErrIllegalParams
	}
	index := p.Repeats.GetHashsIndex(fullIndex)
	if index < 0 || index >= len(p.Hashs) {
		return Hash{}, false, ErrIllegalParams
	}
	h = p.Hashs[index]
	if p.Paths.Bit(fullIndex) == 1 {
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

// p==nil:
// 1 byte (common.NilOrFalse)
//
// p!=nil && len(p.Repeats)==0
// 1 byte (common.NotNilOrTrue)
// + binary.BigEndian.PutUint16(len(Hashs))
// + Hashs[0]
// + ...
// + Hashs[len(Hashs)-1]
// + binary.BigEndian.PutUint16(len(Paths.Bytes())) + Paths.Bytes()
//
// p!=nil && len(p.Repeats)>0
// 1 byte (common.Version0)
// + binary.BigEndian.PutUint16(len(Hashs))
// + Hashs[0]
// + ...
// + Hashs[len(Hashs)-1]
// + binary.BigEndian.PutUint16(len(Paths.Bytes())) + Paths.Bytes()
// + binary.BigEndian.PutUint16(len(Repeats))
// + binary.BigEndian.PutUint16(Repeats[0].Index) + binary.BigEndian.PutUint16(Repeats[0].Times)
// + ...
// + binary.BigEndian.PutUint16(Repeats[len(Repeats)-1].Index) + binary.BigEndian.PutUint16(Repeats[len(Repeats)-1].Times)
func (p *MerkleProofs) Serialization(w io.Writer) error {
	if p == nil {
		if _, err := w.Write([]byte{rtl.NilOrFalse}); err != nil {
			return err
		}
		return nil
	} else if len(p.Repeats) == 0 {
		if _, err := w.Write([]byte{rtl.NotNilOrTrue}); err != nil {
			return err
		}
	} else {
		if _, err := w.Write([]byte{rtl.Version0}); err != nil {
			return err
		}
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

	if len(p.Repeats) > 0 {
		binary.BigEndian.PutUint16(l, uint16(len(p.Repeats)))
		if _, err = w.Write(l); err != nil {
			return err
		}
		for i := 0; i < len(p.Repeats); i++ {
			binary.BigEndian.PutUint16(l, uint16(p.Repeats[i].Index))
			if _, err = w.Write(l); err != nil {
				return err
			}
			binary.BigEndian.PutUint16(l, uint16(p.Repeats[i].Times))
			if _, err = w.Write(l); err != nil {
				return err
			}
		}
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
	_, err = io.ReadFull(r, sizebuf)
	if err != nil {
		return
	}
	hashSize := int(binary.BigEndian.Uint16(sizebuf))
	p.Hashs = make([]Hash, hashSize)
	for i := 0; i < hashSize; i++ {
		_, err = io.ReadFull(r, p.Hashs[i][:])
		if err != nil {
			return
		}
	}

	var array []byte
	array, err = readArray(sizebuf, r)
	if err != nil {
		return
	}
	p.Paths = new(big.Int)
	p.Paths.SetBytes(array)

	p.Repeats = nil
	if flag[0] == rtl.Version0 {
		if _, err = io.ReadFull(r, sizebuf); err != nil {
			return false, err
		}
		repeatsSize := int(binary.BigEndian.Uint16(sizebuf))
		p.Repeats = make(MoreTimes, repeatsSize)
		buf := make([]byte, 4)
		for i := 0; i < repeatsSize; i++ {
			if _, err = io.ReadFull(r, buf); err != nil {
				return false, err
			}
			p.Repeats[i] = MoreTime{
				Index: int(binary.BigEndian.Uint16(buf[:2])),
				Times: int(binary.BigEndian.Uint16(buf[2:])),
			}
		}
	}

	return
}

func (p *MerkleProofs) Summary() string {
	if p == nil {
		return "MP<nil>"
	}
	return fmt.Sprintf("MP{Path:%s Hashs:%d}", p.Paths, len(p.Hashs))
}

func (p MerkleProofs) String() string {
	buf := BytesBufferPool.Get().(*bytes.Buffer)
	defer BytesBufferPool.Put(buf)
	buf.Reset()

	buf.WriteString("MProof{")
	buf.WriteString(fmt.Sprintf("(0x%s,%s),", (*math.BigInt)(p.Paths).HexString(), p.Paths))
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

	buf.WriteString(fmt.Sprintf("\n%s\tPath: 0x%x", base, p.Paths.Bytes()))
	_ = p._hashsIterate(func(h Hash, index, startFullIndex int, times int) error {
		if times > 1 {
			orders := big.NewInt(0)
			pathBytes := p.Paths.Bytes()
			sub, err := SubBytes(pathBytes, startFullIndex, times)
			if err != nil {
				return err
			}
			if len(sub) > 0 {
				orders.SetBytes(sub)
			}
			// for i := 0; i < times; i++ {
			// 	if p.Paths.Bit(i+startFullIndex) == 1 {
			// 		orders.SetBit(orders, i, 1)
			// 	}
			// }
			buf.WriteString(fmt.Sprintf("\n%s\t%d-(F:%d-%d): (0x%s)%x +%d",
				base, index, startFullIndex, startFullIndex+times-1, (*math.BigInt)(orders).HexString(), h[:], times))
		} else {
			buf.WriteString(fmt.Sprintf("\n%s\t%d-(F:%d): (%d)%x",
				base, index, startFullIndex, p.Paths.Bit(startFullIndex), h[:]))
		}
		return nil
	})
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

func SlicesToHashs(bss [][]byte) [][]byte {
	var hashList [][]byte
	for i := 0; i < len(bss); i++ {
		if len(bss[i]) == 0 {
			hashList = append(hashList, CopyBytes(NilHashSlice))
		} else {
			hashList = append(hashList, Hash256NoError(bss[i]))
		}
	}
	return hashList
}

func SlicesMerkleHash(values [][]byte, toBeProof int, proofs *MerkleProofs) (rootHash []byte, err error) {
	hashList := SlicesToHashs(values)
	return MerkleHash(hashList, toBeProof, proofs)
}

func SlicesMerkleHashComplete(values [][]byte, toBeProof int, proofs *MerkleProofs) (rootHash []byte, err error) {
	hashList := SlicesToHashs(values)
	return MerkleHashComplete(hashList, toBeProof, proofs)
}

func ValuesToHashs(values interface{}) ([][]byte, error) {
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
	return hashList, nil
}

func ValuesMerkleTreeHash(values interface{}, toBeProof int, proofs *MerkleProofs) (rootHash []byte, err error) {
	hashList, err := ValuesToHashs(values)
	if err != nil {
		return nil, err
	}
	return MerkleHashComplete(hashList, toBeProof, proofs)
}

// MerkleHash Calculate merkle tree root hash with hashlist parameter according to fixed algorithm.
// If proofs is not nil, put the merkle tree proof of the value of hashList[tobeproof] into proofs in order
// Return error is not nil if there's an error, []byte is meaningless. Proofs DOES NOT GUARANTEE no change at this time
// toBeProof is the index of the object to be proved in the hashlist array
func MerkleHashCompleteOld(hashList [][]byte, toBeProof int, proofs *MerkleProofs) ([]byte, error) {
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
	// for i := len(hashList); i < max; i++ {
	// 	hashList = append(hashList, CopyBytes(NilHashSlice))
	// }

	hashVal := func(p int) []byte {
		if p >= len(hashList) {
			return NilHashSlice
		}
		return hashList[p]
	}

	b := make([][]byte, max>>1)
	// var hh []byte

	for max > 1 {
		// Calculate the value of each layer of the balanced binary tree from bottom to top
		max >>= 1
		// b := make([][]byte, max)
		for i := 0; i < max; i++ {
			p1 := i << 1
			p2 := p1 + 1
			ba := hashVal(p1)
			bb := hashVal(p2)
			b[i] = HashPair(ba, bb)
			// p1 := 2 * i
			// p2 := p1 + 1
			// // Calculate hashes adjacent to each other
			// hh = HashPair(hashList[p1], hashList[p2])
			// b[i] = hh

			if proofs != nil && toBeProof >= 0 {
				if toBeProof == p1 {
					proofs.Append(BytesToHash(bb), false)
				} else if toBeProof == p2 {
					proofs.Append(BytesToHash(ba), true)
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

func ValuesMerkleHash(values interface{}, toBeProof int, proofs *MerkleProofs) (rootHash []byte, err error) {
	hashList, err := ValuesToHashs(values)
	if err != nil {
		return nil, err
	}
	return MerkleHash(hashList, toBeProof, proofs)
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

func InvalidHash(bs []byte) bool {
	return len(bs) < HashLength || bytes.Equal(bs, EmptyHash[:]) ||
		bytes.Equal(bs, NilHashSlice) || bytes.Equal(bs, EmptyNodeHashSlice)
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
	if h1.Equal(h2) {
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
