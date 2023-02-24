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

package trie

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

const childrenLength = 16

// NodeType is a byte which used to describe the node type
// bit[7]: 1 if prefix is not nil
// bit[6]: 1 if children array is not empty
// bit[5]: 1 if value is not nil
// bit[4]: when bit[7]=1, 1 if prefix length is odd, 0 if prefix length is even
// bit[3-0]: when bit[4]=1, first byte of prefix, otherwise=0x0
type NodeType byte

func (t NodeType) HasPrefix() bool {
	return t&0x80 > 0
}

func (t NodeType) PrefixOddLength() bool {
	return t&0x10 > 0
}

func (t NodeType) FirstPrefix() byte {
	return byte(t & 0x0F)
}

func (t NodeType) HasChildren() bool {
	return t&0x40 > 0
}

func (t NodeType) HasValue() bool {
	return t&0x20 > 0
}

func (t NodeType) String() string {
	if t.PrefixOddLength() {
		return fmt.Sprintf("<P:%t, C:%t, V:%t, '%x'>", t.HasPrefix(), t.HasChildren(), t.HasValue(), t.FirstPrefix())
	} else {
		return fmt.Sprintf("<P:%t, C:%t, V:%t>", t.HasPrefix(), t.HasChildren(), t.HasValue())
	}
}

// for JSON serialization method
type KeyPart []byte

func (k KeyPart) Clone() KeyPart {
	if k == nil {
		return nil
	}
	ret := make(KeyPart, len(k))
	copy(ret, k)
	return ret
}

func (k *KeyPart) UnmarshalText(input []byte) error {
	b := make(hexutil.Bytes, 0)
	if err := b.UnmarshalText(input); err != nil {
		return err
	}
	*k = KeyPart(b)
	return nil
}

func (k KeyPart) MarshalText() ([]byte, error) {
	if len(k) == 0 {
		return k, nil
	}
	return hexutil.Bytes(k).MarshalText()
}

func (k KeyPart) Bytes() []byte {
	return k
}

type ChildFlag [2]byte

func (c ChildFlag) Clone() ChildFlag {
	var ret ChildFlag
	copy(ret[:], c[:])
	return ret
}

func (c *ChildFlag) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("ChildFlag", input, c[:])
}

func (c ChildFlag) MarshalText() ([]byte, error) {
	return hexutil.Bytes(c[:]).MarshalText()
}

// NodeHeader is used to describe the node serialize value
// 1. 1st byte for NodeType
// 2. if node has prefix, then put compressed prefix byte slice after NodeType. (first nibble
// 	  is in NodeType if the length of prefix is odd)
// 3. if node has children node(s), then use 2 bytes to indicate which index of children
//    array has node. byte[0].bit[0-7] <-> node.children[0-7], byte[1].bit[0-7] <-> node.children[8-15]
type NodeHeader struct {
	NT           NodeType  `json:"nodetype"`
	KeyString    KeyPart   `json:"keystring"`
	ChildrenFlag ChildFlag `json:"childrenflag"`
}

func (h NodeHeader) Equal(o NodeHeader) bool {
	return h.NT == o.NT && bytes.Equal(h.KeyString, o.KeyString) && h.ChildrenFlag == o.ChildrenFlag
}

func (h NodeHeader) Clone() NodeHeader {
	return NodeHeader{
		NT:           h.NT,
		KeyString:    h.KeyString.Clone(),
		ChildrenFlag: h.ChildrenFlag.Clone(),
	}
}

func newNodeHeader(n *node) *NodeHeader {
	ret := &NodeHeader{}
	ret.NT = n.ntype()
	if ret.NT.HasPrefix() {
		ret.KeyString = prefixToKeystring(n.prefix)
	}
	if ret.NT.HasChildren() {
		for i := 0; i < childrenLength; i++ {
			if n.children[i] != nil {
				ret.ChildrenFlag[i/8] |= byte(0x1 << uint8(i%8))
			}
		}
	}
	return ret
}

func (h NodeHeader) String() string {
	buf := new(bytes.Buffer)
	buf.WriteString("NodeHeader{")
	buf.WriteString(fmt.Sprintf("type=%s, ", h.NT))
	buf.WriteString("prefix=")
	if s := h.KeyHexString(); len(s) > 0 {
		buf.Write(s)
	}
	buf.WriteString(", children(")
	for i := 0; i < childrenLength; i++ {
		if h.HasChild(i) {
			buf.WriteByte(valuebyteToHexbyte(byte(i)))
		}
	}
	buf.WriteString(")")
	buf.WriteByte('}')
	return buf.String()
}

func (h *NodeHeader) KeyHexString() []byte {
	return prefixToHexstring(keystringToPrefix(h.NT, h.KeyString.Bytes()))
}

func (h *NodeHeader) KeyToPrefix() []byte {
	return keystringToPrefix(h.NT, h.KeyString.Bytes())
}

func (h NodeHeader) HasChild(index int) bool {
	return h.NT.HasChildren() && ((h.ChildrenFlag[index/8] & byte(0x1<<uint8(index%8))) > 0)
}

func (h NodeHeader) HasChildren() bool {
	return h.NT.HasChildren()
}

func (h *NodeHeader) HashValue() ([]byte, error) {
	return common.EncodeAndHash(h)
}

func (h *NodeHeader) Serialization(w io.Writer) error {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(h.NT))
	if h.NT.HasPrefix() {
		if err := rtl.Encode(h.KeyString, buf); err != nil {
			return err
		}
	}
	if h.NT.HasChildren() {
		if _, err := buf.Write(h.ChildrenFlag[:]); err != nil {
			return err
		}
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func (h *NodeHeader) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	buf := make([]byte, 1)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return
	}
	h.NT = NodeType(buf[0])

	if h.NT.HasPrefix() {
		pb := &buf
		if err = rtl.Decode(r, pb); err != nil {
			return
		}
		h.KeyString = *pb
	}

	if h.NT.HasChildren() {
		if _, err = io.ReadFull(r, h.ChildrenFlag[:]); err != nil {
			return
		}
	}
	return
}

type (
	// NodeValueEncode encode the first parameter and write the result into io.Writer
	NodeValueEncode func(o interface{}, w io.Writer) error

	// NodeValueDecode decode the byte stream load from io.Reader into an object and return it
	NodeValueDecode func(r io.Reader) (o interface{}, err error)

	// NodeValueHasher hashes the input parameter and return the hashed value
	// returnd value length must equals common.HashLength
	NodeValueHasher func(value interface{}, valueBytes []byte) (hashBytes []byte, err error)

	// NodeValueExpander expands node value
	NodeValueExpander func(hashBytes []byte, adapter db.DataAdapter) (valueBytes []byte, err error)
)

type node struct {
	prefix   []byte
	children [childrenLength]*node
	value    interface{}

	// cache
	dirty       bool   // node data has been changed
	hash        []byte // initial hash or cache of current node hash
	headerhash  []byte // cache of node header hash
	valuehash   []byte // cache of value hash
	valuestream []byte // cache of serialized value stream
	generation  uint64 // created generation

	valueEncode   NodeValueEncode   // Used to serialize the value in node to io.Writer as the value to save
	valueDecode   NodeValueDecode   // Deserialize the data from database to node value in the trie
	valueHasher   NodeValueHasher   // To calculate the hash of the node value, as part of the key when save to database
	valueExpander NodeValueExpander // Used to return the serialization of the value corresponding to the specified valuehash
}

func DefaultValueHasher(value interface{}, _ []byte) ([]byte, error) {
	// if len(valuebytes) < common.HashLength {
	// 	return valuebytes, nil
	// }
	return common.HashObject(value)
	// return common.Hash256s(valuebytes)
}

func DefaultValueExpander(hashbytes []byte, adapter db.DataAdapter) ([]byte, error) {
	valueBytes, err := adapter.Load(hashbytes)
	if err != nil {
		return nil, common.NewDvppError(fmt.Sprintf("load %x value data error", hashbytes), err)
	}
	return valueBytes, nil
}

func NewNodeWithFuncs(hash []byte, generation uint64, encode NodeValueEncode, decode NodeValueDecode,
	hasher NodeValueHasher, expander NodeValueExpander) *node {
	r := &node{
		hash:        hash,
		generation:  generation,
		dirty:       false,
		valueEncode: encode,
		valueDecode: decode,
	}
	if hasher != nil {
		r.valueHasher = hasher
	}
	if expander != nil {
		r.valueExpander = expander
	}
	return r
}

func NewNode(hash []byte, generation uint64, typ reflect.Type) *node {
	codec, err := rtl.NewStructCodec(typ)
	if err != nil {
		panic(common.NewDvppError("NewNode error:", err))
	}
	return &node{
		hash:        hash,
		generation:  generation,
		dirty:       false,
		valueEncode: codec.Encode,
		valueDecode: codec.Decode,
	}
}

/*
states
*/

func (n *node) isDirty() bool {
	return n.dirty
}

func (n *node) isEmpty() bool {
	// no prefixstring, no child nodes, no value, no valuehash, no node hash
	return !n.hasPrefix() && !n.hasChildren() && !n.hasValue() &&
		isEmptyNodeHash(n.hash) &&
		len(n.valuehash) == 0
}

// Because of the previous bug will lead to trie.root The node has prefix, but it is an empty node
// The data has been in error and needs to be restored to the normal state when the error is read
// TODO ignore the error when the chain has been restarted
func (n *node) inErrorStatus() bool {
	return n.hasPrefix() && !isEmptyNodeHash(n.hash) && !n.hasChildren() && !n.hasValue() && !n.isValueCollapsed()
}

func isEmptyNodeHash(h []byte) bool {
	return len(h) < common.HashLength || bytes.Compare(h, common.EmptyNodeHashSlice) == 0
}

func (n *node) isCollapsed() bool {
	// has valid node hash, optional prefixstring, no child nodes, no value, no valuehash
	if isEmptyNodeHash(n.hash) {
		// if len(n.hash) < common.RealCipher.LengthOfHash() {
		return false
	}
	return !n.hasChildren() && !n.hasValue() && len(n.valuehash) == 0
}

func (n *node) isValueCollapsed() bool {
	return len(n.valuehash) >= common.HashLength && !n.hasValue()
}

func (n *node) hasPrefix() bool {
	return len(n.prefix) > 0
}

func (n *node) hasChild(index int) bool {
	return n.children[index] != nil
}

func (n *node) hasChildren() bool {
	for i := 0; i < childrenLength; i++ {
		if n.hasChild(i) {
			return true
		}
	}
	return false
}

func (n *node) hasValue() bool {
	return n.value != nil
}

/*
cache
*/

func (n *node) prefixChanged() {
	// log.Debugf("prefix changed: %s", n)
	n.headerhash = nil
	n.hash = nil
	n.dirty = true
}

func (n *node) valueChanged() {
	// log.Debugf("value changed: %s", n)
	n.valuehash = nil
	n.valuestream = nil
	n.hash = nil
	n.dirty = true
}

func (n *node) childChanged() {
	// log.Debugf("child changed: %s", n)
	n.headerhash = nil
	n.hash = nil
	n.dirty = true
}

func (n *node) prefixLength() int {
	return len(n.prefix)
}

/*
prefix operations
*/

func (n *node) matchPrefix(prefixString []byte) int {
	return matchPrefix(n.prefix, prefixString)
}

func (n *node) setPrefix(prefixString []byte) {
	if bytes.Equal(n.prefix, prefixString) {
		return
	}

	if l := len(prefixString); l > 0 {
		if len(n.prefix) >= l {
			n.prefix = n.prefix[:l]
		} else {
			n.prefix = make([]byte, len(prefixString))
		}
		copy(n.prefix, prefixString)
	} else {
		n.prefix = nil
	}
	n.prefixChanged()
}

func (n *node) chopPrefixHead(l int) error {
	if l > len(n.prefix) {
		return common.ErrInsufficientLength
	}
	if n.prefix != nil {
		n.prefix = n.prefix[l:]
		n.prefixChanged()
	}
	return nil
}

func (n *node) chopPrefixTail(l int) error {
	if l > len(n.prefix) {
		return common.ErrInsufficientLength
	}
	if n.prefix != nil {
		n.prefix = n.prefix[:len(n.prefix)-l]
		n.prefixChanged()
	}
	return nil
}

/*
value operations
*/

func (n *node) setValue(newv interface{}) (changed bool, oldv interface{}, countdelta int) {
	if n.value == nil && newv == nil {
		return false, nil, 0
	}

	if n.value != nil && newv != nil {
		countdelta = 0
	} else if n.value == nil && newv != nil {
		countdelta = 1
	} else if n.value != nil && newv == nil {
		countdelta = -1
	}

	oldv = n.value
	n.value = newv

	n.valueChanged()
	return true, oldv, countdelta
}

/*
child node operations
*/

func (n *node) setChild(index int, child *node) (oldChild *node) {
	oldChild = n.children[index]
	n.children[index] = child

	n.childChanged()
	return oldChild
}

func (n *node) expandValue(adapter db.DataAdapter) error {
	var f NodeValueExpander = DefaultValueExpander
	if n.valueExpander != nil {
		f = n.valueExpander
	}
	valueBytes, err := f(n.valuehash, adapter)
	if err != nil {
		return err
	}
	buf := bytes.NewBuffer(valueBytes)
	v, err := n.valueDecode(buf)
	if err != nil {
		return err
	}
	n.value = v
	if CheckNodeValueHash {
		var h []byte
		if n.valueHasher != nil {
			h, _ = n.valueHasher(n.value, valueBytes)
		} else {
			h, _ = DefaultValueHasher(n.value, valueBytes)
		}
		if bytes.Equal(h, n.valuehash) == false {
			log.Errorf("[TRIE] hash of %+v, have:%x want:%x", v, h, n.valuehash)
		}
	}

	return err
}

/*
hashes: header hash, value hash
*/
// ntype create one byte which higher nibble(4bits) indicates:
// bit[7]: 1 if prefix is not nil
// bit[6]: 1 if children array is not empty
// bit[5]: 1 if value is not nil
// bit[4]: when bit[7]=1, 1 if prefix length is odd, 0 if prefix length is even
// bit[3-0]: when bit[4]=1, first byte of prefix, otherwise=0x0
func (n *node) ntype() NodeType {
	b := byte(0x00)
	if l := len(n.prefix); l > 0 {
		b |= 0x80
		if l&0x01 == 1 {
			b |= 0x10
			b |= n.prefix[0] & 0x0F
		}
	}
	if n.hasChildren() {
		b |= 0x40
	}
	if n.hasValue() {
		b |= 0x20
	}
	return NodeType(b)
}

func (n *node) HashValue() ([]byte, error) {
	if n.hash != nil {
		return n.hash, nil
	}
	h, err := n.computeHash(0, nil)
	if err != nil {
		return nil, err
	}
	n.hash = h
	return h, nil
}

func (n *node) headerHash() ([]byte, error) {
	if n.headerhash != nil {
		return n.headerhash, nil
	}

	// encode header
	header := newNodeHeader(n)
	h, err := header.HashValue()
	if err != nil {
		return nil, err
	}
	// cache
	n.headerhash = h
	return h, nil
}

// returns hash of the value, serialization of the value and error
func (n *node) valueHash() ([]byte, []byte, error) {
	if n.hasValue() {
		if n.valuehash != nil && n.valuestream != nil {
			return n.valuehash, n.valuestream, nil
		}
		buf := new(bytes.Buffer)
		err := n.valueEncode(n.value, buf)
		if err != nil {
			return nil, nil, err
		}
		valuebytes := buf.Bytes()
		var r []byte
		if n.valueHasher != nil {
			r, err = n.valueHasher(n.value, valuebytes)
		} else {
			r, err = DefaultValueHasher(n.value, valuebytes)
		}
		if err != nil {
			return nil, nil, err
		}
		n.valuehash = r
		n.valuestream = valuebytes
		return r, valuebytes, nil
	}
	return nil, nil, nil
}

/*
serialization
*/

func (n *node) serialChildAndValue(w io.Writer) (count int, err error) {
	l := 0
	// write all child node hash in order
	var ch []byte
	for i := 0; i < childrenLength; i++ {
		if n.hasChild(i) {
			ch, err = n.children[i].HashValue()
			if err != nil {
				return
			}
			l, err = w.Write(ch)
			if l > 0 {
				count += l
			}
			if err != nil {
				return
			}
		}
	}

	if n.hasValue() {
		// write value hash if value exist
		ch, _, err := n.valueHash()
		if err != nil {
			return count, err
		}
		l, err = w.Write(ch)
		if l > 0 {
			count += l
		}
		if err != nil {
			return count, err
		}
	}
	return
}

// Serialization encode node and write to an io.Writer
// 1. write encode header
// 2. write all not nil child hash value in fix length(32bytes) in index order
// 3. write value hash in fix length(32bytes)
func (n *node) Serialization(w io.Writer) error {
	header := newNodeHeader(n)
	if err := header.Serialization(w); err != nil {
		return err
	}
	if _, err := n.serialChildAndValue(w); err != nil {
		return err
	}
	return nil
}

// Deserialization deserialize the node object from an io.Reader.
func (n *node) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	if n == nil {
		return false, rtl.ErrDecodeIntoNil
	}

	// decode NodeHeader object
	header := new(NodeHeader)
	if _, err = header.Deserialization(r); err != nil {
		return
	}
	// decode prefix
	n.prefix = header.KeyToPrefix()

	// decode children
	if header.NT.HasChildren() {
		// read real child hashs
		for i := 0; i < childrenLength; i++ {
			n.children[i] = nil
			if header.HasChild(i) {
				buf := make([]byte, common.HashLength)
				l, err := io.ReadFull(r, buf)
				if l == common.HashLength {
					n.children[i] = NewNodeWithFuncs(buf, n.generation, n.valueEncode, n.valueDecode, n.valueHasher, n.valueExpander)
					if err != nil {
						log.Warnf("ignored an error occurs when Deserialize node: %v", err)
					}
				} else if err != nil {
					return shouldBeNil, err
				}
			}
		}
	}
	// decode value
	if header.NT.HasValue() {
		buf := make([]byte, common.HashLength)
		l, err := io.ReadFull(r, buf)
		if l == common.HashLength {
			n.valuehash = buf
			if err != nil {
				log.Warnf("ignored an error occurs when Deserialize node: %v", err)
			}
		} else if err != nil {
			return shouldBeNil, err
		}
	}

	return false, nil
}

/*
functions
*/

func (n *node) collapse() error {
	if n.isCollapsed() {
		return common.ErrAlreadyDone
	}
	_, err := n.HashValue()
	if err != nil {
		return err
	}

	for i := 0; i < childrenLength; i++ {
		n.children[i] = nil
	}
	n.value = nil
	n.valuehash = nil
	n.valuestream = nil
	// log.Debugf("[TRIE] node collpased: %x", common.ForPrint(n.hash))
	return nil
}

func (n *node) collapseValue() error {
	if n.isValueCollapsed() {
		return common.ErrAlreadyDone
	}
	h, _, e := n.valueHash()
	if e != nil {
		return e
	}
	n.valuehash = h
	n.value = nil
	n.valuestream = nil
	// log.Debugf("[TRIE] node value collpased: %x", common.ForPrint(n.valuehash))
	return nil
}

func (n *node) ToString(recursive bool) string {
	buf := new(bytes.Buffer)
	nt := n.ntype()
	has := false
	buf.WriteString("node{")
	if nt.HasPrefix() {
		has = true
		buf.WriteString("prefix:[")
		buf.Write(prefixToHexstring(n.prefix))
		buf.WriteByte(']')
	}
	if nt.HasChildren() {
		if has {
			buf.WriteString(", ")
		}
		buf.WriteString("children:[")
		a := false
		for i := 0; i < childrenLength; i++ {
			if n.children[i] != nil {
				if a {
					buf.WriteString(", ")
				}
				buf.WriteByte(valuebyteToHexbyte(byte(i)))
				if recursive {
					buf.WriteString(": ")
					buf.WriteString(n.children[i].String())
				}
				a = true
			}
		}
		buf.WriteByte(']')
		has = true
	}
	if nt.HasValue() {
		if has {
			buf.WriteString(", ")
		}
		buf.WriteString("value:[")
		buf.WriteString(fmt.Sprintf("%v", n.value))
		buf.WriteString("]")
		has = true
	}
	// if len(n.hash) > 0 {
	// 	if has {
	// 		buf.WriteString(", ")
	// 	}
	// 	buf.WriteString("hash:[")
	// 	buf.WriteString(fmt.Sprintf("%x", n.hash))
	// 	buf.WriteString("]")
	// 	has = true
	// }
	buf.WriteByte('}')
	return buf.String()
}

func (n *node) String() string {
	return n.ToString(false)
}

func (n *node) print() string {
	buf := new(bytes.Buffer)
	buf.WriteString("{")
	buf.WriteString("prefix=")
	buf.Write(prefixToHexstring(n.prefix))
	if n.value != nil {
		buf.WriteString(", value=")
		buf.WriteString(fmt.Sprintf("%s", n.value))
	}
	buf.WriteString(", child[")
	for i := 0; i < childrenLength; i++ {
		if n.children[i] != nil {
			buf.WriteByte(valuebyteToHexbyte(byte(i)))
		}
	}
	buf.WriteString("]")
	if n.hash != nil {
		buf.WriteString(", hash=")
		buf.WriteString(hex.EncodeToString(n.hash))
	}
	if n.valuehash != nil {
		buf.WriteString(", valuehash=")
		buf.WriteString(fmt.Sprintf("%s", hex.EncodeToString(n.valuehash)))
	}
	if n.isCollapsed() {
		buf.WriteString(", collapsed")
	}
	if n.isDirty() {
		buf.WriteString(", dirty")
	}
	buf.WriteString("}")
	return buf.String()
}

// func (n *node) GetProof(index byte, proof *common.ProofHash) error {
func (n *node) GetProof(ptype ProofType, proofs *ProofChain) error {
	_, err := n.computeHash(ptype, proofs)
	if err != nil {
		return err
	}
	return nil
}

// Calculate the hash value of the current node. If the proofs is not nil, the nodeproof of
// this node is added to the proof chain according to ptype
// Hash(Hash(Hash(n.Header), Hash(n.Value)), MerkleHashComplete(n.Child))
func (n *node) computeHash(ptype ProofType, proofs *ProofChain) ([]byte, error) {
	if n == nil {
		return common.NilHashSlice, nil
	}

	if !(ptype.IsProofChild() || ptype.IsProofValue() || ptype.IsProofExistence()) {
		// node can only generate tree related proofs
		// panic(fmt.Sprintf("not support %s in node", ptype))
		return nil, fmt.Errorf("not support %s in node", ptype)
	}

	nodehasher := new(NodeHasher)

	header := newNodeHeader(n)
	nodehasher.Header = *header

	if n.isValueCollapsed() {
		nodehasher.ValueHash = common.BytesToHashP(n.valuehash)
	} else {
		if n.hasValue() {
			valueHash, _, err := n.valueHash()
			if err != nil {
				return nil, err
			}
			nodehasher.ValueHash = common.BytesToHashP(valueHash)
		}
	}

	proofNum := -1
	if n.hasChildren() {
		// proof of child tree
		hashList := make([][]byte, 0)
		for j := 0; j < childrenLength; j++ {
			if n.hasChild(j) {
				if proofs != nil && int(ptype) == j {
					// if proof is needed
					// get the position of the child node to be proved in the leaf node
					proofNum = len(hashList)
				}
				hh, err := n.children[j].HashValue()
				if err != nil {
					return nil, err
				}
				hashList = append(hashList, hh)
			}
		}
		nodehasher.ChildHashs = hashList
	}

	// if proofs != nil {
	// 	fmt.Printf("making NodeProof for Node: %s\n", header)
	// }
	// proofNum==-1 when ptype==ProofExistence
	nodeHash, nodeProof, err := nodehasher.MakeProof(proofs != nil, ptype, proofNum)
	if err != nil {
		return nil, err
	}
	if proofs != nil && nodeProof != nil {
		*proofs = append(*proofs, nodeProof)
		// fmt.Printf("NodeProof: %s, Chain:%s\n", nodeProof, *proofs)
	}
	return nodeHash, nil
}

func (n *node) canCollapse() bool {
	return !n.isDirty() && bytes.Compare(n.hash, common.EmptyNodeHashSlice) != 0 && !n.isCollapsed()
	// // Emptynodehashslice is the hash value of an empty node. The existence of a hash value
	// // indicates that it has been folded
	// return !n.isDirty() && !n.isCollapsed()
}

func (n *node) shouldCollapse(gen, lmt uint64) bool {
	return gen-n.generation > lmt && n.canCollapse()
}

func (n *node) shouldCollapseValue(lmt int) bool {
	return !n.isDirty() && !n.isValueCollapsed() && len(n.valuestream) > lmt
}

func (n *node) mergeTheLastChild(t *Trie) bool {
	if n.hasValue() {
		return false
	}

	// locate the only child index
	childid := -1
	for i := 0; i < childrenLength; i++ {
		if n.children[i] != nil {
			if childid == -1 {
				// Record the first child node ID found
				childid = i
			} else {
				// If the child node has been found before, clear the record (not only one child node)
				childid = -1
				break
			}
		}
	}

	if childid >= 0 {
		// only one child left
		// When there is only one child node, the child node should be merged to the current node
		childnode := n.children[childid]
		if err := t.fullExpand(childnode); err != nil {
			// wrong data, should panic?
			panic(err)
		}
		// Setting the location of the original child node nil must be completed before the merging,
		// because the merging may put the child of the original child in the corresponding location,
		// and setting the location to nil after the merging will cause data loss
		n.children[childid] = nil

		n.prefix = append(n.prefix, byte(childid))
		if len(childnode.prefix) > 0 {
			n.prefix = append(n.prefix, childnode.prefix...)
		}
		n.prefixChanged()

		changed := false
		for i := 0; i < len(childnode.children); i++ {
			if childnode.children[i] != nil {
				n.children[i] = childnode.children[i]
				changed = true
			}
		}
		if changed {
			n.childChanged()
		}
		if childnode.hasValue() {
			n.value = childnode.value
			n.valueChanged()
		}
		return true
	}
	return false
}

//
// // Returns whether it can be merged. If it is true, it can be merged and merged successfully.
// // Otherwise, it returns false
// func (n *node) mergeNode(index int, child *node) bool {
// 	if index < 0 || index > 15 {
// 		panic("illegal child index merged")
// 	}
// 	if child == nil {
// 		panic("nil child merged")
// 	}
// 	// If the merged node is not expanded, it cannot be merged
// 	if child.isCollapsed() || child.isValueCollapsed() {
// 		return false
// 	}
// 	// At present, we do not consider the case of different key lengths
// 	// if n.hasValue() && child.hasValue() {
// 	// 	// If the node to be merged has value, it cannot be merged
// 	// 	return false
// 	// }
//
// 	n.prefix = append(n.prefix, byte(index))
// 	if len(child.prefix) > 0 {
// 		n.prefix = append(n.prefix, child.prefix...)
// 	}
// 	n.prefixChanged()
//
// 	changed := false
// 	for i := 0; i < len(child.children); i++ {
// 		if child.children[i] != nil {
// 			n.children[i] = child.children[i]
// 			changed = true
// 		}
// 	}
// 	if changed {
// 		n.childChanged()
// 	}
// 	if child.hasValue() {
// 		n.value = child.value
// 		n.valueChanged()
// 	}
// 	// log.Infof("%s -> %s", child, n)
// 	return true
// }
