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
	"errors"
	"fmt"
	"math/big"

	"github.com/ThinkiumGroup/go-common"
)

var (
	ErrMismatchProof = errors.New("proof mismatched")
	ErrMissingValue  = errors.New("value missing")
	ErrMissingChild  = errors.New("child missing")
	ErrNotExist      = errors.New("not exist")
)

// TODO Optimization: When proving children, when the number of children is less than 4, pass
//  all other children's Hash directly in the proof in order, otherwise, pass 4 levels of proof.
//  When proving value, do not pass or only pass a Hash (ChildHashs[0]) as children trie rootHash
// TODO 优化：证明孩子时，当孩子个数少于4个时，则在证明中直接按顺序传所有其他孩子的Hash，否则，传4层证明。
//  证明value时，不传或只传一个Hash（ChildHashs[0]）为children trie rootHash

type NodeHasher struct {
	Header     NodeHeader   // NodeHeader of the node in Trie
	ValueHash  *common.Hash // hash of the node value, could be nil
	ChildHashs [][]byte     // hash value array of all non-nil children, nil if there are no children
}

// needProof: whether proof needed
// ptype: proof type if needProof==true
// If the child node is to be proved, then the index is a non-negative number and must not be
// greater than 15, which is used to indicate that the value of the corresponding index of
// ChildHashs is the target value to be prooved.
func (h *NodeHasher) MakeProof(needProof bool, ptype ProofType, index int) (nodeHash []byte, nodeProof *NodeProof, err error) {

	headerHash, err := h.Header.HashValue()
	if err != nil {
		return nil, nil, err
	}

	valueHash := common.NilHashSlice
	if h.ValueHash != nil {
		valueHash = h.ValueHash[:]
	}

	left := common.HashPair(headerHash, valueHash)

	var childProof *common.MerkleProofs
	if h.Header.HasChildren() {
		var right []byte
		if !needProof {
			right, err = common.MerkleHashComplete(h.ChildHashs, -1, nil)
		} else {
			childProof = common.NewMerkleProofs()
			right, err = common.MerkleHashComplete(h.ChildHashs, index, childProof)
		}
		if err != nil {
			return nil, nil, err
		}
		left = common.HashPair(left, right)
	}

	if needProof {
		nodeProof = NewNodeProof(ptype, h.Header, h.ValueHash, childProof)
	} else {
		nodeProof = nil
	}

	return left, nodeProof, nil
}

// 0-15: to proof a child node
// 16: to proof node value
// 254: to proof existence
// 255: merkle trie proof
type ProofType uint8

const (
	// 0x00 ~ 0x0F The index of the child node for the node to proof
	ProofValue      ProofType = 0x10 // To prove the value of the current node, valueHash should be nil
	ProofHdsSummary ProofType = 0x11 // Prove each summary in the packaged Hds, HdsRoot=Merkle{[]Hash{Hash(ChainID(4bytes)+Height(8bytes)), Header.Hash}}
	ProofExistence  ProofType = 0xFE // To prove whether the value of a key exists
	ProofMerkleOnly ProofType = 0xFF // Hash only child nodes without Header and Value. Used to support simple
	//                               // merkle trees. The index of the proved child is no longer recorded.
	//                               // For example: SmallCombinedTrie，HistoryTree

	ProofHeaderDeltas    ProofType = 0x20 // To proof header balance delta (deltas generated in local chain)
	ProofHeaderHistory   ProofType = 0x21 // To proof header history hash
	ProofHeaderStateRoot ProofType = 0x23 // To proof header state root
	ProofHeaderVCCRoot   ProofType = 0x24 // To proof header VCC root
	ProofHeaderCCCRoot   ProofType = 0x25 // To proof header Cashed root
	ProofHeaderHdsRoot   ProofType = 0x26 // To proof header Headers root

	ProofHeaderBase  ProofType = 0x30 // proof header type = ProofHeaderBase + models.BH* (Header column index)
	ProofHeaderLimit           = 0xa0 // [0x30, 0x80) including 80 items, which is the maximum number of properties of block
)

// var (
// 	// Type to be proved -> index of value to be proved in HashList
// 	proofableMap = map[ProofType]int{
// 		ProofHeaderDeltas:    12,
// 		ProofHeaderHistory:   1,
// 		ProofHeaderStateRoot: 13,
// 		ProofHeaderVCCRoot:   16,
// 		ProofHeaderCCCRoot:   17,
// 		ProofHeaderHdsRoot:   20,
// 	}
// )
//
// func ProofableMap(typ ProofType) (int, bool) {
// 	i, ok := proofableMap[typ]
// 	return i, ok
// }

func (p ProofType) IsProofChild() bool {
	return p <= 15
}

func (p ProofType) IsProofValue() bool {
	return p == ProofValue
}

func (p ProofType) IsProofHdsSummary() bool {
	return p == ProofHdsSummary
}

func (p ProofType) IsProofExistence() bool {
	return p == ProofExistence
}

func (p ProofType) IsProofMerkleOnly() bool {
	return p == ProofMerkleOnly
}

func (p ProofType) IsProofHeaderProperty() (headerIndex int, ok bool) {
	switch p {
	case ProofHeaderDeltas:
		return 12, true
	case ProofHeaderHistory:
		return 1, true
	case ProofHeaderStateRoot:
		return 13, true
	case ProofHeaderVCCRoot:
		return 16, true
	case ProofHeaderCCCRoot:
		return 17, true
	case ProofHeaderHdsRoot:
		return 20, true
	default:
		if p >= ProofHeaderBase && p < ProofHeaderLimit {
			return int(p - ProofHeaderBase), true
		}
		return 0, false
	}
}

func (p ProofType) String() string {
	if p.IsProofChild() {
		return fmt.Sprintf("C%d", p)
	}
	if p.IsProofValue() {
		return "V"
	}
	if p.IsProofHdsSummary() {
		return "S"
	}
	if p.IsProofExistence() {
		return "E"
	}
	if p.IsProofMerkleOnly() {
		return "M"
	}
	if _, ok := p.IsProofHeaderProperty(); ok {
		return fmt.Sprintf("H%d", p)
	}
	return "NA"
}

// 1. To prove the existence of ValueHash on leaf nodes, such as the existence of TX and SPV. Or:
// 2. To prove the non-existence of a key according to the provided Header, and you need to match
//    the key from top to bottom.
// 3. When PType is ProofHeaderXXXXXXXX, to proof the corresponding field in BlockHeader:
//    In this case, ValueHash is the special prefix of different fields, and the hash value of the
//    field sequence number can be used to prove that this field is being proved, and ChildProofs
//    is the proof to BlockHeader.Hash
type NodeProof struct {
	PType       ProofType            `json:"type"`   // Limit the content that this node can prove, which is used to judge in proving step.
	Header      NodeHeader           `json:"header"` // Description of the current node, including: whether there is prefix, what is prefix, which child node has data, and whether there is value
	ValueHash   *common.Hash         `json:"value"`  // Hash of the value, or special prefix when proving a BlockHeader field
	ChildProofs *common.MerkleProofs `json:"merkle"` // The proofs of merkle tree of the child nodes' hashs. It does not participate in proof when it's nil.
	//								 				 // If PType==ProofValue, the value is to be proved. In the case, ChildProofs can has only one or zero hash value. If there is one hash value, the hash is the hash of the children part.
}

func (n *NodeProof) Equal(o *NodeProof) bool {
	if n == o {
		return true
	}
	if n == nil || o == nil {
		return false
	}
	return n.PType == o.PType &&
		n.Header.Equal(o.Header) &&
		n.ValueHash.Equal(o.ValueHash) &&
		n.ChildProofs.Equal(o.ChildProofs)
}

func (n *NodeProof) Clone() *NodeProof {
	if n == nil {
		return nil
	}
	ret := new(NodeProof)
	ret.PType = n.PType
	ret.Header = n.Header.Clone()
	ret.ValueHash = n.ValueHash.Clone()
	ret.ChildProofs = n.ChildProofs.Clone()
	return ret
}

func NewNodeProof(ptype ProofType, header NodeHeader, valueHash *common.Hash, childProofs *common.MerkleProofs) *NodeProof {
	if ptype.IsProofValue() {
		// the value is to be proved，valueHash should be nil
		valueHash = nil
	}
	return &NodeProof{
		PType:       ptype,
		Header:      header,
		ValueHash:   valueHash,
		ChildProofs: childProofs,
	}
}

func NewMerkleOnlyProof(ptype ProofType, proofs *common.MerkleProofs) *NodeProof {
	if ptype.IsProofMerkleOnly() == false {
		panic(fmt.Sprintf("expecting a ProofMerkleOnly Type, but %s", ptype))
	}
	return NewNodeProof(ptype, NodeHeader{}, nil, proofs)
}

func NewHeaderPropertyProof(ptype ProofType, indexHash *common.Hash, proofs *common.MerkleProofs) *NodeProof {
	if _, ok := ptype.IsProofHeaderProperty(); !ok {
		panic(fmt.Sprintf("expecting a ProofHeaderProperty type, but %s", ptype))
	}
	return NewNodeProof(ptype, NodeHeader{}, indexHash, proofs)
}

func NewHdsSummaryProof(summary *common.Hash, proofs *common.MerkleProofs) *NodeProof {
	return NewNodeProof(ProofHdsSummary, NodeHeader{}, summary, proofs)
}

func NewLeafNodeProof(header NodeHeader) *NodeProof {
	return NewNodeProof(
		ProofValue, // proving value
		header,
		nil, // to be proved value not included
		nil) // no children in leaf node
}

// only the case of value on leaf node is supported, that is, the length of all keys is the same
func NewBranchNodeProof(childIndex uint8, header NodeHeader, childProofs *common.MerkleProofs) *NodeProof {
	return NewNodeProof(ProofType(childIndex), header, nil, childProofs)
}

func (n *NodeProof) Summary() string {
	if n.ValueHash != nil {
		return fmt.Sprintf("NP{PTYPE:%s, Header:%s, Value:%x, Children:%s}", n.PType, n.Header, n.ValueHash[:5], n.ChildProofs.Summary())
	} else {
		return fmt.Sprintf("NP{PTYPE:%s, Header:%s, Value:<nil>, Children:%s}", n.PType, n.Header, n.ChildProofs.Summary())
	}
}

func (n *NodeProof) String() string {
	if n.ValueHash != nil {
		return fmt.Sprintf("NP{PTYPE:%s, Header:%s, Value:%x, Children:%s}", n.PType, n.Header, n.ValueHash[:5], n.ChildProofs)
	} else {
		return fmt.Sprintf("NP{PTYPE:%s, Header:%s, Value:<nil>, Children:%s}", n.PType, n.Header, n.ChildProofs)
	}
}

func (n *NodeProof) InfoString(level common.IndentLevel) string {
	if n == nil {
		return "NP<nil>"
	}
	base := level.IndentString()
	return fmt.Sprintf("NP{"+
		"\n%s\tPTYPE: %s"+
		"\n%s\tHeader: %s"+
		"\n%s\tValue: %x"+
		"\n%s\tChildren: %s"+
		"\n%s}",
		base, n.PType,
		base, n.Header,
		base, common.ForPrint(n.ValueHash, 0),
		base, n.ChildProofs.InfoString(level+1),
		base)
}

// iterate all hash values in the current NodeProof
func (n *NodeProof) Iterate(hashCallback func(val []byte, order bool) error) error {
	if n == nil {
		return common.ErrNil
	}

	if n.PType.IsProofMerkleOnly() {
		// standard proof of a merkle tree
		if err := n.ChildProofs.Iterate(hashCallback); err != nil {
			return fmt.Errorf("proof merkle failed: %v", err)
		}
		return nil
	}

	var left []byte
	if n.PType.IsProofChild() {
		// proof child node
		headerHash, err := n.Header.HashValue()
		if err != nil {
			return fmt.Errorf("header hash failed: %v", err)
		}

		valueHash := common.NilHashSlice
		if n.ValueHash != nil {
			valueHash = n.ValueHash[:]
		}
		left = common.HashPair(headerHash, valueHash)
		if n.ChildProofs != nil {
			if err := n.ChildProofs.Iterate(hashCallback); err != nil {
				return fmt.Errorf("proof child childProofs failed: %v", err)
			}
		}
		if err := hashCallback(left, true); err != nil {
			return fmt.Errorf("proof child headerHash+valueHash failed: %v", err)
		}
	} else if n.PType.IsProofValue() {
		// proof value of the node
		headerHash, err := n.Header.HashValue()
		if err != nil {
			return fmt.Errorf("header hash failed: %v", err)
		}

		if err := hashCallback(headerHash, true); err != nil {
			return fmt.Errorf("proof value headerHash failed: %v", err)
		}
		if n.ChildProofs != nil {
			if len(n.ChildProofs.Hashs) == 0 {
				// if there is no value, which can be explained by Header, it will not perform hashing
			} else if len(n.ChildProofs.Hashs) == 1 {
				if err := hashCallback(n.ChildProofs.Hashs[0][:], false); err != nil {
					return fmt.Errorf("proof value childProofs failed: %v", err)
				}
			} else {
				return errors.New("only 1 hash most promitted in ChildProofs when proof the value of the node")
			}
		}
	} else if n.PType.IsProofHdsSummary() {
		// It has the same structure and algorithm as block proof
		if n.ValueHash == nil {
			return errors.New("proof hds missing valueHash")
		}
		// if n.ChildProofs == nil || len(n.ChildProofs.Hashs) == 0 {
		// 	return errors.New("proof hds missing child proofs")
		// }
		if err := hashCallback(n.ValueHash[:], true); err != nil {
			return fmt.Errorf("proof hds valueHash failed: %v", err)
		}
		if err := n.ChildProofs.Iterate(hashCallback); err != nil {
			return fmt.Errorf("proof hds childProofs failed: %v", err)
		}
	} else if _, ok := n.PType.IsProofHeaderProperty(); ok {
		// To proof fields in BlockHeader
		if n.ValueHash == nil {
			return errors.New("proof header missing valueHash")
		}
		if n.ChildProofs == nil || len(n.ChildProofs.Hashs) == 0 {
			return errors.New("proof header missing child proofs")
		}
		if err := hashCallback(n.ValueHash[:], true); err != nil {
			return fmt.Errorf("proof header valueHash failed: %v", err)
		}
		if err := n.ChildProofs.Iterate(hashCallback); err != nil {
			return fmt.Errorf("proof header childProofs failed: %v", err)
		}
	} else {
		// n.PType.IsProofExsitence()
		// To prove the existence, the current node is used to prove the existence and cannot
		// be used to prove the value
		return ErrMismatchProof
	}

	return nil
}

// Calculate the proof value of a value or child node represented by toBeProof by passing through
// current proofing node
// If PType.IsProofChild(): Hash(Hash(Hash(Header), ValueHash), ChildProofs.Proof(toBeProof))
// If PType.IsProofValue():
//   if ChildProofs.Len() > 1 : error
//   if ChildProofs.Len() == 1 : Hash(Hash(Hash(Header), toBeProof), ChildProofs.Hashs[0])
//   if ChildProofs.Len() == 0 : Hash(Hash(Header), toBeProof)
// If PType.IsProofMerkleOnly(): ChildProofs.Proof(toBeProof)
// If PType.IsProofHeaderProperty(): ChildProofs.Proof(Hash(ValueHash, toBeProof)), in this case,
//                                   ValueHash is the hash value of the sequence number of the
//                                   corresponding field
// If PType.IsProofHdsSummary(): ChildProofs.Proof(Hash(ValueHash, toBeProof)), in this case,
//                               ValueHash is the hash of the chain+Height corresponding to the
//                               summary
func (n *NodeProof) Proof(toBeProof common.Hash) ([]byte, error) {
	if n == nil {
		return nil, common.ErrNil
	}

	result := toBeProof[:]
	if err := n.Iterate(func(val []byte, order bool) error {
		var errr error
		result, errr = common.HashPairOrder(order, val, result)
		return errr
	}); err != nil {
		return nil, err
	}
	return result, nil
	// if n.PType.IsProofMerkleOnly() {
	// 	// standard proof of a merkle tree
	// 	return n.ChildProofs.Proof(toBeProof)
	// }
	//
	// var left []byte
	// var err error
	// if n.PType.IsProofChild() {
	// 	// proof child node
	// 	headerHash, err := n.Header.HashValue()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	valueHash := common.NilHashSlice
	// 	if n.ValueHash != nil {
	// 		valueHash = n.ValueHash[:]
	// 	}
	// 	left = common.HashPair(headerHash, valueHash)
	// 	right := toBeProof[:]
	// 	if n.ChildProofs != nil {
	// 		right, err = n.ChildProofs.Proof(toBeProof)
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 	}
	// 	left = common.HashPair(left, right)
	// } else if n.PType.IsProofValue() {
	// 	// proof value of the node
	// 	headerHash, err := n.Header.HashValue()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	left = common.HashPair(headerHash, toBeProof[:])
	// 	if n.ChildProofs != nil {
	// 		if len(n.ChildProofs.Hashs) == 0 {
	// 			// if there is no value, which can be explained by Header, it will not perform hashing
	// 		} else if len(n.ChildProofs.Hashs) == 1 {
	// 			left = common.HashPair(left, n.ChildProofs.Hashs[0][:])
	// 		} else {
	// 			return nil, errors.New("only 1 hash most promitted in ChildProofs when proof the value of the node")
	// 		}
	// 	}
	// } else if n.PType.IsProofHdsSummary() {
	// 	// It has the same structure and algorithm as block proof
	// 	if n.ValueHash == nil {
	// 		return nil, ErrMissingValue
	// 	}
	// 	if n.ChildProofs == nil || len(n.ChildProofs.Hashs) == 0 {
	// 		return nil, ErrMissingChild
	// 	}
	// 	left = common.HashPair(n.ValueHash[:], toBeProof[:])
	// 	left, err = n.ChildProofs.Proof(common.BytesToHash(left))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// } else if _, ok := n.PType.IsProofHeaderProperty(); ok {
	// 	// To proof fields in BlockHeader
	// 	if n.ValueHash == nil {
	// 		return nil, ErrMissingValue
	// 	}
	// 	if n.ChildProofs == nil || len(n.ChildProofs.Hashs) == 0 {
	// 		return nil, ErrMissingChild
	// 	}
	// 	left = common.HashPair(n.ValueHash[:], toBeProof[:])
	// 	left, err = n.ChildProofs.Proof(common.BytesToHash(left))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// } else {
	// 	// n.PType.IsProofExsitence()
	// 	// To prove the existence, the current node is used to prove the existence and cannot
	// 	// be used to prove the value
	// 	return nil, ErrMismatchProof
	// }
	//
	// return left, nil
}

// Compare the nibbles in keyprefix with the prefix of the current node and the index of the
// child array to determine whether the value pointed to by the keyprefix is in the current
// node or its descendant node
// matched: true means that the target is in the current node or its desendant node
// valueHash: When matched = = true and exactly matches the current node, hash of value is
//            returned. Otherwise, return nil
// suffix: Return the remaining part of keyprefix after matching, which is used to continue
//         calling this method on the child node
// err: If the data is incomplete or incorrect, err will return a non nil value, and other
//      return values are invalid
//      In this case，matched==true&&valueHash!=nil，means the target value is found,
//                   matched==true&&valueHash==nil，means the current node is matched and the
//                                                  next level needs to be matched
func (n *NodeProof) ExistenceMatch(keyprefix []byte) (matched bool, valueHash *common.Hash, suffix []byte, err error) {
	if n == nil {
		return false, nil, nil, common.ErrNil
	}
	if !n.PType.IsProofChild() &&
		!n.PType.IsProofValue() &&
		!n.PType.IsProofExistence() {
		// Only the proofs generated by ITrie have the matching of keys and the theory of existence
		return false, nil, nil, ErrMismatchProof
	}
	// Because NodeProof must be generated along the way of the key from root to the leaf
	// node to be proved, the prefix of each level node should be exactly the prefix of
	// keyprefix, otherwise it does not exist.
	nodePrefix := n.Header.KeyToPrefix()
	if len(keyprefix) == 0 {
		if len(nodePrefix) == 0 {
			// matches exactly, judge whether it exists or not
			if n.PType.IsProofValue() {
				// current proof proves node value, there's no valueHash
				return true, nil, nil, ErrMismatchProof
			}
			if n.ValueHash == nil {
				return true, nil, nil, ErrMissingValue
			}
			return true, n.ValueHash, nil, nil
		} else {
			// cannot match, does not exist
			return false, nil, nil, nil
		}
	}

	// If the current proof has no prefix, skip this step
	if len(nodePrefix) > 0 {
		matched := matchPrefix(nodePrefix, keyprefix)
		if matched == 0 {
			// All the superiors match correctly, but the prefix does not match at current node,
			// indicating that the value does not exist
			return false, nil, keyprefix, nil
		}
		nodeRemains := len(nodePrefix) - matched
		keyRemains := len(keyprefix) - matched

		if nodeRemains != 0 {
			// nodePrefix is not the prefix of keyprefix, which means keyprefix does not exist
			return false, nil, keyprefix[matched:], nil
		}
		// if nodePrefix is equal to keyprefix
		if keyRemains == 0 {
			// nodeRemains == 0 at this time
			if n.PType.IsProofValue() {
				// The current node proves value, and there is no ValueHash
				return true, nil, nil, ErrMismatchProof
			}
			if n.ValueHash == nil {
				return true, nil, nil, ErrMissingValue
			}
			return true, n.ValueHash, nil, nil
		}
		// If nodePrefix is the prefix of keyprefix, it is necessary to determine whether the
		// corresponding child node exists
		keyprefix = keyprefix[matched:]
	}

	// Does keyprefix points to an existed child
	if !n.Header.HasChild(int(keyprefix[0])) {
		// If there is no child node, the value you are looking for does not exist
		return false, nil, keyprefix, nil
	}

	// At this time, keyprefix is the remaining part after matching with the current prefix.
	// We need to continue to find the child node
	if !n.PType.IsProofChild() {
		// it's not a proof of child nodes
		return false, nil, keyprefix, ErrMismatchProof
	}

	if byte(n.PType) != keyprefix[0] {
		// It's not proof of the child node be want to find
		return false, nil, keyprefix, ErrMismatchProof
	}

	// The current path to the current node is matched, and the remaining keyprefix is returned
	return true, nil, keyprefix[1:], nil
}

func (n *NodeProof) ExistenceHash() ([]byte, error) {
	if n.PType.IsProofExistence() == false {
		return nil, fmt.Errorf("only ExistenceProof can Hash, but it's %s", n.PType)
	}
	headerHash, err := n.Header.HashValue()
	if err != nil {
		return nil, err
	}
	valueHash := common.NilHashSlice
	if n.ValueHash != nil {
		valueHash = n.ValueHash[:]
	}
	left := common.HashPair(headerHash, valueHash)
	if n.ChildProofs != nil {
		if len(n.ChildProofs.Hashs) == 0 {
			// if there is no value, which can be explained by Header, it will not perform hashing
		} else if len(n.ChildProofs.Hashs) == 1 {
			left = common.HashPair(left, n.ChildProofs.Hashs[0][:])
		} else {
			return nil, errors.New("only 1 hash most promitted in ChildProofs when proof the value of the node")
		}
	}
	return left, nil
}

func (n *NodeProof) IsHeaderOf(chainId common.ChainID, height common.Height) bool {
	if n == nil || n.ValueHash == nil {
		return false
	}
	i, ok := n.PType.IsProofHeaderProperty()
	if !ok {
		return false
	}
	// i, ok := ProofableMap(n.PType)
	// if !ok {
	// 	return false
	// }
	h := common.HeaderIndexHash(common.ToHeaderPosHashBuffer(chainId, height), byte(i))
	if bytes.Equal(h, n.ValueHash[:]) {
		return true
	}
	return false
}

func (n *NodeProof) IsHdsSummaryOf(chainId common.ChainID, height common.Height) bool {
	if n == nil || !n.PType.IsProofHdsSummary() || n.ValueHash == nil {
		return false
	}
	buf := common.ToHeaderPosHashBuffer(chainId, height)
	h := common.Hash256NoError(buf[:12])
	if bytes.Equal(h, n.ValueHash[:]) {
		return true
	}
	return false
}

// in the order of the proof tree from bottom to top
type ProofChain []*NodeProof

func (c ProofChain) Equal(o ProofChain) bool {
	if len(c) != len(o) {
		return false
	}
	for i := 0; i < len(c); i++ {
		if c[i].Equal(o[i]) == false {
			return false
		}
	}
	return true
}

func (c ProofChain) Clone() ProofChain {
	if c == nil {
		return nil
	}
	ret := make(ProofChain, len(c))
	for i := 0; i < len(c); i++ {
		ret[i] = c[i].Clone()
	}
	return ret
}

// Whether the value pointed by keyprefix (the nibbles of the key, can be converted back to the
// binary array of the key through prefixtokey) exists
// non-nil: exist, return hash of the value, nil：not exist
// If the data is incomplete or incorrect, err will return a non nil value, the return value of
// *common.Hash is invalid
func (c ProofChain) Exist(keyprefix []byte) (*common.Hash, error) {
	i := len(c) - 1
	for ; i >= 0; i-- {
		matched, valueHash, suffix, err := c[i].ExistenceMatch(keyprefix)
		if err != nil {
			return nil, err
		}
		if !matched {
			return nil, nil
		}
		if valueHash != nil {
			return valueHash, nil
		}
		// When matched==true && valueHash==nil, you need to use the suffix after keyprefix
		// matched to look down
		keyprefix = suffix
	}
	return nil, nil
}

// whether the value indicated by the key exists in the trie that generates the proofchain
func (c ProofChain) IsExist(key []byte) (bool, error) {
	if len(key) == 0 {
		return false, common.ErrNil
	}
	prefix := keyToPrefix(key)
	h, err := c.Exist(prefix)
	if err != nil {
		return false, err
	}
	return h != nil, nil
}

// When the current proof chain is proofing existence, this method returns the root hash of
// the trie that generates the proof chain
func (c ProofChain) ExistenceHash() (rootHash []byte, err error) {
	if len(c) == 0 {
		return nil, ErrMissingValue
	}
	if c[0] == nil {
		return nil, common.ErrNil
	}
	if c[0].PType.IsProofExistence() == false {
		// The current proof node only supports the proof of existence, other types must provide
		// the value of tobeproof to calculate
		return nil, ErrMismatchProof
	} else {
		rootHash, err = c[0].ExistenceHash()
		if err != nil {
			return nil, err
		}
	}
	for i := 1; i < len(c); i++ {
		input := common.BytesToHash(rootHash)
		rootHash, err = c[i].Proof(input)
		if err != nil {
			return nil, err
		}
	}
	return
}

// Calculate the hash value from toBeProof through the whole proof chain
func (c ProofChain) Proof(toBeProof common.Hash) ([]byte, error) {
	if len(c) == 0 {
		return toBeProof[:], nil
	}
	h := toBeProof[:]
	callback := func(val []byte, order bool) error {
		var errr error
		if h, errr = common.HashPairOrder(order, val, h); errr != nil {
			return errr
		}
		return nil
	}
	if err := c.Iterate(callback); err != nil {
		return nil, fmt.Errorf("proof failed: %v", err)
	}
	return h, nil
}

func (c ProofChain) Iterate(hashCallback func(val []byte, order bool) error) error {
	for i, pc := range c {
		if err := pc.Iterate(hashCallback); err != nil {
			return fmt.Errorf("iterate at %d failed: %v", i, err)
		}
	}
	return nil
}

func (c ProofChain) ToMerkles() (*common.MerkleProofs, error) {
	if len(c) == 0 {
		return nil, nil
	}
	mp := common.NewMerkleProofs()
	callback := func(val []byte, order bool) error {
		if len(val) != common.HashLength {
			return errors.New("invalid hash value")
		}
		mp.Append(common.BytesToHash(val), order)
		return nil
	}
	if err := c.Iterate(callback); err != nil {
		return nil, fmt.Errorf("to merkles failed: %v", err)
	}
	return mp, nil
}

func (c ProofChain) ToItems() ([]common.HashItem, error) {
	if len(c) == 0 {
		return nil, nil
	}
	var items []common.HashItem
	err := c.Iterate(func(val []byte, order bool) error {
		items = append(items, common.HashItem{Val: common.BytesToHash(val), Order: order})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (c ProofChain) BigKey() *big.Int {
	key := big.NewInt(0)
	pos := 0
	for _, np := range c {
		pos = np.ChildProofs.BigKey(key, pos)
	}
	return key
}

func (c ProofChain) HistoryProof(height common.Height, hob []byte) ([]byte, error) {
	if len(c) == 0 {
		return nil, errors.New("nil history proof")
	}
	if height.IsNil() && len(hob) == 0 {
		return nil, errors.New("nil height and hash")
	}
	if !height.IsNil() { // nil height for no height checking
		// check height
		bigint := c.BigKey()
		bigheight := new(big.Int).SetUint64(uint64(height))
		if bigint.Cmp(bigheight) != 0 {
			return nil, fmt.Errorf("proof of Height:%s not %s", bigint, bigheight)
		}
	}
	if len(hob) > 0 {
		hisRoot, err := c.Proof(common.BytesToHash(hob))
		if err != nil {
			return nil, fmt.Errorf("history proof failed: %v", err)
		}
		return hisRoot, nil
	}
	return nil, nil
}

func (c ProofChain) InfoString(level common.IndentLevel) string {
	return level.InfoString(c)
}

func (c ProofChain) String() string {
	if c == nil {
		return "<nil>"
	}
	buf := new(bytes.Buffer)
	buf.WriteByte('[')
	for i, np := range c {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(np.Summary())
	}
	buf.WriteByte(']')
	return buf.String()
}

// evidence for something
type Proof struct {
	ToBeProof *common.Hash // hash value of the object to be proved
	Proofs    ProofChain   // Proof chain, each proof node includes proof type and proof value
}

func (p Proof) Proof() ([]byte, error) {
	if p.ToBeProof == nil {
		return nil, common.ErrNil
	}
	return p.Proofs.Proof(*(p.ToBeProof))
}

func (p Proof) Exist(keyprefix []byte) (*common.Hash, error) {
	return p.Proofs.Exist(keyprefix)
}

func VerifyProofChain(toBeProof common.Hash, proofChain ProofChain, expected []byte) bool {
	proofed, err := proofChain.Proof(toBeProof)
	if err != nil {
		return false
	}
	return bytes.Equal(proofed, expected)
}
