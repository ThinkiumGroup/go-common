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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

const (
	HistoryTreeDepth = 16 // Tree height: Any value can be reached after 16 nodes (including the root node)
	ValueKeyLength   = 4  // The height of the tree in each node is 4 (to reach value after 4 nodes)
)

// An 8-byte unsigned integer (block height) is serialized into 8 bytes in
// big-endian (high order first) order, and then create a complete binary
// tree with one nibble one level of TreeNode
type HistoryTree struct {
	expecting uint64         // the expecting key (next key), starting from 0
	root      *TreeNode      // root node
	adapter   db.DataAdapter // database
	lock      sync.Mutex
}

func (h *HistoryTree) Expecting() uint64 {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h.expecting
}

func (h *HistoryTree) _info() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{Expecting:%d Root:%s}", h.expecting, h.root.MakeFullString(false))
}

func (h *HistoryTree) String() string {
	if h == nil {
		return "HistoryTree<nil>"
	}
	h.lock.Lock()
	defer h.lock.Unlock()
	return fmt.Sprintf("HistoryTree%s", h._info())
}

func _newHistoryTree(da db.DataAdapter, rootHash []byte, checkPrecedingNil bool) (*HistoryTree, error) {
	var expecting uint64
	var rootNode *TreeNode
	if len(rootHash) != common.HashLength || bytes.Compare(common.NilHashSlice, rootHash) == 0 {
		// root node is nil
	} else {
		rootNode = NewTreeNode()
		if err := rootNode.putValue(da, nil, rootHash); err != nil {
			return nil, err
		}
		prefix, _, _, err := findRightmost(rootNode, da, checkPrecedingNil)
		if err != nil {
			return nil, err
		}
		if len(prefix) != HistoryTreeDepth {
			// nibble slice has a mismatching length
			return nil, common.ErrIllegalStatus
		}
		height, err := prefixToHeight(prefix)
		if err != nil {
			return nil, err
		}
		expecting = height + 1
	}
	tree := &HistoryTree{
		expecting: expecting,
		root:      rootNode,
		adapter:   da,
	}
	log.Debugf("NewHistoryTree(root:%x) = %s successed", rootHash, tree)
	return tree, nil
}

func NewHistoryTree(dbase db.Database, rootHash []byte, checkPrecedingNil bool) (*HistoryTree, error) {
	adapter := db.NewKeyPrefixedDataAdapter(dbase, db.KPHistoryNode)
	return _newHistoryTree(adapter, rootHash, checkPrecedingNil)
}

func RestoreTreeFromProofs(dbase db.Database, key uint64, value []byte, proofs ProofChain) (tree *HistoryTree, err error) {
	if len(value) != common.HashLength || len(proofs) != HistoryTreeDepth {
		return nil, common.ErrIllegalParams
	}
	adapter := db.NewKeyPrefixedDataAdapter(dbase, db.KPHistoryNode)

	last := HistoryTreeDepth - 1
	prefix := heightToPrefix(key)

	nodes := make([]*TreeNode, HistoryTreeDepth)

	for i := 0; i < HistoryTreeDepth; i++ {
		if i == 0 {
			// leaf node
			nodes[i], err = newNodeByProof(adapter, int(prefix[last-i]), value, nil, proofs[i].ChildProofs)
		} else {
			// non-leaf node
			nodes[i], err = newNodeByProof(adapter, int(prefix[last-i]), nil, nodes[i-1], proofs[i].ChildProofs)
		}
		if err != nil {
			return nil, err
		}
	}

	// create tree
	tree = &HistoryTree{
		expecting: key + 1,
		root:      nodes[last],
		adapter:   adapter,
	}
	return tree, nil
}

func heightToPrefix(key uint64) []byte {
	buf := make([]byte, 8)
	// uint64 to 8 bytes in big-endian
	binary.BigEndian.PutUint64(buf, key)
	// 8 bytes in big-endian to nibbles
	prefix := keyToPrefix(buf)
	return prefix
}

func prefixToHeight(prefix []byte) (uint64, error) {
	if len(prefix) != HistoryTreeDepth {
		return 0, common.ErrIllegalParams
	}
	key := prefixToKey(prefix)
	return binary.BigEndian.Uint64(key), nil
}

func findRightmost(root *TreeNode, adapter db.DataAdapter, checkPrecedingNil bool) (prefixToLeaf []byte,
	rightmostNode *TreeNode, rightmostLeaf []byte, err error) {
	if root == nil {
		return nil, nil, nil, common.ErrNil
	}
	node := root
	prefixToLeaf = make([]byte, 0)
	for i := 0; i < HistoryTreeDepth; i++ {
		if node.isCollapsed() {
			err = node.expand(adapter)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		if node.IsLeaf() {
			index, leaf := node.rightmostLeaf(checkPrecedingNil)
			if index < 0 || leaf == nil {
				// missing leaf node
				return nil, nil, nil, ErrMissingValue
			}
			if index >= childrenLength {
				// out of bound, should not be here
				return nil, nil, nil, common.ErrUnknown
			}
			prefixToLeaf = append(prefixToLeaf, byte(index))
			return prefixToLeaf, node, leaf, nil
		} else {
			index, child := node.rightmostChild(checkPrecedingNil)
			if index < 0 || child == nil {
				log.Errorf("ErrMissingChild: i=%d prefix:%x index=%d child==nil:%t", i, prefixToLeaf, index, child == nil)
				// missing child
				return nil, nil, nil, ErrMissingChild
			}
			if index >= childrenLength {
				// should not be here
				return nil, nil, nil, common.ErrUnknown
			}
			prefixToLeaf = append(prefixToLeaf, byte(index))
			node = child
		}
	}
	// out of max height
	return nil, nil, nil, common.ErrIllegalStatus
}

type nodeTracer struct {
	pos       byte      // selected child is which index of the current node (0-15)
	nodeInPos *TreeNode // parent[pos] == nodeInPos
}

// starting from start node, along the path specified by prefix, locate the node pointed
// to by prefix and return. If tracers is not nil, the location path will be stored in
// tracers in order.
// lastNode: The parent node of the target node or leaf value. If the parent node is not
//           located, it is nil
// index: The position of the target node or leaf value in its parent node, if the target
//        node or leaf value does not exist, return -1
// value: Target leaf value, nil if it does not exist.
// exist: Whether the target node or leaf value exists
// err: error
func locateNode(start *TreeNode, prefix []byte, adapter db.DataAdapter, tracers *[]nodeTracer) (lastNode *TreeNode,
	index int, value []byte, exist bool, err error) {
	if start == nil {
		return nil, -1, nil, false, common.ErrNotFound
	}
	node := start
	if len(prefix) > HistoryTreeDepth {
		return nil, -1, nil, false, common.ErrIllegalParams
	}
	for i := 0; i < len(prefix); i++ {
		index := int(prefix[i])
		if index >= childrenLength {
			return nil, -1, nil, false, common.ErrIllegalParams
		}
		if node.isCollapsed() {
			err = node.expand(adapter)
			if err != nil {
				return nil, -1, nil, false, err
			}
		}
		if node.IsLeaf() {
			if i != (len(prefix) - 1) {
				// reaches the leaf node without the prefix ending, error
				return nil, -1, nil, false, common.ErrIllegalParams
			}
			if node.Leafs[int(prefix[i])] == nil {
				return node, -1, nil, false, nil
			} else {
				return node, index, node.Leafs[index], true, nil
			}
		} else {
			if i == (len(prefix) - 1) {
				// return nil, -1, nil, false, common.ErrIllegalParams
				// found result in advance
				if node.Children[index] != nil {
					return node, index, nil, true, nil
				} else {
					return node, -1, nil, false, nil
				}
			}
			if node.Children[index] == nil {
				return node, -1, nil, false, nil
			} else {
				node = node.Children[index]
				if tracers != nil {
					*tracers = append(*tracers, nodeTracer{pos: prefix[i], nodeInPos: node})
				}
			}
		}
	}
	// should not be here
	return nil, -1, nil, false, common.ErrUnknown
}

func (h *HistoryTree) Rebase(dbase db.Database) (*HistoryTree, error) {
	if h == nil {
		return nil, nil
	}
	h.lock.Lock()
	defer h.lock.Unlock()

	if err := h._commit(); err != nil {
		return nil, err
	}
	root, err := h._hashValue()
	if err != nil {
		return nil, err
	}
	return NewHistoryTree(dbase, root, false)
}

func (h *HistoryTree) Clone() *HistoryTree {
	if h == nil {
		return nil
	}
	h.lock.Lock()
	defer h.lock.Unlock()

	_ = h._commit()
	root, _ := h._hashValue()
	ht, _ := _newHistoryTree(h.adapter.Clone(), root, false)
	return ht
}

func (h *HistoryTree) _hashValue() ([]byte, error) {
	if h == nil || h.root == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	return h.root.HashValue()
}

func (h *HistoryTree) HashValue() ([]byte, error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h._hashValue()
}

func (h *HistoryTree) CommitAndHash() ([]byte, error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	if err := h._commit(); err != nil {
		return nil, fmt.Errorf("commit failed: %v", err)
	}
	root, err := h._hashValue()
	if err != nil {
		return nil, fmt.Errorf("hash failed: %v", err)
	}
	return root, nil
}

func (h *HistoryTree) CollapseBefore(key uint64) error {
	h.lock.Lock()
	defer h.lock.Unlock()
	prefix := heightToPrefix(key)
	if len(prefix) != HistoryTreeDepth {
		return common.ErrIllegalParams
	}
	lastNoneZeroPos := HistoryTreeDepth
	for ; lastNoneZeroPos > 0; lastNoneZeroPos-- {
		if prefix[lastNoneZeroPos-1] != 0x0 {
			break
		}
	}
	if lastNoneZeroPos == HistoryTreeDepth || lastNoneZeroPos == 0 {
		// The lowest bit is not zero or the prefix is all zeros, then no folding is required
		return nil
	}
	parentNode, index, _, exist, err := locateNode(h.root, prefix[:lastNoneZeroPos], h.adapter, nil)
	if err != nil {
		return err
	}
	if !exist || parentNode == nil {
		return ErrNotExist
	}
	if index <= 0 {
		return common.ErrUnknown
	}
	if parentNode.IsLeaf() {
		return common.ErrIllegalStatus
	}
	if parentNode.Children[index-1].isDirty {
		return common.ErrIllegalStatus
	}
	// fmt.Printf("going to collapse node at %s.%d\n", prefixToHexstring(prefixString[:lastNoneZeroPos-1]), index-1)
	return parentNode.Children[index-1].collapse(h.adapter)
}

// append at the end in order, if key != expecting, or value is empty, return ErrIllegalParams
func (h *HistoryTree) Append(key uint64, value []byte) (err error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if key != h.expecting {
		return common.ErrIllegalParams
	}

	if len(value) == 0 {
		return common.ErrIllegalStatus
	}

	prefix := heightToPrefix(key)

	current := h.root
	if current == nil {
		h.root = NewTreeNode()
		current = h.root
		current.isLeaf = false
	}

	// Use the recursive method to easily set the isDirty of the node on the path
	changed, err := current.appendDescendant(h.adapter, prefix, 0, value)
	if err != nil {
		return err
	}
	if changed {
		h.expecting++
	}

	return nil
}

func (h *HistoryTree) Has(key uint64) bool {
	h.lock.Lock()
	defer h.lock.Unlock()

	_, exist := h.Get(key)
	return exist
}

func (h *HistoryTree) Get(key uint64) (value []byte, exist bool) {
	h.lock.Lock()
	defer h.lock.Unlock()

	prefix := heightToPrefix(key)
	var err error
	_, value, exist, err = h.root.traceDescendant(h.adapter, prefix, 0, false, nil)
	if err != nil {
		return nil, false
	}
	return common.CopyBytes(value), exist
}

func (h *HistoryTree) GetProof(key uint64) (value []byte, proofs ProofChain, ok bool) {
	if h == nil {
		return nil, nil, false
	}
	h.lock.Lock()
	defer h.lock.Unlock()

	if h.root == nil {
		return nil, nil, false
	}
	prefix := heightToPrefix(key)
	tracers := make([]nodeTracer, 1)
	tracers[0] = nodeTracer{pos: 0xff, nodeInPos: h.root}
	_, index, value, exist, err := locateNode(h.root, prefix, h.adapter, &tracers)
	if err != nil {
		log.Errorf("HistoryTree.GetProof error %v", err)
		return nil, nil, false
	}
	if !exist || index < 0 {
		return nil, nil, false
	}

	for i := len(tracers) - 1; i >= 0; i-- {
		node := tracers[i].nodeInPos
		_, _, proof, err := node.makeProof(index)
		if err != nil {
			log.Errorf("HistoryTree.GetProof error: %v", err)
			return nil, nil, false
		}
		proofs = append(proofs, NewMerkleOnlyProof(ProofMerkleOnly, proof))
		index = int(tracers[i].pos)
	}

	return common.CopyBytes(value), proofs, true
}

// Merge the proofs under the same rootHash into the tree
func (h *HistoryTree) MergeProof(key uint64, value []byte, proofs ProofChain) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if len(value) != common.HashLength || proofs == nil {
		return errors.New("value or proofs is nil")
	}
	if h.root == nil {
		return errors.New("historytree is nil")
	}
	// proofsKey, _ := proofs.Key()
	proofsKey := proofs.BigKey().Uint64()
	if proofsKey != key {
		return fmt.Errorf("key and proofs is not match, KEY:%d but Proofs.Key():%d", key, proofsKey)
	}

	// Check whether it is the content of the same tree
	root, err := h._hashValue()
	if err != nil {
		return common.NewDvppError("get history tree root hash error", err)
	}
	proofRoot, err := proofs.Proof(common.BytesToHash(value))
	if err != nil {
		return fmt.Errorf("get proofs(%s) root error: %v", proofs, err)
	}
	if !bytes.Equal(root, proofRoot) {
		return errors.New("proofs is not created from the same tree")
	}

	prefix := heightToPrefix(key)
	tracers := make([]nodeTracer, 0)
	_, _, leafvalue, exist, err := locateNode(h.root, prefix, h.adapter, &tracers)
	if err != nil {
		return fmt.Errorf("locateNode by %d -> (%x) failed: %v", key, prefix, err)
	}
	if exist {
		if bytes.Equal(value, leafvalue) {
			// the merging value already exists
			return nil
		}
		// target leaf node already exists, and the values are not match
		return fmt.Errorf("want value(%x), but found a different leaf(%x) in the tree",
			common.ForPrint(value), common.ForPrint(leafvalue))
	}
	nodes := make([]*TreeNode, HistoryTreeDepth)
	last := HistoryTreeDepth - 1
	// Place root and existing nodes on the path into the nodes list in reverse order
	nodes[last] = h.root
	for i := 0; i < len(tracers); i++ {
		nodes[last-1-i] = tracers[i].nodeInPos
	}

	// Create missing node or complement information from bottom to top
	for i := 0; i < HistoryTreeDepth; i++ {
		if nodes[i] == nil {
			// creating when the node is missing
			if i == 0 {
				// leaf node
				nodes[i], err = newNodeByProof(h.adapter, int(prefix[last-i]), value, nil, proofs[i].ChildProofs)
			} else {
				// non-leaf node
				nodes[i], err = newNodeByProof(h.adapter, int(prefix[last-i]), nil, nodes[i-1], proofs[i].ChildProofs)
			}
			if err != nil {
				return fmt.Errorf("newNodeByProof(%d) at %d error: %v", int(prefix[last-i]), i, err)
			}
		} else {
			// merge when the node already exists
			if i == 0 {
				err = nodes[i].mergeProof(h.adapter, int(prefix[last-i]), value, nil, proofs[i].ChildProofs)
			} else {
				err = nodes[i].mergeProof(h.adapter, int(prefix[last-i]), nil, nodes[i-1], proofs[i].ChildProofs)
			}
			if err != nil {
				return fmt.Errorf("mergeProof(%d) at %d error: %v", int(prefix[last-i]), i, err)
			}
		}
	}
	return nil
}

func (h *HistoryTree) _commit() (err error) {
	if h == nil || h.root == nil {
		return nil
	}
	return h.root.commitNode(h.adapter)
}

func (h *HistoryTree) Commit() error {
	h.lock.Lock()
	defer h.lock.Unlock()
	return h._commit()
}

// In order to be able to serialize and deserialize, there can be no undetermined
// type (interface{}, or interfaces), so it cannot be made into an infinite level tree.
//
// Each treenode is a 4-level complete binary tree composed of up to 16 child nodes.
//
// In branchs, use "" as the key to store the root hash of the current node, and "0"
// to store the root hash of all binary subtrees prefixed with 0. Similarly, "1", "00",
// "01", "10", "11", "000", "001", "010", "011", "100", "101", "110" and "111" are the
// root hash of subtrees prefixed with themselves
//
// Leafs stores the hash values of all leaf nodes
type TreeNode struct {
	isDirty  bool                      // whether the current node data has changed. If the data has changed, it needs to be re serialized
	isLeaf   bool                      // Whether the current node is a leaf node. As a HistoryTree with fixed height (8 bytes or 16 nibbles), the TreeNode represented by the last nibble is the leaf node
	Branchs  map[string][]byte         // key (binary prefix code string) - > hash of lower level
	Children [childrenLength]*TreeNode // current node is a non-leaf node: the index corresponds to the child node, not used with Leafs in the same time
	Leafs    [childrenLength][]byte    // current node is a leaf node: hash value of leaf node, index is the last nibble of the key in binary tree, not used with Children in the same time
}

func NewTreeNode() *TreeNode {
	return &TreeNode{
		Branchs: make(map[string][]byte),
	}
}

// When value is a legal hash value, a new leaf node is generated. Otherwise, when the
// child is not nil, a new non leaf node is generated.
func newNodeByProof(adapter db.DataAdapter, index int, value []byte, child *TreeNode,
	proof *common.MerkleProofs) (rn *TreeNode, err error) {
	if index < 0 || index >= childrenLength ||
		(len(value) != common.HashLength && child == nil) ||
		proof == nil || proof.Len() != ValueKeyLength {
		return nil, common.ErrIllegalParams
	}

	node := &TreeNode{
		isLeaf:  len(value) == common.HashLength, // If value is a legal hash value, it is a leaf node
		Branchs: make(map[string][]byte),
	}
	if err := node.mergeProof(adapter, index, value, child, proof); err != nil {
		return nil, err
	}
	return node, nil
}

// Converts a byte to a binary byte array, where each byte is 0x0 or 0x1
func ToBinary(b byte, length int) ([]byte, error) {
	if length > 8 || length < 1 {
		return nil, common.ErrUnsupported
	}
	bs := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		bs[i] = b & 0x1 // 每个字节都是0x0或0x1，不是'0' '1'
		b = b >> 1
	}
	return bs, nil
}

// The binary byte array represented by bs is restored to a byte. Each byte of bs is 0x0 or
// 0x1, and supports up to 8 bits of binary
func ToByte(bs []byte) (byte, error) {
	if len(bs) > 8 {
		return 0, common.ErrUnsupported
	}
	var b byte
	var i uint
	l := uint(len(bs))
	for i = 0; i < l; i++ {
		if bs[i] == 0x1 {
			b |= 0x1 << (l - i - 1)
		}
	}
	return b, nil
}

func (n *TreeNode) copy() (*TreeNode, error) {
	if n == nil {
		return nil, nil
	}
	root, _, _, err := n.HashAtPrefix(nil)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	node := NewTreeNode()
	node.Branchs[""] = root
	node.isLeaf = n.isLeaf
	return node, nil
}

func (n *TreeNode) Reset() {
	n.Branchs = make(map[string][]byte)
	for i := 0; i < childrenLength; i++ {
		n.Children[i] = nil
		n.Leafs[i] = nil
	}
	n.isDirty = false
}

func (n *TreeNode) hasChild() bool {
	for i := 0; i < childrenLength; i++ {
		if n.Children[i] != nil {
			return true
		}
	}
	return false
}

// check lower level nodes
// hasChild: whether a child node exists
// missingChild: whether there should be child nodes, but it is not in this list (for example,
//               the node generated by the proof is not all nodes)
func (n *TreeNode) checkChildren() (hasChild bool, missingChild bool, lastChild int) {
	alreadyNil := false
	lastChild = -1
	for i := 0; i < childrenLength; i++ {
		if n.Children[i] != nil {
			hasChild = true
			lastChild = i
			if alreadyNil {
				missingChild = true
			}
		} else {
			alreadyNil = true
		}
	}
	return
}

func (n *TreeNode) rightmostChild(checkPrecedingNil bool) (index int, child *TreeNode) {
	index = -1
	for i := 0; i < childrenLength; i++ {
		if n.Children[i] != nil {
			index = i
			child = n.Children[i]
			// once a non-nil value presented, it returns immediately when nil present.
			// That is, only preceding continuous nil is allowed
			checkPrecedingNil = true
		} else {
			if checkPrecedingNil {
				return
			}
		}
	}
	// return childrenLength - 1, child
	return
}

func (n *TreeNode) hasLeaf() bool {
	for i := 0; i < childrenLength; i++ {
		if n.Leafs[i] != nil {
			return true
		}
	}
	return false
}

// check leaf nodes
// hasLeaf: whether a leaf node exists
// missingLeaf: whether there should be leaf nodes but not in this list (for example, the nodes
//              generated by the proof are not full nodes)
func (n *TreeNode) checkLeafs() (hasLeaf bool, missingLeaf bool, lastLeaf int) {
	alreadyNil := false
	lastLeaf = -1
	for i := 0; i < childrenLength; i++ {
		if n.Leafs[i] != nil {
			hasLeaf = true
			lastLeaf = i
			if alreadyNil {
				missingLeaf = true
			}
		} else {
			alreadyNil = true
		}
	}
	return
}

func (n *TreeNode) rightmostLeaf(checkPrecedingNil bool) (index int, leaf []byte) {
	index = -1
	for i := 0; i < childrenLength; i++ {
		if n.Leafs[i] != nil {
			index = i
			leaf = n.Leafs[i]
			// once a non-nil value presented, it returns immediately when nil present.
			// That is, only preceding continuous nil is allowed
			checkPrecedingNil = true
		} else {
			if checkPrecedingNil {
				return
			}
		}
	}
	// return childrenLength - 1, leaf
	return
}

func (n *TreeNode) isEmpty() bool {
	if len(n.Branchs) > 0 {
		return false
	}
	if n.isLeaf {
		return !n.hasLeaf()
	}
	return !n.hasChild()
}

func (n *TreeNode) isCollapsed() bool {
	if len(n.Branchs) != 1 {
		return false
	}
	_, exist := n.Branchs[""]
	if !exist {
		return false
	}
	if n.isLeaf && n.hasLeaf() == false {
		return true
	}
	if n.isLeaf == false && n.hasChild() == false {
		return true
	}
	return false
}

func (n *TreeNode) IsLeaf() bool {
	return n.isLeaf
}

func (n *TreeNode) expand(adapter db.DataAdapter) error {
	if n.isCollapsed() == false {
		return common.ErrIllegalStatus
	}
	root, exist := n.Branchs[""]
	if !exist || len(root) == 0 {
		return common.ErrNotFound
	}
	err := n.readFull(root, adapter)
	// fmt.Printf("expand node from %x\n", root)
	return err
}

func (n *TreeNode) collapse(adapter db.DataAdapter) error {
	if n.isCollapsed() {
		return nil
	}
	if n.isDirty {
		err := n.saveFull(adapter)
		if err != nil {
			return err
		}
		if n.isDirty {
			// save failed with no error??
			return nil
		}
	}
	h, _, _, err := n.HashAtPrefix(nil)
	if err != nil {
		return err
	}
	n.Reset()
	n.Branchs[string([]byte(nil))] = h
	// fmt.Printf("node collapsed to %x\n", h)
	return nil
}

func (n *TreeNode) commitNode(adapter db.DataAdapter) (err error) {
	if !n.isDirty {
		return nil
	}
	if n.isLeaf {
		if err = n.saveFull(adapter); err == nil {
			n.isDirty = false
		}
		return err
	}
	for i := 0; i < childrenLength; i++ {
		if n.Children[i] != nil && n.Children[i].isDirty {
			if err := n.Children[i].commitNode(adapter); err != nil {
				return err
			}
		}
	}
	if err = n.saveFull(adapter); err == nil {
		n.isDirty = false
	}
	return err
}

// Add a method to save TreeNode for ordinary nodes (SPEC/COMM)
// In order to enable the new node to synchronize the main chain data from the surrounding nodes,
// it is necessary that not only the data node and the memo node save the data of HistoryTree.
// Because other nodes do not have full history data, they need to write to disk in different ways
// according to different situations.
// 1. If all leaves exist in the node, only leaves are written
// 2. Otherwise, if the missing data on Leafs can find the data in the corresponding Branchs through
//    its prefix, it will be saved together with the corresponding Branchs data

type serialNode struct {
	IsLeaf          bool                   // Is it a leaf node
	NeededBranchs   map[string][]byte      // Copy of Branchs
	ChildrenOrLeafs [childrenLength][]byte // It stores values of the leaf if IsLeaf is true, or stores children's hash
}

func (sn *serialNode) String() string {
	return fmt.Sprintf("sn{Leaf:%t Branchs:%x Child:%x}", sn.IsLeaf, sn.NeededBranchs, sn.ChildrenOrLeafs)
}

// for serialization only
func (n *TreeNode) toSerialNode() (sn *serialNode, err error) {
	if n == nil {
		return nil, nil
	}
	sn = new(serialNode)
	sn.IsLeaf = n.isLeaf
	sn.NeededBranchs = n.Branchs
	if sn.IsLeaf {
		for i := 0; i < childrenLength; i++ {
			if n.Leafs[i] != nil {
				sn.ChildrenOrLeafs[i] = n.Leafs[i]
			}
		}
	} else {
		for i := 0; i < childrenLength; i++ {
			if n.Children[i] != nil {
				sn.ChildrenOrLeafs[i], _, _, err = n.Children[i].HashAtPrefix(nil)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return sn, nil
}

// for de-serialization only
func (n *TreeNode) fromSerialNode(adapter db.DataAdapter, sn *serialNode) {
	if sn == nil {
		return
	}
	n.isLeaf = sn.IsLeaf
	for i := 0; i < childrenLength; i++ {
		n.Children[i] = nil
		n.Leafs[i] = nil
	}
	n.Branchs = sn.NeededBranchs
	if n.isLeaf {
		n.Leafs = sn.ChildrenOrLeafs
	} else {
		for i := 0; i < childrenLength; i++ {
			if sn.ChildrenOrLeafs[i] != nil {
				n.Children[i] = NewTreeNode()
				_ = n.Children[i].putValue(adapter, []byte(""), sn.ChildrenOrLeafs[i])
			}
		}
	}
	n.isDirty = false
}

func (n *TreeNode) saveEntireNode(root []byte, _ int, adapter db.DataAdapter) error {
	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(buf)
	buf.Reset()
	// the first byte: 0xff, represents this is a serialization of *serialNode
	buf.WriteByte(0xff)
	sn, err := n.toSerialNode()
	if err != nil {
		return err
	}
	if err = rtl.Encode(sn, buf); err != nil {
		return err
	}
	if err = adapter.Save(root, buf.Bytes()); err != nil {
		return err
	}
	n.isDirty = false
	return nil
}

// Only the real data, that is, the hash value of children or leafs, is saved, and the data in
// Branchs does not need to be saved
// If the value of children / leaves of the node is missing (nil value exists to the left of the
// rightmost non nil value), it will not be saved because it is temporary data, For example, the
// proof of the last data synchronized from the data node is meaningless and can only be used to
// verify and generate a new hash
func (n *TreeNode) saveFull(adapter db.DataAdapter) error {
	if n == nil {
		return nil
	}
	if n.isDirty == false {
		return nil
	}

	root, _, _, err := n.HashAtPrefix(nil)
	if err != nil {
		return err
	}
	if root == nil {
		// current node is empty
		return nil
	}

	saveEntire := false
	lastIndex := -1
	if n.isLeaf {
		hasLeaf, missingLeaf, lastLeaf := n.checkLeafs()
		if hasLeaf == false || missingLeaf == true || lastLeaf < (childrenLength-1) {
			// If there is no leaf data or missing leaf data (i.e. not all nodes), you need to
			// save the whole node data
			saveEntire = true
			lastIndex = lastLeaf
		}
	} else {
		hasChild, missingChild, lastChild := n.checkChildren()
		if hasChild == false || missingChild == true || lastChild < (childrenLength-1) {
			// save the whole node data
			saveEntire = true
			lastIndex = lastChild
		}
	}

	if saveEntire {
		return n.saveEntireNode(root, lastIndex, adapter)
	}

	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(buf)
	buf.Reset()
	// The first byte is not 0xff, which means only the value is stored
	if n.isLeaf {
		buf.WriteByte(0x1)
	} else {
		buf.WriteByte(0x0)
	}
	err = n.encodeDescendants(buf)
	if err != nil {
		return err
	}
	if err = adapter.Save(root, buf.Bytes()); err != nil {
		return err
	} else {
		// log.Infof("save full node(%s) Key:%x", n.NoneRecursiveString(), root)
	}
	n.isDirty = false
	return err
}

// Recover the node data from the database, only recover the real data, that is, the hash value
// of children or leaves
func (n *TreeNode) readFull(root []byte, adapter db.DataAdapter) error {
	if n == nil {
		return common.ErrNil
	}

	n.Reset()
	if len(root) == 0 || bytes.Compare(root, common.NilHashSlice) == 0 {
		return nil
	}

	content, err := adapter.Load(root)
	if err != nil {
		return err
	}

	if len(content) == 0 {
		return nil
	}

	loadEntire := false

	// When the first byte is 0xff, it indicates that the content is the serialization of the
	// *serialNode; otherwise, it indicates that the content is only the value
	if content[0] == 0x1 {
		n.isLeaf = true
	} else if content[0] == 0x0 {
		n.isLeaf = false
	} else if content[0] == 0xff {
		loadEntire = true
	} else {
		return common.ErrIllegalStatus
	}

	buf := bytes.NewBuffer(content[1:])
	vr := rtl.NewValueReader(buf, 0)
	if loadEntire {
		sn := new(serialNode)
		if err = rtl.Decode(vr, sn); err != nil {
			return err
		}
		n.fromSerialNode(adapter, sn)
	} else {
		err = n.decodeDescendants(adapter, vr)
	}
	return err
}

// Remove all ancestors on the path indicated by prefix from the Branchs cache
func (n *TreeNode) clearAncestors(prefix []byte) error {
	if len(prefix) == 0 {
		return nil
	}
	l := len(prefix)
	if l >= ValueKeyLength {
		prefix = prefix[:3]
		l = 3
	}
	for i := 0; i < l; i++ {
		if prefix[i] > 0x1 {
			return common.ErrIllegalParams
		}
	}

	for i := 0; i <= l; i++ {
		delete(n.Branchs, string(prefix[:l-i]))
	}
	return nil
}

func (n *TreeNode) putValue(adapter db.DataAdapter, prefix []byte, hashs []byte) error {
	if n.isCollapsed() {
		if adapter == nil {
			return common.ErrNoAdapter
		}
		if err := n.expand(adapter); err != nil {
			return common.ErrIllegalStatus
		}
	}
	if len(prefix) >= ValueKeyLength {
		return common.ErrUnsupported
	}
	// check for legitimacy
	for i := 0; i < len(prefix); i++ {
		if prefix[i] > 0x1 {
			return common.ErrIllegalParams
		}
	}
	n.Branchs[string(prefix)] = common.CopyBytes(hashs)
	return nil
}

func (n *TreeNode) putChild(index int, child *TreeNode, appendCheck bool) error {
	if n.isCollapsed() {
		return common.ErrIllegalStatus
	}
	if n.isLeaf {
		// it's a leaf node, leafs can be set only
		return common.ErrIllegalStatus
	}
	if index < 0 || index >= childrenLength {
		return common.ErrIllegalParams
	}
	if appendCheck {
		// Check whether new nodes are added in strict order
		for i := 0; i < index; i++ {
			if n.Children[i] == nil {
				return ErrMissingChild
			}
		}
	}
	n.Children[index] = child
	prefix, _ := ToBinary(byte(index), ValueKeyLength)
	_ = n.clearAncestors(prefix)
	n.isDirty = true
	return nil
}

func (n *TreeNode) putLeaf(index int, value []byte, appendCheck bool) error {
	if n.isCollapsed() {
		return common.ErrIllegalStatus
	}
	if n.isLeaf == false {
		// it's a non-leaf node, child node can be set only
		return common.ErrIllegalStatus
	}
	if index < 0 || index >= childrenLength || len(value) == 0 {
		return common.ErrIllegalParams
	}
	if appendCheck {
		// Check whether new nodes are added in strict order
		for i := 0; i < index; i++ {
			if n.Leafs[i] == nil {
				return ErrMissingValue
			}
		}
	}
	n.Leafs[index] = common.CopyBytes(value)
	// fmt.Printf("putLeaf(%x, %x, %t)\n%v\n", index, value, appendCheck, n)
	prefix, _ := ToBinary(byte(index), ValueKeyLength)
	_ = n.clearAncestors(prefix)
	n.isDirty = true
	return nil
}

func (n *TreeNode) mergeProof(adapter db.DataAdapter, index int, value []byte, child *TreeNode,
	proof *common.MerkleProofs) error {
	if n == nil {
		return common.ErrNil
	}
	if n.isLeaf {
		n.Leafs[index] = common.CopyBytes(value)
	} else {
		n.Children[index] = child
	}

	bs, _ := ToBinary(byte(index), ValueKeyLength)
	for i := 0; i < ValueKeyLength; i++ {
		h, _, err := proof.Get(i)
		if err != nil {
			return err
		}
		if !h.IsNil() {
			// reverse the last bit
			bs[len(bs)-1] = (^bs[len(bs)-1]) & 0x1
			if i == 0 {
				if !h.IsNil() {
					// leaf of tree in this node (height==4)
					p, _ := ToByte(bs)
					if n.isLeaf {
						n.Leafs[p] = common.CopyBytes(h[:])
					} else {
						if n.Children[p] == nil {
							// Creating a node with only root hash is equal to a collapsed node
							n.Children[p] = NewTreeNode()
							if err := n.Children[p].putValue(adapter, nil, h.Bytes()); err != nil {
								return err
							}
						} else {
							if err := n.Children[p].putValue(adapter, nil, h.Bytes()); err != nil {
								return err
							}
						}
					}
				}
			} else {
				// the middle layer node of merkle tree
				if err := n.putValue(adapter, bs, h.Bytes()); err != nil {
					return err
				}
			}
		}
		bs = bs[:len(bs)-1]
	}

	n.isDirty = true
	return nil
}

// append or get leaf value according to prefixString
// adapter: When the nodes on the path collapse, the data source is used to expand the nodes
// prefixString: each byte of prefixString represents a nibble of the key (height)
// offset: the index of prefixString is being processed
// append: true for appending，false for getting
// toBeAppend: appending value of the tree
// return changed: whether the data of current node has changed
// return value: target leaf data
// return exist: whether the target leaf data is existed
// return err: if there's an error occured
func (n *TreeNode) traceDescendant(adapter db.DataAdapter, prefixString []byte, offset int, append bool,
	toBeAppend []byte) (changed bool, value []byte, exist bool, err error) {
	if len(prefixString) <= offset {
		return false, nil, false, nil
	}
	if n.isCollapsed() {
		if err = n.expand(adapter); err != nil {
			return false, nil, false, err
		}
	}
	maxpos := len(prefixString) - 1
	if offset == maxpos && n.IsLeaf() == false {
		// the last nibble of prefix should be on the leaf node
		return false, nil, false, common.ErrIllegalParams
	}
	if offset < maxpos && n.IsLeaf() {
		// meet the leaf node too early
		return false, nil, false, common.ErrIllegalParams
	}
	index := int(prefixString[offset])
	if n.IsLeaf() {
		if append {
			err = n.putLeaf(index, toBeAppend, false)
			if err != nil {
				return false, nil, false, err
			} else {
				return true, n.Leafs[index], true, nil
			}
		} else {
			exist = n.Leafs[index] != nil
			return false, n.Leafs[index], exist, nil
		}
	} else {
		// non-leaf node
		if n.Children[index] != nil {
			changed, value, exist, err = n.Children[index].traceDescendant(adapter, prefixString, offset+1,
				append, toBeAppend)
			if changed {
				prefixInNode, _ := ToBinary(prefixString[offset], ValueKeyLength)
				_ = n.clearAncestors(prefixInNode)
				n.isDirty = true
			}
			return
		} else {
			if append {
				newnode := NewTreeNode()
				// create a leaf node if next nibble is the last one
				if offset+1 == maxpos {
					newnode.isLeaf = true
				} else {
					newnode.isLeaf = false
				}
				changed, value, exist, err = newnode.traceDescendant(adapter, prefixString, offset+1, append, toBeAppend)
				if err != nil {
					return false, nil, false, err
				}
				n.Children[index] = newnode
				prefixInNode, _ := ToBinary(prefixString[offset], ValueKeyLength)
				_ = n.clearAncestors(prefixInNode)
				n.isDirty = true
				return true, value, exist, nil
			} else {
				return false, nil, false, nil
			}
		}
	}
}

func (n *TreeNode) appendDescendant(adapter db.DataAdapter, prefixString []byte, offset int, value []byte) (
	changed bool, err error) {
	changed, _, _, err = n.traceDescendant(adapter, prefixString, offset, true, value)
	return
}

func (n *TreeNode) HashValue() ([]byte, error) {
	if n == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}

	r, _, _, err := n.HashAtPrefix(nil)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	return r, nil
}

// Computes the root hash of the subtree indicated by the specified prefix
// If there are no nodes under the subtree, return nil
// If a node is missing in any step, NilHash is used instead
// leftIsNil, rightIsNil returns whether the left and right children are nil values when
// calculating the current node hash, and if err is not nil, the two values are meaningless.
func (n *TreeNode) HashAtPrefix(prefix []byte) (hashAtPrefix []byte, leftIsNil bool, rightIsNil bool, err error) {
	if len(prefix) > ValueKeyLength {
		return nil, false, false, common.ErrUnsupported
	}
	if len(prefix) == ValueKeyLength {
		p, err := ToByte(prefix)
		if err != nil {
			return nil, false, false, err
		}
		hashAtPrefix, err = n.LeafHash(int(p))
		return hashAtPrefix, false, false, err
	}
	r, exist := n.Branchs[string(prefix)]
	if exist && r != nil {
		return common.CopyBytes(r), false, false, nil
	}

	child := make([]byte, len(prefix)+1)
	copy(child, prefix)

	// left child
	left, lln, lrn, err := n.HashAtPrefix(child)
	if err != nil {
		return nil, false, false, err
	}
	// location = 6
	if lln && !lrn {
		// the left child of the left child has no value, and the right child of the left child
		// has value, this is an error state
		return nil, false, false, ErrMissingValue
	}

	// right child
	child[len(child)-1] = 0x1
	right, rln, rrn, err := n.HashAtPrefix(child)
	if err != nil {
		return nil, false, false, err
	}
	if rln && !rrn {
		// the left child of the right child has no value, and the right child of the right child
		// has value, this is an error state
		return nil, false, false, ErrMissingValue
	}
	if lrn && right != nil {
		if !lln {
			// Since the left child of the left child has a value, hash with one-sided calculation
			// will succeed and cached. The cached value will hide the fact that it has a child as
			// nil at the next time it is accessed. So this cache needs to be cleared.
			child[len(child)-1] = 0x0
			delete(n.Branchs, string(child))
		}
		// the right child of the left child has no value, and the right child has value, this is
		// an error state
		return nil, false, false, ErrMissingValue
	}

	if left == nil {
		if right == nil {
			// return nil if both child nodes of current node in the binary tree are nil
			return nil, true, true, nil
		} else {
			// it has already checked at "lrn && right!=nil", so it should not be here
			// left child has no value, and right child has value, this is an error state
			return nil, false, false, ErrMissingValue
		}
	} else {
		if right == nil {
			rightIsNil = true
			right = common.NilHashSlice
		}
	}

	h := common.HashPair(left, right)
	n.Branchs[string(prefix)] = common.CopyBytes(h)
	return h, leftIsNil, rightIsNil, nil
}

func (n *TreeNode) LeafHash(index int) (leafHash []byte, err error) {
	if index < 0 || index >= childrenLength {
		return nil, common.ErrIllegalParams
	}
	if n.isLeaf {
		return common.CopyBytes(n.Leafs[index]), nil
	} else {
		if n.Children[index] == nil {
			return nil, nil
		}
		leafHash, _, _, err = n.Children[index].HashAtPrefix(nil)
		return
	}
}

// generate merkle proof by specified index
// rootHash: root hash of current node
// toBeProof: hash of prooved position (specified by index)
// proof: merkle proof
func (n *TreeNode) makeProof(index int) (rootHash []byte, toBeProof []byte, proof *common.MerkleProofs, err error) {
	if n == nil {
		return nil, nil, nil, common.ErrNil
	}
	if index < 0 || index >= childrenLength {
		return nil, nil, nil, common.ErrIllegalParams
	}
	if (n.isLeaf && n.Leafs[index] == nil) || (n.isLeaf == false && n.Children[index] == nil) {
		// The proved position must have a value, because the whole tree is filled from left to
		// right, and the hash is also calculated from left to right. Nilhash can be filled only
		// in the last hash of each layer. Therefore, the leaves of nil value are not directly
		// involved in the calculation of roothash
		return nil, nil, nil, common.ErrNil
	}

	toBeProof = common.CopyBytes(n.Leafs[index])
	proof = common.NewMerkleProofs()

	var left, right []byte
	// layer1
	if index%2 == 0 {
		left, err = n.LeafHash(index)
		if err != nil {
			return nil, nil, nil, err
		}
		right, err = n.LeafHash(index + 1)
		if err != nil {
			return nil, nil, nil, err
		}
		if right == nil {
			right = common.NilHashSlice
		}
		proof.Append(common.BytesToHash(right), false)
	} else {
		left, err = n.LeafHash(index - 1)
		if err != nil {
			return nil, nil, nil, err
		}
		if left == nil {
			// Because it is a complete binary tree from left to right, the left side of non-nil value cannot be nil
			return nil, nil, nil, ErrMissingValue
		}
		right, err = n.LeafHash(index)
		if err != nil {
			return nil, nil, nil, err
		}
		proof.Append(common.BytesToHash(left), true)
	}
	rootHash = common.HashPair(left, right)

	// Layer 2-4, calculate the hash layer by layer from bottom to top, and record the proof path
	// convert index to 4-byte binary
	bits, err := ToBinary(byte(index), ValueKeyLength)
	for i := 2; i >= 0; i-- {
		if bits[i] == 0x0 {
			left = rootHash
			rightPrefix := make([]byte, i+1)
			copy(rightPrefix, bits[:i])
			rightPrefix[i] = 0x1
			right, _, _, err = n.HashAtPrefix(rightPrefix)
			if err != nil {
				return nil, nil, nil, err
			}
			if right == nil {
				right = common.NilHashSlice
			}
			proof.Append(common.BytesToHash(right), false)
		} else {
			leftPrefix := make([]byte, i+1)
			copy(leftPrefix, bits[:i])
			leftPrefix[i] = 0x0
			var lln, lrn bool
			left, lln, lrn, err = n.HashAtPrefix(leftPrefix)
			if err != nil {
				return nil, nil, nil, err
			}
			if left == nil || lln || lrn {
				return nil, nil, nil, ErrMissingValue
			}
			proof.Append(common.BytesToHash(left), true)
		}
		rootHash = common.HashPair(left, right)
	}
	return
}

func (n *TreeNode) MakeFullString(recursive bool) string {
	if n == nil {
		return "<nil>"
	}
	buf := bytes.NewBuffer(nil)
	for k, v := range n.Branchs {
		if buf.Len() > 0 {
			buf.WriteString(", ")
		}
		kk := []byte(k)
		for i := 0; i < len(kk); i++ {
			if kk[i] == 0x0 {
				buf.WriteByte('0')
			} else {
				buf.WriteByte('1')
			}
		}
		if recursive {
			buf.WriteByte(':')
			buf.WriteString(fmt.Sprintf("%x", v))
		}
	}
	branchStr := string(buf.Bytes())

	if n.isLeaf {
		buf.Reset()
		for i := byte(0); i < childrenLength; i++ {
			if n.Leafs[i] == nil {
				continue
			}
			if recursive {
				if buf.Len() > 0 {
					buf.WriteString(", ")
				}
			}
			buf.WriteByte(valuebyteToHexbyte(i))
			if recursive {
				buf.WriteByte(':')
				buf.WriteString(fmt.Sprintf("%x", n.Leafs[i]))
			}
		}
		leafStr := string(buf.Bytes())
		return fmt.Sprintf("Node{branchs:{%s} leafs:[%s]}", branchStr, leafStr)
	} else {
		buf.Reset()
		for i := byte(0); i < childrenLength; i++ {
			if n.Children[i] == nil {
				continue
			}
			if recursive {
				if buf.Len() > 0 {
					buf.WriteString(", ")
				}
			}
			buf.WriteByte(valuebyteToHexbyte(i))
			if recursive {
				buf.WriteByte(':')
				buf.WriteString(fmt.Sprintf("%s", n.Children[i].MakeFullString(recursive)))
			}
		}
		childrenStr := string(buf.Bytes())
		return fmt.Sprintf("Node{branchs:{%s} children:[%s]}", branchStr, childrenStr)
	}
}

func (n *TreeNode) NoneRecursiveString() string {
	return n.MakeFullString(false)
}

func (n *TreeNode) String() string {
	return n.MakeFullString(true)
}

func (n *TreeNode) encodeDescendants(w io.Writer) (err error) {
	if n.isLeaf {
		err = rtl.Encode(n.Leafs, w)
	} else {
		var hashslice [childrenLength][]byte
		for i := 0; i < childrenLength; i++ {
			if n.Children[i] != nil {
				hashslice[i], _, _, err = n.Children[i].HashAtPrefix(nil)
				if err != nil {
					return err
				}
			}
		}
		err = rtl.Encode(hashslice, w)
	}
	return
}

func (n *TreeNode) Serialization(w io.Writer) error {
	var err error
	if n == nil {
		_, err = w.Write([]byte{0x80})
		return err
	}
	if n.isLeaf {
		_, err = w.Write([]byte{0x1})
	} else {
		_, err = w.Write([]byte{0x0})
	}
	if err != nil {
		return err
	}
	err = rtl.Encode(n.Branchs, w)
	if err != nil {
		return err
	}
	err = n.encodeDescendants(w)
	return err
}

func (n *TreeNode) decodeDescendants(adapter db.DataAdapter, vr rtl.ValueReader) (err error) {
	var hashslice [childrenLength][]byte
	err = rtl.Decode(vr, &hashslice)
	if err != nil {
		return err
	}
	if n.isLeaf {
		n.Leafs = hashslice
	} else {
		for i := 0; i < childrenLength; i++ {
			if hashslice[i] == nil {
				n.Children[i] = nil
			} else {
				n.Children[i] = NewTreeNode()
				if err = n.Children[i].putValue(adapter, []byte(""), hashslice[i]); err != nil {
					return err
				}
			}
		}
	}
	return
}

func (n *TreeNode) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	flag := make([]byte, 1)
	_, err = r.Read(flag)
	if err != nil {
		return
	}
	if flag[0] == 0x80 {
		return true, nil
	}
	if flag[0] == 0x1 {
		n.isLeaf = true
	} else if flag[0] == 0 {
		n.isLeaf = false
	} else {
		return false, common.ErrIllegalStatus
	}

	// To read data continuously, make sure it's a valuereader
	vr, ok := r.(rtl.ValueReader)
	if !ok {
		vr = rtl.NewValueReader(r, 0)
	}

	err = rtl.Decode(vr, &(n.Branchs))
	if err != nil {
		return
	}

	err = n.decodeDescendants(nil, vr)
	return
}

// return new TreeNode without any child or leaf after index
func (n *TreeNode) _chop(index int, indexingChanged bool) (newnode *TreeNode, changed bool, err error) {
	if n == nil || index < 0 {
		return nil, false, nil
	}
	if index > (childrenLength - 1) {
		return nil, false, errors.New("illegal index")
	}
	node := NewTreeNode()
	node.isLeaf = n.isLeaf
	if n.isLeaf {
		if n.Leafs[index] == nil {
			return nil, false, fmt.Errorf("no leaf value at index:%d", index)
		}
		for i := 0; i <= index; i++ {
			node.Leafs[i] = common.CopyBytes(n.Leafs[i])
		}
		if index < (childrenLength-1) && n.Leafs[index+1] != nil {
			changed = true
		}
	} else {
		if n.Children[index] == nil {
			return nil, false, fmt.Errorf("no child node at index:%d", index)
		}
		for i := 0; i <= index; i++ {
			if n.Children[i] != nil {
				child, err := n.Children[i].copy()
				if err != nil {
					return nil, false, fmt.Errorf("copy child index:%d failed: %v", i, err)
				}
				node.Children[i] = child
			}
		}
		if index < (childrenLength-1) && n.Children[index+1] != nil {
			changed = true
		}
	}

	choped := make(map[string]struct{})
	i := index + 1
	if indexingChanged {
		i = index
	}
	for ; i < childrenLength; i = i + 2 {
		prefix, _ := ToBinary(byte(i), ValueKeyLength)
		for j := 0; j <= 3; j++ {
			choped[string(prefix[:3-j])] = struct{}{}
		}
	}
	for prefix, h := range n.Branchs {
		if _, exist := choped[prefix]; exist {
			changed = true
		} else {
			node.Branchs[prefix] = h
		}
	}
	return node, changed, nil
}

func (h *HistoryTree) Chop(byKey uint64) (*HistoryTree, error) {
	h.lock.Lock()
	defer h.lock.Unlock()
	prefix := heightToPrefix(byKey)
	cursor := h.root
	var newroot, lastnode, newnode *TreeNode
	var hasChanged bool
	var lastChangedI int
	var err error
	for i, index := range prefix {
		if cursor == nil {
			return nil, fmt.Errorf("no more node for index:%d of %d", i, prefix)
		}
		if cursor.isCollapsed() {
			if err = cursor.expand(h.adapter); err != nil {
				return nil, fmt.Errorf("expand node of index:%d prefix:%d failed: %v", i, prefix, err)
			}
		}
		var changed bool
		newnode, changed, err = cursor._chop(int(index), false)
		if err != nil || newnode == nil {
			return nil, fmt.Errorf("chop index:%d of %d failed: %v", i, prefix, err)
		}
		if changed {
			hasChanged = changed
			lastChangedI = i
		}
		if !cursor.isLeaf {
			cursor = cursor.Children[int(index)]
		}
		if i == 0 {
			newroot = newnode
		} else {
			lastnode.Children[prefix[i-1]] = newnode
		}
		lastnode = newnode
	}

	if hasChanged {
		cursor = newroot
		for i := 0; i < lastChangedI; i++ {
			changedPrefix, _ := ToBinary(prefix[i], ValueKeyLength)
			for j := 0; j <= 3; j++ {
				delete(cursor.Branchs, string(changedPrefix[:3-j]))
			}
			cursor = cursor.Children[prefix[i]]
		}
	}

	return &HistoryTree{
		expecting: byKey + 1,
		root:      newroot,
		adapter:   h.adapter,
	}, nil
}
