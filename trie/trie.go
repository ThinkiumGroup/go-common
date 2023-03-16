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
	"io"
	"reflect"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

const (
	maxGenSize   = 100
	maxValLength = 4096
)

var CheckNodeValueHash = false

func init() {
	dbase := db.NewMemDB()
	defer func() {
		_ = dbase.Close()
	}()

	type aaa struct {
		A int
	}

	na := db.NewKeyPrefixedDataAdapter(dbase, []byte("1"))
	va := db.NewKeyPrefixedDataAdapter(dbase, []byte("2"))
	t := NewTrieWithValueType(nil, na, va, reflect.TypeOf((*aaa)(nil)))
	var err error
	common.EmptyNodeHashSlice, err = t.HashValue()
	if err != nil {
		panic(err)
	}
	common.EmptyNodeHash = common.BytesToHash(common.EmptyNodeHashSlice)
	log.Debugf("trie.EmtpyNodeHash set to: %s", common.EmptyNodeHash)
}

type (
	ITrie interface {
		HashValue() (hashValue []byte, err error)
		Get(key []byte) (value interface{}, ok bool)
		Put(key []byte, value interface{}) bool
		PutValue(value TrieValue) bool
		Delete(key []byte) (changed bool, oldValue interface{})
		IsDirty() bool
		Commit() error
		// According to the key, the value object corresponding to the key and its proof chain
		// are returned. ok returns whether the corresponding value is found successfully and
		// the proof is generated
		GetProof(key []byte) (value interface{}, proof ProofChain, ok bool)
		GetExistenceProof(key []byte) (exist bool, proofs ProofChain, err error)
		ValueIterator() ValueIterator
	}

	Revertable interface {
		ITrie
		LiveValueIterator() ValueIterator
		PreHashValue() ([]byte, error)
		PreCommit() ([]byte, error)
		Rollback()
	}

	TrieValue interface {
		Key() []byte
	}

	Trie struct {
		root         *node
		nodeAdapter  db.DataAdapter
		valueAdapter db.DataAdapter
		valueCount   int

		lock sync.Mutex

		gen uint64
	}

	// Record the path node of trie search for a key
	// nodePosition{ pos: NodeA.Index, nodeInPos: NodeA.Children[NodeA.Index] }
	nodePosition struct {
		pos       byte  // the index which child selected of the current node (0-15)
		nodeInPos *node // child node of selected child in Children array by pos as index
	}
)

func newTrie(root *node, nadapter db.DataAdapter, vadapter db.DataAdapter) *Trie {
	return &Trie{
		root:         root,
		nodeAdapter:  nadapter,
		valueAdapter: vadapter,
		gen:          root.generation,
	}
}

func NewTrie(hash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter, valueType reflect.Type,
	hasher NodeValueHasher) *Trie {
	codec, err := rtl.NewStructCodec(valueType)
	if err != nil {
		panic(fmt.Errorf("new StructCodec error: %v", err))
	}
	return NewTrieWithValueFuncs(hash, nadapter, vadapter, codec.Encode, codec.Decode, hasher)
}

func NewTrieWithValueFuncs(hash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter,
	encode NodeValueEncode, decode NodeValueDecode, hasher NodeValueHasher) *Trie {
	root := NewNodeWithFuncs(hash, 1, encode, decode, hasher)
	return newTrie(root, nadapter, vadapter)
}

func NewTrieWithValueCodec(hash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter,
	encode NodeValueEncode, decode NodeValueDecode) *Trie {
	return NewTrieWithValueFuncs(hash, nadapter, vadapter, encode, decode, nil)
}

func NewTrieWithValueType(hash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter, valueType reflect.Type) *Trie {
	return NewTrie(hash, nadapter, vadapter, valueType, nil)
}

func (t *Trie) createNode(startNode *node, prefix []byte, childIndex int) *node {
	ret := NewNodeWithFuncs(nil, startNode.generation, startNode.valueEncode, startNode.valueDecode,
		startNode.valueHasher)
	if len(prefix) > 0 {
		ret.setPrefix(prefix)
	}
	if childIndex >= 0 {
		startNode.setChild(childIndex, ret)
		// log.Debugf("TRIE create child: %s.%c->%s", prefixToHexstring(startNode.prefix),
		// 	valuebyteToHexbyte(byte(childIndex)), prefixToHexstring(prefix))
	} else {
		// log.Debugf("TRIE create node: %s", prefixToHexstring(prefix))
	}
	return ret
}

func (t *Trie) SubTrie(keyPrefix []byte) *Trie {
	// TODO: TBD
	return nil
}

func (t *Trie) Clone() *Trie {
	if t == nil {
		return nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	_ = t.commitLocked()
	rootHash, _ := t.hashLocked()
	return &Trie{
		root: NewNodeWithFuncs(rootHash, t.gen, t.root.valueEncode,
			t.root.valueDecode, t.root.valueHasher),
		nodeAdapter:  t.nodeAdapter,
		valueAdapter: t.valueAdapter,
		gen:          t.gen,
	}
}

func (t *Trie) Rebase(dbase db.Database) (*Trie, error) {
	if t == nil {
		return nil, nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	if err := t.commitLocked(); err != nil {
		return nil, err
	}
	root, err := t.hashLocked()
	if err != nil {
		return nil, err
	}
	na, _ := db.RebaseAdapter(t.nodeAdapter, dbase)
	va, _ := db.RebaseAdapter(t.valueAdapter, dbase)
	return &Trie{
		root: NewNodeWithFuncs(root, 0, t.root.valueEncode,
			t.root.valueDecode, t.root.valueHasher),
		nodeAdapter:  na,
		valueAdapter: va,
		gen:          0,
	}, nil
}

func (t *Trie) Inherit(root []byte) *Trie {
	if t == nil {
		return nil
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	rootHash := common.CopyBytes(root)
	return &Trie{
		root: NewNodeWithFuncs(rootHash, 0, t.root.valueEncode,
			t.root.valueDecode, t.root.valueHasher),
		nodeAdapter:  t.nodeAdapter,
		valueAdapter: t.valueAdapter,
		gen:          0,
	}
}

func (t *Trie) hashLocked() ([]byte, error) {
	return t.root.HashValue()
}

func (t *Trie) Count() int {
	return t.valueCount
}

func (t *Trie) IsEmpty() bool {
	return t.root.isEmpty()
}

func (t *Trie) HashValue() ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.hashLocked()
}

func (t *Trie) CommitAndHash() ([]byte, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	if err := t.commitLocked(); err != nil {
		return nil, fmt.Errorf("commit failed: %v", err)
	}
	root, err := t.hashLocked()
	if err != nil {
		return nil, fmt.Errorf("hash failed: %v", err)
	}
	return root, nil
}

func (t *Trie) Get(key []byte) (interface{}, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	prefix := keyToPrefix(key)
	return t.get(t.root, prefix, 0, nil)
}

// Take startNode as the root and prefixString[offset:] as the key to get the value in the node
// of the corresponding location. And the node paths are sequentially appended to the trace parameter.
// Each nodePosition in trace:
// 		nodePosition.nodeInPos: the node selected for the current lookup
// 		nodePosition.pos: the index of current startNode.children[] which is the node selected
func (t *Trie) get(startNode *node, prefixString []byte, offset int, trace *[]nodePosition) (interface{}, bool) {
	if err := t.fullExpand(startNode); err != nil {
		return nil, false
	}

	if offset >= len(prefixString) {
		if startNode.hasValue() {
			return startNode.value, true
		} else {
			return nil, false
		}
	}

	if startNode.isEmpty() {
		// current node is empty or
		return nil, false
	}

	suffix := prefixString[offset:]
	startPrefixLength := startNode.prefixLength()
	inPrefixLength := len(suffix)
	matchLength := startNode.matchPrefix(suffix)
	if matchLength > startPrefixLength || matchLength > inPrefixLength {
		panic(fmt.Errorf("matchLength=%d, startPrefixLength=%d, inPrefixLength=%d",
			matchLength, startPrefixLength, inPrefixLength))
	}
	inRemains := inPrefixLength - matchLength
	startRemains := startPrefixLength - matchLength

	if startRemains == 0 {
		// input prefix is starting with current node's prefix
		if inRemains == 0 {
			// if current node prefix matches with input prefix, return current node value
			return startNode.value, startNode.value != nil
		}
		// inRemains > 0, go down the path by child node
		childIndex := int(suffix[matchLength])
		if startNode.children[childIndex] == nil {
			// no child in the path of prefix, return
			return nil, false
		}
		// expand child first
		if startNode.children[childIndex].isCollapsed() {
			if err := t.expandNode(startNode.children[childIndex]); err != nil {
				log.Errorf("expand %s error: %s", startNode.children[childIndex], err)
				return nil, false
			}
		}

		// t.lruCache.Add(startNode.children[childIndex], nil)
		if trace != nil {
			*trace = append(*trace, nodePosition{suffix[matchLength], startNode.children[childIndex]})
		}
		return t.get(startNode.children[childIndex], prefixString, offset+matchLength+1, trace)
	} else {
		// there're remains in current node's prefix not match with input prefix, not found
		return nil, false
	}
}

func (t *Trie) putLocked(key []byte, value interface{}) bool {
	prefix := keyToPrefix(key)
	changed, needReplace, changedRoot := t.insert(t.root, prefix, 0, value)
	if changed && needReplace {
		t.root = changedRoot
	}
	return changed
}

func (t *Trie) PutValue(value TrieValue) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.putLocked(value.Key(), value)
}

func (t *Trie) Put(key []byte, value interface{}) bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.putLocked(key, value)
}

func setNodePrefixAndValue(t *Trie, node *node, prefix []byte, value interface{}) {
	node.setPrefix(prefix)
	_, _, delta := node.setValue(value)
	t.valueCount = t.valueCount + delta
	//  update node generation
	node.generation = t.gen
}

func (t *Trie) insert(startNode *node, prefixString []byte, offset int, value interface{}) (changed bool, needReplace bool, changedRoot *node) {

	if err := t.fullExpand(startNode); err != nil {
		return false, false, startNode
	}

	//  update node generation
	startNode.generation = t.gen

	// set value to current node and return
	if offset >= len(prefixString) {
		// no more prefix, no more actions
		changed, _, delta := startNode.setValue(value)
		t.valueCount = t.valueCount + delta
		return changed, false, startNode
	}
	if startNode.isEmpty() {
		// current node is empty
		setNodePrefixAndValue(t, startNode, prefixString[offset:], value)
		return true, false, startNode
	}

	suffix := prefixString[offset:]
	startPrefixLength := startNode.prefixLength()
	inPrefixLength := len(suffix)
	matchLength := startNode.matchPrefix(suffix)
	if matchLength > startPrefixLength || matchLength > inPrefixLength {
		panic(fmt.Errorf("matchLegnth=%d, startPrefixLength=%d, inPrefixLength=%d",
			matchLength, startPrefixLength, inPrefixLength))
	}
	inRemains := inPrefixLength - matchLength
	startRemains := startPrefixLength - matchLength

	if startRemains == 0 {
		// input prefix is starting with current node's prefix
		if inRemains == 0 {
			// matchs the current node
			changed, _, delta := startNode.setValue(value)
			t.valueCount = t.valueCount + delta
			return changed, false, startNode
		}
		// input prefix is longer then current node's prefix, and start with it
		// go in child
		nextNode := startNode.children[int(suffix[matchLength])]
		if nextNode == nil {
			// create new node if there's no child for the input prefix
			valueNode := t.createNode(startNode, suffix[matchLength+1:], int(suffix[matchLength]))
			_, _, delta := valueNode.setValue(value)
			t.valueCount = t.valueCount + delta
			return true, false, startNode
		} else {
			// expand current child node
			if err := t.fullExpand(nextNode); err != nil {
				return false, false, startNode
			}
		}
		// go down the path by child node
		nchanged, nneedReplace, nchangeRoot := t.insert(nextNode, prefixString, offset+matchLength+1, value)
		if nchanged {
			startNode.childChanged()
			if nneedReplace {
				startNode.setChild(int(suffix[matchLength]), nchangeRoot)
			}
		}
		return nchanged, false, nextNode
	}
	// startRemains > 0
	// there're remains in current node's prefix not match with input prefix, should split
	newNode := t.createNode(startNode, suffix[:matchLength], -1)

	// add startNode to newNode.children[startNode.prefix[matchLength]]
	newNode.setChild(int(startNode.prefix[matchLength]), startNode)
	if err := startNode.chopPrefixHead(matchLength + 1); err != nil {
		panic(fmt.Errorf("startNode.chopPrefixHead(%d) error: %v", matchLength+1, err.Error()))
	}

	if inRemains == 0 {
		// if no more input prefix remains, value should set to newNode
		_, _, delta := newNode.setValue(value)
		t.valueCount = t.valueCount + delta
	} else {
		// create new valueNode and add to newNode.children[suffix[matchLength]]
		valueNode := t.createNode(newNode, suffix[matchLength+1:], int(suffix[matchLength]))
		_, _, delta := valueNode.setValue(value)
		t.valueCount = t.valueCount + delta
	}
	return true, true, newNode
}

func (t *Trie) deleteLocked(key []byte) (changed bool, oldValue interface{}) {
	prefix := keyToPrefix(key)
	c, shouldRemove, o := t.delete(t.root, prefix, 0)
	if shouldRemove {
		// When the root node needs to be deleted, that is, the whole tree is empty, because
		// it has been judged that both value and children are empty when deleting
		t.root.setPrefix(nil)
	}
	return c, o
}

func (t *Trie) Delete(key []byte) (changed bool, oldValue interface{}) {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.deleteLocked(key)
}

func (t *Trie) removeValue(node *node) (changed bool, shouldRemove bool, oldValue interface{}) {
	var delta int
	changed, oldValue, delta = node.setValue(nil)
	t.valueCount = t.valueCount + delta
	if !node.hasChildren() {
		// when value removed, if current node has no child, then the node should be removed from trie
		return changed, true, oldValue
	}
	merged := node.mergeTheLastChild(t)
	changed = changed || merged
	return
}

func (t *Trie) fullExpand(n *node) error {
	if n == nil {
		return nil
	}
	if n.isCollapsed() {
		if err := t.expandNode(n); err != nil {
			log.Errorf("expand %s error: %s", n, err)
			return err
		}
	}
	if n.isValueCollapsed() {
		if err := t.expandNodeValue(n); err != nil {
			log.Errorf("expand node value %s error: %s", n, err)
			return err
		}
	}
	return nil
}

func (t *Trie) delete(startNode *node, prefixString []byte, offset int) (changed bool, shouldRemove bool, oldValue interface{}) {
	// log.Debugf("TRIE delete %s", prefixToHexstring(prefixString[offset:]))
	// expand node if it's collapsed
	if err := t.fullExpand(startNode); err != nil {
		return false, false, nil
	}

	// return unchange if current node is empty
	if startNode.isEmpty() {
		return false, false, nil
	}

	//  update node generation
	startNode.generation = t.gen

	// remove current node value, if no more prefix
	if offset >= len(prefixString) {
		changed, shouldRemove, oldValue = t.removeValue(startNode)
		return
	}

	suffix := prefixString[offset:]
	startPrefixLength := startNode.prefixLength()
	inPrefixLength := len(suffix)
	matchLength := startNode.matchPrefix(suffix)
	if matchLength > startPrefixLength || matchLength > inPrefixLength {
		panic(fmt.Errorf("matchLegnth=%d, startPrefixLength=%d, inPrefixLength=%d",
			matchLength, startPrefixLength, inPrefixLength))
	}
	inRemains := inPrefixLength - matchLength
	startRemains := startPrefixLength - matchLength

	if startRemains == 0 {
		if inRemains == 0 {
			// prefix matchs the current node
			return t.removeValue(startNode)
		}
		// input prefix is longer then current node's prefix, and start with it
		nextNode := startNode.children[int(suffix[matchLength])]
		if nextNode == nil {
			// no child in the path of input prefix
			return false, false, nil
		}
		// go in child
		nchanged, nshouldRemove, oldValue := t.delete(nextNode, prefixString, offset+1+matchLength)
		if nchanged {
			startNode.childChanged()
			if nshouldRemove {
				// remove the child node
				// log.Debugf("TRIE remove node: %s", nextNode)
				startNode.setChild(int(suffix[matchLength]), nil)
			}
		}

		if !startNode.hasChildren() && !startNode.hasValue() {
			// At this time, it is necessary to judge whether the current node has no child node
			// and value at the same time, so as to confirm that the node can be deleted
			return nchanged, true, oldValue
		}

		startNode.mergeTheLastChild(t)

		return nchanged, false, oldValue
	}
	// startRemains > 0, target prefix not exist in the trie
	return false, false, nil
}

func (t *Trie) expandTrie(node *node) error {
	if err := t.fullExpand(node); err != nil {
		return err
	}
	for i := 0; i < childrenLength; i++ {
		if node.children[i] != nil {
			if err := t.expandTrie(node.children[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *Trie) expandNode(node *node) error {
	if !node.isCollapsed() {
		return nil
	}
	if t.nodeAdapter == nil {
		return nil
	}
	// the expanded node must update generation
	node.generation = t.gen
	hashes := node.hash
	nodebytes, err := t.nodeAdapter.Load(hashes)
	if err != nil {
		return fmt.Errorf("load %s data error: %v", node, err)
	}
	buf := rtl.NewValueReader(bytes.NewBuffer(nodebytes), 256)
	if err = rtl.Decode(buf, node); err != nil {
		return fmt.Errorf("decode nodebytes@[%x] DA:%s error: %v", hashes, t.nodeAdapter, err)
	}
	if node.inErrorStatus() {
		log.Warnf("[BUGFIX] an error node found:%v, nodeHash:%x, nodeValue:%x", node, hashes, nodebytes)
		// oldprefix := node.prefix
		// node.setPrefix(nil)
		// log.Warnf("[BUGFIX] remove prefix: %x, nodeHash set to empty", oldprefix)
		node.hash = common.CopyBytes(common.EmptyNodeHashSlice)
	}
	err = t.expandNodeValue(node)

	// t.lruCache.add(node,node)
	// log.Debugf("expanded %s", node)
	return err
}

func (t *Trie) expandNodeValue(node *node) error {
	if node.isCollapsed() {
		return t.expandNode(node)
	}
	if !node.isValueCollapsed() || t.valueAdapter == nil {
		return nil
	}
	if err := node.expandValue(t.valueAdapter); err != nil {
		return err
	}
	return nil
}

func (t *Trie) isDirtyLocked() bool {
	return t.root.isDirty()
}

func (t *Trie) IsDirty() bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.root.isDirty()
}

func (t *Trie) commitLocked() error {
	e := t.flushToDB(t.root)
	if e == nil {
		t.gen++
	}
	return e
}

func (t *Trie) Commit() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.commitLocked()
}

func (t *Trie) Collapse() error {
	if t.root != nil {
		if t.root.canCollapse() {
			if err := t.root.collapse(); err != nil {
				return err
			}
		}
		// if t.root.shouldCollapseValue(maxValLength) {
		// 	if err := t.root.collapseValue(); err != nil {
		// 		return err
		// 	}
		// }
	}
	return nil
}

func (t *Trie) flushToDB(flushRoot *node) error {
	// traverse the subtree of flushRoot in depth-first mode, save the dirty nodes
	return t.iterateSave(flushRoot)
}

func (t *Trie) iterateSave(node *node) error {
	// depth-first traversal
	for i := 0; i < childrenLength; i++ {
		if node.children[i] != nil {
			_ = t.iterateSave(node.children[i])
		}
	}
	if node.isDirty() {
		if err := t.saveOneNode(node); err != nil {
			return err
		}
	} else {
		if node.shouldCollapse(t.gen, maxGenSize) {
			err := node.collapse()
			if err != nil {
				log.Errorf("[COLLAPSE] err %v", err)
			}
		} else {
			if node.shouldCollapseValue(maxValLength) {
				_ = node.collapseValue()
			}
		}
	}
	return nil
}

func (t *Trie) saveOneNode(node *node) error {
	// save node value
	vh, vb, err := node.valueHash()
	if err != nil {
		return fmt.Errorf("encode node value error: %v", err)
	}
	// if len(hash)<common.HashLength, we don't save it to database
	if vh != nil && len(vh) >= common.HashLength {
		if t.valueAdapter != nil {
			if err = t.valueAdapter.Save(vh, vb); err != nil {
				return fmt.Errorf("save node value@[%x] error: %v", vh, err)
			}
		}
	}
	// save node
	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(buf)
	buf.Reset()
	err = rtl.Encode(node, buf)
	if err != nil {
		return fmt.Errorf("encode %s error: %v", node, err)
	}

	h, err := node.HashValue()
	if err != nil {
		return fmt.Errorf("hash %s error: %v", node, err)
	}
	if t.nodeAdapter != nil {
		if err = t.nodeAdapter.Save(h, buf.Bytes()); err != nil {
			return fmt.Errorf("save node@[%x] error: %v", h, err)
		}
	}
	// log.Debugf("saved %s: %x", node, h)
	node.dirty = false
	return nil
}

func (t *Trie) stringLocked(printValueNodeOnly bool) string {
	buf := new(bytes.Buffer)

	t.iteratePrint(buf, "", t.root, printValueNodeOnly)
	return buf.String()
}

func (t *Trie) String() string {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.stringLocked(false)
}

func (t *Trie) PrintValues() string {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.stringLocked(true)
}

func (t *Trie) ValueString() string {
	// t.lock.Lock()
	// defer t.lock.Unlock()

	buf := common.BytesBufferPool.Get().(*bytes.Buffer)
	defer common.BytesBufferPool.Put(buf)
	buf.Reset()
	buf.WriteByte('<')
	i := 0
	t.IterateAll(true, func(key []byte, value interface{}) (shouldContinue bool) {
		if i > 0 {
			buf.Write([]byte(", "))
		}
		buf.WriteString(fmt.Sprintf("%s", value))
		i++
		return true
	})
	buf.WriteByte('>')
	return buf.String()
}

// func (t *Trie) iteratePrintNodes(buf *bytes.Buffer, prefix string, node *node) {
// 	if node == nil {
// 		return
// 	}
// 	curprefix := prefix + string(prefixToHexstring(node.prefix))
// 	if node.hasValue() {
// 		buf.WriteString(curprefix)
// 		buf.WriteString(fmt.Sprintf(".value=%v\n", node.value))
// 	}
// 	for i := 0; i < childrenLength; i++ {
// 		if node.hasChild(i) {
// 			child := node.children[i]
// 			t.iteratePrintNodes(buf, fmt.Sprintf("%s%c", curprefix, valuebyteToHexbyteArray[i]), child)
// 		}
// 	}
// }

func (t *Trie) iteratePrint(buf *bytes.Buffer, prefix string, node *node, valueOnly bool) {
	if node == nil {
		return
	}
	if node.isCollapsed() {
		if err := t.expandNode(node); err != nil {
			log.Errorf("iteratePrint: expand node %s failed: %v", node, err)
			return
		}
	}
	p := prefix
	if len(prefix) > 0 {
		p = prefix + "."
	}
	if valueOnly == false || (valueOnly && node.hasValue()) {
		if node.isValueCollapsed() {
			if err := t.expandNodeValue(node); err != nil {
				log.Errorf("iteratePrint: expand value %s failed: %v", node, err)
			}
		}
		buf.WriteString(p)
		buf.WriteString(node.print())
		buf.WriteString("\n")
	}
	for i := 0; i < childrenLength; i++ {
		if node.hasChild(i) {
			t.iteratePrint(buf, fmt.Sprintf("%s%c", prefix+string(prefixToHexstring(node.prefix)),
				valuebyteToHexbyteArray[i]), node.children[i], valueOnly)
		}
	}
}

// func (t *Trie) getProofLocked(key []byte) (val interface{}, proof common.ProofHash, ok bool) {
func (t *Trie) getProofLocked(key []byte) (val interface{}, proofs ProofChain, ok bool) {
	trace := make([]nodePosition, 1, 16)
	// Use an illegal pos to indicate that root is not the child of any node
	trace[0] = nodePosition{childrenLength + 1, t.root}
	prefix := keyToPrefix(key)
	val, ok = t.get(t.root, prefix, 0, &trace)
	if !ok {
		// rh, _ := t.hashLocked()
		// // value does not exist, proof cannot be provided
		// log.Errorf("value not found by Key:%x at RootHash:%x", key, rh)
		return nil, proofs, false
	}

	nodeChild := nodePosition{16, nil}
	for i := len(trace) - 1; i >= 0; i-- {
		nd := trace[i]
		if nd.nodeInPos.isCollapsed() {
			if err := t.expandNode(nd.nodeInPos); err != nil {
				log.Errorf("expand %s error: %s", nd.nodeInPos, err)
				return nil, proofs, false
			}
		}

		err := nd.nodeInPos.GetProof(ProofType(nodeChild.pos), &proofs)
		if err != nil {
			log.Errorf("get proof from the child failed: %v", err)
			return val, nil, false
		}

		nodeChild = nd
	}
	return val, proofs, true
}

func (t *Trie) GetProof(key []byte) (val interface{}, proof ProofChain, ok bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.getProofLocked(key)
}

func (t *Trie) getExistenceLocked(key []byte) (exist bool, proofs ProofChain, err error) {
	trace := make([]nodePosition, 1, 16)
	trace[0] = nodePosition{pos: childrenLength + 1, nodeInPos: t.root}
	prefix := keyToPrefix(key)
	_, exist = t.get(t.root, prefix, 0, &trace)

	nodeChild := nodePosition{16, nil}
	l := len(trace)
	for i := l - 1; i >= 0; i-- {
		if trace[i].nodeInPos.isCollapsed() {
			if err = t.expandNode(trace[i].nodeInPos); err != nil {
				log.Errorf("expand %s error: %s", trace[i].nodeInPos, err)
				return
			}
		}
		if i == l-1 {
			// The last node requires proof existence
			err = trace[i].nodeInPos.GetProof(ProofExistence, &proofs)
		} else {
			// The remaining nodes are proof child nodes
			err = trace[i].nodeInPos.GetProof(ProofType(nodeChild.pos), &proofs)
		}
		if err != nil {
			log.Errorf("fail to get existence of the child, error: %v", err)
			return
		}
		nodeChild = trace[i]
	}
	return
}

func (t *Trie) GetExistenceProof(key []byte) (exist bool, proofs ProofChain, err error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.getExistenceLocked(key)
}

func (t *Trie) unmarshalNewTrieLocked(r io.Reader, valueType reflect.Type, keyFunc func(interface{}) []byte) (*Trie, error) {
	trie := NewTrieWithValueFuncs(nil, t.nodeAdapter, t.valueAdapter, t.root.valueEncode,
		t.root.valueDecode, t.root.valueHasher)

	reader, ok := r.(rtl.ValueReader)
	if !ok {
		reader = rtl.NewValueReader(r, 0)
	}

	for reader.HasMore() {
		newValue := reflect.New(valueType)
		if err := rtl.Decode(reader, newValue.Interface()); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		nv := newValue.Elem().Interface()
		if nv != nil {
			key := keyFunc(nv)
			if key != nil {
				trie.Put(key, nv)
			}
		}
	}
	return trie, nil
}

func (t *Trie) UnmarshalNewTrie(r io.Reader, valueType reflect.Type, keyFunc func(interface{}) []byte) (*Trie, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.unmarshalNewTrieLocked(r, valueType, keyFunc)
}

func (t *Trie) ValueIterator() ValueIterator {
	// t.lock.Lock()
	// defer t.lock.Unlock()

	newt := t.Clone()
	return NewValueIterator(newt)
}

func (t *Trie) IterateAll(noNil bool, callback func(key []byte, value interface{}) (shouldContinue bool)) {
	if t == nil {
		return
	}
	it := t.ValueIterator()
	for it.Next() {
		k, v := it.Current()
		if noNil && (k == nil || v == nil) {
			continue
		}
		if !callback(k, v) {
			break
		}
	}
	return
}

func (t *Trie) ReversedValueIterator() ValueIterator {
	newt := t.Clone()
	return newReversedValueIterator(newt)
}

func (t *Trie) Dump(to db.Database) error {
	if t == nil || t.root == nil || t.root.isEmpty() {
		return nil
	}
	if t.root.isDirty() {
		return errors.New("trie is dirty")
	}
	var err error
	var na, va db.DatabasedAdapter
	if tna, ok := t.nodeAdapter.(db.DatabasedAdapter); ok {
		na, err = tna.Rebase(to)
		if err != nil {
			return fmt.Errorf("rebase node adapter failed: %v", err)
		}
	} else {
		return errors.New("invalid node adapter")
	}
	if tva, ok := t.valueAdapter.(db.DatabasedAdapter); ok {
		va, err = tva.Rebase(to)
		if err != nil {
			return fmt.Errorf("rebase value adapter failed: %v", err)
		}
	}
	rootHash := t.root.hash
	it := newNodeIterator(t)
	for {
		n := it.Next(nil)
		if n == nil {
			break
		}
		if common.InvalidHash(n.hash) {
			continue
		}

		// dump node
		nodebytes, err := t.nodeAdapter.Load(n.hash)
		if err != nil {
			return fmt.Errorf("load node bytes at:%x of root:%x failed: %v", n.hash, rootHash, err)
		}
		if len(nodebytes) > 0 {
			if err = na.Save(n.hash, nodebytes); err != nil {
				return fmt.Errorf("dump node bytes at:%x of root:%x failed: %v", n.hash, rootHash, err)
			}
		}

		if err := t.expandNode(n); err != nil {
			return fmt.Errorf("expand node at:%x of root:%x failed: %v", n.hash, rootHash, err)
		}

		// dump value
		if va != nil && len(n.valuehash) >= common.HashLength {
			valuebytes, err := t.valueAdapter.Load(n.valuehash)
			if err != nil {
				return fmt.Errorf("load node value bytes at:%x of root:%x - %x failed: %v",
					n.valuehash, rootHash, n.hash, err)
			}
			if len(valuebytes) > 0 {
				if err = va.Save(n.valuehash, valuebytes); err != nil {
					return fmt.Errorf("dump node value bytes at:%x of root:%x - %x failed: %v",
						n.valuehash, rootHash, n.hash, err)
				}
			}
		}
	}
	return nil
}
