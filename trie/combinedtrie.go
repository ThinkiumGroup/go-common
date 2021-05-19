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
	"io"
	"sort"
	"sync"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

type (
	// Trie with ITrie as value
	SmallCombinedTrie struct {
		lock     sync.RWMutex
		keys     sort.StringSlice // the keys of the sub-trie in ascending alphabetical order
		valueMap map[string]*Trie // Key -> sub-trie

		adapter db.DataAdapter
	}

	smallCombinedIterator struct {
		trie *SmallCombinedTrie
		keys []string
		pos  int
	}
)

func (it *smallCombinedIterator) Next() bool {
	for it.pos < (len(it.keys) - 1) {
		it.pos++
		if it.pos < 0 {
			it.pos = -1
			continue
		}
		v, ok := it.trie.Get([]byte(it.keys[it.pos]))
		if ok && v != nil {
			return true
		}
	}
	return false
}

func (it *smallCombinedIterator) Current() (key []byte, value interface{}) {
	if it.pos < 0 || it.pos >= len(it.keys) {
		return nil, nil
	}
	v, ok := it.trie.Get([]byte(it.keys[it.pos]))
	if !ok {
		return nil, nil
	}
	return []byte(it.keys[it.pos]), v
}

func NewCombinedTrie(adapter db.DataAdapter) *SmallCombinedTrie {
	return &SmallCombinedTrie{
		valueMap: make(map[string]*Trie),
		keys:     make(sort.StringSlice, 0),
		adapter:  adapter,
	}
}

func (c *SmallCombinedTrie) addKey(key string) {
	c.keys = append(c.keys, key)
	c.keys.Sort()
}

func (c *SmallCombinedTrie) deleteKey(key string) {
	i := c.keys.Search(key)
	if key == c.keys[i] {
		copy(c.keys[i:], c.keys[i+1:])
		c.keys = c.keys[:len(c.keys)-1]
	}
}

func (c *SmallCombinedTrie) computeHash(index int, proofs *ProofChain) ([]byte, error) {
	if len(c.keys) == 0 {
		return common.NilHashSlice, nil
	}
	hashList := make([][]byte, 0, len(c.keys))
	for i := 0; i < len(c.keys); i++ {
		t, ok := c.valueMap[c.keys[i]]
		if !ok {
			continue
		}
		h, err := t.HashValue()
		if err != nil {
			return nil, err
		}
		hashList = append(hashList, h)
	}
	var merkleProof *common.MerkleProofs
	if proofs != nil {
		// fmt.Printf("making SmallCombinedTrie proof: %x, index:%d\n", c.keys, index)
		merkleProof = common.NewMerkleProofs()
	}
	root, err := common.MerkleHashComplete(hashList, index, merkleProof)
	if err != nil {
		return nil, err
	}
	if proofs != nil {
		// nodeProof := NewNodeProof(ProofMerkleOnly, NodeHeader{}, nil, merkleProof)
		nodeProof := NewMerkleOnlyProof(ProofMerkleOnly, merkleProof)
		*proofs = append(*proofs, nodeProof)
		// fmt.Printf("NodeProof: %s, Chain:%s\n", nodeProof, *proofs)
	}
	return root, nil
}

func (c *SmallCombinedTrie) Keys() []string {
	c.lock.RLock()
	defer c.lock.RUnlock()
	keysSlice := make([]string, len(c.keys))
	copy(keysSlice, c.keys)
	return keysSlice
}

func (c *SmallCombinedTrie) HashValue() (hashValue []byte, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.computeHash(0, nil)
}

func (c *SmallCombinedTrie) Get(key []byte) (interface{}, bool) {
	if key == nil {
		return nil, false
	}
	c.lock.RLock()
	defer c.lock.RUnlock()
	value, ok := c.valueMap[string(key)]
	if !ok {
		return nil, false
	}
	return value, true
}

func (c *SmallCombinedTrie) Put(key []byte, value interface{}) bool {
	if key == nil {
		return false
	}
	t, ok := value.(*Trie)
	if !ok {
		return false
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	k := string(key)
	_, exist := c.valueMap[k]
	c.valueMap[k] = t
	if !exist {
		c.addKey(k)
	}
	return true
}

func (c *SmallCombinedTrie) PutValue(value TrieValue) bool {
	return c.Put(value.Key(), value)
}

func (c *SmallCombinedTrie) Delete(key []byte) (changed bool, oldValue interface{}) {
	if key == nil {
		return false, nil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	k := string(key)
	oldValue, exist := c.valueMap[k]
	if exist {
		delete(c.valueMap, k)
		c.deleteKey(k)
		return true, oldValue
	}
	return false, nil
}

func (c *SmallCombinedTrie) IsDirty() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, t := range c.valueMap {
		if t.IsDirty() {
			return true
		}
	}
	return false
}

func (c *SmallCombinedTrie) Commit() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, t := range c.valueMap {
		if t != nil {
			if t.IsDirty() {
				if err := t.Commit(); err != nil {
					return err
				}
			}
		}
	}
	// save top hash
	if err := c.saveRoot(); err != nil {
		return err
	}
	return nil
}

func (c *SmallCombinedTrie) saveRoot() error {
	if c.adapter == nil {
		log.Warn("SmallCombinedTrie save root without DataAdapter")
		return nil
	}
	buf := new(bytes.Buffer)
	for i := 0; i < len(c.keys); i++ {
		t, ok := c.valueMap[c.keys[i]]
		if !ok || t == nil {
			continue
		}
		h, err := t.HashValue()
		if err != nil {
			return err
		}
		if err = rtl.Encode(c.keys[i], buf); err != nil {
			return err
		}
		if err = rtl.Encode(h, buf); err != nil {
			return err
		}
	}
	// trie hash
	h, err := c.computeHash(0, nil)
	if err != nil {
		return err
	}
	if err := c.adapter.Save(h, buf.Bytes()); err != nil {
		return err
	}
	return nil
}

// TODO optimization needed
func (c *SmallCombinedTrie) loadRoot(rootHash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter,
	encode NodeValueEncode, decode NodeValueDecode, hasher NodeValueHasher, expander NodeValueExpander) error {
	if rootHash == nil {
		return nil
	}
	value, err := c.adapter.Load(rootHash)
	if err != nil {
		return err
	}
	if len(value) == 0 {
		return common.ErrNil
	}
	buf := bytes.NewBuffer(value)
	vr := rtl.NewValueReader(buf, 0)
	for vr.HasMore() {
		k := new([]byte)
		v := new([]byte)
		if err := rtl.Decode(vr, k); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := rtl.Decode(vr, v); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		var key, trieHash []byte
		if k != nil {
			key = *k
		}
		if v != nil {
			trieHash = *v
		}
		t := NewTrieWithValueFuncs(trieHash, nadapter, vadapter, encode, decode, hasher, expander)
		s := string(key)
		_, exist := c.valueMap[s]
		if !exist {
			c.valueMap[s] = t
			c.keys = append(c.keys, s)
		}
	}
	c.keys.Sort()
	return nil
}

func (c *SmallCombinedTrie) InitTrie(rootHash []byte, nadapter db.DataAdapter, vadapter db.DataAdapter,
	encode NodeValueEncode, decode NodeValueDecode, hasher NodeValueHasher, expander NodeValueExpander) error {
	if rootHash == nil {
		return common.ErrNil
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.loadRoot(rootHash, nadapter, vadapter, encode, decode, hasher, expander)
}

// func (c *SmallCombinedTrie) GetProof(key []byte) (value interface{}, proof common.ProofHash, ok bool) {
func (c *SmallCombinedTrie) GetProof(key []byte) (value interface{}, proof ProofChain, ok bool) {
	if key == nil {
		return nil, nil, false
	}
	c.lock.RLock()
	defer c.lock.RUnlock()

	// fmt.Printf("making proof for SmallCombinedTrie: key: %x\n", key)
	k := string(key)
	// if the value in the current keys has an inclusion relationship (for example,
	// a key is a prefix of another key), an error may occur
	// 如果当前keys中的值存在包含关系（如一个key是另一个key的前缀）时，则可能出错
	for i := 0; i < len(c.keys); i++ {
		// if strings.HasPrefix(k, c.keys[i]) {
		//	t, ok := c.valueMap[c.keys[i]]
		//	if !ok || t == nil {
		//		return nil, nil, false
		//	}
		//	k = strings.TrimPrefix(k, c.keys[i])
		//	value, proof, ok := t.GetProof([]byte(k))
		//	if !ok {
		//		return value, proof, ok
		//	}
		//	if proof != nil {
		if c.keys[i] == k {
			proof = make(ProofChain, 0)
			value = c.valueMap[k]
			// hh, _ := c.valueMap[k].Hash()
			// proof = append(proof, hh)
			_, err := c.computeHash(i, &proof)
			if err != nil {
				return nil, nil, false
			}
			return value, proof, true
		}
		// }
	}
	return nil, nil, false
}

func (c *SmallCombinedTrie) GetExistenceProof(key []byte) (exist bool, proofs ProofChain, err error) {
	return false, nil, common.ErrUnsupported
}

func (c *SmallCombinedTrie) ValueIterator() ValueIterator {
	return &smallCombinedIterator{
		trie: c,
		keys: c.Keys(),
		pos:  -1,
	}
}

func (c *SmallCombinedTrie) Marshal(w io.Writer) error {
	it := c.ValueIterator()
	for it.Next() {
		k, v := it.Current()
		if err := rtl.Encode(k, w); err != nil {
			return err
		}
		if err := rtl.Encode(v, w); err != nil {
			return err
		}
	}
	return nil
}
