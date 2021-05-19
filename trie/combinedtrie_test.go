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
	"reflect"
	"testing"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/stephenfire/go-rtl"
)

func TestSmallCombinedTrie_Commit(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
		return
	}
	defer dbase.Close()

	trieadapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("ss"))
	nadapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("sn"))
	vadapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("sv"))
	codec, err := rtl.NewStructCodec(reflect.TypeOf((*trieValue)(nil)))
	if err != nil {
		t.Error(err)
		return
	}

	k1 := []byte("k1")
	k2 := []byte("k2")
	k3 := []byte("k3")

	t1 := NewTrieWithValueCodec(nil, nadapter, vadapter, codec.Encode, codec.Decode)
	t2 := NewTrieWithValueCodec(nil, nadapter, vadapter, codec.Encode, codec.Decode)
	t3 := NewTrieWithValueCodec(nil, nadapter, vadapter, codec.Encode, codec.Decode)

	for i := 0; i < len(values); i++ {
		t1.Put(values[i].key, values[i].value)
	}

	for i := 0; i < len(values2); i++ {
		t2.Put(values2[i].key, values2[i].value)
	}

	trie := NewCombinedTrie(trieadapter)
	trie.Put(k1, t1)
	trie.Put(k2, t2)
	trie.Put(k3, t3)

	trie.Commit()
	root, err := trie.HashValue()
	if err != nil {
		t.Error(err)
		return
	}

	// check reload
	trie1 := NewCombinedTrie(trieadapter)
	trie1.InitTrie(root, nadapter, vadapter, codec.Encode, codec.Decode, nil, nil)
	root1, err := trie1.HashValue()
	if err != nil {
		t.Error(err)
		return
	}
	if bytes.Compare(root, root1) != 0 {
		t.Error("commit/reload failed")
	} else {
		t.Logf("commit/reload ok: %X", root1)
	}
}

func TestCombinedTrie(t *testing.T) {

	k1 := []byte("k1")
	k2 := []byte("k2")
	k3 := []byte("k3")
	k4 := []byte("k4")

	t1 := NewTrieWithValueType(nil, nil, nil, reflect.TypeOf((*trieValue)(nil)))
	t2 := NewTrieWithValueType(nil, nil, nil, reflect.TypeOf((*trieValue1)(nil)))
	t3 := NewTrieWithValueType(nil, nil, nil, reflect.TypeOf((*trieValue)(nil)))

	for i := 0; i < len(values); i++ {
		t1.Put(values[i].key, values[i].value)
	}

	for i := 0; i < len(value1s2); i++ {
		t2.Put(value1s2[i].key, value1s2[i].value)
	}

	root1, err := t1.HashValue()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("root1 = %X", root1)

	root2, err := t2.HashValue()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("root2 = %X", root2)

	root3, err := t3.HashValue()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("root3 = %X", root3)

	trie := NewCombinedTrie(nil)
	trie.Put(k1, t1)
	trie.Put(k2, t2)
	trie.Put(k3, t3)

	trie.Commit()

	root, err := trie.HashValue()
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("root = %X", root)

	// get
	if !checkCombinedOneTrie(k1, root1, trie, t) {
		return
	} else {
		t.Log("t1 check")
	}

	if !checkCombinedOneTrie(k2, root2, trie, t) {
		return
	} else {
		t.Log("t2 check")
	}

	if !checkCombinedOneTrie(k3, root3, trie, t) {
		return
	} else {
		t.Log("t3 check")
	}

	t4, ok := trie.Get(k4)
	if ok || t4 != nil {
		t.Error("k4 should not be there")
	}

	// iterator
	kmap := map[string][]byte{
		string(k1): root1,
		string(k2): root2,
		string(k3): root3,
	}
	it := trie.ValueIterator()
	var count int
	for it.Next() {
		count++
		k, v := it.Current()
		if v != nil {
			tt, _ := v.(ITrie)
			h, _ := tt.HashValue()
			hh, ok := kmap[string(k)]
			if !ok {
				t.Errorf("%X not found", k1)
			} else {
				if bytes.Compare(h, hh) != 0 {
					t.Errorf("hash should be %X but %X", hh, h)
				} else {
					t.Logf("iterate: %X -> %v", k, v)
				}
			}
		}
	}
	if count != len(kmap) {
		t.Errorf("iterator iterates %d values, should be %d", count, len(kmap))
	}

	valuekey := make([]byte, 0)
	valuekey = append(valuekey, k1...)
	// valuekey = append(valuekey, values[0].key...)

	t.Logf("=======================%x", valuekey)
	// fmt.Printf("=======================%x\n", valuekey)
	value, proof, ok := trie.GetProof(valuekey)
	if !ok || proof == nil || value == nil {
		t.Error("proof error")
		return
	} else {
		t.Logf("proof: %s", proof)
	}

	tvalue, ok := value.(ITrie)
	if !ok {
		t.Errorf("expecting an ITrie object")
		return
	}
	valueHash, err := tvalue.HashValue()
	if err != nil {
		t.Errorf("ITrie Hash error: %v", err)
		return
	}
	// if common.VerifyProof(proof, root) {
	if VerifyProofChain(common.BytesToHash(valueHash), proof, root) {
		t.Log("proof ok")
	} else {
		t.Error("proof failed")
	}
}

func checkCombinedOneTrie(key []byte, shouldHash []byte, trie ITrie, t *testing.T) bool {
	tv1, ok := trie.Get(key)
	if !ok {
		t.Errorf("%X lost", key)
		return false
	}
	t11, ok := tv1.(ITrie)
	if !ok {
		t.Errorf("%X type error", key)
		return false
	}
	root11, err := t11.HashValue()
	if err != nil {
		t.Errorf("%X hash error: %s", key, err)
		return false
	}
	return bytes.Compare(root11, shouldHash) == 0
}
