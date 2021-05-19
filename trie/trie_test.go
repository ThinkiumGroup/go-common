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
	"os"
	"reflect"
	"testing"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/stephenfire/go-rtl"
	"github.com/syndtr/goleveldb/leveldb"
)

type trieValue struct {
	A int
	B string
}

func (tv trieValue) String() string {
	return fmt.Sprintf("{a:%d, b:%s}", tv.A, tv.B)
}

type inputs struct {
	key   []byte
	value *trieValue
}

type trieTrace struct {
	key   []byte
	count int
}

var (
	values = []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{1, "node-0xf01234"}},
		{[]byte{0xf1, 0x23, 0x45}, &trieValue{2, "node-0xf12345"}},
		{[]byte{0xf0, 0xab, 0xcd}, &trieValue{3, "node-0xf0abcd"}},
		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue{4, "node-0xf1234567"}},
		{[]byte{0xf0}, &trieValue{5, "node-0xf0"}},
		{[]byte{0xb0, 0x12, 0x34, 0x56}, &trieValue{6, "node-0xb0123456"}},
		{[]byte{0xf1, 0x34, 0x56}, &trieValue{7, "node-0xf13456"}},
		{[]byte{0xf1, 0x23, 0x57}, &trieValue{8, "node-0xf12357"}},
		{[]byte{0xb0, 0x12, 0x34}, &trieValue{0, "node-0xb01234"}},
	}

	values2 = []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{11, "new-node-0xf01234"}},
		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue{14, "new-node-0xf1234567"}},
		{[]byte{0xb1, 0x23, 0x45, 0x67}, &trieValue{20, "new-node-0xb1234567"}},
	}

	values3 = []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{11, "new-node-0xf01234"}},
		{[]byte{0xf0}, &trieValue{5, "node-0xf0"}},
		{[]byte{0xf1, 0x23, 0x58}, nil},
	}

	tracing = []trieTrace{
		{[]byte{0xf1, 0x23, 0x45, 0x67}, 6},
		{[]byte{0xf1, 0x34, 0x56}, 4},
		{[]byte{0xb0, 0x12, 0x34, 0x56}, 4},
		{[]byte{0xb1, 0x23, 0x45, 0x67}, 3},
	}

	existence = []inputs{
		{[]byte{0xF0, 0x12, 0x34, 0x56}, nil},
		{[]byte{0xb1}, nil},
	}

	// oldRootHash, _ = hex.DecodeString("e9913667751c15982201b0e4fe2ad890bf314842646afad1a18d692300b6bfe4")
	// newRootHash, _ = hex.DecodeString("2119a68c7c36e5df12aa06522fb8839222478c453ceaac32b50dc3ed81b33d9f")
	oldRootHash []byte
	newRootHash []byte

	oldSyncMap = make(map[string]inputs)
	newSyncMap = make(map[string]inputs)

	testdbpath = common.HomeDir() + "/temp/dvppdata/trie"

	emptyValue struct{}
)

func createTrie(hash []byte, dbase db.Database) *Trie {
	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
	valueAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("vn"))
	return NewTrieWithValueType(hash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue)(nil)))
}

func clearDb(t *testing.T) {
	if err := os.RemoveAll(testdbpath); err != nil {
		t.Error(err)
	} else {
		t.Log("path remove ok")
	}
}

func putInputToOldSyncMap(input inputs) {
	key := string(input.key)
	oldSyncMap[key] = input
	newSyncMap[key] = input
}

func putInputToNewSyncMap(input inputs) {
	key := string(input.key)
	newSyncMap[key] = input
}

func TestPut(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	trie := createTrie(nil, dbase)
	// t.Log(trie.root)
	roothash, _ := trie.HashValue()
	t.Logf("nil trie hash: %X", roothash)

	for i := 0; i < len(values); i++ {
		trie.Put(values[i].key, *(values[i].value))
		putInputToOldSyncMap(values[i])
	}
	t.Log(trie)
	trie.Commit()
	t.Log(trie)
	for i := 0; i < 1; i++ {
		trie.Put(values3[i].key, *(values3[i].value))
		putInputToOldSyncMap(values3[i])
	}
	trie.Commit()
	t.Log(trie)
	trie.Put(values2[2].key, *(values2[2].value))
	putInputToOldSyncMap(values2[2])
	t.Log(trie)
	trie.Commit()

	t.Log(trie)
	h, err := trie.HashValue()

	vl, _ := trie.Get(values[1].key)
	t.Log(vl)
	t.Log(trie)
	vl, _ = trie.Get(values2[2].key)
	t.Log(vl)
	t.Log(trie)
	c, o := trie.Delete(values[5].key)
	t.Log(c)
	t.Log(o)
	t.Log(trie)
	if err != nil {
		t.Error(err)
	} else {
		oldRootHash = h
		t.Logf("%x", h)
	}

	it := NewValueIterator(trie)
	for it.Next() {
		k, n := it.Current()
		if n != nil {
			t.Logf("TRAVEL: %x %v", k, n)
		}
	}
	t.Log(trie)
}

func TestPut2(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	roothash := oldRootHash
	// roothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
	// roothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
	trie := createTrie(roothash, dbase)

	t.Log(trie.root)

	for i := 0; i < len(values2); i++ {
		trie.Put(values2[i].key, *(values2[i].value))
		putInputToNewSyncMap(values2[i])
		t.Log(trie)
	}

	trie.Commit()
	h, err := trie.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		newRootHash = h
		t.Logf("%x", h)
	}

	it := NewValueIterator(trie)
	for it.Next() {
		k, n := it.Current()
		if n != nil {
			t.Logf("TRAVEL: %v %v", k, n)
		}
	}
}

func makeKeyMap(valuess ...[]inputs) map[string]struct{} {
	ret := make(map[string]struct{})
	for i := 0; i < len(valuess); i++ {
		for j := 0; j < len(valuess[i]); j++ {
			ret[string(valuess[i][j].key)] = emptyValue
		}
	}
	return ret
}

func findValueKey(value interface{}) []byte {
	if value == nil {
		return nil
	}
	for i := 0; i < len(values); i++ {
		if reflect.DeepEqual(values[i].value, value) {
			return values[i].key
		}
	}
	for i := 0; i < len(values2); i++ {
		if reflect.DeepEqual(values2[i].value, value) {
			return values2[i].key
		}
	}
	return nil
}

func TestTrieIterator(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()
	keymap := make(map[string]struct{})

	// oldRootHash, _ := hex.DecodeString("4801f431b825bba17a731c6eb657f54bcb3d0ca7ee85805fee290abe17a56c1c")
	trie := createTrie(oldRootHash, dbase)
	it := NewValueIterator(trie)
	for it.Next() {
		k, v := it.Current()
		if v != nil {
			key := findValueKey(v)
			if key == nil {
				t.Errorf("old trie no key found for value %v", v)
			} else {
				if bytes.Compare(key, k) != 0 {
					t.Errorf("key not equal %X != %X", key, k)
				}
				keystr := string(key)
				_, ok := keymap[keystr]
				if ok {
					t.Error("old trie duplicated key found", keystr)
				} else {
					t.Logf("%x -> %v", key, v)
					keymap[keystr] = emptyValue
				}
			}
		}
	}
	if len(keymap) == len(oldSyncMap) {
		t.Log("old trie iterate success")
	} else {
		t.Error("old trie iterate failed")
	}

	keymap = make(map[string]struct{})

	// nhash, _ := hex.DecodeString("2119a68c7c36e5df12aa06522fb8839222478c453ceaac32b50dc3ed81b33d9f")
	trie = createTrie(newRootHash, dbase)
	it = NewValueIterator(trie)
	for it.Next() {
		k, v := it.Current()
		if v != nil {
			key := findValueKey(v)
			if key == nil {
				t.Errorf("new trie no key found for value %v", v)
			} else {
				if bytes.Compare(key, k) != 0 {
					t.Errorf("key not equal: %X <> %X", key, k)
				}
				keystr := string(key)
				_, ok := keymap[keystr]
				if ok {
					t.Error("new trie duplicated key found", keystr)
				} else {
					t.Logf("%x -> %v", key, v)
					keymap[keystr] = emptyValue
				}
			}
		}
	}
	newkeymap := makeKeyMap(values, values2)
	if len(keymap) == len(newkeymap) {
		t.Log("new trie iterate success")
	} else {
		t.Error("new trie iterate failed")
	}

}

func TestSerialization(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	trie := createTrie(oldRootHash, dbase)
	buf := new(bytes.Buffer)
	if err := trie.Marshal(buf); err != nil {
		t.Error("trie marshal err", err)
	} else {
		t.Log("trie marshalled")
	}

	trie1, err := trie.UnmarshalNewTrie(buf, reflect.TypeOf((*trieValue)(nil)), func(v interface{}) []byte {
		if v == nil {
			return nil
		}
		return findValueKey(v)
	})
	if err != nil {
		t.Error("unmarshal trie error", err)
		return
	} else {
		t.Logf("trie unmarshalled")
	}
	hash1, err := trie1.HashValue()
	if err != nil {
		t.Error("trie hash error", err)
		return
	} else {
		t.Log("trie hashed")
	}
	if bytes.Equal(oldRootHash, hash1) {
		t.Log("trie unmarshal success")
		return
	} else {
		t.Error("trie unmarshal failed")
	}
}

func TestIterate(t *testing.T) {
	dbase, err := leveldb.OpenFile(testdbpath, nil)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	iter := dbase.NewIterator(nil, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()
		t.Logf("%x: %x", key, value)
	}
	iter.Release()
	err = iter.Error()
	if err != nil {
		t.Error(err)
	}
}

func TestLoadNode(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
	hash := newRootHash
	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
	trie := createTrie(hash, dbase)
	if err := trie.expandTrie(trie.root); err != nil {
		t.Error(err)
	}
	fmt.Println("new trie:\n", trie)

	// oldroothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
	oldroothash := oldRootHash
	// oldroothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
	trieOld := createTrie(oldroothash, dbase)
	if err := trieOld.expandTrie(trieOld.root); err != nil {
		t.Error(err)
	}
	fmt.Println("old trie:\n", trieOld)
}

func TestGet(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
	hash := newRootHash
	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
	trie := createTrie(hash, dbase)

	// for i := 0; i < len(values2); i++ {
	for kkk, vvv := range newSyncMap {
		key := []byte(kkk)
		v, ok := trie.Get(key)
		if ok {
			vv := v.(*trieValue)
			if reflect.DeepEqual(vv, vvv.value) {
				t.Logf("found %x, %t : %s", key, ok, v)
			} else {
				t.Errorf("found but not equals: %x, got %s should be %s", key, vv, vvv.value)
			}
		} else {
			t.Errorf("not found %x", key)
		}
	}

	// oldroothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
	oldroothash := oldRootHash
	// oldroothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
	trieOld := createTrie(oldroothash, dbase)

	// for i := 0; i < len(values); i++ {
	for kkk, vvv := range oldSyncMap {
		key := []byte(kkk)
		v, ok := trieOld.Get(key)
		if ok {
			vv := v.(*trieValue)
			if reflect.DeepEqual(vv, vvv.value) {
				t.Logf("found %x, %t : %s", key, ok, v)
			} else {
				t.Errorf("found but not equals: %x", key)
			}
		} else {
			t.Errorf("not found %x", key)
		}
	}
}

func TestDelete(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
	hash := newRootHash
	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
	trie := createTrie(hash, dbase)
	t.Log(trie)

	for i := 0; i < len(values3); i++ {
		key := values3[i].key
		changed, oldvalue := trie.Delete(key)
		t.Logf("Delete(%s)=(changed=%t, oldValue=%v)", hex.EncodeToString(key), changed, oldvalue)

		if (oldvalue == nil && values3[i].value == nil) || reflect.DeepEqual(values3[i].value, oldvalue) {
			t.Log("delete ok")
		} else {
			t.Errorf("deleted value(%s) error: should be (%s)", oldvalue, *(values3[i].value))
		}
		t.Log(trie)
	}

	trie.Commit()
	h, err := trie.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%x", h)
	}
	// 641a66e7f7ead95b25c5d4e27b23801c8a8304132afcae2d37267c80795d0c59
}

func TestOneNodeDelete(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	trie := createTrie(nil, dbase)

	value1 := &trieValue{
		A: 1293,
		B: "2222222",
	}

	key, err := common.HashObject(value1)
	if err != nil {
		t.Error(err)
		return
	}
	trie.Put(key, value1)
	trie.Commit()
	t.Log(trie)
	h, err := trie.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("added root hash: %x", h)
	}
	trie2 := createTrie(h, dbase)
	c, o := trie2.Delete(key)
	t.Logf("changed:%t old:%v", c, o)
	trie2.Commit()
	t.Log(trie2)
	h, err = trie2.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("deleted root hash: %x", h)
	}

	trie3 := createTrie(h, dbase)
	o, ok := trie3.Get(key)
	if !ok {
		t.Logf("%v %t", o, ok)
	} else {
		t.Errorf("%v %t", o, ok)
	}
	h, _ = trie3.HashValue()
	if bytes.Equal(h, EmptyNodeHashSlice) {
		t.Logf("its empty")
	} else {
		t.Errorf("it should be empty, root: %x", h)
	}
}

func TestTwoNodeDelete(t *testing.T) {
	key1 := []byte{0, 0, 0}
	value1 := &trieValue{
		A: 0,
		B: "0",
	}
	key2 := []byte{0, 0, 0, 1}
	value2 := &trieValue{
		A: 1,
		B: "1",
	}

	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	trie := createTrie(nil, dbase)

	trie.Put(key1, value1)
	trie.Commit()
	h1, _ := trie.HashValue()
	t.Logf("add one root: %x", h1)

	trie.Put(key2, value2)

	trie.Commit()
	h, _ := trie.HashValue()
	t.Logf("added root: %x", h)

	trie2 := createTrie(h, dbase)
	trie2.Delete(key2)
	trie2.Commit()
	h, _ = trie2.HashValue()
	if bytes.Equal(h, EmptyNodeHashSlice) {
		t.Errorf("it should not be empty!")
	} else {
		t.Logf("its not empty")
		if bytes.Equal(h1, h) {
			t.Logf("equals with one node: %x", h)
		} else {
			t.Errorf("not equal with one node: %x should be %x", h, h1)
		}
	}

	trie2.Delete(key1)
	h, _ = trie2.HashValue()
	if bytes.Equal(h, EmptyNodeHashSlice) {
		t.Log("its empty!")
	} else {
		t.Errorf("its not empty, root:%x", h)
	}
}

func TestTrace(t *testing.T) {
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	hash := newRootHash
	trie := createTrie(hash, dbase)

	for i := 0; i < len(tracing); i++ {
		prefix := keyToPrefix(tracing[i].key)
		trace := make([]nodePosition, 1)
		trace[0] = nodePosition{16, trie.root}
		_, ok := trie.get(trie.root, prefix, 0, &trace)
		if !ok {
			t.Errorf("%s not found", prefix)
		} else {
			if len(trace) != tracing[i].count {
				t.Errorf("found %d nodes in tracing route, should be %d", len(trace), tracing[i].count)
			} else {
				t.Log("found by", trace)
			}
		}
	}
}

func TestGetValue(t *testing.T) {

	clearDb(t)
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	trie := createTrie(nil, dbase)
	t.Log(trie.root)

	for i := 0; i < len(values); i++ {
		trie.Put(values[i].key, values[i].value)
		t.Log(trie)
	}
	trie.Commit()

	for i := 0; i < len(values); i++ {
		// t.Log("len:", trie.lruCache.Len())
		v, ok := trie.Get(values[i].key)
		if ok {
			vv := v.(*trieValue)
			if reflect.DeepEqual(vv, values[i].value) {
				t.Logf("found %x, %t : %s", values[i].key, ok, v)
			} else {
				t.Errorf("found but not equals: %x", values[i].key)
			}
		} else {
			t.Errorf("not found %x", values[i].key)
		}
	}
}

func TestProof(t *testing.T) {
	clearDb(t)

	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	// hash := newRootHash
	trie := createTrie(nil, dbase)
	t.Log(trie.root)

	// initial trie
	for i := 0; i < len(values); i++ {
		trie.Put(values[i].key, *(values[i].value))
	}
	trie.Commit()
	t.Log(trie)
	h, err := trie.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("%x", h)
	}

	for i := 0; i < len(values); i++ {
		t.Logf("%d----------------------------------------------------------------", i)
		fmt.Printf("%d----------------------------------------------------------------\n", i)
		// trie.Put(values[i].key, *(values[i].value))
		// t.Log(trie)
		//
		// trie.Commit()
		v, proof, ok := trie.GetProof(values[i].key)
		if !ok {
			t.Error("fail to get proof")
		}
		t.Logf("proof for %x : %s", values[i].key, proof)
		bf, err := rtl.Marshal(proof)
		if err != nil {
			t.Error(err)
		}

		var p ProofChain
		if err = rtl.Unmarshal(bf, &p); err != nil {
			t.Error(err)
		}
		t.Logf("%v", p)
		if ok {
			vh, err := common.HashObject(v)
			if err != nil {
				t.Errorf("hash object failed: %v", err)
				break
			}
			if VerifyProofChain(common.BytesToHash(vh), proof, h) {
				t.Logf("The proof pass.")
			} else {
				t.Errorf("The proof does not pass. valueHash: %x", vh[:5])
			}
		}

		// exsitence
		exist, proof, err := trie.GetExistenceProof(values[i].key)
		if err != nil {
			t.Error("make existence proof error: ", err)
			continue
		}
		t.Logf("exsitence proof for %x: %s", values[i].key, proof)
		isexist, err := proof.IsExist(values[i].key)
		if err != nil {
			t.Error("existence proof failed: ", err)
			continue
		}
		if exist == isexist {
			t.Logf("existence check: %t", exist)
		} else {
			t.Errorf("existence failed")
		}
	}

	for i := 0; i < len(existence); i++ {
		// exsitence
		exist, proof, err := trie.GetExistenceProof(existence[i].key)
		if err != nil {
			t.Error("make existence proof error: ", err)
			continue
		}
		t.Logf("exsitence proof for %x: %s", existence[i].key, proof)
		isexist, err := proof.IsExist(existence[i].key)
		if err != nil {
			t.Error("existence proof failed: ", err)
			continue
		}
		if exist == isexist {
			t.Logf("existence check: %t", exist)
		} else {
			t.Errorf("existence failed")
		}
	}
}

func TestExistence(t *testing.T) {
	clearDb(t)
	dbase, err := db.NewLDB(testdbpath)
	if err != nil {
		t.Error(err)
	}
	defer dbase.Close()

	tries := createTrie(nil, dbase)

	hash1, _ := common.Hash256s([]byte{0})
	exist1, proofs1, err1 := tries.GetExistenceProof(hash1)
	t.Logf("%x: exist:%t, proof:%s, err:%v", hash1, exist1, proofs1, err1)

	tries.Put(hash1, hash1)
	tries.Commit()

	t.Log(tries)
	hash2, _ := common.Hash256s([]byte{1})
	exist2, proofs2, err2 := tries.GetExistenceProof(hash2)
	t.Logf("%x: exist:%t, proof:%s, err:%v", hash2, exist2, proofs2, err2)

	hash1, _ = common.Hash256s([]byte{0})
	exist1, proofs1, err1 = tries.GetExistenceProof(hash1)
	t.Logf("%x: exist:%t, proof:%s, err:%v", hash1, exist1, proofs1, err1)
}
