// // Copyright 2020 Thinkium
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
//
package trie

//
// import (
// 	"encoding/hex"
// 	"fmt"
// 	"os"
// 	"reflect"
// 	"testing"
//
// 	common "github.com/ThinkiumGroup/go-common"
// 	"github.com/ThinkiumGroup/go-common/db"
// 	"github.com/stephenfire/go-rtl"
// 	"github.com/syndtr/goleveldb/leveldb"
// )
//
// type trieValue1 struct {
// 	A int
// 	B string
// }
//
// func (tv trieValue1) String() string {
// 	return fmt.Sprintf("{a:%d, b:%s}", tv.A, tv.B)
// }
//
// type inputs1 struct {
// 	key   []byte
// 	value *trieValue1
// }
//
// var (
// 	value1s = []inputs1{
// 		{[]byte{0xf0, 0x12, 0x34}, &trieValue1{1, "node-0xf01234"}},
// 		{[]byte{0xf1, 0x23, 0x45}, &trieValue1{2, "node-0xf12345"}},
// 		{[]byte{0xf0, 0xab, 0xcd}, &trieValue1{3, "node-0xf0abcd"}},
// 		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue1{4, "node-0xf1234567"}},
// 		{[]byte{0xf0}, &trieValue1{5, "node-0xf0"}},
// 		{[]byte{0xb0, 0x12, 0x34, 0x56}, &trieValue1{6, "node-0xb0123456"}},
// 		{[]byte{0xf1, 0x34, 0x56}, &trieValue1{7, "node-0xf13456"}},
// 		{[]byte{0xf1, 0x23, 0x57}, &trieValue1{8, "node-0xf12357"}},
// 		{[]byte{0xb0, 0x12, 0x34}, &trieValue1{0, "node-0xb01234"}},
// 	}
//
// 	value1s2 = []inputs1{
// 		{[]byte{0xf0, 0x12, 0x34}, &trieValue1{11, "new-node-0xf01234"}},
// 		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue1{14, "new-node-0xf1234567"}},
// 		{[]byte{0xb1, 0x23, 0x45, 0x67}, &trieValue1{20, "new-node-0xb1234567"}},
// 	}
//
// 	value1s3 = []inputs1{
// 		{[]byte{0xf0, 0x12, 0x34}, &trieValue1{11, "new-node-0xf01234"}},
// 		{[]byte{0xf0}, &trieValue1{5, "node-0xf0"}},
// 		{[]byte{0xf1, 0x23, 0x58}, nil},
// 	}
//
// 	oldRootHash1 []byte
// 	newRootHash1 []byte
//
// 	testdbpath1 = common.HomeDir() + "/temp/dvppdata/trie1"
// )
//
// func valuehasher(value interface{}, valueBytes []byte) (hashBytes []byte, err error) {
// 	if len(valueBytes) >= (common.HashLength - 1) {
// 		return nil, common.ErrInsufficientLength
// 	}
// 	hashBytes = common.LeftPadBytes(valueBytes, common.HashLength)
// 	hashBytes[0] = byte(len(valueBytes))
// 	return hashBytes, nil
// }
//
// func valueexpander(hashBytes []byte, adapter db.DataAdapter) (valueBytes []byte, err error) {
// 	l := int(hashBytes[0])
// 	valueBytes = make([]byte, l)
// 	copy(valueBytes, hashBytes[len(hashBytes)-l:])
// 	return valueBytes, nil
// }
//
// func TestPut1(t *testing.T) {
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
// 	valueAdapter := db.NewTransparentDataAdapter()
// 	trie := NewTrie(nil, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	t.Log(trie.root)
//
// 	for i := 0; i < len(value1s); i++ {
// 		trie.Put(value1s[i].key, *(value1s[i].value))
// 		t.Log(trie)
// 	}
//
// 	trie.Commit()
// 	h, err := trie.HashValue()
// 	if err != nil {
// 		t.Error(err)
// 	} else {
// 		oldRootHash1 = h
// 		t.Logf("%x", h)
// 	}
// }
//
// func TestPut12(t *testing.T) {
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
// 	valueAdapter := db.NewTransparentDataAdapter()
// 	roothash := oldRootHash1
// 	// roothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
// 	// roothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
// 	trie := NewTrie(roothash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	t.Log(trie.root)
//
// 	for i := 0; i < len(value1s2); i++ {
// 		trie.Put(value1s2[i].key, *(value1s2[i].value))
// 		t.Log(trie)
// 	}
//
// 	trie.Commit()
// 	h, err := trie.HashValue()
// 	if err != nil {
// 		t.Error(err)
// 	} else {
// 		newRootHash1 = h
// 		t.Logf("%x", h)
// 	}
// }
//
// func TestIterate1(t *testing.T) {
// 	dbase, err := leveldb.OpenFile(testdbpath1, nil)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	iter := dbase.NewIterator(nil, nil)
// 	for iter.Next() {
// 		key := iter.Key()
// 		value := iter.Value()
// 		t.Logf("%x: %x", key, value)
// 	}
// 	iter.Release()
// 	err = iter.Error()
// 	if err != nil {
// 		t.Error(err)
// 	}
// }
//
// func TestLoadNode1(t *testing.T) {
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
// 	hash := newRootHash1
// 	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
// 	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
// 	valueAdapter := db.NewTransparentDataAdapter()
// 	trie := NewTrie(hash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	if err := trie.expandTrie(trie.root); err != nil {
// 		t.Error(err)
// 	}
// 	fmt.Println("new trie:\n", trie)
//
// 	// oldroothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
// 	oldroothash := oldRootHash1
// 	// oldroothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
// 	trieOld := NewTrie(oldroothash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	if err := trieOld.expandTrie(trieOld.root); err != nil {
// 		t.Error(err)
// 	}
// 	fmt.Println("old trie:\n", trieOld)
// }
//
// func TestGet1(t *testing.T) {
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
// 	hash := newRootHash1
// 	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
// 	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
// 	valueAdapter := db.NewTransparentDataAdapter()
// 	trie := NewTrie(hash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	for i := 0; i < len(value1s2); i++ {
// 		v, ok := trie.Get(value1s2[i].key)
// 		if ok {
// 			vv := v.(trieValue1)
// 			if reflect.DeepEqual(vv, *(value1s2[i].value)) {
// 				t.Logf("found %x, %t : %s", value1s2[i].key, ok, v)
// 			} else {
// 				t.Errorf("found but not equals: %x", value1s2[i].key)
// 			}
// 		} else {
// 			t.Errorf("not found %x", value1s2[i].key)
// 		}
// 	}
//
// 	// oldroothash, _ := hex.DecodeString("1171cdb982621cab7b7576e15110507d2fb6cba589495ef3347e3c9f1dedf11e")
// 	oldroothash := oldRootHash1
// 	// oldroothash, _ := hex.DecodeString("3621c2856d2b72eaa197a6b1d71efd34b8cd05af726090325c0ef2f4d15e7f98")
// 	trieOld := NewTrie(oldroothash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	for i := 0; i < len(value1s); i++ {
// 		v, ok := trieOld.Get(value1s[i].key)
// 		if ok {
// 			vv := v.(trieValue1)
// 			if reflect.DeepEqual(vv, *(value1s[i].value)) {
// 				t.Logf("found %x, %t : %s", value1s[i].key, ok, v)
// 			} else {
// 				t.Errorf("found but not equals: %x", value1s[i].key)
// 			}
// 		} else {
// 			t.Errorf("not found %x", value1s[i].key)
// 		}
// 	}
// }
//
// func TestDelete1(t *testing.T) {
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	// hash, _ := hex.DecodeString("58bf9c5cc68693366375c51d91fe16e53b31a7bc5a7984e48097f78e0302581b")
// 	hash := newRootHash1
// 	// hash, _ := hex.DecodeString("05c5171e71b0e87051a1108f0d89017dcd7e428bbf41dcadde24432ffe3ae57a")
// 	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
// 	valueAdapter := db.NewTransparentDataAdapter()
// 	trie := NewTrie(hash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue1)(nil)).Elem(), valuehasher, valueexpander)
// 	t.Log(trie)
//
// 	for i := 0; i < len(value1s3); i++ {
// 		key := value1s3[i].key
// 		changed, oldvalue := trie.Delete(key)
// 		t.Logf("Delete(%s)=(changed=%t, oldValue=%v)", hex.EncodeToString(key), changed, oldvalue)
//
// 		if (oldvalue == nil && value1s3[i].value == nil) || reflect.DeepEqual(*(value1s3[i].value), oldvalue) {
// 			t.Log("delete ok")
// 		} else {
// 			t.Errorf("deleted value(%s) error: should be (%s)", oldvalue, *(value1s3[i].value))
// 		}
// 		t.Log(trie)
// 	}
//
// 	trie.Commit()
// 	h, err := trie.HashValue()
// 	if err != nil {
// 		t.Error(err)
// 	} else {
// 		t.Logf("%x", h)
// 	}
// 	// 641a66e7f7ead95b25c5d4e27b23801c8a8304132afcae2d37267c80795d0c59
// }
//
// func clearDb1(t *testing.T) {
// 	if err := os.RemoveAll(testdbpath1); err != nil {
// 		t.Error(err)
// 	} else {
// 		t.Log("path remove ok")
// 	}
// }
//
// func TestProof1(t *testing.T) {
// 	clearDb1(t)
//
// 	dbase, err := db.NewLDB(testdbpath1)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	defer dbase.Close()
//
// 	// hash := newRootHash
// 	trie := createTrie(nil, dbase)
// 	t.Log(trie.root)
//
// 	for i := 0; i < len(value1s); i++ {
// 		t.Logf("----------------------------------------------------------------")
// 		// t.Log("len:", trie.lruCache.Len())
// 		trie.Put(value1s[i].key, *(value1s[i].value))
// 		t.Log(trie)
//
// 		trie.Commit()
// 		// if trie.root.hash == nil{
// 		// 	t.Logf("The root hash is empty.")
// 		// }
// 		h, err := trie.HashValue()
// 		if err != nil {
// 			t.Error(err)
// 		} else {
// 			t.Logf("%x", h)
// 		}
// 		v, proof, ok := trie.GetProof(value1s[i].key)
// 		if !ok {
// 			t.Error("fail to get proof")
// 		}
// 		bf, err := rtl.Marshal(proof)
// 		if err != nil {
// 			t.Error(err)
// 		}
//
// 		p := &ProofChain{}
// 		if err = rtl.Unmarshal(bf, p); err != nil {
// 			t.Error(err)
// 		}
// 		t.Logf("%v", p)
// 		if ok {
// 			vh, err := common.HashObject(v)
// 			if err != nil {
// 				t.Errorf("hash object failed: %v", err)
// 				break
// 			}
// 			if VerifyProofChain(common.BytesToHash(vh), proof, h) {
// 				t.Logf("The proof pass.")
// 			} else {
// 				t.Error("The proof does not pass.")
// 			}
// 		}
// 	}
// }
