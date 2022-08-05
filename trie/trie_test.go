package trie

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/ThinkiumGroup/go-common/hexutil"
)

type trieValue struct {
	A int
	B string
}

func (v *trieValue) Clone() *trieValue {
	if v == nil {
		return nil
	}
	return &trieValue{A: v.A, B: v.B}
}

func (v *trieValue) Equal(o *trieValue) bool {
	if v == o {
		return true
	}
	if v == nil || o == nil {
		return false
	}
	return v.A == o.A && v.B == o.B
}

func (v *trieValue) String() string {
	if v == nil {
		return "Value<nil>"
	}
	return fmt.Sprintf("Value{a:%d, b:%s}", v.A, v.B)
}

type inputs struct {
	key   []byte
	value *trieValue
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

	moreValues = []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{11, "new-node-0xf01234"}},
		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue{14, "new-node-0xf1234567"}},
		{[]byte{0xb1, 0x23, 0x45, 0x67}, &trieValue{20, "new-node-0xb1234567"}},
		{[]byte{0xb0, 0x12, 0x34, 0x67, 0x89}, &trieValue{21, "new-node-0xb012346789"}},
	}

	deleteValues = []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{11, "new-node-0xf01234"}},    // should not merge
		{[]byte{0xf0}, &trieValue{5, "node-0xf0"}},                         // should merge
		{[]byte{0xb0, 0x12, 0x34}, &trieValue{0, "node-0xb01234"}},         // should not merge
		{[]byte{0xb0, 0x12, 0x34, 0x56}, &trieValue{6, "node-0xb0123456"}}, // should merge
		{[]byte{0xf1, 0x23, 0x45}, &trieValue{2, "node-0xf12345"}},
		{[]byte{0xf0, 0xab, 0xcd}, &trieValue{3, "node-0xf0abcd"}},
		{[]byte{0xf1, 0x34, 0x56}, &trieValue{7, "node-0xf13456"}},
		{[]byte{0xf1, 0x23, 0x57}, &trieValue{8, "node-0xf12357"}},
		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue{14, "new-node-0xf1234567"}},
		{[]byte{0xb1, 0x23, 0x45, 0x67}, &trieValue{20, "new-node-0xb1234567"}},
		{[]byte{0xb0, 0x12, 0x34, 0x67, 0x89}, &trieValue{21, "new-node-0xb012346789"}},
	}
)

func _checkTrieValues(tr *Trie, valueMap map[string]*trieValue) error {
	if len(valueMap) == 0 && tr == nil {
		return nil
	}
	m := make(map[string]*trieValue)
	for k, v := range valueMap {
		m[k] = v
	}
	it := tr.ValueIterator()
	for it.Next() {
		k, v := it.Current()
		value := v.(*trieValue)
		key := hexutil.Encode(k)
		vv, exist := m[key]
		if !exist {
			return fmt.Errorf("%s in Trie but not in Map: %s", key, value)
		}
		if !reflect.DeepEqual(vv, value) {
			return fmt.Errorf("%s in Trie:%x not equals with in Map:%s", key, value, vv)
		}
		delete(m, key)
	}
	if len(m) > 0 {
		return fmt.Errorf("%v left in Map", m)
	}
	return nil
}

func _testCreateTrie(hash []byte, dbase db.Database) *Trie {
	nodeAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("in"))
	valueAdapter := db.NewKeyPrefixedDataAdapter(dbase, []byte("vn"))
	return NewTrieWithValueType(hash, nodeAdapter, valueAdapter, reflect.TypeOf((*trieValue)(nil)))
}

func _putAndCheckTrieValues(tr *Trie, valueMap map[string]*trieValue, vs []inputs) error {
	for _, input := range vs {
		v := input.value.Clone()
		if tr.Put(input.key, v) {
			key := hexutil.Encode(input.key)
			valueMap[key] = v
		}
	}
	return _checkTrieValues(tr, valueMap)
}

func _deleteAndCheckTrieValues(tr *Trie, valueMap map[string]*trieValue, vs []inputs) error {
	for _, input := range vs {
		changed, oldValue := tr.Delete(input.key)
		key := hexutil.Encode(input.key)
		mapvalue := valueMap[key]
		if !changed || !reflect.DeepEqual(oldValue, input.value) || !reflect.DeepEqual(oldValue, mapvalue) {
			return fmt.Errorf("delete %s:%s failed, got changed:%t oldValue:%v", key, input.value, changed, oldValue)
		}
	}
	root, _ := tr.HashValue()
	if !bytes.Equal(root, common.EmptyNodeHashSlice) {
		return fmt.Errorf("should be an empty trie, but root:%x", root)
	}
	return nil
}

func TestAll(t *testing.T) {
	dbase := db.NewMemDB()
	defer func() {
		_ = dbase.Close()
	}()

	tr := _testCreateTrie(nil, dbase)
	rootHash, _ := tr.HashValue()
	if !bytes.Equal(rootHash, common.EmptyNodeHashSlice) {
		t.Fatalf("creating an empty trie with wrong root:%x, should be:%x", rootHash, common.EmptyNodeHashSlice)
	}

	valueMap := make(map[string]*trieValue)
	if err := _putAndCheckTrieValues(tr, valueMap, values); err != nil {
		t.Fatalf("put values failed: %v", err)
	}

	if err := tr.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	root, _ := tr.HashValue()
	t.Logf("ROOT:%x\n%s", root, tr)

	// recreate and check
	tr = _testCreateTrie(root, dbase)
	t.Logf("trie recreated at ROOT:%x", root)

	if err := _deleteAndCheckTrieValues(tr, valueMap, values); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("restore and delete values check")

	tr = _testCreateTrie(root, dbase)
	if err := _putAndCheckTrieValues(tr, valueMap, moreValues); err != nil {
		t.Fatalf("put more values failed: %v", err)
	}

	if err := tr.Commit(); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	root, _ = tr.HashValue()
	t.Logf("more ROOT:%x\n%s", root, tr)

	tr = _testCreateTrie(root, dbase)
	t.Logf("trie recreated at more ROOT:%x", root)

	if err := _deleteAndCheckTrieValues(tr, valueMap, deleteValues); err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("delete and merge check")
}
