package trie

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/ThinkiumGroup/go-common/db"
)

type _trieValueNode struct {
	key string
	val *trieValue
}

func (n _trieValueNode) String() string {
	return fmt.Sprintf("{Key:%s}", n.key)
}

type _trieValueNodes []_trieValueNode

func (ns _trieValueNodes) Len() int {
	return len(ns)
}

func (ns _trieValueNodes) Swap(i, j int) {
	ns[i], ns[j] = ns[j], ns[i]
}

func (ns _trieValueNodes) Less(i, j int) bool {
	return bytes.Compare([]byte(ns[i].key), []byte(ns[j].key)) < 0
}

func (ns _trieValueNodes) Equal(os _trieValueNodes) error {
	if len(ns) != len(os) {
		return fmt.Errorf("expecting length:%d but:%d", len(ns), len(os))
	}
	if len(ns) == 0 {
		return nil
	}
	for i := 0; i < len(ns); i++ {
		if ns[i].key != os[i].key || ns[i].val.Equal(os[i].val) == false {
			return fmt.Errorf("index:%d expecting:%s but:%s", i, ns[i], os[i])
		}
	}
	return nil
}

func _checkValueIterator(t *testing.T, tr *Trie, m map[string]*trieValue) error {
	if len(m) == 0 {
		return nil
	}
	vals := make(_trieValueNodes, 0, len(m))
	for k, val := range m {
		vals = append(vals, _trieValueNode{
			key: k,
			val: val,
		})
	}
	sort.Sort(vals)

	var itvals _trieValueNodes
	it := tr.ValueIterator()
	for it.Next() {
		key, val := it.Current()
		tv := val.(*trieValue)
		itvals = append(itvals, _trieValueNode{
			key: hex.EncodeToString(key),
			val: tv,
		})
	}
	if err := vals.Equal(itvals); err != nil {
		return fmt.Errorf("iterater failed: %v, vals:%s itvals:%s", err, vals, itvals)
	}

	it = tr.ReversedValueIterator()
	var reversedVals _trieValueNodes
	for it.Next() {
		key, val := it.Current()
		tv := val.(*trieValue)
		reversedVals = append(reversedVals, _trieValueNode{
			key: hex.EncodeToString(key),
			val: tv,
		})
	}
	rvals := make(_trieValueNodes, len(reversedVals))
	for i, v := range reversedVals {
		rvals[len(rvals)-1-i] = v
	}
	if err := vals.Equal(rvals); err != nil {
		return fmt.Errorf("reversed iterater failed: %v, vals:%s rvals:%s", err, vals, itvals)
	}

	t.Logf("=> %s", vals)
	t.Logf("<= %s", reversedVals)
	return nil
}

func TestTrieValueIterator(t *testing.T) {
	values := []inputs{
		{[]byte{0xf0, 0x12, 0x34}, &trieValue{1, "node-0xf01234"}},
		{[]byte{0x00, 0x33, 0x34}, &trieValue{1, "node-0x003334"}},
		{[]byte{0xf1, 0x23, 0x45}, &trieValue{2, "node-0xf12345"}},
		{[]byte{0xb0, 0x12, 0x34, 0x67, 0x89}, &trieValue{12, "new-node-0xb012346789"}},
		{[]byte{0xf0, 0xab, 0xcd}, &trieValue{3, "node-0xf0abcd"}},
		{[]byte{0x10}, &trieValue{1, "node-0x10"}},
		{[]byte{0xf1, 0x23, 0x45, 0x67}, &trieValue{4, "node-0xf1234567"}},
		{[]byte{0xf0}, &trieValue{5, "node-0xf0"}},
		{[]byte{0xb0, 0x12, 0x34, 0x56}, &trieValue{6, "node-0xb0123456"}},
		{[]byte{0xf1, 0x34, 0x56}, &trieValue{7, "node-0xf13456"}},
		{[]byte{0xf1, 0x23, 0x57}, &trieValue{8, "node-0xf12357"}},
		{[]byte{0xb0, 0x12, 0x34}, &trieValue{10, "node-0xb01234"}},
		{[]byte{0xb1, 0x23, 0x45, 0x67}, &trieValue{11, "new-node-0xb1234567"}},
	}

	dbase := db.NewMemDB()
	tr := _testCreateTrie(nil, dbase)
	m := make(map[string]*trieValue)
	for _, val := range values {
		key := hex.EncodeToString(val.key)
		m[key] = val.value
		tr.Put(val.key, val.value)
		if err := tr.Commit(); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
		if err := _checkValueIterator(t, tr, m); err != nil {
			t.Fatalf("m:%s, check failed: %v", m, err)
		} else {
			t.Logf("m:%s check", m)
		}
	}

	for _, val := range values {
		key := hex.EncodeToString(val.key)
		delete(m, key)
		tr.Delete(val.key)
		if err := tr.Commit(); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
		if err := _checkValueIterator(t, tr, m); err != nil {
			t.Fatalf("m:%s, check failed: %v", m, err)
		} else {
			t.Logf("m:%s check", m)
		}
	}
}
