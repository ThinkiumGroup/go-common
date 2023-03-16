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
	"fmt"
	"reflect"
	"testing"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/db"
	"github.com/stephenfire/go-rtl"
)

func encodeAndDecode(t *testing.T, tn *TreeNode) (*TreeNode, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	err := rtl.Encode(tn, buf)
	if err != nil {
		// t.Errorf("encode error: %v", err)
		return nil, err
	}
	bs := buf.Bytes()
	t.Logf("encoded: %x", bs)

	buf = bytes.NewBuffer(bs)
	tn2 := &TreeNode{}
	err = rtl.Decode(buf, tn2)
	if err != nil {
		// t.Errorf("decode error: %v", err)
		return nil, err
	}
	return tn2, nil
}

func TestTreeNode(t *testing.T) {
	tn1 := &TreeNode{
		isLeaf:  true,
		Branchs: map[string][]byte{"000": []byte("v000")},
		Leafs:   [childrenLength][]byte{[]byte("00000"), []byte("00001"), []byte("00002")},
	}

	tn2, err := encodeAndDecode(t, tn1)
	if err != nil {
		t.Errorf("encode/decode error: %v", err)
		return
	}

	if reflect.DeepEqual(tn1, tn2) {
		t.Logf("%v -> %v check", tn1, tn2)
	} else {
		t.Errorf("%v -> %v failed", tn1, tn2)
		return
	}

	tn3 := &TreeNode{
		isLeaf:   false,
		Branchs:  make(map[string][]byte),
		Children: [childrenLength]*TreeNode{tn1},
	}

	tn4, err := encodeAndDecode(t, tn3)
	if err != nil {
		t.Errorf("encode/decode tn3 error: %v", err)
		return
	}
	if tn3.isLeaf != tn4.isLeaf || reflect.DeepEqual(tn3.Branchs, tn4.Branchs) == false {
		t.Errorf("%v -> %v failed", tn3, tn4)
		return
	}
	for i := 0; i < childrenLength; i++ {
		if tn3.Children[i] == nil && tn4.Children[i] == nil {
			continue
		}
		if (tn3.Children[i] == nil && tn4.Children[i] != nil) || (tn4.Children[i] == nil && tn3.Children[i] != nil) {
			t.Errorf("%v -> %v failed", tn3, tn4)
			return
		}
		h3, err := tn3.Children[i].HashValue()
		if err != nil {
			t.Errorf("%v -> %v failed error:%v", tn3, tn4, err)
			return
		}
		h4, err := tn4.Children[i].HashValue()
		if err != nil {
			t.Errorf("%v -> %v failed error:%v", tn3, tn4, err)
			return
		}
		if bytes.Equal(h3, h4) == false {
			t.Errorf("%v -> %v failed error: mismatch hash at %d", tn3, tn4, i)
			return
		}
	}
	t.Logf("%v -> %v check", tn3, tn4)
}

func TestHistoryTree(t *testing.T) {
	dbase := db.NewMemDB()
	defer func() {
		_ = dbase.Close()
	}()
	htree, err := NewHistoryTree(dbase, []byte("al"), nil, true)
	if err != nil {
		t.Fatalf("new tree error: %v", err)
	}
	if htree.root != nil || htree.expecting != 0 || htree.adapter == nil {
		t.Fatalf("new tree wrong")
	} else {
		t.Log("new tree ok")
	}

	nilhash, err := htree.HashValue()
	if err != nil {
		t.Fatalf("htree.HashValue error: %v", err)
	}
	if bytes.Equal(nilhash, common.NilHashSlice) {
		t.Logf("emtpy htree hash equals to NilHashSlice: %x", nilhash)
	} else {
		t.Fatalf("empty htree hash: %x not equals to NilHashSlice: %x", nilhash, common.NilHashSlice)
	}

	buf := make([]byte, 8)
	var h uint64
	for h = 0; h <= 10; h++ {
		binary.BigEndian.PutUint64(buf, h)
		v, err := common.Hash256s(buf)
		if err != nil {
			t.Errorf("hash %x error: %v", buf, err)
			return
		}
		err = htree.Append(h, v)
		if err != nil {
			t.Errorf("Append(%d,%x) error: %v", h, v, err)
			return
		} else {
			t.Logf("Append(%d,%x) ok", h, v)
		}
	}
	if err = htree._commit(); err != nil {
		t.Errorf("Commit error: %v", err)
	} else {
		t.Log("Commit check")
	}

	root10, err := htree.HashValue()
	if err != nil {
		t.Errorf("HashValue error: %v", err)
		return
	} else {
		t.Logf("root10: %x", root10)
	}

	binary.BigEndian.PutUint64(buf, h+1)
	v, _ := common.Hash256s(buf)
	err = htree.Append(h+1, v)
	if err != common.ErrIllegalParams {
		t.Errorf("Append not in order (%d, %x) should be %v", h+1, v, common.ErrIllegalParams)
		return
	} else {
		t.Logf("Append not in order (%d, %x) got an %v check", h+1, v, common.ErrIllegalParams)
	}

	root10, err = htree.HashValue()
	if err != nil {
		t.Errorf("HashValue error: %v", err)
		return
	} else {
		t.Logf("root10: %x", root10)
	}

	value, proofs, ok := htree.GetProof(10)
	if !ok {
		t.Errorf("GetProof(10) failed: %v, %v, %t", value, proofs, ok)
		return
	} else {
		t.Logf("GetProof(10) %v, %v, %t", value, proofs, ok)
	}

	binary.BigEndian.PutUint64(buf, 10)
	v, _ = common.Hash256s(buf)
	if bytes.Equal(v, value) == false {
		t.Errorf("Hash256(Serialize(10)) != %x should be %x", value, v)
		return
	} else {
		t.Logf("Hash256(Serialize(10)) == %x check", v)
	}

	pv, err := proofs.Proof(common.BytesToHash(v))
	if err != nil {
		t.Errorf("Proof(%x) error: %v", v, err)
		return
	}
	if bytes.Equal(pv, root10) == false {
		t.Errorf("Proof(%x) != %v but %v failed", v, root10, pv)
		return
	} else {
		t.Logf("Proof(%x) == %v check", v, root10)
	}

	fmt.Printf("===========RestoreTreeFromProofs(db,10,%x,%v)===========\n", value, proofs)
	htree2, err := RestoreTreeFromProofs(dbase, []byte("al"), 10, value, proofs)
	if err != nil {
		t.Errorf("restore tree from proofs error: %v", err)
		return
	} else {
		t.Logf("restored tree: %v", htree2)
	}

	binary.BigEndian.PutUint64(buf, h)
	v, _ = common.Hash256s(buf)
	fmt.Printf("===========htree.Append(%d) begin===========\n", h)
	err = htree.Append(h, v)
	if err != nil {
		t.Errorf("htree.Append(%d,%x) error: %v", h, v, err)
		return
	} else {
		t.Logf("htree.Append(%d,%x) ok", h, v)
	}

	fmt.Printf("===========htree2.Append(%d) begin===========\n", h)
	err = htree2.Append(h, v)
	if err != nil {
		t.Errorf("htree2.Append(%d,%x) error: %v", h, v, err)
		return
	} else {
		t.Logf("htree2.Append(%d,%x) ok", h, v)
	}

	fmt.Println("===========htree.HashValue begin===========")
	hhash, err := htree.HashValue()
	if err != nil {
		t.Errorf("htree.HashValue() error: %v", err)
		return
	}

	fmt.Println("===========htree2.HashValue begin===========")
	hhash2, err := htree2.HashValue()
	if err != nil {
		t.Errorf("htree2.HashValue() error: %v", err)
		return
	}

	if !bytes.Equal(hhash, hhash2) {
		t.Errorf("htree.Hash: %x != htree2.Hash: %x", hhash, hhash2)
		return
	} else {
		t.Logf("htree.Hash == htree2.Hash %x check", hhash)
	}

	h++
	binary.BigEndian.PutUint64(buf, h)
	v, _ = common.Hash256s(buf)
	fmt.Printf("===========htree.Append(%d) begin===========\n", h)
	err = htree.Append(h, v)
	if err != nil {
		t.Errorf("htree.Append(%d,%x) error: %v", h, v, err)
		return
	} else {
		t.Logf("htree.Append(%d,%x) ok", h, v)
	}

	fmt.Printf("===========htree2.Append(%d) begin===========\n", h)
	err = htree2.Append(h, v)
	if err != nil {
		t.Errorf("htree2.Append(%d,%x) error: %v", h, v, err)
		return
	} else {
		t.Logf("htree2.Append(%d,%x) ok", h, v)
	}

	fmt.Println("===========htree.HashValue begin===========")
	hhash, err = htree.HashValue()
	if err != nil {
		t.Errorf("htree.HashValue() error: %v", err)
		return
	}

	fmt.Println("===========htree2.HashValue begin===========")
	hhash2, err = htree2.HashValue()
	if err != nil {
		t.Errorf("htree2.HashValue() error: %v", err)
		return
	}

	if !bytes.Equal(hhash, hhash2) {
		t.Errorf("htree.Hash: %x != htree2.Hash: %x", hhash, hhash2)
		return
	} else {
		t.Logf("htree.Hash == htree2.Hash %x check", hhash)
	}
}

func TestHistoryTree_Append(t *testing.T) {
	dbase := db.NewMemDB()
	defer func() {
		_ = dbase.Close()
	}()
	htree, err := NewHistoryTree(dbase, []byte("al"), nil, true)
	if err != nil {
		t.Errorf("new tree error: %v", err)
		return
	}

	var p1 uint64 = 35
	var p2 uint64 = 104

	buf := make([]byte, 8)
	var h uint64
	for h = 0; h <= p1; h++ {
		binary.BigEndian.PutUint64(buf, h)
		v, err := common.Hash256s(buf)
		if err != nil {
			t.Errorf("hash %x error: %v", buf, err)
			return
		}
		err = htree.Append(h, v)
		if err != nil {
			t.Errorf("Append(%d,%x) error: %v", h, v, err)
			return
		} else {
			t.Logf("Append(%d,%x) ok", h, v)
		}
		if err = htree._commit(); err != nil {
			t.Errorf("Commit error: %v", err)
			return
		} else {
			t.Logf("Commit check %s", htree)
		}
		if err = htree.CollapseBefore(h); err != nil {
			t.Errorf("CollapseBefore(%d) error: %v", h, err)
			return
		}
	}

	root1, err := htree.HashValue()
	if err != nil {
		t.Errorf("HashValue error: %v", err)
		return
	} else {
		t.Logf("root1: %x", root1)
	}

	value, proofs, ok := htree.GetProof(p1)
	if !ok {
		t.Errorf("GetProof(%d) failed: %v, %v, %t", p1, value, proofs, ok)
		return
	} else {
		t.Logf("GetProof(%d) %v, %v, %t", p1, value, proofs, ok)
	}

	v, exist := htree.Get(p1)
	if !exist || !bytes.Equal(value, v) {
		t.Errorf("Get(%d)=%x not %x", p1, v, value)
		return
	}

	pv, err := proofs.Proof(common.BytesToHash(v))
	if err != nil {
		t.Errorf("Proof(%x) error: %v", v, err)
		return
	}
	if bytes.Equal(pv, root1) == false {
		t.Errorf("Proof(%x) != %v but %v failed", v, root1, pv)
		return
	} else {
		t.Logf("Proof(%x) == %v check", v, root1)
	}

	htree2, err := RestoreTreeFromProofs(dbase, []byte("al"), p1, value, proofs)
	if err != nil {
		t.Errorf("restore tree from proofs error: %v", err)
		return
	} else {
		t.Logf("restored tree: %v", htree2)
	}

	for h = p1 + 1; h <= p2; h++ {
		binary.BigEndian.PutUint64(buf, h)
		v, err := common.Hash256s(buf)
		if err != nil {
			t.Errorf("hash %x error: %v", buf, err)
			return
		}
		err = htree2.Append(h, v)
		if err != nil {
			t.Errorf("Append(%d,%x) error: %v", h, v, err)
			return
		} else {
			t.Logf("Append(%d,%x) ok", h, v)
		}
	}

	root2, err := htree2.HashValue()
	if err != nil {
		t.Errorf("HashValue(%d) error: %v", p2, err)
		return
	} else {
		t.Logf("root2: %x", root2)
	}

}

func hashuint64(h uint64, buf []byte) []byte {
	binary.BigEndian.PutUint64(buf, h)
	v, _ := common.Hash256s(buf)
	return v
}

func appendhistory(htree *HistoryTree, start, end uint64) error {
	buf := make([]byte, 8)
	for h := start; h < end; h++ {
		v := hashuint64(h, buf)
		err := htree.Append(h, v)
		if err != nil {
			return err
		}
		if err = htree._commit(); err != nil {
			return err
		}
		if err = htree.CollapseBefore(h); err != nil {
			return err
		}
	}
	return nil
}

func TestHistoryRestore(t *testing.T) {
	dbase := db.NewMemDB()
	defer func() {
		_ = dbase.Close()
	}()
	htree, err := NewHistoryTree(dbase, []byte("al"), nil, true)
	if err != nil {
		t.Errorf("new tree error: %v", err)
		return
	}

	var start, end uint64 = 0, 16
	if err := appendhistory(htree, start, end); err != nil {
		t.Errorf("Append from %d to %d error: %v", start, end, err)
		return
	} else {
		t.Logf("Append from %d to %d ok", start, end)
	}

	hash0x0f, _ := htree.HashValue()
	p := end - 1
	value, proofs, ok := htree.GetProof(p)
	if !ok {
		t.Errorf("GetProof(%d) failed: %x, %v, %t", p, value, proofs, ok)
		return
	} else {
		t.Logf("GetProof(%d) %x, %v, %t, root:%x", p, value, proofs, ok, hash0x0f)
	}

	if err = appendhistory(htree, end, end+1); err != nil {
		t.Errorf("Append %d error: %v", end, err)
		return
	} else {
		t.Logf("append %d ok", end)
	}

	hash0x0f1, _ := htree.HashValue()
	value, proofs, ok = htree.GetProof(p)
	if !ok {
		t.Errorf("GetProof(%d) failed: %x, %v, %t", p, value, proofs, ok)
		return
	} else {
		t.Logf("GetProof(%d) %x, %v, %t, root:%x", p, value, proofs, ok, hash0x0f1)
	}

	htree2, _ := NewHistoryTree(dbase, []byte("al"), hash0x0f, true)
	value, proofs, ok = htree2.GetProof(p)
	if !ok {
		t.Errorf("GetProof(%d) failed: %x, %v, %t", p, value, proofs, ok)
		return
	} else {
		t.Logf("GetProof(%d) %x, %v, %t, root:%x", p, value, proofs, ok, hash0x0f)
	}
}

//
// func historytreeproof(t *testing.T, htree *HistoryTree, p uint64) (value []byte, proofs ProofChain, ok bool) {
// 	value, proofs, ok = htree.GetProof(p)
// 	if !ok || len(proofs) != HistoryTreeDepth {
// 		t.Errorf("GetProof(%d) failed: %x, %v, %t", p, value, proofs, ok)
// 		return nil, nil, false
// 	} else {
// 		t.Logf("GetProof(%d) %x, %v, %t", p, value, proofs, ok)
// 	}
// 	return
// }

func TestHistoryTree_MergeProof(t *testing.T) {
	dbase1 := db.NewMemDB()
	defer func() {
		_ = dbase1.Close()
	}()
	dbase2 := db.NewMemDB()
	defer func() {
		_ = dbase2.Close()
	}()

	htree1, err := NewHistoryTree(dbase1, []byte("al"), nil, true)
	if err != nil {
		t.Fatalf("new tree error: %v", err)
	}
	start, end := uint64(0), uint64(3000)
	if err := appendhistory(htree1, start, end); err != nil {
		t.Fatalf("append from %d to %d error: %v", start, end, err)
	} else {
		t.Logf("Append from %d to %d ok", start, end)
	}

	value15, proofs15, ok := htree1.GetProof(15)
	if !ok {
		t.Fatal("get proof 15 failed")
	}
	value128, proofs128, ok := htree1.GetProof(128)
	if !ok {
		t.Fatal("get proof 128 failed")
	}
	value200, proofs200, ok := htree1.GetProof(200)
	if !ok {
		t.Fatal("get proof 200 failed")
	}
	value2345, proofs2345, ok := htree1.GetProof(2345)
	if !ok {
		t.Fatal("get proof 2345 failed")
	}
	last := htree1.Expecting() - 1
	valuel, proofsl, ok := htree1.GetProof(last)
	if !ok {
		t.Fatalf("get proof (%d) failed", last)
	}

	htree2, err := RestoreTreeFromProofs(dbase2, []byte("al"), last, valuel, proofsl)
	if err != nil {
		t.Fatalf("restore tree from proofs error: %v", err)
	} else {
		t.Logf("restored tree: %v", htree2)
	}

	merge := func(key uint64, value []byte, proofs ProofChain) bool {
		if err := htree2.MergeProof(key, value, proofs); err != nil {
			t.Logf("mergeProof(%d,%x,%s) error: %v", key, value, proofs, err)
			return false
		} else {
			t.Logf("mergeProof(%d) ok", key)
		}
		return true
	}

	if merge(16, value15, proofs15) == false {
		t.Logf("wrong height detected, check")
	} else {
		t.Fatal("proofs and height not match, should not ok")
	}

	if !merge(15, value15, proofs15) ||
		!merge(128, value128, proofs128) ||
		!merge(200, value200, proofs200) ||
		!merge(2345, value2345, proofs2345) {
		t.Fatalf("merge check failed")
		return
	}

	rootCompare := func(htree1 *HistoryTree, htree2 *HistoryTree) bool {
		root1, err := htree1.HashValue()
		if err != nil {
			t.Logf("hash error: %v", err)
			return false
		}
		root2, err := htree2.HashValue()
		if err != nil {
			t.Logf("htree2.hash failed: %v", err)
			return false
		}
		if !bytes.Equal(root1, root2) {
			t.Logf("historyTree root not equal (%x) (%x)", root1, root2)
			return false
		}
		return true
	}

	if err = htree2._commit(); err != nil {
		t.Fatalf("htree2.commit failed: %v", err)
	}
	if !rootCompare(htree1, htree2) {
		t.Fatal("roots of htree1 htree2 are not equal")
	}

	start1, end1 := end, end+300
	if err = appendhistory(htree1, start1, end1); err != nil {
		t.Fatalf("append1 %d->%d error: %v", start1, end1, err)
	}
	if err = appendhistory(htree2, start1, end1); err != nil {
		t.Fatalf("append2 %d->%d error: %v", start1, end1, err)
	}

	if !rootCompare(htree1, htree2) {
		t.Fatal("roots of htree1 htree2 are not equal 2")
	}
	root1, _ := htree1.HashValue()

	value152, proofs152, ok := htree2.GetProof(15)
	if !ok {
		t.Fatal("htree2 get proof 15 failed")
	}
	value1282, proofs1282, ok := htree2.GetProof(128)
	if !ok {
		t.Fatal("htree2 get proof 128 failed")
	}
	value2002, proofs2002, ok := htree2.GetProof(200)
	if !ok {
		t.Fatal("htree2 get proof 200 failed")
	}
	value23452, proofs23452, ok := htree1.GetProof(2345)
	if !ok {
		t.Fatal("htree2 get proof 2345 failed")
	}

	if !bytes.Equal(value15, value152) || !bytes.Equal(value128, value1282) ||
		!bytes.Equal(value200, value2002) || !bytes.Equal(value2345, value23452) {
		t.Fatal("values' of htree2 not equal with htree1s'")
	}

	prooffunc := func(key uint64, value []byte, proofs ProofChain, rootHash []byte) bool {
		// h, ok := proofs.Key()
		// if ok {
		// 	if key != h {
		// 		return false
		// 	}
		// }
		h := proofs.BigKey().Uint64()
		if key != h {
			t.Fatalf("proof.BigKey=%d but key input=%d", h, key)
			return false
		}
		r, err := proofs.Proof(common.BytesToHash(value))
		if err != nil {
			t.Fatalf("%d.Proof(%x) %s error: %v", key, value, proofs, err)
			return false
		}
		if bytes.Equal(r, rootHash) {
			t.Logf("%d proofs check %s", key, proofs)
			return true
		} else {
			t.Fatalf("%d proofs %s failed", key, proofs)
			return false
		}
	}

	if !prooffunc(15, value152, proofs152, root1) ||
		!prooffunc(128, value1282, proofs1282, root1) ||
		!prooffunc(200, value2002, proofs2002, root1) ||
		!prooffunc(2345, value23452, proofs23452, root1) {
		return
	}
}

// // specific data test, not a unit test
// func TestLoadPartTree(t *testing.T) {
// 	dbase, err := db.NewLDB("/Users/stephen/temp/dvppdir/data/data7/db0")
// 	if err != nil {
// 		t.Errorf("%v", err)
// 		return
// 	}
// 	defer dbase.Close()
// 	root, _ := hex.DecodeString("283e288c296ff2d88187ae013a4f6a20b2ded1bcd79248c2effc5b462621a9e5")
// 	htree, err := NewHistoryTree(dbase, root, false)
// 	if err != nil {
// 		t.Errorf("new history tree error: %v", err)
// 		return
// 	}
// 	h := randomBytes(common.HashLength)
// 	t.Logf("Appending: Height:%d Hash:%x", htree.expecting, h)
// 	if err = htree.Append(htree.expecting, h); err != nil {
// 		t.Errorf("append error: %v", err)
// 		return
// 	}
// 	t.Logf("ok, history tree: %s", htree)
// }

func TestHistoryTree_Chop(t *testing.T) {
	count := uint64(3000)
	dbase := db.NewMemDB()
	rootMap := make(map[uint64][]byte)
	valMap := make(map[uint64][]byte)
	tree, err := NewHistoryTree(dbase, []byte("al"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for key := uint64(0); key < count; key++ {
		val := randomBytes(common.HashLength)
		if err := tree.Append(key, val); err != nil {
			t.Fatalf("append(key:%d, val:%x) failed: %v", key, val, err)
		}
		valMap[key] = val
		root, err := tree.CommitAndHash()
		if err != nil {
			t.Fatalf("commit and hash at key:%d failed: %v", key, err)
		}
		rootMap[key] = root
		if key > 0 {
			if err := _examChop(tree, rootMap, valMap, key); err != nil {
				t.Fatalf("_examChop(%d) failed: %v", key, err)
			} else {
				t.Logf("_examChop(%d) ok", key)
			}
		}
	}
	t.Log("ok")
}

func _examChop(tree *HistoryTree, rootMap, valMap map[uint64][]byte, key uint64) error {
	i := uint64(0)
	if key > 33 {
		i = key - 33
	}
	for ; i < key; i++ {
		choped, err := tree.Chop(i)
		if err != nil {
			return fmt.Errorf("chop(i:%d) %s failed: %v", i, tree, err)
		}
		root, err := choped.HashValue()
		if err != nil {
			return fmt.Errorf("chop(i:%d) %s hash failed: %v", i, choped, err)
		}
		exproot, _ := rootMap[i]
		if !bytes.Equal(exproot, root) {
			return fmt.Errorf("chop(i:%d) %s root %x not match with %x", i, choped, root, exproot)
		}

		val, proof, ok := choped.GetProof(i)
		if !ok {
			return fmt.Errorf("chop(i:%d) %s GetProof(%d) failed", i, choped, i)
		}
		if expval := valMap[i]; !bytes.Equal(val, expval) {
			return fmt.Errorf("chop(i:%d) Proofs of %d, value:%x not match with %s", i, i, val, expval)
		}
		proofed, err := proof.Proof(common.BytesToHash(val))
		if err != nil {
			return fmt.Errorf("chop(i:%d) %s proofs:%s proof(%x) failed: %v", i, choped, proof, val, err)
		}
		if !bytes.Equal(proofed, root) {
			return fmt.Errorf("chop(i:%d) %s proofs:%s proof(%x)=%x not match %x", i, choped, proof, val, proofed, root)
		}

		for j := i + 1; j < i+20 && j <= key; j++ {
			val, _ := valMap[j]
			if val == nil {
				return fmt.Errorf("value of key:%d not found", j)
			}
			if err := choped.Append(j, val); err != nil {
				return fmt.Errorf("jchoped(i:%d) %s append (key:%d val:%x) failed: %v", i, choped, j, val, err)
			}
			if jroot, err := choped.HashValue(); err != nil {
				return fmt.Errorf("jchoped(i:%d) %s hash failed: %v", i, choped, err)
			} else {
				jexproot := rootMap[j]
				if !bytes.Equal(jroot, jexproot) {
					return fmt.Errorf("jchoped(i:%d) %s root %x not match with %x", i, choped, jroot, jexproot)
				}
			}
		}
	}
	return nil
}
