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

package common

import (
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"testing"

	"github.com/stephenfire/go-rtl"
)

func TestNodeID_ParseBytes(t *testing.T) {

	var nb []byte = nil
	if nb == nil && len(nb) == 0 {
		t.Log("empty slice check ok")
	} else {
		t.Error("empty slice check failed")
	}

	nb = make([]byte, NodeIDBytes+1)

	n, err := io.ReadFull(rand.Reader, nb)
	if n != len(nb) || err != nil {
		t.Error("generate failed")
	}

	// var nid *nodeID
	id, err := ParseNodeIDBytes(nb)
	if err != nil {
		fmt.Print("WRONG: ", id, "\n")
		t.Error("illegal length check failed")
	} else {
		t.Log("wrong length check ok")
	}

	nb = nb[:NodeIDBytes]
	id, err = ParseNodeIDBytes(nb)
	if err != nil {
		t.Error("legal length check failed")
	} else {
		fmt.Print(id, "\n")
		t.Log("legal length check ok")
	}
}

func TestNodeIDSet(t *testing.T) {
	ids := make([]*NodeID, 20)
	for i := 0; i < 20; i++ {
		ids[i], _ = ParseNodeIDBytes(rtl.Numeric.UintToBytes(uint64(i)))
	}

	set := NewNodeIDSet(ids[3], ids[0], ids[2], ids[1])
	checkNodeIDSet(t, set, ids[:4])

	set.Delete(ids[3])
	checkNodeIDSet(t, set, ids[:3])

	ok := set.Put(ids[1])
	if ok {
		t.Error("put duplicated id error")
	}
	checkNodeIDSet(t, set, ids[:3])

	for i := 0; i < len(ids); i++ {
		set.Put(ids[i])
	}
	sort.Sort(set)
	checkNodeIDSet(t, set, ids)
}

func checkNodeIDSet(t *testing.T, set *NodeIDSet, ids []*NodeID) {
	if set.Len() != len(ids) {
		t.Errorf("length error, %d should be %d", set.Len(), len(ids))
	}
	for i := 0; i < set.Len(); i++ {
		id, ok := set.Get(i)
		if !ok {
			t.Errorf("get %d error", i)
		} else {
			if id == nil {
				t.Errorf("get %d failed", i)
			} else if *id != *ids[i] {
				t.Errorf("%s should be %s", *id, *ids[i])
			}
		}
		t.Logf("set.Get(%d) check", i)
		index, ok := set.GetIndex(ids[i])
		if !ok {
			t.Errorf("%X not found in set, should in %d", (*ids[i])[:], i)
		} else {
			if index != i {
				t.Errorf("index = %d should be %d", index, i)
			}
		}
		t.Logf("set.GetIndex(%X) check", (*ids[i])[:])
	}
}

func TestAddress(t *testing.T) {
	addr := BytesToAddress(RandomBytes(AddressLength))
	t.Logf("%s", addr)
}

func TestForPrint(t *testing.T) {
	h := BytesToHash(RandomBytes(HashLength))
	hp := &h
	t.Logf("%x", ForPrint(hp))

	a := BytesToAddress(RandomBytes(AddressLength))
	ap := &a
	t.Logf("%x", ForPrint(ap))

	s := []byte("12345678992342")
	sp := &s
	t.Logf("%x %x", ForPrint(s), ForPrint(sp))

	ss := []byte("343")
	ssp := &ss
	t.Logf("%x %x", ForPrint(ss), ForPrint(ssp))
}

func TestHash_Equals(t *testing.T) {
	h1 := BytesToHash(RandomBytes(HashLength))
	h2 := BytesToHash(h1[:])
	h3 := BytesToHash(RandomBytes(HashLength))

	t.Logf("h1==h2?%t, h2!=h3?%t, h1==h2?false?%t", h1 == h2, h2 != h3, h1 == h3)
}
