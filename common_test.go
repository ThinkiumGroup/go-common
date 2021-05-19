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
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestServiceStatus(t *testing.T) {
	ss := ServiceStatus(SSCreated)

	if ss == SSCreated {
		t.Log("create ok")
	} else {
		t.Error("create failed")
	}

	ss.CheckInit()
	if ss == SSInitialized {
		t.Log("init ok")
	} else {
		t.Error("init failed")
	}

	ss.CheckStart()
	if ss == SSStarted {
		t.Log("start ok")
	} else {
		t.Error("start failed")
	}

	ss.CheckStop()
	if ss == SSStopped {
		t.Log("stop ok")
	} else {
		t.Error("stop failed")
	}
}

func TestSmap(t *testing.T) {
	var m sync.Map
	m.Store("123", 567)
	m.Store(32323, "43")

	x := 76
	m.Store(&x, "shabi")

	fmt.Println(&x)

	if v, ok := m.Load("123"); !ok || v != 567 {
		t.Error("get wrong value")
	}

	if v, ok := m.Load(32323); !ok || v != "43" {
		t.Error("get wrong value")
	}
	if v, ok := m.Load(&x); !ok || v != "shabi" {
		t.Error("get wrong value")
	}
	// m.Range(f func(key, v interface{}){}bool)

	all := 0
	f := func(k, v interface{}) bool {
		all = all + 1
		return true
	}

	m.Range(f)
	fmt.Println(all)
	//	log.Info(all)
	a := []byte{'4', '3'}
	fmt.Println(a)

}

func TestChainInfos(t *testing.T) {
	a := &ChainInfos{
		ChainStruct: ChainStruct{
			ID:       1,
			ParentID: 0,
			Mode:     Branch,
		},
	}
	nid1, _ := ParseNodeID("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	nid2, _ := ParseNodeID("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	nid3, _ := ParseNodeID("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	if !a.AddDataNode(*nid1) {
		t.Error("add error")
		return
	} else {
		t.Logf("%X added", nid1)
	}
	if a.AddDataNode(*nid1) {
		t.Error("duplicate key add error")
		return
	} else {
		t.Logf("%X duplicated", nid1)
	}
	if len(a.Datas) != 1 {
		t.Error("length should be 1")
		return
	}

	if !a.AddDataNode(*nid2) {
		t.Error("add error")
		return
	} else {
		t.Logf("%X added", nid2)
	}
	if a.AddDataNode(*nid2) {
		t.Error("duplicate key add error")
		return
	} else {
		t.Logf("%X duplicated", nid2)
	}
	if len(a.Datas) != 2 {
		t.Error("length should be 2")
		return
	}

	a.RemoveDataNode(*nid3)
	if len(a.Datas) != 2 {
		t.Error("remove an unexist node, length should still be 2")
		return
	}

	if !a.AddDataNode(*nid3) {
		t.Error("add error")
		return
	} else {
		t.Logf("%X added", nid3)
	}
	if a.AddDataNode(*nid3) {
		t.Error("duplicate key add error")
		return
	} else {
		t.Logf("%X duplicated", nid3)
	}
	if len(a.Datas) != 3 {
		t.Error("length should be 3")
		return
	}

	a.RemoveDataNode(*nid2)
	if len(a.Datas) != 2 {
		t.Error("length should be 2 after remove nid2")
		return
	}
	if bytes.Compare(a.Datas[0][:], (*nid1)[:]) != 0 {
		t.Errorf("first should be %X", *nid1)
		return
	}
	if bytes.Compare(a.Datas[1][:], (*nid3)[:]) != 0 {
		t.Errorf("second should be %X", *nid3)
	}

	a.RemoveDataNode(*nid1)
	a.RemoveDataNode(*nid3)
	if len(a.Datas) != 0 {
		t.Error("length should be 0")
		return
	}

	a.RemoveDataNode(*nid1)
	if len(a.Datas) != 0 {
		t.Error("length should be 0")
		return
	}
	t.Log("test ok")
}
