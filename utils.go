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
	"errors"
	"fmt"
	"io"
	"os/user"
	"reflect"
	"strconv"
)

func CloneByteSlice(bytes []byte) []byte {
	if bytes == nil {
		return nil
	}
	if len(bytes) == 0 {
		return make([]byte, 0, 0)
	}
	clone := make([]byte, len(bytes), len(bytes))
	copy(clone, bytes)
	return clone
}

func ReverseBytes(bs []byte) []byte {
	l := len(bs)
	for j := 0; j < l/2; j++ {
		k := l - j - 1
		bs[j], bs[k] = bs[k], bs[j]
	}
	return bs
}

func RandomBytes(length int) []byte {
	b := make([]byte, length)
	io.ReadFull(rand.Reader, b)
	return b
}

func HomeDir() string {
	u, err := user.Current()
	if err != nil {
		panic(DvppError{"could not get current user", err})
	} else {
		return u.HomeDir
	}
}

func FormalizeBasePath(path string) string {
	p := []byte(path)
	if len(p) > 0 {
		if p[len(p)-1] != '/' {
			path = path + "/"
		}
	} else {
		path = "./"
	}
	return path
}

func DatabasePath(basePath string, id ChainID) string {
	return basePath + "db" + strconv.Itoa(int(id))
}

// When sorting a pointer type object slice, the Less method needs to be written. The first part
// is to determine whether the object indicated by the i and j is nil. Nil is considered to be
// the smallest. If both are nil, they are considered to be equal. Only when both of them are not
// nil, the subsequent comparison is needed, and there is no need to check nil at this time.
// When needCompare returns false, the Less method can directly return the returned less value;
// otherwise, the comparison of the indexed objects needs to continue
func PointerSliceLess(slice interface{}, i, j int) (less bool, needCompare bool) {
	if slice == nil {
		return false, false
	}
	val := reflect.ValueOf(slice)
	if val.Kind() != reflect.Slice {
		return false, false
	}
	if i == j || i < 0 || j < 0 || val.IsNil() || val.Len() <= i || val.Len() <= j {
		return false, false
	}

	vali, valj := val.Index(i), val.Index(j)
	if vali.Kind() != reflect.Ptr || valj.Kind() != reflect.Ptr {
		return false, false
	}

	if vali.IsNil() && valj.IsNil() {
		return false, false
	}
	if vali.IsNil() {
		return true, false
	}
	if valj.IsNil() {
		return false, false
	}
	return false, true
}

func CompareSlices(a, b interface{}, objComparer func(c, d interface{}) int) int {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Len() == 0 && vb.Len() == 0 {
		return 0
	}
	for i := 0; i < va.Len() && i < vb.Len(); i++ {
		p := objComparer(va.Index(i).Interface(), vb.Index(i).Interface())
		if p != 0 {
			return p
		}
	}
	if va.Len() == vb.Len() {
		return 0
	} else if va.Len() < vb.Len() {
		return -1
	} else {
		return 1
	}
}

func ByteSlicesToNodeIDs(bss [][]byte) (NodeIDs, error) {
	if len(bss) == 0 {
		return nil, nil
	}
	dedup := make(map[NodeID]struct{})
	for _, nodeid := range bss {
		if len(nodeid) != NodeIDBytes {
			return nil, fmt.Errorf("illegal nodeid: %x", nodeid)
		}
		nid := BytesToNodeID(nodeid)
		if _, exist := dedup[nid]; exist {
			return nil, errors.New("duplicated node found")
		}
		dedup[nid] = struct{}{}
	}
	nids := make(NodeIDs, 0, len(dedup))
	for nid, _ := range dedup {
		nids = append(nids, nid)
	}
	return nids, nil
}

func IsNodeIDIn(nidhs []Hash, nid NodeID) bool {
	if len(nidhs) == 0 {
		return false
	}
	h := nid.Hash()
	for _, nidh := range nidhs {
		if nidh == h {
			return true
		}
	}
	return false
}
