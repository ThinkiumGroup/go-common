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
	"fmt"
	"io"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
)

// returns the length of the overlapped prefix between sub and of
func matchPrefix(sub []byte, of []byte) int {
	i := 0
	for ; i < len(sub) && i < len(of); i++ {
		if sub[i] != of[i] {
			break
		}
	}
	return i
}

func prefixToKeystring(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	p := prefix
	if len(prefix)&0x1 == 1 {
		p = prefix[1:]
	}
	r := make([]byte, len(p)/2)
	for i := 0; i < len(r); i++ {
		r[i] = (p[i*2]&0xF)<<4 | (p[i*2+1] & 0xF)
	}
	return r
}

func keystringToPrefix(nt NodeType, encoded []byte) []byte {
	if !nt.HasPrefix() {
		return nil
	}
	if !nt.PrefixOddLength() && len(encoded) == 0 {
		return nil
	}
	l := len(encoded) * 2
	if nt.PrefixOddLength() {
		l += 1
	}
	r := make([]byte, l)
	i := 0
	if nt.PrefixOddLength() {
		r[i] = nt.FirstPrefix()
		i++
	}
	for j := 0; j < len(encoded); j++ {
		r[i] = encoded[j] >> 4
		i++
		r[i] = encoded[j] & 0x0F
		i++
	}
	return r
}

func keyToPrefix(key []byte) []byte {
	if len(key) == 0 {
		return nil
	}
	r := make([]byte, len(key)*2)
	for i := 0; i < len(key); i++ {
		r[i*2] = key[i] >> 4
		r[i*2+1] = key[i] & 0x0F
	}
	return r
}

// When the length of prefix is odd, the prefix is supplemented with 0
func prefixToKey(prefix []byte) []byte {
	length := len(prefix)
	l := (length + 1) / 2
	ret := make([]byte, l)
	i := 0
	p := prefix
	if length%2 == 1 {
		p = prefix[1:]
		ret[0] = prefix[0] & 0xF
		i = 1
	}
	for j := 0; j < len(p); j++ {
		pos := i + j/2
		ret[pos] = (ret[pos] << 4) | (p[j] & 0xF)
	}
	return ret
}

func hexbyteToValuebyte(h byte) byte {
	switch h {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return h - '0'
	case 'a', 'b', 'c', 'd', 'e', 'f':
		return h - 'a' + 10
	case 'A', 'B', 'C', 'D', 'E', 'F':
		return h - 'A' + 10
	}
	return byte(childrenLength)
}

var (
	valuebyteToHexbyteArray = [...]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}
)

func valuebyteToHexbyte(v byte) byte {
	return valuebyteToHexbyteArray[v&0xF]
}

func prefixToHexstring(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	l := len(prefix)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = valuebyteToHexbyte(prefix[i])
	}
	return ret
}

func hexstringToPrefix(s []byte) []byte {
	if len(s) == 0 {
		return nil
	}
	l := len(s)
	ret := make([]byte, l)
	for i := 0; i < l; i++ {
		ret[i] = hexbyteToValuebyte(s[i])
	}
	return ret
}

func (t *Trie) Marshal(w io.Writer) error {
	it := t.ValueIterator()
	for it.Next() {
		_, v := it.Current()
		if v != nil {
			if err := rtl.Encode(v, w); err != nil {
				return err
			}
		}
	}
	return nil
}

func MarshalAsMap(t ITrie, w io.Writer) error {
	it := t.ValueIterator()
	for it.Next() {
		k, v := it.Current()
		if k != nil {
			if err := rtl.Encode(k, w); err != nil {
				return err
			}
			if err := rtl.Encode(v, w); err != nil {
				return err
			}
		}
	}
	return nil
}

func CheckTrieRoot(root []byte, rootShouldBe []byte) error {
	if !bytes.Equal(root, rootShouldBe) {
		return fmt.Errorf("check failed, expecting %x but %x",
			common.ForPrint(rootShouldBe),
			common.ForPrint(root))
	}
	return nil
}

type BatchPutter struct {
	t     *Trie // target Trie
	m     int   // how many times of putting with one time persisting and folding
	count int   // count of putting
}

func NewBatchPutter(t *Trie, mod int) *BatchPutter {
	return &BatchPutter{t: t, count: 0, m: mod}
}

func (p *BatchPutter) Put(key []byte, value interface{}) (bool, error) {
	if p.t.Put(key, value) {
		p.count++
		if p.count%p.m == 0 {
			if err := p.t.Commit(); err == nil {
				if err = p.t.Collapse(); err != nil {
					return true, err
				}
			} else {
				return true, err
			}
		}
		return true, nil
	} else {
		return false, nil
	}
}

func (p *BatchPutter) Count() int {
	return p.count
}
