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

package db

import (
	"sync"

	"github.com/ThinkiumGroup/go-common"
)

type (
	MemDB struct {
		mem sync.Map
	}

	memBatch struct {
		cmds []*batcher
	}

	batchType byte

	batcher struct {
		typ   batchType
		key   []byte
		value []byte
	}
)

const (
	putBatcher batchType = iota
	deleteBatcher
)

func NewMemDB() Database {
	return &MemDB{}
}

func CopySlice(val []byte) []byte {
	if val == nil {
		return nil
	}
	r := make([]byte, len(val))
	if len(val) > 0 {
		copy(r, val)
	}
	return r
}

func (m *MemDB) Put(key, value []byte) error {
	if key == nil || value == nil {
		return common.ErrNil
	}
	k := CopySlice(key)
	v := CopySlice(value)
	s := string(k)
	// fmt.Printf("%x -> %x\n", s, v)
	m.mem.Store(s, v)
	return nil
}

func (m *MemDB) Has(key []byte) (bool, error) {
	s := string(key)
	v, ok := m.mem.Load(s)
	if !ok || v == nil {
		return false, nil
	}
	return true, nil
}

func (m *MemDB) Get(key []byte) ([]byte, error) {
	s := string(key)
	v, ok := m.mem.Load(s)
	if !ok || v == nil {
		return nil, nil
	}
	r, ok := v.([]byte)
	if !ok {
		return nil, nil
	}
	return CopySlice(r), nil
}

func (m *MemDB) Delete(key []byte) error {
	s := string(key)
	m.mem.Delete(s)
	return nil
}

func (m *MemDB) NewBatch() Batch {
	return &memBatch{}
}

func (m *MemDB) Batch(batch Batch) error {
	b, ok := batch.(*memBatch)
	if !ok {
		panic("expecting a memBatch")
	}
	for i := 0; i < len(b.cmds); i++ {
		switch b.cmds[i].typ {
		case putBatcher:
			m.Put(b.cmds[i].key, b.cmds[i].value)
		case deleteBatcher:
			m.Delete(b.cmds[i].key)
		}
	}
	return nil
}

func (m *MemDB) Close() error {
	return nil
}

func (b *memBatch) Put(key, value []byte) error {
	b.cmds = append(b.cmds, &batcher{typ: putBatcher, key: key, value: value})
	return nil
}

func (b *memBatch) Delete(key []byte) error {
	b.cmds = append(b.cmds, &batcher{typ: deleteBatcher, key: key})
	return nil
}

func (b *memBatch) Size() int {
	return len(b.cmds)
}
