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
	"fmt"
	"strings"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/syndtr/goleveldb/leveldb"
)

type LDB struct {
	filePath string
	db       *leveldb.DB

	common.AbstractService
}

func NewLDB(path string) (*LDB, error) {
	ldb := &LDB{filePath: path}
	ldb.InitFunc = ldb.initial
	ldb.StartFunc = ldb.start
	ldb.CloseFunc = ldb.stop

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	ldb.db = db

	// initialization and startup (in order to be in the correct state when Close)
	ldb.Init()
	ldb.Start()

	return ldb, nil
}

func (db *LDB) initial() error {
	return nil
}

func (db *LDB) start() error {
	return nil
}

func (db *LDB) stop() error {
	err := db.db.Close()
	if err != nil {
		return err
	}
	return nil
}

func (db *LDB) Path() string {
	return db.filePath
}

func (db *LDB) Put(key, value []byte) error {
	return db.db.Put(key, value, nil)
}

func (db *LDB) Has(key []byte) (bool, error) {
	return db.db.Has(key, nil)
}

func (db *LDB) Get(key []byte) ([]byte, error) {
	value, err := db.db.Get(key, nil)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
	}
	return value, err
}

func (db *LDB) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

func (db *LDB) NewBatch() Batch {
	return &ldbBatch{
		b: new(leveldb.Batch),
	}
}

func (db *LDB) Batch(batch Batch) error {
	lb, ok := batch.(*ldbBatch)
	if !ok {
		return fmt.Errorf("illegal batch type, expect *ldbBatch, but %v", batch)
	}
	db.db.Write(lb.b, nil)
	return nil
}

type ldbBatch struct {
	b    *leveldb.Batch
	size int
}

func (b *ldbBatch) Put(key, value []byte) error {
	b.b.Put(key, value)
	b.size++
	return nil
}

func (b *ldbBatch) Delete(key []byte) error {
	b.b.Delete(key)
	b.size++
	return nil
}

func (b *ldbBatch) Size() int {
	return b.size
}
