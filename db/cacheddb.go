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
	"sync/atomic"

	"github.com/hashicorp/golang-lru"
)

var cacheBatchValue = struct{}{}

type cachedBatch struct {
	batch Batch
	keys  map[string]struct{}
}

func (b *cachedBatch) Put(key, value []byte) error {
	if err := b.batch.Put(key, value); err != nil {
		return err
	}
	b.keys[string(key)] = cacheBatchValue
	return nil
}

func (b *cachedBatch) Delete(key []byte) error {
	if err := b.batch.Delete(key); err != nil {
		return err
	}
	b.keys[string(key)] = cacheBatchValue
	return nil
}

func (b *cachedBatch) Size() int {
	return b.batch.Size()
}

type cachedDB struct {
	baseDB Database
	cache  *lru.Cache

	writecount uint64 // counter for writing
	hitcount   uint64 // counter for hitting the cache when reading
	misscount  uint64 // counter for missed when reading，hitcount + misscount == readcount
}

func NewCachedDBWithPath(path string, cacheSize int) (Database, error) {
	db, err := NewLDB(path)
	if err != nil {
		return nil, err
	}
	if cacheSize <= 0 {
		return db, nil
	}
	cdb, err := NewCachedDB(db, cacheSize)
	if err != nil {
		db.Close()
		return nil, err
	}
	return cdb, nil
}

func NewCachedDB(db Database, cacheSize int) (*cachedDB, error) {
	c, e := lru.New(cacheSize)
	if e != nil {
		return nil, e
	}
	return &cachedDB{
		baseDB: db,
		cache:  c,
	}, nil
}

func (d *cachedDB) Put(key, value []byte) error {
	atomic.AddUint64(&(d.writecount), 1)
	if err := d.baseDB.Put(key, value); err != nil {
		return err
	}
	d.cache.Remove(string(key))
	return nil
}

func (d *cachedDB) Has(key []byte) (bool, error) {
	_, ok := d.cache.Get(string(key))
	if ok {
		atomic.AddUint64(&(d.hitcount), 1)
		return true, nil
	}
	atomic.AddUint64(&(d.misscount), 1)
	return d.baseDB.Has(key)
}

func (d *cachedDB) Get(key []byte) ([]byte, error) {
	ckey := string(key)
	v, ok := d.cache.Get(ckey)
	if ok {
		atomic.AddUint64(&(d.hitcount), 1)
		return v.([]byte), nil
	}
	atomic.AddUint64(&(d.misscount), 1)
	r, err := d.baseDB.Get(key)
	if err != nil {
		return nil, err
	}
	d.cache.Add(ckey, r)
	return r, nil
}

func (d *cachedDB) Delete(key []byte) error {
	atomic.AddUint64(&(d.writecount), 1)
	d.cache.Remove(string(key))
	return d.baseDB.Delete(key)
}

func (d *cachedDB) NewBatch() Batch {
	return &cachedBatch{
		batch: d.baseDB.NewBatch(),
		keys:  make(map[string]struct{}),
	}
}
func (d *cachedDB) Batch(batch Batch) error {
	atomic.AddUint64(&(d.writecount), 1)
	if cb, ok := batch.(*cachedBatch); ok {
		for k, _ := range cb.keys {
			d.cache.Remove(k)
		}
		batch = cb.batch
	}
	return d.baseDB.Batch(batch)
}
func (d *cachedDB) Close() error {
	return d.baseDB.Close()
}
