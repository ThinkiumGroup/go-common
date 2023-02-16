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

	"github.com/ThinkiumGroup/go-common"
)

type DataAdapter interface {
	Load(key []byte) (value []byte, err error)
	Save(key []byte, value []byte) error
	Clone() DataAdapter
}

type DatabasedAdapter interface {
	DataAdapter
	Rebase(dbase Database) (DatabasedAdapter, error)
}

func RebaseAdapter(adapter DataAdapter, dbase Database) (DataAdapter, error) {
	if adapter == nil {
		return nil, nil
	}
	switch da := adapter.(type) {
	case DatabasedAdapter:
		return da.Rebase(dbase)
	default:
		return da, nil
	}
}

type KeyBatch struct {
	batch       Batch
	keyConvFunc func([]byte) []byte
}

func (k *KeyBatch) Put(key, value []byte) error {
	if k.keyConvFunc != nil {
		return k.batch.Put(k.keyConvFunc(key), value)
	} else {
		return k.batch.Put(key, value)
	}
}

func (k *KeyBatch) Delete(key []byte) error {
	if k.keyConvFunc != nil {
		return k.batch.Delete(k.keyConvFunc(key))
	} else {
		return k.batch.Delete(key)
	}
}

func (k *KeyBatch) Size() int {
	return k.batch.Size()
}

type keyPrefixedDataAdapter struct {
	database  Database
	keyPrefix []byte
}

func NewKeyPrefixedDataAdapter(database Database, keyPrefix []byte) DataAdapter {
	ret := &keyPrefixedDataAdapter{database: database}
	if len(keyPrefix) > 0 {
		ret.keyPrefix = make([]byte, len(keyPrefix))
		copy(ret.keyPrefix, keyPrefix)
	} else {
		ret.keyPrefix = nil
	}
	return ret
}

func (k *keyPrefixedDataAdapter) String() string {
	return fmt.Sprintf("KeyPrefixed(%x)", k.keyPrefix)
}

func (k *keyPrefixedDataAdapter) Clone() DataAdapter {
	return &keyPrefixedDataAdapter{
		database:  k.database,
		keyPrefix: common.CopyBytes(k.keyPrefix),
	}
}

func (k *keyPrefixedDataAdapter) Rebase(dbase Database) (DatabasedAdapter, error) {
	return &keyPrefixedDataAdapter{
		database:  dbase,
		keyPrefix: common.CopyBytes(k.keyPrefix),
	}, nil
}

func (k *keyPrefixedDataAdapter) key(key []byte) []byte {
	if k.keyPrefix == nil {
		return key
	}
	return PrefixKey(k.keyPrefix, key)
}

func (k *keyPrefixedDataAdapter) Load(key []byte) (value []byte, err error) {
	return k.database.Get(k.key(key))
}

func (k *keyPrefixedDataAdapter) Save(key, value []byte) error {
	return k.database.Put(k.key(key), value)
}

func (k *keyPrefixedDataAdapter) NewBatch() Batch {
	return &KeyBatch{batch: k.database.NewBatch(), keyConvFunc: k.key}
}

func (k *keyPrefixedDataAdapter) SaveBatch(batch Batch) error {
	return k.database.Batch(batch)
}

/*
 * implements Database
 */

func (k *keyPrefixedDataAdapter) Put(key, value []byte) error {
	return k.Save(key, value)
}

func (k *keyPrefixedDataAdapter) Has(key []byte) (bool, error) {
	return k.database.Has(k.key(key))
}

func (k *keyPrefixedDataAdapter) Get(key []byte) ([]byte, error) {
	return k.Load(key)
}

func (k *keyPrefixedDataAdapter) Delete(key []byte) error {
	return k.database.Delete(k.key(key))
}

func (k *keyPrefixedDataAdapter) Batch(batch Batch) error {
	return k.SaveBatch(batch)
}

func (k *keyPrefixedDataAdapter) Close() error {
	return nil
}

type transparentDataAdapter struct{}

func NewTransparentDataAdapter() DataAdapter {
	return &transparentDataAdapter{}
}

func (t *transparentDataAdapter) String() string {
	return "transparent"
}

func (t *transparentDataAdapter) Load(key []byte) (value []byte, err error) {
	return key, err
}

func (t *transparentDataAdapter) Save(key, value []byte) error {
	return nil
}

func (t *transparentDataAdapter) Clone() DataAdapter {
	return &transparentDataAdapter{}
}

type KeyDatabase struct {
	database Database
	keyFunc  func([]byte) []byte
}

func (d *KeyDatabase) Put(key, value []byte) error {
	return d.database.Put(d.keyFunc(key), value)
}

func (d *KeyDatabase) Has(key []byte) (bool, error) {
	return d.database.Has(d.keyFunc(key))
}

func (d *KeyDatabase) Get(key []byte) ([]byte, error) {
	return d.database.Get(d.keyFunc(key))
}

func (d *KeyDatabase) Delete(key []byte) error {
	return d.database.Delete(d.keyFunc(key))
}

func (d *KeyDatabase) NewBatch() Batch {
	return &KeyBatch{batch: d.database.NewBatch(), keyConvFunc: d.keyFunc}
}

func (d *KeyDatabase) Batch(batch Batch) error {
	return d.database.Batch(batch)
}

func (d *KeyDatabase) Close() error {
	d.keyFunc = nil
	return nil
}
