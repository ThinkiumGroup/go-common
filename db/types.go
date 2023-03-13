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
	"errors"
)

var (
	ErrNotFound = errors.New("data not found")
	ErrReadOnly = errors.New("read only database")
)

func PrefixKey(prefix []byte, key []byte) []byte {
	ret := make([]byte, len(prefix)+len(key))
	if len(prefix) > 0 {
		copy(ret, prefix)
	}
	if len(key) > 0 {
		copy(ret[len(prefix):], key)
	}
	return ret
}

func PrefixKey2(prefix1 []byte, prefix2 []byte, key []byte) []byte {
	l1 := len(prefix1)
	l2 := l1 + len(prefix2)
	l3 := l2 + len(key)
	ret := make([]byte, l3)
	if l1 > 0 {
		copy(ret, prefix1)
	}
	if len(prefix2) > 0 {
		copy(ret[l1:], prefix2)
	}
	if len(key) > 0 {
		copy(ret[l2:], key)
	}
	return ret
}

type Writer interface {
	Put(key, value []byte) error
	Delete(key []byte) error
}

type Batch interface {
	Put(key, value []byte) error
	Delete(key []byte) error
	Size() int
}

type Database interface {
	Put(key, value []byte) error
	Has(key []byte) (bool, error)
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	NewBatch() Batch
	Batch(batch Batch) error
	Close() error
}

func GetNilError(db Database, key []byte) ([]byte, error) {
	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNotFound
	}
	return data, nil
}

func BatchWrite(dbase Database, threshold, length int,
	write func(j int, w Writer) (ok bool, err error)) (count int, err error) {
	var batch Batch
	index := 0
	for i := 0; i < length; i++ {
		if index == 0 {
			batch = dbase.NewBatch()
		}
		ok, err := write(i, batch)
		if err != nil {
			return count, err
		}
		if !ok {
			continue
		}
		index = index + 1
		if index == threshold || i == (length-1) {
			if err = dbase.Batch(batch); err != nil {
				return count, err
			}
			count = count + index
			index = 0
		}
	}
	return count, nil
}
