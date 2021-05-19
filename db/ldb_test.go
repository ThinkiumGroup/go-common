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
	"bytes"
	"os"
	"strconv"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

var path = common.HomeDir() + "/temp/dvppdata/ldb"

func ldb(db Database, t *testing.T) {
	for i := 1; i <= 10; i++ {
		k := []byte("key" + strconv.Itoa(i))
		v := []byte("value" + strconv.Itoa(i))
		if err := db.Put(k, v); err != nil {
			t.Error(err)
		} else {
			t.Log(k, v, "saved")
		}
	}

	has, err := db.Has([]byte("key2"))
	if err != nil {
		t.Error(err)
	}
	if !has {
		t.Error("key2 not found")
	} else {
		t.Log("key2 found")
	}

	has, err = db.Has([]byte("key20"))
	if err != nil {
		t.Error(err)
	}
	if has {
		t.Error("key20 found")
	} else {
		t.Log("key20 not found")
	}

	if err = db.Delete([]byte("key5")); err != nil {
		t.Error("key5 delete error", err)
	} else {
		t.Log("key5 delete ok")
	}

	has, err = db.Has([]byte("key5"))
	if err != nil {
		t.Error(err)
	}
	if has {
		t.Error("key5 found")
	} else {
		t.Log("key5 deleted")
	}

	has, err = db.Has([]byte("key6"))
	if err != nil {
		t.Error(err)
	}
	if !has {
		t.Error("key6 not found")
	} else {
		t.Log("key6 found")
	}
}

func writeDuplicate(db Database, t *testing.T) {
	err := db.Put([]byte("key3"), []byte("value-3"))
	t.Log("save key3: ", err)
}

func read(db Database, t *testing.T) {
	for i := 1; i <= 10; i++ {
		k := []byte("key" + strconv.Itoa(i))
		v := []byte("value" + strconv.Itoa(i))
		vv, err := db.Get(k)
		if err != nil {
			if i == 5 {
				t.Log("key5 deleted, not found is ok")
			} else {
				t.Error(err)
			}
		} else {
			t.Log(string(v), string(vv), bytes.Equal(v, vv))
		}
	}
}

func batch(db Database, t *testing.T) {
	b := db.NewBatch()
	b.Delete([]byte("key9"))
	b.Put([]byte("key9"), []byte("value-9"))
	b.Delete([]byte("key8"))
	b.Put([]byte("key8"), []byte("value-8"))

	if err := db.Batch(b); err != nil {
		t.Error(err)
	}

	v9, err := db.Get([]byte("key9"))
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal([]byte("value-9"), v9) {
		t.Log("new value9 ok")
	} else {
		t.Error("new value9 error")
	}

	v8, err := db.Get([]byte("key8"))
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal([]byte("value-8"), v8) {
		t.Log("new value8 ok")
	} else {
		t.Error("new value8 error")
	}
}

func TestLDB(t *testing.T) {
	db, err := NewLDB(path)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	ldb(db, t)
}

func TestWriteDuplicate(t *testing.T) {
	db, err := NewLDB(path)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	writeDuplicate(db, t)
}

func TestRead(t *testing.T) {
	db, err := NewLDB(path)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	read(db, t)
}

func TestBatch(t *testing.T) {
	db, err := NewLDB(path)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	batch(db, t)
}

func TestClear(t *testing.T) {
	if err := os.RemoveAll(path); err != nil {
		t.Error(err)
	} else {
		t.Log("path remove ok")
	}
}

func TestCachedDB(t *testing.T) {
	db, err := NewCachedDBWithPath(path, 100)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	ldb(db, t)
}

func TestCachedWriteDuplicate(t *testing.T) {
	db, err := NewCachedDBWithPath(path, 100)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	writeDuplicate(db, t)
}

func TestCachedRead(t *testing.T) {
	db, err := NewCachedDBWithPath(path, 100)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	read(db, t)
	read(db, t)
}

func TestCachedBatch(t *testing.T) {
	db, err := NewCachedDBWithPath(path, 100)
	if err != nil {
		t.Error(err)
	}
	defer db.Close()

	batch(db, t)
}

func TestCachedClear(t *testing.T) {
	if err := os.RemoveAll(path); err != nil {
		t.Error(err)
	} else {
		t.Log("path remove ok")
	}
}
