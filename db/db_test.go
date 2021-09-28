package db

import (
	"bytes"
	"strconv"
	"testing"
)

type dbTester struct{}

func (d dbTester) has(t *testing.T, dbase Database, key []byte, expecting bool) {
	exist, err := dbase.Has(key)
	if err != nil {
		t.Fatalf("Has(%x) failed %v", key, err)
	}
	if expecting != exist {
		t.Fatalf("has(%x)=%t expecting:%t", key, exist, expecting)
	} else {
		t.Logf("has(%x)=%t", key, exist)
	}
}

func (d dbTester) get(t *testing.T, dbase Database, key []byte, expecting []byte) {
	data, err := dbase.Get(key)
	if err != nil {
		t.Fatalf("Get(%x) failed: %v", key, err)
	}
	if bytes.Equal(data, expecting) {
		t.Logf("Get(%x)=%x", key, data)
	} else {
		t.Fatalf("Get(%x)=%x expecting:%x", key, data, expecting)
	}
}

func (d dbTester) test(t *testing.T, dbase Database) {
	// init put
	for i := 1; i <= 10; i++ {
		k := []byte("key" + strconv.Itoa(i))
		v := []byte("value" + strconv.Itoa(i))
		if err := dbase.Put(k, v); err != nil {
			t.Fatalf("%v", err)
		} else {
			t.Logf("%x -> %x saved", k, v)
		}
	}

	{
		// duplicated writing
		if err := dbase.Put([]byte("key3"), []byte("value-3")); err != nil {
			t.Fatalf("duplicated writing failed: %v", err)
		} else {
			d.get(t, dbase, []byte("key3"), []byte("value-3"))
		}
	}

	{
		// has
		d.has(t, dbase, []byte("key2"), true)
		d.has(t, dbase, []byte("key20"), false)

		if err := dbase.Delete([]byte("key5")); err != nil {
			t.Fatalf("key5 delete failed: %v", err)
		} else {
			t.Log("key5 delete ok")
		}

		d.has(t, dbase, []byte("key5"), false)
		d.has(t, dbase, []byte("key6"), true)
	}

	{
		// batch
		b := dbase.NewBatch()
		b.Delete([]byte("key9"))
		b.Put([]byte("key9"), []byte("value-9"))
		b.Delete([]byte("key8"))
		b.Put([]byte("key8"), []byte("value-8"))

		if err := dbase.Batch(b); err != nil {
			t.Fatalf("Batch failed: %v", err)
		}

		d.get(t, dbase, []byte("key9"), []byte("value-9"))
		d.get(t, dbase, []byte("key8"), []byte("value-8"))
	}
}

func TestTemporary(t *testing.T) {
	dbase := NewMemDB()
	if err := dbase.Put([]byte("key2"), []byte("value2")); err != nil {
		t.Fatalf("initial %x->%x failed: %v", []byte("key2"), []byte("value2"), err)
	} else {
		t.Logf("initial %x->%x ok", []byte("key2"), []byte("value2"))
	}
	tbase := Temporary(dbase)
	dbt := dbTester{}
	dbt.test(t, tbase)
	dbt.get(t, dbase, []byte("key2"), []byte("value2"))
}
