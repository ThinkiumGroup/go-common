package db

import "sync"

type readOnlyDB struct {
	dbase Database
}

func ReadOnly(dbase Database) Database {
	switch t := dbase.(type) {
	case *readOnlyDB:
		return t
	default:
		return &readOnlyDB{dbase: dbase}
	}
}

func (r *readOnlyDB) Put(key, value []byte) error {
	return ErrReadOnly
}
func (r *readOnlyDB) Has(key []byte) (bool, error) {
	return r.dbase.Has(key)
}

func (r *readOnlyDB) Get(key []byte) ([]byte, error) {
	return r.dbase.Get(key)
}

func (r *readOnlyDB) Delete(key []byte) error {
	return ErrReadOnly
}

func (r *readOnlyDB) NewBatch() Batch {
	return nil
}

func (r *readOnlyDB) Batch(batch Batch) error {
	return ErrReadOnly
}

func (r *readOnlyDB) Close() error {
	return ErrReadOnly
}

type temporaryDB struct {
	read    Database
	mem     Database
	deleted map[string]struct{}
	lock    sync.RWMutex
}

func Temporary(dbase Database) Database {
	return &temporaryDB{
		read:    dbase,
		mem:     NewMemDB(),
		deleted: make(map[string]struct{}),
	}
}

func (t *temporaryDB) _put(key, value []byte) error {
	if err := t.mem.Put(key, value); err == nil {
		delete(t.deleted, string(key))
		return nil
	} else {
		return err
	}
}

func (t *temporaryDB) Put(key, value []byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t._put(key, value)
}

func (t *temporaryDB) Has(key []byte) (bool, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	_, deleted := t.deleted[string(key)]
	if deleted {
		return false, nil
	}
	has, _ := t.mem.Has(key)
	if has {
		return true, nil
	}
	return t.read.Has(key)
}

func (t *temporaryDB) Get(key []byte) ([]byte, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	_, deleted := t.deleted[string(key)]
	if deleted {
		return nil, nil
	}
	bs, err := t.mem.Get(key)
	if err != nil {
		return nil, err
	}
	if bs != nil {
		return bs, nil
	}
	return t.read.Get(key)
}

func (t *temporaryDB) _delete(key []byte) error {
	t.deleted[string(key)] = struct{}{}
	t.mem.Delete(key)
	return nil
}

func (t *temporaryDB) Delete(key []byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t._delete(key)
}

func (t *temporaryDB) NewBatch() Batch {
	return &memBatch{}
}

func (t *temporaryDB) Batch(batch Batch) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	b, ok := batch.(*memBatch)
	if !ok {
		panic("expecting a memBatch")
	}
	for i := 0; i < len(b.cmds); i++ {
		switch b.cmds[i].typ {
		case putBatcher:
			t._put(b.cmds[i].key, b.cmds[i].value)
		case deleteBatcher:
			t._delete(b.cmds[i].key)
		}
	}
	return nil
}

func (t *temporaryDB) Close() error {
	return nil
}
