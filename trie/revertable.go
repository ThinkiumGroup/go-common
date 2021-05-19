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
	"sync"

	"github.com/ThinkiumGroup/go-common"
)

type RevertableTrie struct {
	Origin *Trie         // committed value
	Live   *Trie         // not committed value
	chkpts []common.Hash // checkpoints (root hash) that records temporary data and can be rolled back
	lock   sync.Mutex
}

func (r *RevertableTrie) Copy() *RevertableTrie {
	if r == nil {
		return nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	ret := new(RevertableTrie)
	if r.Origin != nil {
		ret.Origin = r.Origin.Clone()
	}
	return ret
}

func (r *RevertableTrie) SetTo(newTrie *Trie) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if newTrie == nil {
		return common.ErrNil
	}
	r.Origin = newTrie
	r.Live = nil
	return nil
}

// Check the availability of live, copy one from original if not have, and report an error if
// original does not exist
func (r *RevertableTrie) checkLiveLocked() error {
	if r.Live == nil {
		if r.Origin == nil {
			return common.ErrNil
		}
		r.Live = r.Origin
		r.Origin = r.Live.Clone()
	}
	return nil
}

func (r *RevertableTrie) HashValue() (hashValue []byte, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Origin == nil {
		return nil, nil
	}
	return r.Origin.HashValue()
}

func (r *RevertableTrie) Get(key []byte) (value interface{}, ok bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Origin == nil {
		return nil, false
	}
	return r.Origin.Get(key)
}

func (r *RevertableTrie) GetLive(key []byte) (value interface{}, ok bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Live != nil {
		return r.Live.Get(key)
	} else {
		if r.Origin == nil {
			return nil, false
		}
		return r.Origin.Get(key)
	}
}

func (r *RevertableTrie) putLocked(key []byte, value interface{}) bool {
	if err := r.checkLiveLocked(); err != nil {
		return false
	}
	return r.Live.Put(key, value)
}

func (r *RevertableTrie) Put(key []byte, value interface{}) bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.putLocked(key, value)
}

func (r *RevertableTrie) PutValue(value TrieValue) bool {
	r.lock.Lock()
	defer r.lock.Unlock()

	if value == nil {
		return false
	}
	return r.putLocked(value.Key(), value)
}

func (r *RevertableTrie) Delete(key []byte) (changed bool, oldValue interface{}) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err := r.checkLiveLocked(); err != nil {
		return false, nil
	}
	return r.Live.Delete(key)
}

func (r *RevertableTrie) isDirtyLocked() bool {
	if r.Live == nil {
		return false
	}
	return true
}

func (r *RevertableTrie) IsDirty() bool {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.isDirtyLocked()
}

func (r *RevertableTrie) Commit() error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.isDirtyLocked() {
		r.Origin = r.Live
		r.Live = nil
	}
	r.chkpts = nil
	return r.Origin.Commit()
}

func (r *RevertableTrie) GetProof(key []byte) (value interface{}, proof ProofChain, ok bool) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Origin == nil {
		return nil, nil, false
	}
	return r.Origin.GetProof(key)
}

func (r *RevertableTrie) GetExistenceProof(key []byte) (exist bool, proofs ProofChain, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Origin == nil {
		return false, nil, common.ErrNil
	}
	return r.Origin.GetExistenceProof(key)
}

func (r *RevertableTrie) ValueIterator() ValueIterator {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Origin == nil {
		return nil
	}
	return r.Origin.ValueIterator()
}

func (r *RevertableTrie) LiveValueIterator() ValueIterator {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Live == nil && r.Origin == nil {
		return nil
	}
	if r.Live == nil {
		return r.Origin.ValueIterator()
	}
	return r.Live.ValueIterator()
}

func (r *RevertableTrie) PreHashValue() ([]byte, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.Live == nil {
		return r.Origin.HashValue()
	}
	return r.Live.HashValue()
}

func (r *RevertableTrie) preCommitLocked() ([]byte, error) {
	if r.Live == nil {
		if r.Origin == nil {
			return nil, nil
		}
		return r.Origin.HashValue()
	}
	if err := r.Live.Commit(); err != nil {
		return nil, err
	}
	return r.Live.HashValue()
}

func (r *RevertableTrie) PreCommit() ([]byte, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.preCommitLocked()
}

func (r *RevertableTrie) Rollback() {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r == nil {
		return
	}
	r.Live = nil
	r.chkpts = nil
}

// persiste the current live and return:
// chkpt: sequence number of current checkpoint
// root: live root hash when creating checkpoint
// err: when it is not nil, chkpt and root are not available
func (r *RevertableTrie) CheckPoint() (chkpt int, root []byte, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	root, err = r.preCommitLocked()
	if err != nil {
		return -1, nil, err
	}
	rootHash := common.BytesToHash(root)
	r.chkpts = append(r.chkpts, rootHash)
	return len(r.chkpts) - 1, root, nil
}

// Roll back live to the specified checkpoint and return possible errors
// It can succeed only when the value of checkpoint matches the value of root hash with that in
// the record. Otherwise, the failure reason is returned
func (r *RevertableTrie) RevertTo(checkPoint int, root []byte) error {
	if checkPoint < 0 || len(root) == 0 {
		return common.ErrNil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if checkPoint >= len(r.chkpts) {
		return common.ErrNotFound
	}
	h := common.BytesToHash(root)
	if h != r.chkpts[checkPoint] {
		return ErrNotExist
	}
	r.chkpts = r.chkpts[:checkPoint]
	if len(r.chkpts) == 0 {
		r.chkpts = nil
		r.Live = nil
	} else {
		r.Live = r.Live.Inherit(root)
	}
	return nil
}
