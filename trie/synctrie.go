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
)

type SyncTrie struct {
	t ITrie
	l sync.Mutex
}

func NewSyncTrie(t ITrie) *SyncTrie {
	return &SyncTrie{
		t: t,
	}
}

func (s *SyncTrie) HashValue() (hashValue []byte, err error) {
	s.l.Lock()
	defer s.l.Unlock()
	return s.t.HashValue()
}

func (s *SyncTrie) Get(key []byte) (value interface{}, ok bool) {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.Get(key)
}

func (s *SyncTrie) Put(key []byte, value interface{}) bool {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.Put(key, value)
}

func (s *SyncTrie) PutValue(value TrieValue) bool {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.PutValue(value)
}

func (s *SyncTrie) Delete(key []byte) (changed bool, oldValue interface{}) {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.Delete(key)
}

func (s *SyncTrie) IsDirty() bool {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.IsDirty()
}

func (s *SyncTrie) Commit() error {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.Commit()
}

func (s *SyncTrie) GetProof(key []byte) (value interface{}, proof ProofChain, ok bool) {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.GetProof(key)
}

func (s *SyncTrie) GetExistenceProof(key []byte) (exist bool, proofs ProofChain, err error) {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.GetExistenceProof(key)
}

func (s *SyncTrie) ValueIterator() ValueIterator {
	s.l.Lock()
	defer s.l.Unlock()

	return s.t.ValueIterator()
}
