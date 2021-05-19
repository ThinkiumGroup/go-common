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
	"fmt"
	"sync"
)

type (
	tracenode struct {
		index byte
		node  *node
	}

	// every tracenode point to next tracenode.node, the last one point to current node
	// tracenode[i].node.children[tracenode[i].index] == tracenode[i+1].node
	traceStack struct {
		stack   []*tracenode // stack of traversing
		current *node        // current node
		ended   bool         // is the traversal complete
		// lock    sync.Mutex
	}

	// The selector of the current node, when it returns true, will cause the depth traversal
	// program to return the current node to the caller
	// Since there is a lock when calling this method, please note that the external lock will
	// be affected, resulting in deadlock
	NodeSelector func(*Trie, *node) bool

	NodeIterator interface {
		// Next returns next node, return nil if there's no more nodez
		Next() *node
		// Current returns last Next() returned node
		Current() *node
	}

	ValueIterator interface {
		Next() bool
		Current() (key []byte, value interface{})
	}

	nodeIterator struct {
		trie  *Trie
		stack traceStack
		lock  sync.Mutex
	}

	trieValueIterator struct {
		nit *nodeIterator
	}
)

// The children node object pointed to by the current value
func (t tracenode) current(trie *Trie) *node {
	if t.index < 0 || t.index >= childrenLength {
		return nil
	}
	if t.node == nil {
		return nil
	}
	if t.node.isCollapsed() {
		trie.expandNode(t.node)
	}
	return t.node.children[int(t.index)]
}

func (t tracenode) currentPrefix(trie *Trie) []byte {
	if t.index < 0 || t.index >= childrenLength {
		return nil
	}
	if t.node == nil {
		return nil
	}
	if t.node.isCollapsed() {
		trie.expandNode(t.node)
	}
	prefix := make([]byte, len(t.node.prefix)+1)
	copy(prefix, t.node.prefix)
	prefix[len(t.node.prefix)] = t.index
	return prefix
}

// Points the current value to the next child node and returns it, if there are no more child
// nodes, return nil
func (t *tracenode) moveToNext(trie *Trie) *node {
	if t.node != nil && t.node.isCollapsed() {
		trie.expandNode(t.node)
	}
	var i byte = 0
	if t.index > childrenLength {
		t.index = 0
	} else if t.index == childrenLength {
		// do nothing
		// Without this judgment, once the child is traversed once and the method is called
		// twice, it will be traversed again from the beginning
	} else {
		i = t.index + 1
	}
	for ; i < childrenLength; i++ {
		if t.node.children[i] != nil {
			if t.index < childrenLength {
				// node before current node
				if t.node.children[t.index] != nil && t.node.children[t.index].canCollapse() {
					t.node.children[t.index].collapse()
				}
			}
			t.index = i
			return t.node.children[i]
		}
	}
	return nil
}

func (s *traceStack) currentNode(trie *Trie) *node {
	// s.lock.Lock()
	// defer s.lock.Unlock()
	if s.ended {
		return nil
	}
	// if len(s.stack) == 0 {
	// 	return trie.root
	// }
	// return s.stack[len(s.stack)-1].current(trie)
	return s.current
}

func (s *traceStack) currentNodePrefix(trie *Trie) []byte {
	// s.lock.Lock()
	// defer s.lock.Unlock()

	if s.ended {
		return nil
	}
	var prefix []byte
	for i := 0; i < len(s.stack); i++ {
		p := s.stack[i].currentPrefix(trie)
		if len(p) > 0 {
			prefix = append(prefix, p...)
		}
	}
	return prefix
}

func (s *traceStack) depthFirstNextStep(trie *Trie, selector NodeSelector) *node {
	// s.lock.Lock()
	// defer s.lock.Unlock()

	var tn *tracenode
	var n *node
outer:
	for { // depth
		if s.ended {
			return nil
		}
		if len(s.stack) == 0 {
			// If the stack is empty, it means that at the beginning, put the root node on the
			// stack, set the index to an illegal value, and then traverse its child node
			s.stack = append(s.stack, &tracenode{index: childrenLength + 1, node: trie.root})
			if selector == nil || selector(trie, trie.root) {
				s.current = trie.root
				return trie.root
			}
		}
		tn = s.stack[len(s.stack)-1]
		n = tn.current(trie)
		if n != nil {
			// travel children
			for i := 0; i < childrenLength; i++ {
				if n.children[i] != nil {
					s.stack = append(s.stack, &tracenode{index: byte(i), node: n})
					if selector != nil && selector(trie, n.children[i]) == false {
						continue outer
					}
					s.current = n.children[i]
					return n.children[i]
				}
			}
		}
		// travel siblings
		for { // breadth
			nn := tn.moveToNext(trie)
			if nn != nil {
				if selector != nil && selector(trie, nn) == false {
					continue outer
				}
				s.current = nn
				return nn
			}
			// no more nodes then return to parent
			s.stack = s.stack[:len(s.stack)-1]
			if len(s.stack) == 0 {
				// The stack is empty, indicating that even the root node has been traversed,
				// that is, it is completed
				s.ended = true
				s.current = nil
				return nil
			}
			// Go back to the parent node and continue to traverse the other children of the
			// parent node (that is, the siblings of the current node)
			tn = s.stack[len(s.stack)-1]
		}
	}
	s.ended = true
	s.current = nil
	return nil
}

func newNodeIterator(trie *Trie) *nodeIterator {
	return &nodeIterator{
		trie: trie,
		// start with an illegal index, it will be moved to the very first legal
		// position when the first invoking to Next()
		stack: traceStack{stack: nil, current: nil},
	}
}

// Next step to next node which selector returns true.
// if selector is nil, then returns every node when iterating the trie
// return nil means no more node
func (it *nodeIterator) Next(selector NodeSelector) *node {
	it.lock.Lock()
	defer it.lock.Unlock()

	if it.stack.ended {
		return nil
	}
	return it.stack.depthFirstNextStep(it.trie, selector)
	// return it.stack.depthFirstNextStep(nil)
}

func (it *nodeIterator) Current() *node {
	it.lock.Lock()
	defer it.lock.Unlock()

	if it.stack.ended {
		return nil
	}
	return it.stack.currentNode(it.trie)
}

func (it *nodeIterator) CurrentPrefix() []byte {
	it.lock.Lock()
	defer it.lock.Unlock()

	if it.stack.ended {
		return nil
	}
	return it.stack.currentNodePrefix(it.trie)
}

func NewValueIterator(trie *Trie) *trieValueIterator {
	return &trieValueIterator{
		nit: newNodeIterator(trie),
	}
}

func (it *trieValueIterator) Next() bool {
	node := it.nit.Next(func(t *Trie, n *node) bool {
		if n.isCollapsed() {
			t.expandNode(n)
		}
		if n.isValueCollapsed() {
			t.expandNodeValue(n)
		}
		return n.hasValue()
	})
	if node == nil {
		return false
	}
	return true
}

func (it *trieValueIterator) Current() (key []byte, value interface{}) {
	node := it.nit.Current()
	if node == nil {
		return nil, nil
	}
	prefix := it.nit.CurrentPrefix()
	if len(node.prefix) > 0 {
		prefix = append(prefix, node.prefix...)
	}
	if len(prefix) == 0 {
		return nil, node.value
	}
	if len(prefix)%2 != 0 {
		panic(fmt.Sprintf("prefix [%x] length:%d cannot convert to keystring, oldprefix:%x node.prefix:%x",
			prefix, len(prefix), it.nit.CurrentPrefix(), node.prefix))
	}
	return prefixToKeystring(prefix), node.value
}
