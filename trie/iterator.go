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

	"github.com/ThinkiumGroup/go-common/log"
)

type (
	tracenode struct {
		index byte
		node  *node
	}

	// every tracenode point to next tracenode.node, the last one in stack point to stack.current
	// tracenode[i].node.children[tracenode[i].index] == tracenode[i+1].node
	traceStack struct {
		stack   []*tracenode // stack of traversing
		current *node        // current node
		ended   bool         // is the traversal complete
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
func (t tracenode) current(tr *Trie) *node {
	if t.index < 0 || t.index >= childrenLength {
		return nil
	}
	if t.node == nil {
		return nil
	}
	if t.node.isCollapsed() {
		_ = tr.expandNode(t.node)
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
		_ = trie.expandNode(t.node)
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
		_ = trie.expandNode(t.node)
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
		// collapse last index
		if t.node.children[t.index] != nil && t.node.children[t.index].canCollapse() {
			_ = t.node.children[t.index].collapse()
		}
	}
	for ; i < childrenLength; i++ {
		if t.node.children[i] != nil {
			t.index = i
			return t.node.children[i]
		}
	}
	return nil
}

func (s *traceStack) currentNode() *node {
	if s.ended {
		return nil
	}
	return s.current
}

func (s *traceStack) currentNodePrefix(trie *Trie) []byte {
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
}

func (it *nodeIterator) Current() *node {
	it.lock.Lock()
	defer it.lock.Unlock()

	if it.stack.ended {
		return nil
	}
	return it.stack.currentNode()
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
			if err := t.expandNode(n); err != nil {
				log.Errorf("Next: expand node %s failed: %v", n, err)
			}
		}
		if n.isValueCollapsed() {
			if err := t.expandNodeValue(n); err != nil {
				log.Errorf("Next: expand value %s failed: %v", n, err)
			}
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
		panic(fmt.Errorf("prefix [%x] length:%d cannot convert to keystring, oldprefix:%x node.prefix:%x",
			prefix, len(prefix), it.nit.CurrentPrefix(), node.prefix))
	}
	return prefixToKeystring(prefix), node.value
}

type (
	reversedTrace struct {
		node  *node
		index int
	}

	reversedValueIterator struct {
		trie   *Trie
		stack  []*reversedTrace
		status int // 0: not start, 1: started, 2: ended
		lock   sync.Mutex
	}
)

func newReversedValueIterator(tr *Trie) *reversedValueIterator {
	return &reversedValueIterator{trie: tr}
}

func (rt *reversedValueIterator) Current() (key []byte, value interface{}) {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	if rt.status != 1 {
		return nil, nil
	}

	if len(rt.stack) == 0 {
		return nil, nil
	}

	var prefix []byte // nibbles
	for i := 0; i < len(rt.stack); i++ {
		if len(rt.stack[i].node.prefix) > 0 {
			prefix = append(prefix, rt.stack[i].node.prefix...)
		}
		if i < len(rt.stack)-1 && rt.stack[i].index >= 0 && rt.stack[i].index < childrenLength {
			prefix = append(prefix, byte(rt.stack[i].index))
		}
	}
	return prefixToKeystring(prefix), rt.stack[len(rt.stack)-1].node.value
}

func (rt *reversedValueIterator) Next() bool {
	rt.lock.Lock()
	defer rt.lock.Unlock()
	if rt.status > 1 {
		return false
	}
	if rt.status == 0 {
		if rt.trie.root != nil {
			rt.status = 1
			rt.stack = append(rt.stack, &reversedTrace{node: rt.trie.root, index: childrenLength})
		} else {
			rt.status = 2
			return false
		}
	}
	for {
		if len(rt.stack) == 0 {
			rt.status = 2
			return false
		}
		last := rt.stack[len(rt.stack)-1]
		if last.index < 0 {
			// last.node.value just checked
			_ = last.node.collapse()
			rt.stack = rt.stack[:len(rt.stack)-1]
		} else {
			if last.node.isCollapsed() {
				_ = rt.trie.expandNode(last.node)
			}
			if last.node.isValueCollapsed() {
				_ = rt.trie.expandNodeValue(last.node)
			}
			last.index--
			for last.index >= 0 {
				if last.node.children[last.index] == nil {
					// nil child, ignore
					last.index--
					if last.index < 0 {
						// check value when the reversedTrace just before poping out
						if last.node.hasValue() {
							return true
						} else {
							// shortcut, pop node if there's no value
							_ = last.node.collapse()
							rt.stack = rt.stack[:len(rt.stack)-1]
						}
					}
				} else {
					// push child node to stack
					rt.stack = append(rt.stack, &reversedTrace{node: last.node.children[last.index], index: childrenLength})
					break
				}
			}
		}
	}
}
