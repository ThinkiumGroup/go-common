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

import "github.com/ThinkiumGroup/go-common"

type BinaryNode struct {
	Left  []byte
	Right []byte
}

func (n *BinaryNode) HashValue() ([]byte, error) {
	if n == nil {
		return common.CopyBytes(common.NilHashSlice), nil
	}
	a := n.Left
	if a == nil {
		a = common.NilHashSlice
	}
	b := n.Right
	if b == nil {
		b = common.NilHashSlice
	}
	return common.HashPair(a, b), nil
}
