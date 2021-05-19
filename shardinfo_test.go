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

package common

import (
	"math/big"
	"testing"
)

func TestBits(t *testing.T) {
	bs := RandomBytes(10)
	bi := new(big.Int).SetBytes(CopyBytes(bs))
	bt := Bits(bs)

	l := len(bs) * 8
	bls := make([]bool, l)
	last := l - 1
	for i := 0; i < l; i++ {
		index := last - i
		if bt.Bit(BitIndex(index)) != (bi.Bit(i) == 1) {
			t.Errorf("bytes:%x i=%d(%d), index=%d(%t), check failed",
				bs, i, bi.Bit(i), index, bt.Bit(BitIndex(index)))
		} else {
			bls[index] = bi.Bit(i) == 1
		}
	}
	t.Logf("Bit checked: bytes:%x bools:%t", bs, bls)

	ps := []int{5, 8, 15, 24, 70, 79, 80}
	for i := 0; i < len(ps); i++ {
		bits := bt.Bits(ps[i])
		for j := 0; j < len(bits); j++ {
			if bits[j] != bls[j] {
				t.Errorf("bytes:%x len:%d bools:%t bits:%t check failed",
					bs, ps[i], bls[:ps[i]], bits)
			}
		}
	}
	t.Logf("Bits checked: bytes:%x bools:%t", bs, bls)
}
