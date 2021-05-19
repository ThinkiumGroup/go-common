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
	"fmt"
	"sort"
	"strconv"

	"github.com/ThinkiumGroup/go-common/log"
	"github.com/stephenfire/go-rtl"
)

type (
	BitIndex int

	Bits []byte

	AddressShard struct {
		Index BitIndex // The index of the last bit (starting from 0), note that it is not the bit length (starting from 1)
		Value Bits
	}
)

// the index of the location byte
func (p BitIndex) BytePos() int {
	return int(p) >> 3
}

// the bit index of the lowest byte (from highest 0 to lowest 7)
func (p BitIndex) BitPos() uint {
	return uint(p) & 0x7
}

// returns higher n bits of b, which n is is the bit index of the lowest byte
func (p BitIndex) Mask(b byte) byte {
	bits := p.BitPos()
	if bits == 7 {
		return b
	}
	if bits == 0 {
		return 0
	}
	sh := 7 - bits
	bb := b >> sh
	bb = bb << sh
	return bb
}

// return true if the bit at index is 1, otherwise return false
func (bs Bits) Bit(index BitIndex) bool {
	bytePos := index.BytePos()
	if bytePos >= len(bs) {
		return false
	}
	bitPos := index.BitPos()
	return (bs[bytePos]>>(7-bitPos))&0x1 == 0x1
}

// Returns the value of the highest consecutive length bits, and returns true when corresponding
// to bit 1, otherwise false. If the length of bs is not enough, the actual length of the returned
// array may be less than length
func (bs Bits) Bits(length int) []bool {
	if length <= 0 {
		return nil
	}
	r := make([]bool, 0, length)
	x := BitIndex(length).BytePos()
	y := BitIndex(length).BitPos()
	var j uint
	for i := 0; i < len(bs) && i <= x; i++ {
		for j = 0; j < 8; j++ {
			r = append(r, ((bs[i]>>(7-j))&0x1) == 0x1)
			if i >= x && j >= y {
				break
			}
		}
	}
	return r
}

func (bs Bits) Byte(index int) (v byte, exist bool) {
	if index < 0 || index >= len(bs) {
		return 0, false
	}
	return bs[index], true
}

func (s *AddressShard) IsValid() bool {
	if s == nil {
		return false
	}
	if s.Index <= 0 {
		return false
	}
	if s.Index > (AddressLength * 8) {
		return false
	}
	if (len(s.Value) * 8) < int(s.Index) {
		return false
	}
	return true
}

func (s *AddressShard) IsIn(addr Address) bool {
	if s == nil {
		return false
	}
	pos := s.Index.BytePos()
	if pos >= len(addr) {
		return false
	}
	for i := 0; i <= pos; i++ {
		b, e := s.Value.Byte(i)
		if !e {
			return false
		}
		if i == pos {
			// check part of value
			if s.Index.Mask(b) != s.Index.Mask(addr[i]) {
				return false
			}
		} else {
			// check whole value
			if b != addr[i] {
				return false
			}
		}
	}
	return true
}

type (
	AccountShards struct {
		// how many bits mark has, starting from the highest bit of the account address
		maskBits int
		// parent chain
		parent ChainStruct
		// sharding chains
		chains ChainIDs
	}

	AccountSharding struct {
		id     ChainID
		shards AccountShards
	}
)

func NewAccountShards(parent ChainStruct, chains []ChainID) AccountShards {
	if len(chains) <= 0 {
		// if no shards, always shard to parent chain
		return AccountShards{
			maskBits: 0,
			parent:   parent,
			chains:   nil,
		}
	}
	cids := make(ChainIDs, len(chains))
	copy(cids, chains)
	sort.Sort(cids)

	bits := 0
	length := 1
	for length < len(cids) {
		length <<= 1
		bits++
	}

	if bits > MaxExponentOfShards {
		panic("shard size is too big to support. (" + strconv.Itoa(len(chains)) + ")")
	}

	return AccountShards{
		maskBits: bits,
		parent:   parent,
		chains:   cids,
	}
}

func (s AccountShards) index(addr *Address) int {
	// The number of bytes required is calculated according to the mask length
	byteSize := (s.maskBits >> 3) + 1

	// Convert the obtained byte to a number
	bs := addr[0:byteSize]
	i := rtl.Numeric.BytesToInt(bs)

	// Calculate the number of bits to be reserved for the last byte
	mask := s.maskBits & 0x7
	if mask == 0 {
		return i
	}

	// Shift the number to the right to the bit to be reserved
	i >>= uint(8 - mask)
	return i
}

func (s AccountShards) shardTo(addr *Address) ChainID {
	if len(s.chains) <= 0 {
		// if no shards, always shard to parent chain
		return s.parent.ID
	}
	index := s.index(addr)
	return s.chains[index%len(s.chains)]
}

func (s AccountShards) pos(id ChainID) int {
	i := sort.Search(len(s.chains), func(j int) bool {
		return s.chains[j] >= id
	})
	if i < len(s.chains) && s.chains[i] == id {
		return i
	}
	return -1
}

func (s AccountShards) GetMaskBits() uint {
	return uint(s.maskBits)
}

func NewShardInfo(parent ChainStruct, currentChain ChainID, shards []ChainID) ShardInfo {
	log.WithField("CURRENTCHAIN", currentChain).Debugf("NewShardInfo: parent: %v, shards: %v", parent, shards)
	if currentChain == NilChainID && shards == nil {
		// one chain
		return AccountSharding{
			id:     parent.ID,
			shards: NewAccountShards(parent, nil),
		}
	}
	if currentChain == NilChainID {
		panic("invalid current chain id")
	}
	shardSlice := make([]ChainID, 0)
	dupMap := make(map[ChainID]struct{})
	empty := struct{}{}
	for i := 0; i < len(shards); i++ {
		_, ok := dupMap[shards[i]]
		if !ok {
			dupMap[shards[i]] = empty
			shardSlice = append(shardSlice, shards[i])
		}
	}
	if currentChain != parent.ID {
		// If the current chain is not the parent chain of the sharding chain (ShardInfo will
		// also be generated when there is a lower level sharding chain)
		if _, ok := dupMap[currentChain]; !ok {
			shardSlice = append(shardSlice, currentChain)
		}
	}

	shardinfo := AccountSharding{
		id:     currentChain,
		shards: NewAccountShards(parent, shardSlice),
	}
	// log.WithField("CURRENTCHAIN", currentChain).Infof("%v created", shardinfo)
	return shardinfo
}

func (as AccountSharding) Number() int {
	return len(as.shards.chains)
}

func (as AccountSharding) ParentID() ChainID {
	return as.shards.parent.ID
}

func (as AccountSharding) GetMaskBits() uint {
	return as.shards.GetMaskBits()
}

func (as AccountSharding) LocalID() ChainID {
	return as.id
}

func (as AccountSharding) AllIDs() []ChainID {
	return as.shards.chains
}

func (as AccountSharding) ShardTo(v interface{}) ChainID {
	// addr, ok := v.(Address)
	// if !ok {
	// 	panic("not a Address")
	// }
	// return as.shards.shardTo(addr)
	if v == nil {
		return NilChainID
	}
	switch a := v.(type) {
	case Address:
		return as.shards.shardTo(&a)
	case *Address:
		return as.shards.shardTo(a)
	}
	panic("not an Address")
}

// Returns the location of ID in shard
func (as AccountSharding) Pos(id ChainID) int {
	return as.shards.pos(id)
}

func (as *AccountSharding) String() string {
	return fmt.Sprintf("ShardInfo{MaskBits:%d, LocalID:%d, AllIds:%v}", as.GetMaskBits(), as.LocalID(), as.AllIDs())
}
