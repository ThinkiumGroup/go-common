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

const (
	// default configuration
	DefaultP2PPort1   = 31000
	DefaultP2pPort2   = 31050
	DefaultRpcAddress = "127.0.0.1:23017"
	DefaultCompatible = true

	BlocksInEpoch = 1000 // number of blocks in Epoch
	EpochsInEra   = 36
	BlocksInEra   = EpochsInEra * BlocksInEpoch

	// chain id related
	ReservedMaxChainID uint32 = 1 << 20
	MainChainID               = ChainID(0)
	NilChainID                = ChainID(ReservedMaxChainID)

	// length of types
	NodeIDBits        = 512
	NodeIDBytes       = NodeIDBits / 8
	HashLength        = 32
	AddressLength     = 20
	SeedLength        = 20
	ChainBytesLength  = 4 // chain id
	HeightBytesLength = 8 // height

	// upper limit of shards：<= 2^MaxExponentOfShards
	MaxExponentOfShards = 8

	INTMAX int = int(^uint(0) >> 1)
	INTMIN int = ^INTMAX
)

const (
	// chain mode
	Root ChainMode = 0x10 + iota
	Branch
	Shard
	UnknownMode
)

const (
	Consensus    NodeType = 0
	Data         NodeType = 1
	Memo         NodeType = 2
	NoneNodeType NodeType = 0xFF
)

const (
	// network type
	BasicNet NetType = iota
	ConsensusNet1
	ConsensusNet2
	RootDataNet   // Only in the main chain layer, including all data nodes of the main chain and its sub chains
	BranchDataNet // Only in the sub chain layer, including all data nodes of the sub chain and its shards
	// UnknownNet
)

const (
	// event type of monitoring
	P2P = iota
	Event
	Block
)

const (
	// state of system services
	SSCreated ServiceStatus = iota
	SSInitialized
	SSStarted
	SSStopped
)
