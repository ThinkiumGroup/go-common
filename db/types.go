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

package db

import (
	"encoding/binary"
	"errors"

	"github.com/ThinkiumGroup/go-common"
)

var (
	// prefix+hash -> Account Trie Node and Value
	KPAccountNode  = []byte("aa")
	KPAccountValue = []byte("ab")
	// prefix+hash -> Code of Account
	KPCode = []byte("ac")
	// prefix+hash -> Account Storage Trie Node
	KPAccStorageNode = []byte("ad")
	// prefix+hash -> Account Long Storage Trie Node and Value (for system contract)
	KPAccLongNode  = []byte("am")
	KPAccLongValue = []byte("an")
	// shard chain
	// prefix + hash -> AccountDelta Trie Node and Value
	KPDeltaNodeNode  = []byte("ae")
	KPDeltaNodeValue = []byte("af")
	// prefix + header.BalanceDeltaRoot -> combined trie of AccountDelta Tries
	KPDeltaTrie = []byte("ag")
	// prefix + shard.ElectChainID.Formalize() + heightOfBlock.Bytes() -> hash root of Account
	KPDeltaFromTrie = []byte("ah")
	// prefix + DeltaFromKey{ShardID, Height} -> serialization of []*AccountDelta
	KPDeltaFroms          = []byte("ai")
	KPDeltaFromMaxHeight  = []byte("aj")
	KPDeltaFromWaterline  = []byte("ak")
	KPDeltaToBeSent       = []byte("ao")
	KPDFWaterlineSnapshot = []byte("ap")

	// prefix + HistoryTree.Node.Hash -> HistoryTree.Node.Children/Leafs
	KPHistoryNode = []byte("al")

	// prefix+hash -> Transaction Trie Node and Value
	KPTxNode  = []byte("tk")
	KPTxValue = []byte("tv")
	// prefix+hash -> Transaction in block  and index of the all transactions
	KPTxIndex = []byte("ti")

	// prefix + hash -> Verifiable Cash Check Trie Node and Value
	KPVccNode  = []byte("va")
	KPVccValue = []byte("vb")
	// prefix + hash -> Cashed Verifiable Cash Check Trie Node and Value
	KPCVccNode  = []byte("vc")
	KPCVccValue = []byte("vd")
	// prefix + Vcc.Hash -> cash the check Tx.Hash
	KPCVccTxIndex = []byte("ve")

	// prefix+hash(Header) -> block/Header height
	KPBlockNumByHash = []byte("bn")
	// prefix+height -> Header hash
	KPBlockHashByNum = []byte("bh")
	// prefix+hash(header) -> block encoded value
	KPBlock = []byte("bb")
	// prefix -> current Highest block height
	KPCurrentHeight = []byte("bc")
	// prefix+hash(Header) -> Receipts
	KPReceipts = []byte("br")
	// prefix+height -> received data block (not yet processed, just persisted in the database)
	KPBlockNotVerified = []byte("bv")
	// prefix+ChainID+EpochNum -> election results of the EpochNum'th committee
	// key is the elected Epoch, not the Epoch at the time of the election, starting
	// from 0. If the election result fails, continue
	KPEpochComm = []byte("bec")
	// prefix+EpochNum -> Height of the block including the election results of the committee of EpochNum
	KPEpochCommIndex = []byte("bei")

	// main chain
	// prefix + FormalizedChainID -> ChainInfos Trie Node and Value
	KPChainNode  = []byte("cn")
	KPChainValue = []byte("ci")
	// prefix + ChainId + EpochNum -> Committee
	KPChainEpochCommittee = []byte("ce")
	// // prefix + ChainId + Height -> Header
	// KPChainHeightHeader = []byte("ch")
	// // prefix + ChainId + Height -> BlockProof
	// KPChainHeightProof = []byte("cp")

	// save HDS in the parent block to current sub-chain database by the info of the parent block
	// prefix + X.ChainID + X.Height -> {KPConfirmedHdsByParentInfo + parent.ChainID + parent.Height}|(parent.Hds ⊇ X.Height)
	KPConfirmedHdsByParentCursor = []byte("ch")
	// prefix + X.ChainID + X.Height -> {block.Header, block.body.Hds}|(block.ChainID==X.ChainID, block.Height==X.Height)
	KPConfirmedHdsByParentInfo = []byte("cp")

	// // prefix+ChainID -> the latest (block height + block Hash) of current chain has been reported
	// KPLastReportedCursor = []byte("cc")
	// prefix+ChainID -> the latest (block height + block Hash + comm Epoch) has been confirmed by parent chain
	KPLastConfirmedCursor = []byte("cca")
	// prefix+ChainID -> the latest (block height + block Hash + comm Epoch) of sub-chain confirmed by current chain
	KPSubConfirmedCursor = []byte("ccb")

	// the earliest Cursor on the main chain received by the current node and has not yet
	// issued a reward, the reward can be issue from this height to process the Request
	KPRewardHeightCursor = []byte("cf")
	KPRewardBase         = []byte("rb")

	KPRRNode          = []byte("ra") // Required Reserve Trie Node Prefix
	KPRRValue         = []byte("rc") // Required Reserve Trie Value Prefix
	KPRRCNode         = []byte("rd") // Required Reserve Changing Trie Node Prefix
	KPRRCValue        = []byte("re") // Required Reserve Changing Trie Value Prefix
	KPRRRoot          = []byte("rf") // Required Reserve Trie Root Hash: prefix+EraNum -> RootOfRRTrie
	KPSettleInfoNode  = []byte("rg") // Settle info for one node trie node prefix
	KPSettleInfoValue = []byte("ri") // settle info for one node trie value preifx
	KPRRActReceipts   = []byte("rh") // RRAct Receipts in one block, prefix+RRActReceipts.RootHash -> (stream of RRActReceipts)
	KPRRActRptIndex   = []byte("rj") // prefix+TxHash -> (RRActReceipts.RootHash, Index in RRActReceipts)

	KPStorageEntry = []byte("se")

	// prefix + ChainID + Height -> [{BlockHash, AuditPass}]
	KPAuditorMsgs = []byte("aq")

	ErrNotFound = errors.New("data not found")
	ErrReadOnly = errors.New("read only database")
)

func PrefixKey(prefix []byte, key []byte) []byte {
	ret := make([]byte, len(prefix)+len(key))
	if len(prefix) > 0 {
		copy(ret, prefix)
	}
	if len(key) > 0 {
		copy(ret[len(prefix):], key)
	}
	return ret
}

func PrefixKey2(prefix1 []byte, prefix2 []byte, key []byte) []byte {
	l1 := len(prefix1)
	l2 := l1 + len(prefix2)
	l3 := l2 + len(key)
	ret := make([]byte, l3)
	if l1 > 0 {
		copy(ret, prefix1)
	}
	if len(prefix2) > 0 {
		copy(ret[l1:], prefix2)
	}
	if len(key) > 0 {
		copy(ret[l2:], key)
	}
	return ret
}

func ToBlockNumberKey(hashOfHeader []byte) []byte {
	return PrefixKey(KPBlockNumByHash, hashOfHeader)
}

func ToBlockHashKey(height common.Height) []byte {
	return PrefixKey(KPBlockHashByNum, height.Bytes())
}

//
// func ToBlockHeaderKey(hashOfHeader []byte) []byte {
// 	return PrefixKey(KPBlockHeader, hashOfHeader)
// }

func ToBlockTXIndexKey(hashOfTransacion []byte) []byte {
	return PrefixKey(KPTxIndex, hashOfTransacion)
}

func ToBlockReceiptsKey(hashOfHeader []byte) []byte {
	return PrefixKey(KPReceipts, hashOfHeader)
}

func ToBlockKey(hashOfHeader []byte) []byte {
	return PrefixKey(KPBlock, hashOfHeader)
}

func ToBlockNotVerified(height common.Height) []byte {
	return PrefixKey(KPBlockNotVerified, height.Bytes())
}

func ToCurrentHeightKey() []byte {
	return KPCurrentHeight
}

// func ToReceivedDeltaHashKey(fromID common.ChainID, height common.Height) []byte {
// 	return PrefixKey2(KPReceivedDeltaHash, fromID.Formalize(), height.Bytes())
// }

func ToDeltaFromKey(fromID common.ChainID, height common.Height) []byte {
	return PrefixKey2(KPDeltaFroms, fromID.Formalize(), height.Bytes())
}

func ToDeltaFromMaxHeightKey(fromID common.ChainID) []byte {
	return PrefixKey(KPDeltaFromMaxHeight, fromID.Formalize())
}

func ToDeltaFromWaterlineKey(fromID common.ChainID) []byte {
	return PrefixKey(KPDeltaFromWaterline, fromID.Formalize())
}

func ToDeltaToBeSentKey() []byte {
	return KPDeltaToBeSent
}

func ToDFWaterlineSnapshotKey(hashOfWaterlines []byte) []byte {
	return PrefixKey(KPDFWaterlineSnapshot, hashOfWaterlines)
}

func ToChainCommitteeKey(chainId common.ChainID, epochNum common.EpochNum) []byte {
	return PrefixKey2(KPChainEpochCommittee, chainId.Formalize(), epochNum.Bytes())
}

func ToEpochCommKey(chainId common.ChainID, epoch common.EpochNum) []byte {
	return PrefixKey2(KPEpochComm, chainId.Formalize(), epoch.Bytes())
}

func ToEpochCommIndexKey(epoch common.EpochNum) []byte {
	return PrefixKey(KPEpochCommIndex, epoch.Bytes())
}

//
// func ToChainHeightHeaderKey(chainId common.ChainID, height common.Height) []byte {
// 	return PrefixKey2(KPChainHeightHeader, chainId.Formalize(), height.Bytes())
// }
//
// func ToChainHeightProofKey(chainId common.ChainID, height common.Height) []byte {
// 	return PrefixKey2(KPChainHeightProof, chainId.Formalize(), height.Bytes())
// }

func ToFirstRewardCursorKey() []byte {
	return KPRewardHeightCursor
}

func ToLastConfirmedCursorKey(chainId common.ChainID) []byte {
	return PrefixKey(KPLastConfirmedCursor, chainId.Formalize())
}

func ToRewardBaseKey(chainId common.ChainID) []byte {
	return PrefixKey(KPRewardBase, chainId.Formalize())
}

func ToRRKey(era common.EraNum) []byte {
	return PrefixKey(KPRRRoot, era.Bytes())
}

func ToStorageEntryKey(root []byte, num int) []byte {
	nb := make([]byte, 32)
	binary.BigEndian.PutUint32(nb, uint32(num))
	return PrefixKey2(KPStorageEntry, root, nb)
}

func ToRRActReceiptsKey(rootOfReceipts []byte) []byte {
	return PrefixKey(KPRRActReceipts, rootOfReceipts)
}

func ToRRActRptIndexKey(hashOfTx []byte) []byte {
	return PrefixKey(KPRRActRptIndex, hashOfTx)
}

type Writer interface {
	Put(key, value []byte) error
	Delete(key []byte) error
}

type Batch interface {
	Put(key, value []byte) error
	Delete(key []byte) error
	Size() int
}

type Database interface {
	Put(key, value []byte) error
	Has(key []byte) (bool, error)
	Get(key []byte) ([]byte, error)
	Delete(key []byte) error
	NewBatch() Batch
	Batch(batch Batch) error
	Close() error
}

func GetNilError(db Database, key []byte) ([]byte, error) {
	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNotFound
	}
	return data, nil
}

func BatchWrite(dbase Database, threshold, length int,
	write func(j int, w Writer) (ok bool, err error)) (count int, err error) {
	var batch Batch
	index := 0
	for i := 0; i < length; i++ {
		if index == 0 {
			batch = dbase.NewBatch()
		}
		ok, err := write(i, batch)
		if err != nil {
			return count, err
		}
		if !ok {
			continue
		}
		index = index + 1
		if index == threshold || i == (length-1) {
			if err = dbase.Batch(batch); err != nil {
				return count, err
			}
			count = count + index
			index = 0
		}
	}
	return count, nil
}
