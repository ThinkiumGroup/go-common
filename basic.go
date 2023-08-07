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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ThinkiumGroup/go-common/hexutil"
	"github.com/ThinkiumGroup/go-common/log"
	math2 "github.com/ThinkiumGroup/go-common/math"
	"github.com/ThinkiumGroup/go-common/rlp"
)

var (
	TypeOfAddress = reflect.TypeOf((*Address)(nil)).Elem()
	TypeOfHash    = reflect.TypeOf((*Hash)(nil)).Elem()
	EmptyNodeID   = NodeID{}
	EmptyAddress  = Address{}
	SystemNodeID  NodeID // NodeID of current node, which is initialized from the configuration file when the system starts

	TxCount       uint64
	NetDelay      []int                                       // range of system network delay [NetDelay[0]-NetDelay[1]]
	WaitingTime   time.Duration                               // Waiting time for consensus state switching, waiting for other nodes
	LastMsgTime   int64                                       // Timestamp of the last P2P message in the system
	LastEventTime int64                                       // Timestamp of the last consensus event processed
	LastBlockTime int64                                       // Timestamp of the last Block time
	LastBlocks    = LastBlockMap{M: make(map[ChainID]Height)} // The height of the last block processed by each chain
	PkgedBlocks   = LastBlockMap{M: make(map[ChainID]Height)} // Record the last block that each chain has been packaged by main chain
	Overflow      bool                                        // delta pool overflowed?
	NdType        *NodeType
	ForChain      *ChainID
	FullData      bool
	StandAlone    bool // if startup in standalone mode (one chain mode)
)

type (
	NodeID   [NodeIDBytes]byte
	NodeIDs  []NodeID
	EraNum   uint64 // cycle for Required Reserve management
	EpochNum uint64 // cycle for one committee consensus
	BlockNum uint32 // block number in one epoch
	Height   uint64 // block height
	CommID   int

	NodeIDSet struct {
		lock sync.RWMutex
		m    map[NodeID]int
		l    []*NodeID
	}

	LastBlockMap struct {
		lock sync.RWMutex
		M    map[ChainID]Height
	}

	Address [AddressLength]byte

	Addresser interface {
		Address() Address
	}

	NodeType byte

	ElectionType byte
)

// ETManagedCommittee:
//  1. The consensus nodes in this chain will not participate in the election of other chains
//     until the nodes quit from the consensus of this chain
//  2. This type of chain no longer reports reward request, that is, there is no reward
//  3. The start time of the election in this chain is the same as that in VRF, but the election
//     request is broadcast directly on the basic network of main chain without packaging in a
//     block
//  4. Nodes that can participate in the election on thi chain will be stored under the key
//     (models.AddressOfChainSettings, models.ManagedCommNodeIdsName) in this chain in the form
//     of nodeid list. The byte slice value formed by the end to end connection of multiple
//     values. By modifying this value, we can control the list of candidates who can run in
//     the next election.
//  5. When receiving the election request, all nodes will judge whether their nodeid is in the
//     candidate list. If it is, they can join the basic network and the next consensus network
//     of the chain, wait for the synchronization information, and then send the election results
//     (Registration). The process here is same with VRF election, but the registration
//     message type is different
//  6. There's no lower limit for committee.size, and same upper limit with VRF election. The
//     committee is composed of registered and legal candidates, sorted by nodeid from small to
//     large, packaged and broadcast to the network. The process here is same with VRF election,
//     but the election algorithm is different.
//  1. 在此链中共识的节点不再参与其他链的选举，直到节点退出此链的共识
//  2. 此类型链不再上报奖励请求，即无奖励
//  3. 此链的选举开始时间与VRF一致，但选举请求不经过打包直接在0链基础网络上广播
//  4. 可以参与选举的节点，会以NodeID列表的方式存储在本链models.AddressOfChainSettings的
//     models.ManagedCommNodeIdsName为名的键值中，多个值首尾相接形成的byte slice值。通过修改这
//     个值，来控制下次可以参选的候选人名单。
//  5. 所有节点收到选举请求时，会判断自身NodeID是否在候选人名单中，如果在，就可以加入该链基础网络和下
//     届共识网络等待同步信息后再发送选举结果（报名）,此处流程与VRF选举一致，不过报名消息类型不同
//  6. 选举不再控制committee.size的下限，上限与VRF选举一致，Committee由报名的且合法的候选人，按
//     NodeID由小到大排序组成，并打包广播到本链网络中，除选举算法与VRF不同，流程完全一致
const (
	ETNone             ElectionType = 0
	ETVrf              ElectionType = 1
	ETManagedCommittee ElectionType = 4
	// Deprecated
	ETFixedCommittee ElectionType = 2
	// Deprecated
	ETFixedSpectator ElectionType = 3

	NilEpoch  = EpochNum(math.MaxUint64)
	NilEra    = EraNum(math.MaxUint64)
	NilHeight = Height(math.MaxUint64)
	NilBlock  = BlockNum(math.MaxUint32)
)

var (
	nodeTypeNameMap = map[NodeType]string{
		Consensus:    "Consensus",
		Data:         "Data",
		Memo:         "Memo",
		NoneNodeType: "None",
	}

	// The exclusiveness of election type, that is, after entering this type of consensus,
	// whether it can enter other chain consensus
	// true: exclusive, false: not exlusive
	electionExclusiveness = map[ElectionType]bool{
		ETNone:             false,
		ETVrf:              false,
		ETFixedCommittee:   true,
		ETFixedSpectator:   true,
		ETManagedCommittee: true,
	}

	// Record whether the chain using this election type needs to upload the reward request
	electionRewardNeeded = map[ElectionType]bool{
		ETNone:             true,
		ETVrf:              true,
		ETFixedCommittee:   false,
		ETFixedSpectator:   false,
		ETManagedCommittee: false,
	}

	// The name of a valid electiontype in the chain configuration
	validChainElection = map[string]ElectionType{
		"VRF":     ETVrf,
		"MANAGED": ETManagedCommittee,
	}

	// valid ElementType name in chain configuration
	validElectionName = map[ElectionType]string{}
)

func init() {
	for n, e := range validChainElection {
		validElectionName[e] = n
	}
}

func (n NodeType) String() string {
	name, exist := nodeTypeNameMap[n]
	if !exist {
		return fmt.Sprintf("NA_%d", n)
	}
	return name
}

func (ns NodeIDs) IsIn(nid NodeID) bool {
	for _, id := range ns {
		if id == nid {
			return true
		}
	}
	return false
}

// Monitor the event occurrence time
func Watch(tp int) {
	switch tp {
	case P2P:
		LastMsgTime = time.Now().Unix()
	case Event:
		LastEventTime = time.Now().Unix()
	case Block:
		LastBlockTime = time.Now().Unix()
	default:
		return
	}
}

// Monitoring Delta
func WatchDelta(ovfl bool) {
	Overflow = ovfl
}

// monitoring the height
func WatchHeight(id ChainID, height Height) {
	LastBlocks.Set(id, height)
}

func (m *LastBlockMap) Set(key ChainID, value Height) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.M[key] = value
}

func (m *LastBlockMap) Get(key ChainID) (Height, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	h, exist := m.M[key]
	return h, exist
}

// When the value is greater than the currently saved value, replace it and return true.
// Otherwise, return false
func (m *LastBlockMap) CAS(key ChainID, value Height) bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	if v, e := m.M[key]; e && v >= value {
		return false
	} else {
		m.M[key] = value
	}
	return true
}

func (m *LastBlockMap) CopyMap() map[ChainID]Height {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.M == nil {
		return nil
	}
	r := make(map[ChainID]Height, len(m.M))
	for k, v := range m.M {
		r[k] = v
	}
	return r
}

// should proposed blocks number in one epoch
func (i CommID) ShouldPropose(commSize int) int {
	quotient := int(BlocksInEpoch) / commSize
	remaider := int(BlocksInEpoch) % commSize
	if remaider > int(i) {
		quotient++
	}
	return quotient
}

func (i CommID) String() string {
	return fmt.Sprintf("CommID:%d", i)
}

func (nid *NodeID) Bytes() []byte {
	return nid[:]
}

func ParseNodeIDBytes(nodeBytes []byte) (*NodeID, error) {
	r := NodeID{}
	if len(nodeBytes) > NodeIDBytes {
		nodeBytes = nodeBytes[len(nodeBytes)-NodeIDBytes:]
	}
	copy(r[NodeIDBytes-len(nodeBytes):], nodeBytes)
	// copy(r[:], nodeBytes)
	return &r, nil
}

func ParseNodeID(nodeString string) (*NodeID, error) {
	b, err := hex.DecodeString(nodeString)
	if err != nil {
		return nil, err
	}
	return ParseNodeIDBytes(b)
}

func (nid *NodeID) Generate() error {
	id := make([]byte, NodeIDBytes)
	n, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		return err
	}
	if n != NodeIDBytes {
		return ErrInsufficientLength
	}
	copy(nid[:], id)
	return nil
}

// func (nid *nodeID) GenerateFromECDSA(pubkey *ecdsa.PublicKey) error {
// 	id := FromECDSAPub(pubkey)
// 	if id == nil {
// 		return errors.New("generate nodeID failed: invalid public key")
// 	}
// 	// remove the first byte, which is a format indicator
// 	copy(nid[:], id[1:])
// 	return nil
// }

func GenerateNodeID() *NodeID {
	r := new(NodeID)
	r.Generate()
	return r
}

func BytesToNodeID(b []byte) NodeID {
	var a NodeID
	a.SetBytes(b)
	return a
}

func BytesToNodeIDP(b []byte) *NodeID {
	var nid NodeID
	nid.SetBytes(b)
	return &nid
}

func ParseBytesToNodeIds(s []byte) ([]NodeID, error) {
	if len(s)%NodeIDBytes != 0 {
		return nil, errors.New(fmt.Sprintf("input nodeids length illegal (%d)", len(s)))
	}
	var nodeids []NodeID
	for p := 0; p < len(s); p += NodeIDBytes {
		nid := BytesToNodeID(s[p : p+NodeIDBytes])
		nodeids = append(nodeids, nid)
	}
	return nodeids, nil
}

func ParseBytesToNodeIdBytes(s []byte) ([][]byte, error) {
	if len(s)%NodeIDBytes != 0 {
		return nil, errors.New(fmt.Sprintf("input nodeids length illegal (%d)", len(s)))
	}
	var nodeids [][]byte
	for p := 0; p < len(s); p += NodeIDBytes {
		nid := make([]byte, NodeIDBytes)
		copy(nid, s[p:p+NodeIDBytes])
		nodeids = append(nodeids, nid)
	}
	return nodeids, nil
}

func PackNodeIdsToBytes(nodeIds []NodeID) []byte {
	if len(nodeIds) == 0 {
		return nil
	}
	bs := make([]byte, len(nodeIds)*NodeIDBytes)
	for i := 0; i < len(nodeIds); i++ {
		copy(bs[i*NodeIDBytes:(i+1)*NodeIDBytes], nodeIds[i][:])
	}
	return bs
}

func (nid NodeID) isZero() bool {
	for _, v := range nid {
		if v != 0 {
			return false
		}
	}
	return true
}

func (nid NodeID) String() string {
	return hex.EncodeToString(nid[:5])
}

func (nid NodeID) InfoString(_ IndentLevel) string {
	return hex.EncodeToString(nid[:])
}

func (nid *NodeID) Clone() *NodeID {
	if nid == nil {
		return nil
	}
	ret := new(NodeID)
	ret.SetBytes(nid.Bytes())
	return ret
}

func (nid NodeID) New() *NodeID {
	return (&nid).Clone()
}

func (nid *NodeID) SetBytes(b []byte) {
	if len(b) > len(nid) {
		b = b[len(b)-NodeIDBytes:]
	}
	copy(nid[NodeIDBytes-len(b):], b)
}

func (nid NodeID) MarshalText() ([]byte, error) {
	return hexutil.Bytes(nid[:]).MarshalText()
}

func (nid *NodeID) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("nodeid", input, nid[:])
}

func (nid *NodeID) Compare(to *NodeID) int {
	if nid == nil && to == nil {
		return 0
	}
	if nid == nil && to != nil {
		return -1
	}
	if nid != nil && to == nil {
		return 1
	}
	return bytes.Compare((*nid)[:], (*to)[:])
}

// compatible with Hash() method
func (nid *NodeID) HashValue() ([]byte, error) {
	return Hash256s(nid[:])
}

func (nid NodeID) Hash() Hash {
	// return EncodeHash(nid)
	return Hash256(nid[:])
}

func StringsToNodeIDs(strings []string) ([]NodeID, error) {
	if strings == nil {
		return nil, nil
	}
	ids := make([]NodeID, len(strings), len(strings))
	for i := 0; i < len(strings); i++ {
		nid, err := ParseNodeID(strings[i])
		if err != nil {
			return nil, err
		}
		if nid == nil {
			return nil, ErrNil
		}
		ids[i] = *nid
	}
	return ids, nil
}

func (ns *NodeIDs) AppendByHex(nidHex string) error {
	bs, err := hex.DecodeString(nidHex)
	if err != nil {
		return err
	}
	nid := BytesToNodeID(bs)
	*ns = append(*ns, nid)
	return nil
}

func (ns NodeIDs) Len() int {
	return len(ns)
}

func (ns NodeIDs) Swap(i, j int) {
	ns[i], ns[j] = ns[j], ns[i]
}

func (ns NodeIDs) Less(i, j int) bool {
	return bytes.Compare(ns[i][:], ns[j][:]) < 0
}

func (ns NodeIDs) Equal(os NodeIDs) bool {
	if len(ns) == 0 && len(os) == 0 {
		return true
	}
	if len(ns) != len(os) {
		return false
	}
	for i := 0; i < len(ns); i++ {
		if ns[i] != os[i] {
			return false
		}
	}
	return true
}

func (ns NodeIDs) ToMap() map[NodeID]struct{} {
	m := make(map[NodeID]struct{})
	for i := 0; i < len(ns); i++ {
		m[ns[i]] = EmptyPlaceHolder
	}
	return m
}

func (ns NodeIDs) ToBytesSlice() [][]byte {
	if ns == nil {
		return nil
	}
	out := make([][]byte, len(ns))
	for i := 0; i < len(ns); i++ {
		out[i] = CopyBytes(ns[i][:])
	}
	return out
}

func (ns NodeIDs) Clone() NodeIDs {
	if ns == nil {
		return nil
	}
	r := make(NodeIDs, len(ns))
	copy(r, ns)
	return r
}

func (ns NodeIDs) Contains(nid NodeID) bool {
	for _, id := range ns {
		if id == nid {
			return true
		}
	}
	return false
}

func (ns NodeIDs) Union(os NodeIDs) NodeIDs {
	m := make(map[NodeID]struct{}, len(ns)+len(os))
	for _, nid := range ns {
		m[nid] = struct{}{}
	}
	for _, nid := range os {
		m[nid] = struct{}{}
	}
	if len(m) == 0 {
		return nil
	}
	r := make(NodeIDs, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}

func (ns NodeIDs) Remove(os NodeIDs) NodeIDs {
	if len(ns) == 0 {
		return nil
	}
	m := make(map[NodeID]struct{}, len(ns)+len(os))
	for _, nid := range ns {
		m[nid] = struct{}{}
	}
	for _, nid := range os {
		delete(m, nid)
	}
	if len(m) == 0 {
		return nil
	}
	r := make(NodeIDs, 0, len(m))
	for k, _ := range m {
		r = append(r, k)
	}
	return r
}

func (ns NodeIDs) InfoString(level IndentLevel) string {
	return level.InfoString(ns)
}

func NewNodeIDSet(ids ...*NodeID) *NodeIDSet {
	if len(ids) == 0 {
		return &NodeIDSet{
			m: make(map[NodeID]int),
			l: make([]*NodeID, 0),
		}
	}
	m := make(map[NodeID]int, len(ids))
	l := make([]*NodeID, 0)
	for i := 0; i < len(ids); i++ {
		_, exist := m[*ids[i]]
		if exist {
			continue
		}
		m[*ids[i]] = len(l)
		l = append(l, ids[i])
	}
	set := &NodeIDSet{
		m: m,
		l: l,
	}
	sort.Sort(set)
	return set
}

func (ns *NodeIDSet) Len() int {
	ns.lock.RLock()
	defer ns.lock.RUnlock()
	return len(ns.l)
}

func (ns *NodeIDSet) Swap(i, j int) {
	ns.lock.Lock()
	defer ns.lock.Unlock()
	ns.m[*(ns.l[i])] = j
	ns.m[*(ns.l[j])] = i
	ns.l[i], ns.l[j] = ns.l[j], ns.l[i]
}

func (ns *NodeIDSet) Less(i, j int) bool {
	ns.lock.RLock()
	defer ns.lock.RUnlock()
	return bytes.Compare((*(ns.l[i]))[:], (*(ns.l[j]))[:]) < 0
}

func (ns *NodeIDSet) Put(id *NodeID) bool {
	if id == nil {
		return false
	}
	ns.lock.Lock()
	defer ns.lock.Unlock()
	_, exist := ns.m[*id]
	if exist {
		return false
	}
	ns.m[*id] = len(ns.l)
	ns.l = append(ns.l, id)
	return true
}

func (ns *NodeIDSet) Delete(id *NodeID) {
	if id == nil {
		return
	}
	ns.lock.Lock()
	defer ns.lock.Unlock()
	i, exist := ns.m[*id]
	if !exist {
		return
	}
	copy(ns.l[i:], ns.l[i+1:])
	ns.l = ns.l[:len(ns.l)-1]
	delete(ns.m, *id)
}

func (ns *NodeIDSet) Get(i int) (*NodeID, bool) {
	if i < 0 || i >= len(ns.l) {
		return nil, false
	}
	return ns.l[i], true
}

func (ns *NodeIDSet) GetIndex(id *NodeID) (int, bool) {
	if id == nil {
		return 0, false
	}
	ns.lock.RLock()
	defer ns.lock.RUnlock()
	i, ok := ns.m[*id]
	return i, ok
}

func (ns *NodeIDSet) GetNodeIDs(chainid ChainID) NodeIDs {
	if len(ns.l) > 0 {
		nids := make(NodeIDs, len(ns.l))
		sort.Sort(ns)
		for i := 0; i < len(ns.l); i++ {
			nids = append(nids, *ns.l[i])
		}
		return nids
	} else {
		return make(NodeIDs, 0)
	}
}

func (e EraNum) IsNil() bool {
	return e == NilEra
}

func (e *EraNum) Clone() *EraNum {
	if e == nil {
		return nil
	}
	o := *e
	return &o
}

func (e *EraNum) Hash() Hash {
	if e == nil {
		return NilHash
	}
	h, _ := HashObject(e)
	return BytesToHash(h)
}

func (e *EraNum) Equal(o *EraNum) bool {
	if e == o {
		return true
	}
	if e == nil || o == nil {
		return false
	}
	return *e == *o
}

func (e EraNum) Compare(o EraNum) int {
	if e == o {
		return 0
	}
	if e.IsNil() {
		return -1
	}
	if o.IsNil() {
		return 1
	}
	if e < o {
		return -1
	} else {
		return 1
	}
}

func (e *EraNum) Cmp(o *EraNum) int {
	if e == o {
		return 0
	}
	if e == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	return (*e).Compare(*o)
}

func (e *EraNum) String() string {
	if e == nil {
		return ""
	}
	if e.IsNil() {
		return "<nil>"
	}
	return strconv.FormatUint(uint64(*e), 10)
}

func (e *EraNum) Value() EraNum {
	if e == nil {
		return NilEra
	}
	return *e
}

func (e EraNum) Bytes() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, uint64(e))
	return ret
}

func (e *EraNum) Slice() []byte {
	if e == nil {
		return nil
	}
	return (*e).Bytes()
}

func (en *EpochNum) Clone() *EpochNum {
	if en == nil {
		return nil
	}
	o := *en
	return &o
}

func (en EpochNum) IsNil() bool {
	return en == NilEpoch
}

func (en EpochNum) Diff(o EpochNum) (diff uint64, cmpRet int) {
	if en == o {
		return 0, 0
	}
	if en.IsNil() {
		return uint64(o) + 1, -1
	}
	if o.IsNil() {
		return uint64(en) + 1, 1
	}
	if en < o {
		return uint64(o - en), -1
	} else {
		return uint64(en - o), 1
	}
}

func (en EpochNum) Compare(o EpochNum) int {
	if en == o {
		return 0
	}
	if en.IsNil() {
		return -1
	}
	if o.IsNil() {
		return 1
	}
	if en < o {
		return -1
	} else {
		return 1
	}
}

func (en *EpochNum) Cmp(o *EpochNum) int {
	if en == o {
		return 0
	}
	if en == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	return (*en).Compare(*o)
}

func (en EpochNum) FirstHeight() Height {
	if en.IsNil() {
		return NilHeight
	}
	r, overflow := math2.SafeMul(uint64(en), BlocksInEpoch)
	if overflow {
		return NilHeight
	}
	return Height(r)
}

func (en EpochNum) LastHeight() Height {
	if en.IsNil() {
		return NilHeight
	}
	r, overflow := math2.SafeMul(uint64(en), BlocksInEpoch)
	if overflow {
		return NilHeight
	}
	r, overflow = math2.SafeAdd(r, BlocksInEpoch-1)
	if overflow {
		return NilHeight
	}
	return Height(r)
}

func (en EpochNum) String() string {
	if en.IsNil() {
		return "<nil>"
	}
	return strconv.FormatUint(uint64(en), 10)
}

func (en *EpochNum) ToString() string {
	if en == nil {
		return ""
	}
	return (*en).String()
}

func (en EpochNum) Bytes() []byte {
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, uint64(en))
	return ret
}

func (bn BlockNum) Bytes() []byte {
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, uint32(bn))
	return ret
}

func (bn BlockNum) IsNil() bool {
	return bn == NilBlock
}

func (bn BlockNum) IsValid() bool {
	return uint64(bn) < BlocksInEpoch
}

func (bn BlockNum) IsFirstOfEpoch() bool {
	return bn == 0
}

// Is it the last block in an epoch
func (bn BlockNum) IsLastOfEpoch() bool {
	return bn.IsValid() && (uint64(bn)+1) == BlocksInEpoch
}

func (bn BlockNum) String() string {
	if bn.IsNil() {
		return "<nil>"
	}
	if !bn.IsValid() {
		return "<NA>"
	}
	return strconv.Itoa(int(bn))
}

func (h Height) IsNil() bool {
	return h == NilHeight
}

func (h Height) Diff(o Height) (diff uint64, cmpRet int) {
	if h == o {
		return 0, 0
	}
	if h.IsNil() {
		return uint64(o) + 1, -1
	}
	if o.IsNil() {
		return uint64(h) + 1, 1
	}
	if h < o {
		return uint64(o - h), -1
	} else {
		return uint64(h - o), 1
	}
}

func (h Height) Compare(o Height) int {
	if h == o {
		return 0
	}
	if h.IsNil() {
		return -1
	}
	if o.IsNil() {
		return 1
	}
	if h < o {
		return -1
	} else {
		return 1
	}
}

func (h Height) Bytes() []byte {
	ret := make([]byte, HeightBytesLength)
	binary.BigEndian.PutUint64(ret, uint64(h))
	return ret
}

func (h *Height) Slice() []byte {
	if h == nil {
		return nil
	}
	return (*h).Bytes()
}

func (h Height) EraNum() EraNum {
	if h.IsNil() {
		return NilEra
	}
	return EraNum(h) / EraNum(BlocksInEpoch*EpochsInEra)
}

func (h Height) EpochNum() EpochNum {
	if h.IsNil() {
		return NilEpoch
	}
	return EpochNum(h) / EpochNum(BlocksInEpoch)
}

func (h Height) UsefulEpoch() EpochNum {
	if h.IsNil() {
		return 0
	}
	return EpochNum(h) / EpochNum(BlocksInEpoch)
}

func (h Height) BlockNum() BlockNum {
	if h.IsNil() {
		return NilBlock
	}
	return BlockNum(uint64(h) % BlocksInEpoch)
}

func (h Height) UsefulBlock() BlockNum {
	if h.IsNil() {
		return 0
	}
	return BlockNum(uint64(h) % BlocksInEpoch)
}

func (h Height) IsFirstOfEpoch() bool {
	return !h.IsNil() && (uint64(h)%BlocksInEpoch) == 0
}

// Is it the last block in an epoch
func (h Height) IsLastOfEpoch() bool {
	// It is necessary to consider the special case that height is likely to be the maximum value
	// of Uint64 in the genesis block
	return !h.IsNil() && ((uint64(h)+1)%BlocksInEpoch) == 0
}

func (h Height) Split() (epochNum EpochNum, blockNum BlockNum) {
	if h.IsNil() {
		return NilEpoch, NilBlock
	}
	epochNum = EpochNum(h) / EpochNum(BlocksInEpoch)
	blockNum = BlockNum(uint64(h) % BlocksInEpoch)
	return
}

func (h Height) RemoveRemainder(n Height) Height {
	if n == 0 || n == 1 {
		return h
	}
	if h.IsNil() {
		return NilHeight
	}
	q := h / n
	return q * n
}

func BytesToHeight(bs []byte) Height {
	if len(bs) >= 8 {
		return Height(binary.BigEndian.Uint64(bs[len(bs)-8:]))
	} else {
		buf := make([]byte, 8)
		copy(buf[8-len(bs):], bs)
		return Height(binary.BigEndian.Uint64(buf))
	}
}

func ToHeight(epoch EpochNum, bn BlockNum) Height {
	if epoch.IsNil() || !bn.IsValid() {
		return NilHeight
	}
	h1, overflow := math2.SafeMul(uint64(epoch), BlocksInEpoch)
	if overflow {
		return NilHeight
	}
	h2, overflow := math2.SafeAdd(h1, uint64(bn))
	if overflow {
		return NilHeight
	}
	return Height(h2)
	// return Height(uint64(epoch)*BlocksInEpoch + uint64(bn))
}

func (h *Height) Clone() *Height {
	if h == nil {
		return nil
	}
	o := *h
	return &o
}

func (h *Height) Equal(o *Height) bool {
	if h == o {
		return true
	}
	if h == nil || o == nil {
		return false
	}
	return *h == *o
}

func (h Height) FromBig(bi *big.Int) (height Height, ok bool) {
	if bi == nil || bi.Sign() < 0 || bi.Cmp(math2.BigMaxUint64) > 0 {
		return NilHeight, false
	}
	return Height(bi.Uint64()), true
}

func (h *Height) String() string {
	if h == nil {
		return ""
	}
	if h.IsNil() {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *h)
}

func (h Height) HashValue() ([]byte, error) {
	return Hash256s(h.Bytes())
}

func (h *Height) Hash() Hash {
	if h == nil {
		return NilHash
	}
	hh, _ := HashObject(h)
	return BytesToHash(hh)
}

var (
	reservedAddressMap  = make(map[Address]struct{}) // Reserved address, users can not use it (sending tx)
	systemContractMap   = make(map[Address]struct{}) // system contract, reserved address, cannot use as Tx.From
	noCheckAddressMap   = make(map[Address]struct{}) // Special account(reward account/poc account etc.), reserved addresses, could be Tx.From, gasPrice=0
	noGasContractMap    = make(map[Address]struct{}) // system contract with no gas
	reservedAddressLock sync.RWMutex
)

func RegisterReservedAddress(addrs ...Address) {
	reservedAddressLock.Lock()
	defer reservedAddressLock.Unlock()
	for _, addr := range addrs {
		reservedAddressMap[addr] = EmptyPlaceHolder
	}
	log.Infof("%s added to reserved address list", addrs)
}

func RegisterSystemContract(noGas bool, addrs ...Address) {
	reservedAddressLock.Lock()
	defer reservedAddressLock.Unlock()
	for _, addr := range addrs {
		systemContractMap[addr] = EmptyPlaceHolder
		reservedAddressMap[addr] = EmptyPlaceHolder
		if noGas {
			noGasContractMap[addr] = EmptyPlaceHolder
		}
	}
	log.Infof("%s added to system contract (and noGas=%t) list", addrs, noGas)
}

func RegisterNoCheckAddress(addrs ...Address) {
	reservedAddressLock.Lock()
	defer reservedAddressLock.Unlock()
	for _, addr := range addrs {
		noCheckAddressMap[addr] = EmptyPlaceHolder
		reservedAddressMap[addr] = EmptyPlaceHolder
	}
	log.Infof("%s added to no check address list", addrs)
}

func (a Address) IsReserved() bool {
	reservedAddressLock.RLock()
	defer reservedAddressLock.RUnlock()
	_, exist := reservedAddressMap[a]
	return exist
}

func (a Address) NoCheck() bool {
	reservedAddressLock.RLock()
	defer reservedAddressLock.RUnlock()
	_, exist := noCheckAddressMap[a]
	return exist
}

func (a Address) IsSystemContract() bool {
	reservedAddressLock.RLock()
	defer reservedAddressLock.RUnlock()
	_, exist := systemContractMap[a]
	return exist
}

func (a Address) IsNoGas() bool {
	reservedAddressLock.RLock()
	defer reservedAddressLock.RUnlock()
	_, exist := noGasContractMap[a]
	return exist
}

func (a *Address) Value() Address {
	if a == nil {
		return Address{}
	}
	return *a
}

func (a *Address) Clone() *Address {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func (a *Address) ForRLP() *Address {
	if a == nil {
		o := EmptyAddress
		return &o
	}
	o := *a
	return &o
}

func (a *Address) FromRLP() *Address {
	if a == nil {
		return nil
	}
	if *a == EmptyAddress {
		return nil
	}
	o := *a
	return &o
}

func (a Address) Copy() *Address {
	b := a
	return &b
}

func (a *Address) Slice() []byte {
	if a == nil {
		return nil
	}
	return a[:]
}

func (a *Address) Equal(o *Address) bool {
	if a == o {
		return true
	}
	if a == nil || o == nil {
		return false
	}
	return *a == *o
}

func (a *Address) Cmp(o *Address) int {
	if a == o {
		return 0
	}
	if a == nil {
		return -1
	}
	if o == nil {
		return 1
	}
	return bytes.Compare(a.Slice(), o.Slice())
}

// Bytes gets the string representation of the underlying address.
func (a Address) Bytes() []byte { return a[:] }

// Big converts an address to a big integer.
func (a Address) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }

// Hash converts an address to a hash by left-padding it with zeros.
func (a Address) Hash() Hash { return BytesToHash(a[:]) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	// sha := GetHash256()
	// hasher := RealCipher.Hasher()
	hasher := SystemHashProvider.Hasher()
	hasher.Write([]byte(unchecksummed))
	hash := hasher.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
// func (a Address) Format(s fmt.State, c rune) {
// 	fmt.Fprintf(s, "%"+string(c), a[:])
// }

// SetBytes sets the address to the value of b.
// If b is larger than len(a) it will panic.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// MarshalText returns the hex representation of a.
func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

// UnmarshalText parses a hash in hex syntax.
func (a *Address) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Address", input, a[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (a *Address) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(TypeOfAddress, input, a[:])
}

// func NewAddress(b []byte) Address {
// 	var r Address
// 	copy(r[:], b)
// 	return r
// }

func AddressFromPubSlice(pub []byte) (Address, error) {
	if len(pub) == 0 || pub[0] != 4 {
		return Address{}, errors.New("invalid public key")
	}
	var addr Address
	h, err := Hash256s(pub[1:])
	if err != nil {
		return Address{}, err
	}
	copy(addr[:], h[12:])
	return addr, nil
}

//
// func AddressFromPubKey(pubKey *ecdsa.PublicKey) (Address, error) {
// 	pub := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
// 	return AddressFromPubSlice(pub)
// }

func (a *Address) Generate() error {
	id := make([]byte, AddressLength)
	n, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		return err
	}
	if n != AddressLength {
		return ErrInsufficientLength
	}
	copy(a[:], id)
	return nil
}

func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

func (a *Address) ToString() string {
	if a == nil {
		return "<nil>"
	}
	return (*a).String()
}

type Hash [HashLength]byte

func NewHash(b []byte) *Hash {
	var r Hash
	copy(r[:], b)
	return &r
}

func (h Hash) HashValue() ([]byte, error) {
	return h[:], nil
}

func (h Hash) IsNil() bool {
	return h == NilHash
}

func (h Hash) IsEmpty() bool {
	return h == EmptyHash
}

func (h Hash) IsEmptyNode() bool {
	return h == EmptyNodeHash
}

func (h Hash) Invalid() bool {
	return h == EmptyHash || h == NilHash || h == EmptyNodeHash
}

func (h *Hash) Slice() []byte {
	if h == nil {
		return nil
	}
	return h[:]
}

func (h *Hash) Clone() *Hash {
	if h == nil {
		return nil
	}
	return NewHash(h[:])
}

func (h *Hash) ForRLP() *Hash {
	if h == nil {
		o := EmptyHash
		return &o
	}
	return NewHash(h[:])
}

func (h *Hash) FromRLP() *Hash {
	if h == nil {
		return nil
	}
	if *h == EmptyHash {
		return nil
	}
	o := *h
	return &o
}

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// Big converts a hash to a big integer.
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }

// Hex converts a hash to a hex string.
func (h Hash) Hex() string { return hexutil.Encode(h[:]) }

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (h Hash) TerminalString() string {
	return fmt.Sprintf("%x…%x", h[:3], h[29:])
}

// String implements the stringer interface and is used also by the logger when
// doing full logging into a file.
func (h Hash) String() string {
	return h.Hex()
}

func (h *Hash) PrintString() string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("%x", h[:5])
}

// Format implements fmt.Formatter, forcing the byte slice to be formatted as is,
// without going through the stringer interface used for logging.
// func (h Hash) Format(s fmt.State, c rune) {
// 	fmt.Fprintf(s, "%"+string(c), h[:])
// }

// UnmarshalText parses a hash in hex syntax.
func (h *Hash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Hash", input, h[:])
}

//
// // UnmarshalJSON parses a hash in hex syntax.
// func (h *Hash) UnmarshalJSON(input []byte) error {
// 	return hexutil.UnmarshalFixedJSON(TypeOfHash, input, h[:])
// }

// MarshalText returns the hex representation of h.
func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Generate implements testing/quick.Generator.
func (h Hash) Generate(rand *mrand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

func (h *Hash) SliceEqual(val []byte) bool {
	if h == nil {
		if len(val) == 0 {
			return true
		}
		return false
	}
	return bytes.Equal(h[:], val)
}

func (h *Hash) Equal(v *Hash) bool {
	if h == v {
		return true
	}
	if h == nil || v == nil {
		return false
	}
	return *h == *v
}

func CopyHashs(hs []Hash) []Hash {
	if hs == nil {
		return nil
	}
	r := make([]Hash, len(hs))
	if len(r) > 0 {
		copy(r, hs)
	}
	return r
}

func HashsEquals(hs1, hs2 []Hash) bool {
	if hs1 == nil && hs2 == nil {
		return true
	}
	if hs1 == nil || hs2 == nil {
		return false
	}
	if len(hs1) != len(hs2) {
		return false
	}
	for i := 0; i < len(hs1); i++ {
		if hs1[i] != hs2[i] {
			return false
		}
	}
	return true
}

func HashLess(a, b Hash) bool {
	return bytes.Compare(a[:], b[:]) < 0
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b Address, nonce uint64) Address {
	// buf := new(bytes.Buffer)
	// buf.Write(b[:])
	// rtl.ToBinaryBuffer(nonce, buf)
	// return BytesToAddress(h[12:])
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	h, _ := Hash256s(data)
	return BytesToAddress(h[12:])
}

func CreateAddress2(b Address, salt [32]byte, inithash []byte) Address {
	h, _ := Hash256s([]byte{0xff}, b.Bytes(), salt[:], inithash)
	return BytesToAddress(h[12:])
}

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

func BytesToAddressP(b []byte) *Address {
	a := BytesToAddress(b)
	return &a
}

func StringsToAddresses(strings []string) []Address {
	if strings == nil {
		return nil
	}
	ids := make([]Address, len(strings), len(strings))
	for i := 0; i < len(strings); i++ {
		ids[i] = BytesToAddress([]byte(strings[i]))
	}
	return ids
}

// BigToAddress returns Address with byte values of b.
// If b is larger than len(h), b will be cropped from the left.
func BigToAddress(b *big.Int) Address { return BytesToAddress(b.Bytes()) }

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address or not.
func IsHexAddress(s string) bool {
	if HasHexPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && IsHex(s)
}

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

func BytesToHashP(b []byte) *Hash {
	var h Hash
	h.SetBytes(b)
	return &h
}

// BigToHash sets byte representation of b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) Hash { return BytesToHash(FromHex(s)) }

type Seed [SeedLength]byte

var zeroSeed = Seed{}

// func NewSeed(b []byte) *Seed {
// 	var r Seed
// 	copy(r[:], b)
// 	return &r
// }

func BytesToSeed(b []byte) Seed {
	var s Seed
	s.SetBytes(b)
	return s
}

func BytesToSeedP(b []byte) *Seed {
	s := BytesToSeed(b)
	return &s
}

func (s *Seed) Generate() error {
	id := make([]byte, SeedLength)
	n, err := io.ReadFull(rand.Reader, id)
	if err != nil {
		return err
	}
	if n != SeedLength {
		return ErrInsufficientLength
	}
	copy(s[:], id)
	return nil
}

func (s *Seed) Byte() []byte {
	return s[:]
}

func (s *Seed) Slice() []byte {
	if s == nil {
		return nil
	}
	return s[:]
}

func (s *Seed) SetBytes(b []byte) *Seed {
	if len(b) > SeedLength {
		b = b[len(b)-SeedLength:]
	}

	copy(s[SeedLength-len(b):], b)
	return s
}

func (s *Seed) IsZero() bool {
	if s == nil {
		return false
	}
	return *s == zeroSeed
}

func (s *Seed) Equal(o *Seed) bool {
	if s == o {
		return true
	}
	if s == nil || o == nil {
		return false
	}
	return *s == *o
}

func (s *Seed) Equals(v interface{}) bool {
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return false
	}
	o, ok := v.(*Seed)
	if !ok {
		return false
	}
	if s == o {
		return true
	}
	if s != nil && o != nil && *s == *o {
		return true
	}
	return false
}

func (s *Seed) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%x", s[:5])
}

func (s *Seed) Clone() *Seed {
	if s == nil {
		return nil
	}
	return new(Seed).SetBytes(s.Byte())
}

func (s *Seed) Hash() Hash {
	if s == nil {
		return NilHash
	}
	h, _ := Hash256s(s[:])
	return BytesToHash(h)
}

// String to ElectionType, invalid string bool returns false
func StringToElectionType(name string) (ElectionType, bool) {
	t, exist := validChainElection[name]
	return t, exist
}

func (t ElectionType) IsValid() bool {
	switch t {
	case ETNone, ETVrf, ETManagedCommittee:
		return true
	default:
		return false
	}
}

func (t ElectionType) IsVrf() bool {
	return t == ETNone || t == ETVrf
}

func (t ElectionType) IsManaged() bool {
	return t == ETManagedCommittee
}

// Returns the name of an electiontype that is valid in the chain structure configuration
func (t ElectionType) Name() string {
	n, exist := validElectionName[t]
	if !exist {
		n = validElectionName[ETVrf]
	}
	return n
}

func (t ElectionType) String() string {
	switch t {
	case ETNone:
		return "None"
	case ETVrf:
		return "Vrf"
	// case ETFixedCommittee:
	// 	return "FixedCommittee"
	// case ETFixedSpectator:
	// 	return "FixedSpectator"
	case ETManagedCommittee:
		return "ManagedCommittee"
	default:
		return "Election-" + strconv.Itoa(int(t))
	}
}

func (t ElectionType) Exclusiveness() bool {
	e, exist := electionExclusiveness[t]
	if !exist {
		return false
	}
	return e
}

func (t ElectionType) RewardNeeded() bool {
	r, exist := electionRewardNeeded[t]
	if !exist {
		return false
	}
	return r
}
