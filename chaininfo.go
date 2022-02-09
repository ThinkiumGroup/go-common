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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type (
	// Network entry:
	// only supports network discovery, if it is only BootNode, there is no need to establish a
	// TCP link (otherwise data forwarding is required, and the algorithm will fail in a structured
	// network)
	// BootNode must be a data node, and the data node may not be a BootNode, otherwise it cannot
	// be judged and punished. Therefore, bootnode will still establish a tcp link
	BootNode struct {
		NodeID         NodeID `yaml:"nodeID" json:"nodeID"`       // ID of Node
		IP             string `yaml:"ip" json:"ip"`               //
		BasicPort      uint16 `yaml:"bNetPort" json:"bNetPort"`   // port for basic net
		ConsensusPort0 uint16 `yaml:"cNetPort0" json:"cNetPort0"` // port for consensus net 0
		ConsensusPort1 uint16 `yaml:"cNetPort1" json:"cNetPort1"` // port for consensus net 1
		DataPort       uint16 `yaml:"dNetPort" json:"dNetPort"`   // The data network is only used when transferring data between shard chains, and it uses the DataPort of the parent chain
	}

	// data node for chain
	DataNode struct {
		NodeID     NodeID // ID of node
		IsGenesis  bool   // Whether it is a genesis data node, it is only a flag
		RpcAddress string // The RPC address and port of the data node (in order to resist attacks, the address of the cluster application can be used to proxy a group of full nodes)
	}

	// sorted by（IsGenesis, NodeID)
	DataNodes []DataNode

	ChainInfosShouldBe struct {
		ChainStruct
		ReportTo          ChainID      // Record the destination chain when this chain reports the Header (not necessarily the same as the parent chain, such as: child chain shards are reported to the main chain shard or main chain 0)
		Attributes        ChainAttrs   // Chain attributes (PoC/Reward/NoGas, etc.)
		LocalCurrencyID   CoinID       // ID of the local currency of this chain, 0 is the basic currency, indicating that the chain does not have a local currency
		LocalCurrencyName string       // If there is a local currency, it is the display name of the currency, otherwise it is ""
		AdminPubs         [][]byte     // Administrators' public key list
		GenesisCommIds    NodeIDs      // Members of the genesis committee (orderly, only the genesis chain has a genesis committee, and the first committees of other chains are elected through the creation process)
		BootNodes         []BootNode   // Entrance of the chain, no less than N (N=1)
		Election          ElectionType // The election type of chain consensus committee
		DataNodes         DataNodes    // Chain data node. There is no more genesis and non-genesis, but the number of data nodes should not be less than M (M=3). If there is no data node, it can be considered as a virtual chain
		Extra             string       // Extra information
	}
)

func (ds DataNodes) Len() int {
	return len(ds)
}

func (ds DataNodes) Swap(i, j int) {
	ds[i], ds[j] = ds[j], ds[i]
}

func (ds DataNodes) Less(i, j int) bool {
	if ds[i].IsGenesis == ds[j].IsGenesis {
		return bytes.Compare(ds[i].NodeID[:], ds[j].NodeID[:]) < 0
	}
	if ds[i].IsGenesis {
		return true
	}
	return false
}

type (
	ChainMode  byte
	CoinID     uint16      // ID of currency，TKM=0
	ChainID    uint32      // ID of chain
	ChainAttr  string      // Indicate the type, capacity, characteristics, etc. of the chain
	ChainAttrs []ChainAttr // Multiple Attributes that the chain may have

	ChainIDs []ChainID

	// TODO v1.5.0 The chain ID and the parent chain ID form a logical chain ID tree with chain
	//  0 as the root.
	//  1. main chain (chainid=0) as root of the tree，responsible for maintaining chain structure
	//     and generating global seed
	//  2. shards of main chain：There may be a second layer. When the number of sub chains reaches
	//     a certain level, the main chain can also be partitioned. The parentid of each main chain
	//     shard is the main chain 0. These main chain shards are mainly responsible for receiving,
	//     verifying and packaging the block hashs reported by each sub chain (including sub chain
	//     shards).
	//  3. sub chain：All the business chains which parentids are the main chain. If the sub chain
	//     is not partitioned, the chain is an entity chain, and it needs to report the block to
	//     the superior regularly (when the main chain is not partitioned: to main chain 0; when
	//     the main chain is partitioned: the calculated main chain shard according to the attribute
	//     setting of the shard). Because it is an entity chain, the transaction is performed on
	//     the chain.
	//  4. shards of sub chain：When there are too many sub chain accounts or too many transactions,
	//     the sub chain can be divided into two shards (each shard can continue to be divided, which
	//     means that the users on the old shard are divided into new shards, and the parentid of
	//     all shards is same with each other: sub chain ID). When a sub chain is partitioned, the
	//     sub chain becomes a virtual chain. The virtual chain does not need consensus. All the
	//     shards only need the dataport in the bootnode of the sub chain to build the data network.
	//     All transactions take place on the corresponding shard. The parentid of the sharding chain
	//     is the subchain ID. The shard regularly reports the block information to the superior (the
	//     main chain, which is same as the subchain).
	//
	// TODO v1.5.0 链ID及父链ID组成了一颗以0链为根的逻辑链ID树。
	//  1. 根为0号主链，负责维护链结构及全局Seed；
	//  2. 主链的分片：可能存在的第二层，当子链达到一定数量时主链也可以分片，每个主链分片的ParentID都是0号主链，
	//  这些主链分片主要负责接收、验证及打包各子链（包括子链的分片）上报的块头。
	//  3. 子链：所有业务的链，ParentID为0号主链。如果子链没有分片，则此链为实体链，需要定期向上级（主链无分片
	//  时：向0号主链，主链有分片时：根据主链分片的属性设定计算得到的主链分片）上报块头。因为是实体链，链上完成
	//  相应交易。
	//  4. 子链的分片：当子链账户过多或交易过大时，子链可以分裂为2个分片（每个分片还可以继续分裂，分片分裂仅代表
	//  其用户段被分割到新的分片中，所有分片的ParentID都是相同的：子链ID）。当一个子链有了分片，该子链就成为虚拟
	//  链，该虚拟链无需共识，所有分片仅需要该子链BootNode中的DataPort来组建数据网络。所有交易都发生在对应的分
	//  片上。分片链的ParentID为子链ID，定期向上级(主链)汇报块头信息（同子链）。
	//
	//  Generation of shards (sketch): one existing chain A
	//  1. Create two new chains, A1 and A2, one shard account prefix Bit:0, one prefix Bit:1
	//  2. Stop chain A and make data unchangeable
	//  3. Copy the data of chain A to A1 and A2 (more simply, divide half of the data nodes of
	//     chain A to A1 and the other half to A2, but how to ensure that the operation of chain
	//     A is not affected? )
	//  4. Start elections for the committees of A1 and A2
	//  5. After the two chain elections are all successful, start A1 / A2
	//
	//  分片的生成(初步想法)：已存在的链A
	//  1. 新建2条链A1，A2，一个分片账户前缀Bit:0，一个账户前缀Bit:1
	//  2. 停A链，锁定数据
	//  3. 将链A数据复制给A1, A2(更简单一些，将链A的数据节点分一半给A1，另一半给A2，但是如何保证链A运行不受影响？)
	//  4. 选举A1,A2两条链的委员会
	//  5. 两条链选举全部成功后，启动A1/A2
	//
	ChainStruct struct {
		ID       ChainID   `json:"id"`
		ParentID ChainID   `json:"parentid"`
		Mode     ChainMode `json:"mode"`
	}

	// TODO: v1.3.6，Currently BootNode and DataNode can be set separately, but DataRpcPort should
	//  be in DataNode instead of BootNode.  Two new attributes can be added: GenesisDataInfos and
	//  DataInfos, which are used to save the ID/IP and RPC port number of the data node. In order
	//  to be compatible with the old version, when the new field is empty, the hash is not
	//  calculated, and the chain structure can only be modified through the system contract. Only
	//  then will all the values of GenesisDatas/Datas be filled with RPC information and put into
	//  GenesisDataInfos/DataInfos.
	// TODO: v1.5.0，The DataPort should also be in the DataNode settings; at the same time, the
	//  sharding information needs to be added, because the current sharding prefix is determined
	//  according to the number of shards under the same parent chain, but our chain can only do
	//  one-to-two splits. That is to say, the prefixes of the shards under the same parent chain
	//  are likely to be inconsistent in length. For example, there are 5 shards under chain 1 and
	//  their prefixes are: 00, 01, 100, 101, 11, where 100 and 101 are split by 10. Then, this
	//  information can only be recorded in the chain structure, and it has an effect when generating
	//  ShardInfo.
	//
	// TODO: v1.3.6，目前BootNode和DataNode可以分开设置，但DataRpcPort应该在DataNode中，而不是BootNode。
	//  可以新增两个属性：GenesisDataInfos和DataInfos，用来保存数据节点的ID/IP以及RPC端口号，为了兼容旧版本，
	//  当新增字段为空时不计算Hash，并只有在通过系统合约修改链结构时才会将所有GenesisDatas/Datas的值补上RPC信
	//  息放到GenesisDataInfos/DataInfos中。
	// TODO: v1.5.0，DataPort也应该在DataNode的设置中；同时需要增加分片信息，因为目前的分片前缀是根据在同一
	//  父链下分片的个数确定的，但我们的链只能做一分二的动作，也就是说同一父链下的分片前缀很有可能长度不一致，如1链
	//  下有5个分片他们的前缀分别为：00，01，100，101，11，其中100和101是由10分裂而来的，这个信息只能记录在链结
	//  构中，在生成ShardInfo时产生效果。
	ChainInfos struct {
		ChainStruct    `json:"chain"`
		SecondCoinId   CoinID       // ID of the local currency of this chain, 0 is the basic currency, indicating that the chain does not have a local currency
		SecondCoinName string       // If there is a local currency, it is the display name of the currency, otherwise it is ""
		HaveSecondCoin bool         // not in use, but should be !SecondCoinId.IsSovereign()
		AdminPubs      [][]byte     // Administrators' public key list
		GenesisCommIds NodeIDs      // Members of the genesis committee (orderly, only the genesis chain has a genesis committee, and the first committees of other chains are elected through the creation process)
		BootNodes      []Dataserver // BootNodes information
		Election       ElectionType // The election type of chain consensus committee
		ChainVersion   string       // not in use
		Syncblock      bool         // not in use
		GenesisDatas   NodeIDs      // Genesis data nodes
		Datas          NodeIDs      `json:"datanodes"` // Current data nodes, including all the genesis data nodes
		Attributes     ChainAttrs   // chain attributes
		Version        uint16       // version, 1: add Version and Auditors
		Auditors       NodeIDs      // auditor ids (Auditors+GenesisDatas+Datas=AllAuditors)
	}

	chainInfosV0 struct {
		ChainStruct
		SecondCoinId   CoinID
		SecondCoinName string
		HaveSecondCoin bool
		AdminPubs      [][]byte
		GenesisCommIds NodeIDs
		BootNodes      []Dataserver
		Election       ElectionType
		ChainVersion   string
		Syncblock      bool
		GenesisDatas   NodeIDs
		Datas          NodeIDs
		Attributes     ChainAttrs
	}

	NetType byte

	ShardInfo interface {
		GetMaskBits() uint           // How many digits are used to calculate the shard location
		LocalID() ChainID            // LocalID returns current chain/shard chainID
		AllIDs() []ChainID           // AllOthers returns all chainID besides local chainID
		ShardTo(interface{}) ChainID // ShardTo returns a shard chainID according to the parameter.
		Pos(id ChainID) int          // The index in the shard group of the incoming chainid
		Clone() ShardInfo
	}
)

// return true if it is basic currency, false if it is other currencies (the local currency of each chain)
func (c CoinID) IsSovereign() bool {
	return c == 0
}

const (
	AttrPoC    ChainAttr = "POC"    // Support algorithm of Proof of Capacity
	AttrReward ChainAttr = "REWARD" // Reward chain, there can only be one
	AttrNoGas  ChainAttr = "NOGAS"  // This chain and descendant chain do not charge gas fee, can be covered by descendant chain attribute
)

// Attribute full name uppercase string -> attribute object
var validChainAttrs = map[string]ChainAttr{
	string(AttrPoC):    AttrPoC,
	string(AttrReward): AttrReward,
	string(AttrNoGas):  AttrNoGas,
}

func (a ChainAttr) IsValid() bool {
	_, exist := validChainAttrs[string(a)]
	return exist
}

func (a ChainAttrs) Clone() ChainAttrs {
	if a == nil {
		return nil
	}
	r := make(ChainAttrs, len(a))
	copy(r, a)
	return r
}

func (a ChainAttrs) Len() int {
	return len(a)
}

func (a ChainAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a ChainAttrs) Less(i, j int) bool {
	return strings.Compare(string(a[i]), string(a[j])) < 0
}

func (a ChainAttrs) Contains(attr ChainAttr) bool {
	for i := 0; i < len(a); i++ {
		if a[i] == attr {
			return true
		}
	}
	return false
}

// Because the length is not large, de-duplication runs in rotation
func (a *ChainAttrs) Add(attrs ...ChainAttr) error {
	if a == nil {
		return ErrNil
	}
	for i := 0; i < len(attrs); i++ {
		// if !IsValidChainAttr(attrs[i]) {
		if !attrs[i].IsValid() {
			return ErrIllegalParams
		}
	}
	for i := 0; i < len(attrs); i++ {
		if len(*a) == 0 {
			*a = append(*a, attrs[i])
			continue
		}
		if !a.Contains(attrs[i]) {
			*a = append(*a, attrs[i])
		}
		sort.Sort(*a)
	}
	return nil
}

func (a *ChainAttrs) AddByName(names ...string) error {
	attrs := make([]ChainAttr, len(names))
	for i := 0; i < len(names); i++ {
		attrs[i] = ChainAttr(strings.ToUpper(names[i]))
	}
	return a.Add(attrs...)
}

func (a ChainAttrs) ToStringSlice() []string {
	if a == nil {
		return nil
	}
	out := make([]string, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = string(a[i])
	}
	return out
}

func (a ChainAttrs) ToMap() map[ChainAttr]struct{} {
	if a == nil {
		return nil
	}
	m := make(map[ChainAttr]struct{}, len(a))
	for _, attr := range a {
		m[attr] = struct{}{}
	}
	return m
}

func (a ChainAttrs) FromMap(m map[ChainAttr]struct{}) ChainAttrs {
	if len(m) == 0 {
		return nil
	}
	var ret ChainAttrs
	if cap(a) >= len(m) {
		ret = a[:0]
	} else {
		ret = make(ChainAttrs, 0, len(m))
	}
	for attr := range m {
		ret = append(ret, attr)
	}
	if len(ret) > 1 {
		sort.Sort(ret)
	}
	return ret
}

type NetInfo struct {
	NodeID  *NodeID               // ID of node
	addrMap map[NetType]*Endpoint // Net type -> address
}

func NewNetInfo(id *NodeID, basicAddr, consensusAddr1 string, consensusAddr2 string, dataPort1, dataPort2 string) NetInfo {
	m := make(map[NetType]*Endpoint)
	if len(basicAddr) > 0 {
		m[BasicNet] = &Endpoint{
			NetType: "tcp",
			Address: basicAddr,
		}
	}
	if len(consensusAddr1) > 0 {
		m[ConsensusNet1] = &Endpoint{
			NetType: "tcp",
			Address: consensusAddr1,
		}
	}

	if len(consensusAddr2) > 0 {
		m[ConsensusNet2] = &Endpoint{
			NetType: "tcp",
			Address: consensusAddr2,
		}
	}
	if len(dataPort1) > 0 {
		m[RootDataNet] = &Endpoint{
			NetType: "tcp",
			Address: dataPort1,
		}
	}
	if len(dataPort2) > 0 {
		m[BranchDataNet] = &Endpoint{
			NetType: "tcp",
			Address: dataPort2,
		}
	}
	return NetInfo{
		NodeID:  id,
		addrMap: m,
	}
}

func (n NetInfo) GetAddr(ntype NetType) *Endpoint {
	p, ok := n.addrMap[ntype]
	if !ok {
		return nil
	}
	return p
}

func (n NetInfo) AddAddr(ntype NetType, addr *Endpoint) {
	n.addrMap[ntype] = addr
}

func ChooseConNetByEpoch(num EpochNum) NetType {
	if num%2 == 0 {
		return ConsensusNet1
	}
	return ConsensusNet2
}

var (
	chainModeNames = map[ChainMode]string{
		Root:        "Root",
		Branch:      "Branch",
		Shard:       "Shard",
		UnknownMode: "UnknownMode",
	}

	netTypeNames = map[NetType]string{
		BasicNet:      "BasicNet",
		ConsensusNet1: "CNet1",
		ConsensusNet2: "CNet2",
		RootDataNet:   "RootDataNet",
		BranchDataNet: "BranchDataNet",
		// UnknownNet:    "UnknownNet",
	}

	MainChainStruct = ChainStruct{
		ID:       MainChainID,
		ParentID: NilChainID,
		Mode:     Root,
	}

	// TypeOfChainStructPtr   = reflect.TypeOf((*ChainStruct)(nil))
	TypeOfChainInfosPtr = reflect.TypeOf((*ChainInfos)(nil))
)

func (m ChainMode) String() string {
	s, ok := chainModeNames[m]
	if ok {
		return s
	}
	return "ChainMode-" + strconv.Itoa(int(m))
}

func (id ChainID) IsReserved() bool {
	return uint32(id) < ReservedMaxChainID
}

func (id ChainID) IsNil() bool {
	return uint32(id) == ReservedMaxChainID
}

func (id ChainID) IsMain() bool {
	return id == MainChainID
}

func (id ChainID) IsSub() bool {
	return uint32(id) != ReservedMaxChainID && uint32(id) > 0
}

func (id ChainID) IsUserDefined() bool {
	return uint32(id) > ReservedMaxChainID
}

func (id ChainID) Bytes() []byte {
	buf := make([]byte, ChainBytesLength)
	binary.BigEndian.PutUint32(buf, uint32(id))
	return buf
}

func (id ChainID) Compare(o ChainID) int {
	if id == o {
		return 0
	}
	if id.IsNil() {
		return -1
	}
	if o.IsNil() {
		return 1
	}
	if id < o {
		return -1
	} else {
		return 1
	}
}

func BytesToChainID(bs []byte) ChainID {
	buf := bs
	if len(bs) > ChainBytesLength {
		buf = bs[len(bs)-ChainBytesLength:]
	} else if len(bs) < 4 {
		buf = make([]byte, ChainBytesLength)
		copy(buf[ChainBytesLength-len(bs):], bs)
	}
	return ChainID(binary.BigEndian.Uint32(buf))
}

func (id ChainID) Formalize() []byte {
	return id.Bytes()
}

//
// func (id *ChainID) Serialization(w io.Writer) error {
// 	_, err := w.Write(id.Bytes())
// 	return err
// }
//
// func (id *ChainID) Deserialization(r io.Reader) error {
// 	buf := make([]byte, ChainBytesLength)
// 	_, err := io.ReadFull(r, buf)
// 	if err != nil {
// 		return err
// 	}
// 	*id = ChainID(binary.BigEndian.Uint32(buf))
// 	return nil
// }

func (id ChainID) String() string {
	if id.IsNil() {
		return "<nil>"
	}
	return strconv.Itoa(int(id))
}

func (id ChainID) HashValue() ([]byte, error) {
	return Hash256s(id.Bytes())
}

func (ids ChainIDs) Len() int {
	return len(ids)
}

func (ids ChainIDs) Swap(i, j int) {
	ids[i], ids[j] = ids[j], ids[i]
}

func (ids ChainIDs) Less(i, j int) bool {
	return uint32(ids[i]) < uint32(ids[j])
}

func (ids ChainIDs) Clone() ChainIDs {
	if ids == nil {
		return nil
	}
	ret := make(ChainIDs, len(ids))
	if len(ids) > 0 {
		copy(ret, ids)
	}
	return ret
}

func NewChainStruct(id, parentId ChainID) (cs *ChainStruct, err error) {
	if id.IsNil() {
		return nil, errors.New("illegal chain id")
	}
	if parentId.IsNil() {
		if id.IsMain() {
			return &ChainStruct{ID: id, ParentID: parentId, Mode: Root}, nil
		}
		if StandAlone {
			return &ChainStruct{ID: id, ParentID: parentId, Mode: Branch}, nil
		}
		return nil, errors.New("only main chain or single chain's parent can be nil")
	}
	cs = &ChainStruct{ID: id, ParentID: parentId}
	if parentId.IsMain() {
		cs.Mode = Branch
		return
	}
	cs.Mode = Shard
	return
}

func (s ChainStruct) Validate() error {
	switch s.Mode {
	case Root:
		if !s.ID.IsMain() || !s.ParentID.IsNil() {
			return errors.New("root mode must be main chain")
		}
	case Branch, Shard:
		if s.ID.IsMain() || s.ParentID.IsNil() {
			return errors.New("only root mode could be main chain")
		}
		if s.Mode == Branch && !s.ParentID.IsMain() {
			return errors.New("branch's parent must be main chain")
		}
		if s.Mode == Shard && s.ParentID.IsMain() {
			return errors.New("shard's parent must not be main chain")
		}
	default:
		return errors.New("illegal mode")
	}
	return nil
}

func (s ChainStruct) Clone() ChainStruct {
	o := s
	return o
}

func (s ChainStruct) String() string {
	return fmt.Sprintf("{ChainID:%d ParentID:%d Mode:%s}", s.ID, s.ParentID, s.Mode)
}

func (c *ChainInfos) Clone() *ChainInfos {
	if c == nil {
		return nil
	}
	var bns []Dataserver
	if c.BootNodes != nil {
		bns = make([]Dataserver, len(c.BootNodes))
		for i := 0; i < len(c.BootNodes); i++ {
			bns[i] = c.BootNodes[i]
		}
	}
	r := &ChainInfos{
		ChainStruct:    c.ChainStruct,
		SecondCoinId:   c.SecondCoinId,
		SecondCoinName: c.SecondCoinName,
		HaveSecondCoin: c.HaveSecondCoin,
		AdminPubs:      CopyBytesSlice(c.AdminPubs),
		GenesisCommIds: c.GenesisCommIds.Clone(),
		BootNodes:      bns,
		Election:       c.Election,
		ChainVersion:   c.ChainVersion,
		Syncblock:      c.Syncblock,
		GenesisDatas:   c.GenesisDatas.Clone(),
		Datas:          c.Datas.Clone(),
		Attributes:     c.Attributes.Clone(),
	}
	return r
}

// The target chain which the current chain reports to, It's not necessary consistent with ParentID
func (c *ChainInfos) ReportTo() ChainID {
	if c == nil || c.ParentID.IsNil() {
		return NilChainID
	}
	return MainChainID
}

func (c *ChainInfos) HasAttribute(attr ChainAttr) bool {
	return c.Attributes.Contains(attr)
}

func (c *ChainInfos) IsMainChain() bool {
	return c.ID.IsMain()
}

func (c *ChainInfos) IsPocChain() bool {
	return c.Attributes.Contains(AttrPoC)
}

func (c *ChainInfos) IsRewardChain() bool {
	return c.Attributes.Contains(AttrReward)
}

func (c *ChainInfos) IsGenesisDataNode(nid NodeID) bool {
	mp := c.GenesisDatas.ToMap()
	_, ok := mp[nid]
	return ok
}

func (c *ChainInfos) AddrIsAdmin(addr Address) bool {
	if c == nil {
		return false
	}
	for _, adminPub := range c.AdminPubs {
		adminaddr, err := AddressFromPubSlice(adminPub)
		if err != nil {
			continue
		}
		if adminaddr == addr {
			return true
		}
	}
	return false
}

func (c *ChainInfos) PubIsAdmin(pub []byte) bool {
	if c == nil {
		return false
	}
	for _, adminPub := range c.AdminPubs {
		if len(adminPub) == 0 {
			continue
		}
		if bytes.Equal(adminPub, pub) {
			return true
		}
	}
	return false
}

func (c *ChainInfos) Key() []byte {
	return c.ID.Formalize()
}

func (c *ChainInfos) Index(nid NodeID) int {
	if c == nil {
		return -1
	}
	for idx, nodeId := range c.Datas {
		if bytes.Compare(nid[:], nodeId[:]) == 0 {
			return idx
		}
	}
	return -1
}

func (c *ChainInfos) AddBootNode(bootNode Dataserver) bool {
	if len(c.BootNodes) == 0 {
		c.BootNodes = append(c.BootNodes, bootNode)
		return true
	}

	i := sort.Search(len(c.BootNodes), func(i int) bool {
		return c.BootNodes[i].NodeIDString >= bootNode.NodeIDString
	})
	if i < len(c.BootNodes) && c.BootNodes[i].NodeIDString == bootNode.NodeIDString {
		return false
	}
	c.BootNodes = append(c.BootNodes, bootNode)
	sort.Slice(c.BootNodes, func(i, j int) bool {
		return c.BootNodes[i].NodeIDString < c.BootNodes[j].NodeIDString
	})
	return true
}

func (c *ChainInfos) RemoveBootNode(node NodeID) bool {
	if len(c.BootNodes) == 0 {
		return true
	}
	// check and remove boot server
	i := sort.Search(len(c.BootNodes), func(i int) bool {
		s, _ := hex.DecodeString(c.BootNodes[i].NodeIDString)
		return bytes.Compare(s[:], node[:]) >= 0
	})

	if i < len(c.BootNodes) {
		s, _ := hex.DecodeString(c.BootNodes[i].NodeIDString)
		if bytes.Equal(s[:], node[:]) {
			bdatas := make([]Dataserver, len(c.BootNodes)-1)
			copy(bdatas, c.BootNodes[:i])
			copy(bdatas[i:], c.BootNodes[i+1:])
			c.BootNodes = bdatas
			return true
		}
	}
	return false
}

func (c *ChainInfos) AddDataNode(node NodeID) bool {
	if len(c.Datas) == 0 {
		c.Datas = append(c.Datas, node)
		return true
	}
	k := sort.Search(len(c.Datas), func(i int) bool {
		return bytes.Compare(c.Datas[i][:], node[:]) >= 0
	})

	if k < len(c.Datas) && bytes.Equal(c.Datas[k][:], node[:]) {
		return false
	}
	c.Datas = append(c.Datas, node)
	sort.Sort(c.Datas)
	return true
}

func (c *ChainInfos) RemoveDataNode(node NodeID) bool {
	if len(c.Datas) == 0 {
		return true
	}
	k := sort.Search(len(c.Datas), func(i int) bool {
		return bytes.Compare(c.Datas[i][:], node[:]) >= 0
	})
	if k < len(c.Datas) && bytes.Equal(c.Datas[k][:], node[:]) {
		ndatas := make(NodeIDs, len(c.Datas)-1)
		copy(ndatas, c.Datas[:k])
		copy(ndatas[k:], c.Datas[k+1:])
		c.Datas = ndatas
		return true
	}

	return false
}

func (c *ChainInfos) GetDataNodes() []NodeID {
	return []NodeID(c.Datas)
}

func (c *ChainInfos) GetAuditorMap() map[NodeID]struct{} {
	if c == nil {
		return nil
	}
	dedup := make(map[NodeID]struct{})
	for _, nid := range c.GenesisDatas {
		dedup[nid] = struct{}{}
	}
	for _, nid := range c.Datas {
		dedup[nid] = struct{}{}
	}
	for _, nid := range c.Auditors {
		dedup[nid] = struct{}{}
	}
	return dedup
}

func (c *ChainInfos) GetAuditorIds() NodeIDs {
	dedup := c.GetAuditorMap()
	var nids NodeIDs
	for nid := range dedup {
		nids = append(nids, nid)
	}
	if len(nids) > 1 {
		sort.Sort(nids)
	}
	return nids
}

func (c *ChainInfos) Sort() {
	if c == nil {
		return
	}
	if len(c.AdminPubs) > 1 {
		sort.Slice(c.AdminPubs, func(i, j int) bool {
			return bytes.Compare(c.AdminPubs[i], c.AdminPubs[j]) < 0
		})
	}
	// Because the committee is in order, c.GenesisCommIds is not sorted
	if len(c.BootNodes) > 1 {
		sort.Slice(c.BootNodes, func(i, j int) bool {
			return c.BootNodes[i].Compare(c.BootNodes[j]) < 0
		})
	}
	if len(c.GenesisDatas) > 1 {
		sort.Sort(c.GenesisDatas)
	}
	if len(c.Datas) > 1 {
		sort.Sort(c.Datas)
	}
	if len(c.Attributes) > 1 {
		sort.Sort(c.Attributes)
	}
	if len(c.Auditors) > 1 {
		sort.Sort(c.Auditors)
	}
}

func (c *ChainInfos) String() string {
	if c == nil {
		return "ChainInfo<nil>"
	}
	return fmt.Sprintf("ChainInfo{%s, Coin(%d-%s), Elect:%s, Attrs:%s, Datas:%s, Admins:%d}",
		c.ChainStruct, c.SecondCoinId, c.SecondCoinName, c.Election, c.Attributes, c.Datas, len(c.AdminPubs))
}

func (c *ChainInfos) HasDataNode(nid NodeID) bool {
	if len(c.Datas) == 0 {
		return false
	}
	i := sort.Search(len(c.Datas), func(i int) bool {
		return bytes.Compare(c.Datas[i][:], nid[:]) >= 0
	})
	if i < len(c.Datas) && bytes.Compare(c.Datas[i][:], nid[:]) == 0 {
		return true
	}
	return false
}

func (c *ChainInfos) HashValue() ([]byte, error) {
	if c != nil {
		return EncodeAndHash(c)
	}
	switch c.Version {
	case 0:
		old := &chainInfosV0{
			ChainStruct:    c.ChainStruct,
			SecondCoinId:   c.SecondCoinId,
			SecondCoinName: c.SecondCoinName,
			HaveSecondCoin: c.HaveSecondCoin,
			AdminPubs:      c.AdminPubs,
			GenesisCommIds: c.GenesisCommIds,
			BootNodes:      c.BootNodes,
			Election:       c.Election,
			ChainVersion:   c.ChainVersion,
			Syncblock:      c.Syncblock,
			GenesisDatas:   c.GenesisDatas,
			Datas:          c.Datas,
			Attributes:     c.Attributes,
		}
		return EncodeAndHash(old)
	default:
		return EncodeAndHash(c)
	}
}

func (n NetType) String() string {
	s, ok := netTypeNames[n]
	if ok {
		return s
	}
	return "NetType-" + strconv.Itoa(int(n))
}

type Dataserver struct {
	ChainID        uint32 `yaml:"chainID" 		json:"chainID"`
	NodeIDString   string `yaml:"nodeID" 		json:"nodeID"`
	IP             string `yaml:"ip" 			json:"ip"`
	BasicPort      uint16 `yaml:"bNetPort" 		json:"bNetPort"`
	ConsensusPort0 uint16 `yaml:"cNetPort0" 	json:"cNetPort0"`
	ConsensusPort1 uint16 `yaml:"cNetPort1" 	json:"cNetPort1"`
	DataPort0      uint16 `yaml:"dNetPort0" 	json:"dNetPort0"`
	DataPort1      uint16 `yaml:"dNetPort1" 	json:"dNetPort1"`
	DataRpcPort    uint16 `yaml:"dataRpcPort" 	json:"dataRpcPort"`
}

func (d *Dataserver) Clone() *Dataserver {
	r := *d
	return &r
}

func (d Dataserver) String() string {
	return fmt.Sprintf(""+
		"Dataserver{ChainID:%d NIDStr:%s IP:%s Basic:%d CPort0:%d CPort1:%d DPort0:%d DPort1:%d RpcPort:%d}",
		d.ChainID, d.NodeIDString, d.IP, d.BasicPort, d.ConsensusPort0, d.ConsensusPort1, d.DataPort0,
		d.DataPort1, d.DataRpcPort)
}

func (d *Dataserver) HashValue() ([]byte, error) {
	// hasher := GetHash256()
	hasher := RealCipher.Hasher()
	if _, err := d.hashSerialize(hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// TODO: Serialization needs to increase the seperator between properties, otherwise there will
//  be the same serialization of different data, but because the modification will cause data
//  incompatibility, it needs to be modified during the overall data migration
func (d *Dataserver) hashSerialize(w io.Writer) (int, error) {
	str := []string{
		strconv.Itoa(int(d.ChainID)),
		d.NodeIDString, d.IP,
		strconv.Itoa(int(d.BasicPort)),
		strconv.Itoa(int(d.ConsensusPort0)),
		strconv.Itoa(int(d.ConsensusPort1)),
		strconv.Itoa(int(d.DataPort0)),
		strconv.Itoa(int(d.DataPort1)),
		strconv.Itoa(int(d.DataRpcPort)),
	}
	p := strings.Join(str, "")
	return w.Write([]byte(p))
}

func (d Dataserver) Compare(o Dataserver) int {
	if d == o {
		return 0
	}
	switch {
	case d.ChainID == o.ChainID:
		return bytes.Compare([]byte(d.NodeIDString), []byte(o.NodeIDString))
	case d.ChainID < o.ChainID:
		return -1
	default:
		return 1
	}
}

func (d Dataserver) GetNodeID() (*NodeID, error) {
	return ParseNodeID(d.NodeIDString)
}

func (d *Dataserver) GetRpcAddr() string {
	return d.IP + ":" + strconv.FormatUint(uint64(d.DataRpcPort), 10)
}

func (d Dataserver) Validation() error {
	if len(d.NodeIDString) != NodeIDBytes*2 || len(d.IP) == 0 {
		return errors.New("illegal nodeId or ip")
	}
	if d.BasicPort == 0 || d.ConsensusPort0 == 0 || d.ConsensusPort1 == 0 {
		return errors.New("illegal basic/consensus ports")
	}
	return nil
}
