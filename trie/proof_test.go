package trie

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/ThinkiumGroup/go-common"
)

func _randomMerkleProofs(length int) *common.MerkleProofs {
	mp := common.NewMerkleProofs()
	for i := 0; i < length; i++ {
		h := common.BytesToHash(common.RandomBytes(common.HashLength))
		r := rand.Intn(100)
		b := true
		if r >= 50 {
			b = false
		}
		mp.Append(h, b)
	}
	return mp
}

func _testingNodeProof(t *testing.T, np *NodeProof, proofing common.Hash) {
	h1, err := np.Proof(proofing)
	if err != nil {
		t.Fatalf("NodeProof.Proof failed: %v", err)
	}
	h2 := proofing[:]
	if err := np.Iterate(func(val []byte, order bool) error {
		var errr error
		h2, errr = common.HashPairOrder(order, val, h2)
		return errr
	}); err != nil {
		t.Fatalf("NodeProof.Iterate failed: %v", err)
	}
	if !bytes.Equal(h1, h2) {
		t.Fatalf("NodeProof.Proof=%x but NodeProof.Iterate=%x", h1, h2)
	}
	t.Logf("%s proof and iterate check: %x", np, h2)
}

func _randomValueProof() *NodeProof {
	return NewNodeProof(
		ProofValue,
		NodeHeader{
			NT:           NodeType(rand.Intn(256)),
			KeyString:    []byte("abcdef123"),
			ChildrenFlag: [2]byte{byte(rand.Intn(256)), byte(rand.Intn(256))},
		},
		nil,
		_randomMerkleProofs(1),
	)
}

func _randomMerkleOnly() *NodeProof {
	return NewMerkleOnlyProof(ProofMerkleOnly, _randomMerkleProofs(10))
}

func _randomHeaderDeltas() *NodeProof {
	return NewHeaderPropertyProof(
		ProofHeaderDeltas,
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(6),
	)
}

func _randomHdsSummaryProof() *NodeProof {
	return NewHdsSummaryProof(
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(6),
	)
}

func TestNodeProof_Iterate(t *testing.T) {
	proofing := common.BytesToHash(common.RandomBytes(common.HashLength))

	childProofNode := NewNodeProof(
		1,
		NodeHeader{},
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(5),
	)
	_testingNodeProof(t, childProofNode, proofing)

	valueProofNode := _randomValueProof()
	_testingNodeProof(t, valueProofNode, proofing)

	merkleOnlyNode := _randomMerkleOnly()
	_testingNodeProof(t, merkleOnlyNode, proofing)

	headerProofNode := _randomHeaderDeltas()
	_testingNodeProof(t, headerProofNode, proofing)

	hdsProofNode := _randomHdsSummaryProof()
	_testingNodeProof(t, hdsProofNode, proofing)
}

func _testingProofChain(t *testing.T, pc ProofChain, toBeProof []byte) {
	p1, err := pc.Proof(common.BytesToHash(toBeProof))
	if err != nil {
		t.Fatalf("proof failed: %v", err)
	}

	p2 := common.CopyBytes(toBeProof)
	callback := func(val []byte, order bool) error {
		var errr error
		if p2, errr = common.HashPairOrder(order, val, p2); errr != nil {
			return errr
		}
		return nil
	}
	if err := pc.Iterate(callback); err != nil {
		t.Fatalf("iterate failed: %v", err)
	}

	if bytes.Equal(p1, p2) {
		t.Logf("%x -> %s proofed: %x", toBeProof, pc, p1)
	} else {
		t.Fatalf("%x -> %s failed: Proof:%x Iterate:%x", toBeProof, pc, p1, p2)
	}

	mp, err := pc.ToMerkles()
	if err != nil {
		t.Fatalf("%s ToMerkles failed: %v", pc, err)
	}
	t.Logf("%s ToMerkles %s", pc, mp)
	p3, err := mp.Proof(common.BytesToHash(toBeProof))
	if err != nil {
		t.Fatalf("merkle proofs proof failed: %v", err)
	}
	if bytes.Equal(p1, p3) {
		t.Logf("%x -> %s proofed: %x", toBeProof, mp, p3)
	} else {
		t.Fatalf("%x -> %s failed: %x", toBeProof, mp, p3)
	}
}

func TestProofChain_Iterate(t *testing.T) {
	var pc ProofChain

	pc = append(pc, _randomValueProof(), _randomMerkleOnly(), _randomMerkleOnly(), _randomHdsSummaryProof())
	h := common.RandomBytes(common.HashLength)
	_testingProofChain(t, pc, h)

	pc[len(pc)-1] = _randomHeaderDeltas()
	_testingProofChain(t, pc, h)
}
