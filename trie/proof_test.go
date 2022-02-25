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

func TestNodeProof_Iterate(t *testing.T) {
	proofing := common.BytesToHash(common.RandomBytes(common.HashLength))

	childProofNode := NewNodeProof(
		1,
		NodeHeader{},
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(5),
	)
	_testingNodeProof(t, childProofNode, proofing)

	valueProofNode := NewNodeProof(
		ProofValue,
		NodeHeader{
			NT:           0x99,
			KeyString:    []byte("ab"),
			ChildrenFlag: [2]byte{0x23, 0x4f},
		},
		nil,
		_randomMerkleProofs(1),
	)
	_testingNodeProof(t, valueProofNode, proofing)

	merkleOnlyNode := NewMerkleOnlyProof(
		ProofMerkleOnly,
		_randomMerkleProofs(10),
	)
	_testingNodeProof(t, merkleOnlyNode, proofing)

	headerProofNode := NewHeaderPropertyProof(
		ProofHeaderDeltas,
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(6),
	)
	_testingNodeProof(t, headerProofNode, proofing)

	hdsProofNode := NewHdsSummaryProof(
		common.BytesToHashP(common.RandomBytes(common.HashLength)),
		_randomMerkleProofs(6),
	)
	_testingNodeProof(t, hdsProofNode, proofing)
}
