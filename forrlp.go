package common

import (
	"math/big"

	"github.com/ThinkiumGroup/go-common/math"
)

func BytesForRLP(bs []byte) []byte {
	if bs == nil {
		return []byte{}
	}
	return CopyBytes(bs)
}

func BigIntForRLP(i *big.Int) *big.Int {
	if i == nil {
		return new(big.Int)
	}
	return math.CopyBigInt(i)
}
