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
	"encoding/hex"
	"errors"
	"hash"
	"sync"

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-common/rlp"
)

var (
	RealCipher    = cipher.NewCipher(cipher.SECP256K1SHA3)
	SystemPrivKey cipher.ECCPrivateKey // private key of current node

	ErrSignatureVerifyFailed = errors.New("signature verify failed")
)

func PubKeyCanRecover() bool {
	return RealCipher.Name() == cipher.SECP256K1SHA3
}

func PrivateToPublicSlice(priv []byte) ([]byte, error) {
	eccpriv, err := RealCipher.BytesToPriv(priv)
	if err != nil {
		return nil, err
	}
	return eccpriv.GetPublicKey().ToBytes(), nil
}

func PubToNodeID(pub []byte) (NodeID, error) {
	nidbs, err := RealCipher.PubToNodeIdBytes(pub)
	if err != nil {
		return NodeID{}, err
	}
	return BytesToNodeID(nidbs), nil
}

// sign msg
func SignMsg(msg interface{}) (pub, sig []byte, err error) {
	pub = SystemPrivKey.GetPublicKey().ToBytes()
	mh, err := HashObject(msg)
	if err != nil {
		return nil, nil, err
	}
	sig, err = RealCipher.Sign(RealCipher.PrivToBytes(SystemPrivKey), mh)
	return pub, sig, err
}

// sign msg
func SignHash(hash []byte) (pub, sig []byte, err error) {
	pub = SystemPrivKey.GetPublicKey().ToBytes()
	sig, err = RealCipher.Sign(RealCipher.PrivToBytes(SystemPrivKey), hash)
	return pub, sig, err
}

func VerifyMsgWithPub(v interface{}, pub, sig []byte) (bool, []byte) {
	if sig == nil {
		return false, pub
	}
	mh, err := HashObject(v)
	if err != nil {
		log.Errorf("verify msg %v", err)
		return false, pub
	}
	if pub == nil {
		if PubKeyCanRecover() {
			pub, err = RealCipher.RecoverPub(mh, sig)
			if err != nil || pub == nil {
				return false, nil
			}
		} else {
			return false, nil
		}
	}
	return RealCipher.Verify(pub, mh, sig), pub
}

// verify msg signature
func VerifyMsg(v interface{}, pub, sig []byte) bool {
	ok, _ := VerifyMsgWithPub(v, pub, sig)
	return ok
}

func VerifyHashWithPub(hash, pub, sig []byte) (bool, []byte) {
	if sig == nil || hash == nil {
		return false, nil
	}
	if pub == nil {
		if PubKeyCanRecover() {
			p, err := RealCipher.RecoverPub(hash[:], sig)
			if err != nil || p == nil {
				return false, nil
			}
			pub = p
		} else {
			return false, nil
		}
	}
	return RealCipher.Verify(pub, hash, sig), pub
}

// VerifyHash verify msg hash signature
func VerifyHash(hash, pub, sig []byte) bool {
	ok, _ := VerifyHashWithPub(hash, pub, sig)
	return ok
}

func HexToPrivKey(h string) (cipher.ECCPrivateKey, error) {
	bs, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return RealCipher.BytesToPriv(bs)
}

// hasherPool holds LegacyKeccak256 hashers for rlpHash.
var hasherPool = sync.Pool{
	New: func() interface{} { return RealCipher.Hasher() },
}

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// RlpHash encodes x and hashes the encoded bytes.
func RlpHash(x interface{}) (h Hash) {
	sha := hasherPool.Get().(KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}

// PrefixedRlpHash writes the prefix into the hasher before rlp-encoding x.
// It's used for typed transactions.
func PrefixedRlpHash(prefix byte, x interface{}) (h Hash) {
	sha := hasherPool.Get().(KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	sha.Write([]byte{prefix})
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}
