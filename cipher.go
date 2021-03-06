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

	"github.com/ThinkiumGroup/go-cipher"
	"github.com/ThinkiumGroup/go-common/log"
)

var (
	RealCipher    cipher.Cipher        = cipher.NewCipher(cipher.SECP256K1SHA3)
	SystemPrivKey cipher.ECCPrivateKey // private key of current node

	ErrSignatureVerifyFailed = errors.New("signature verify failed")
)

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

// verify msg signature
func VerifyMsg(v interface{}, pub, sig []byte) bool {
	if sig == nil {
		return false
	}
	mh, err := HashObject(v)
	if err != nil {
		log.Errorf("verify msg %v", err)
		return false
	}
	if pub == nil {
		// pub = RealCipher.PubFromSignature(mh, sig)
		log.Error("missing public key")
		return false
	}
	if pub == nil {
		return false
	}
	return RealCipher.Verify(pub, mh, sig)
}

// verify msg hash signature
func VerifyHash(hash, pub, sig []byte) bool {
	if sig == nil {
		return false
	}
	if pub == nil {
		// pub = RealCipher.PubFromSignature(hash, sig)
		log.Error("missing public key")
		return false
	}
	if pub == nil {
		return false
	}
	return RealCipher.Verify(pub, hash, sig)
}

func HexToPrivKey(h string) (cipher.ECCPrivateKey, error) {
	bs, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return RealCipher.BytesToPriv(bs)
}
