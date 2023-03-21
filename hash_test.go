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
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"testing"

	"github.com/stephenfire/go-rtl"
)

func _testMerkleHashCompleted(length int) error {
	randomHashs := make([][]byte, length)
	for i := 0; i < length; i++ {
		randomHashs[i] = RandomBytes(HashLength)
	}
	h1, err := MerkleHashCompleteOld(randomHashs, -1, nil)
	if err != nil {
		return err
	}
	h2, err := MerkleHashComplete(randomHashs, -1, nil)
	if err != nil {
		return err
	}
	if !bytes.Equal(h1, h2) {
		return errors.New("hash not match")
	}
	for i := 0; i < length; i++ {
		p1 := NewMerkleProofs()
		p2 := NewMerkleProofs()
		_, _ = MerkleHashCompleteOld(randomHashs, i, p1)
		_, _ = MerkleHashComplete(randomHashs, i, p2)
		if !p1.Equal(p2) {
			return fmt.Errorf("proof of index:%d not match", i)
		}
	}
	return nil
}

func TestMerkleHashCompleted(t *testing.T) {
	l := 100
	for i := 1; i < l; i++ {
		if err := _testMerkleHashCompleted(i); err != nil {
			t.Fatalf("failed at i=%d: %v", i, err)
		} else {
			t.Logf("i=%d check", i)
		}
	}
}

func TestEncodeHash(t *testing.T) {
	i := 10
	EncodeHash(i)
}

func TestMerkleHash(t *testing.T) {
	l := 8
	hashList := make([][]byte, l)
	for i := 0; i < len(hashList); i++ {
		hashList[i] = RandomBytes(32)
	}

	t.Logf("%x", hashList)

	// p1 := make(ProofHash, 0)
	// root1, err := MerkleHash(hashList, l/2, &p1)
	p1 := NewMerkleProofs()
	root1, err := MerkleHashComplete(hashList, l/2, p1)
	if err != nil {
		t.Errorf("MerkleHash error: %v", err)
		return
	}
	t.Logf("MerkleHash: root: %x, proof: %s", root1, p1)

	p2 := NewMerkleProofs()
	root2, err := MerkleHashComplete(hashList, l/2, p2)
	if err != nil {
		t.Errorf("MerkleHashComplete error: %v", err)
		return
	}
	t.Logf("MerkleHashComplete: root: %x, proof: %s", root2, p2)

	if bytes.Equal(root1, root2) {
		t.Logf("Merkles' same")
	} else {
		t.Errorf("Merkles' not same")
	}

	buf := new(bytes.Buffer)
	if err := rtl.Encode(p2, buf); err != nil {
		t.Errorf("marshal error: %v", err)
	} else {
		bs := buf.Bytes()
		t.Logf("stream: %x", bs)
		p3 := new(MerkleProofs)
		if err := rtl.Decode(buf, p3); err != nil {
			t.Errorf("unmarshal error: %v", err)
		} else {
			t.Logf("unmarshaled: %s", p3)
		}
	}
}

type HashTestObjA struct {
	A int
	B string
	C *Hash
}

type HashTestObjB struct {
	D Address
	E Height
	F ChainID
}

func (b *HashTestObjB) HashValue() ([]byte, error) {
	return EncodeAndHash(b)
}

func (b *HashTestObjB) Serialization(w io.Writer) error {
	_, err := w.Write(b.D[:])
	if err != nil {
		return err
	}
	_, err = w.Write(b.E.Bytes())
	if err != nil {
		return err
	}
	_, err = w.Write(b.F.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func (b *HashTestObjB) Deserialization(r io.Reader) (shouldBeNil bool, err error) {
	buf := make([]byte, AddressLength)
	_, err = r.Read(buf)
	if err != nil {
		return
	}
	b.D = BytesToAddress(buf)
	buf = buf[:HeightBytesLength]
	_, err = r.Read(buf)
	if err != nil {
		return
	}
	b.E = BytesToHeight(buf)
	buf = buf[:ChainBytesLength]
	_, err = r.Read(buf)
	if err != nil {
		return
	}
	b.F = BytesToChainID(buf)
	return
}

func TestHashObject(t *testing.T) {
	a := &HashTestObjA{
		A: 10,
		B: "we are",
		C: BytesToHashP(NilHashSlice),
	}
	ba1, err := rtl.Marshal(a)
	if err != nil {
		t.Error(err)
		return
	}
	ha1, _ := Hash256s(ba1)
	ha2, err := HashObject(a)
	if err != nil {
		t.Error(err)
		return
	}
	if bytes.Equal(ha1, ha2) {
		t.Log("Hash256s(encoding.Marshal(HashTestObjA)) == HashObject(HashTestObjA)")
	} else {
		t.Error("Hash256s(encoding.Marshal(HashTestObjA)) != HashObject(HashTestObjA)")
	}

	b := &HashTestObjB{
		D: BytesToAddress(NilHashSlice),
		E: 19991,
		F: 12,
	}
	bb1, err := rtl.Marshal(b)
	if err != nil {
		t.Error(err)
		return
	}
	hb1, _ := Hash256s(bb1)
	hb2, err := HashObject(b)
	if err != nil {
		t.Error(err)
		return
	}
	if bytes.Equal(hb1, hb2) {
		t.Log("Hash256s(encoding.Marshal(HashTestObjB)) == HashObject(HashTestObjB)")
	} else {
		t.Error("Hash256s(encoding.Marshal(HashTestObjB)) != HashObject(HashTestObjB)")
	}
}

func TestMerkleNil(t *testing.T) {
	a, err := MerkleHashComplete(nil, -1, nil)
	if err != nil {
		t.Errorf("%v", err)
	} else {
		t.Logf("%x", a)
	}
}

func TestNewMerkleHash(t *testing.T) {
	root, err := MerkleHash([][]byte{[]byte("abcdef")}, 0, nil)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		t.Logf("%x", root)
	}
}

func TestHashMethods(t *testing.T) {
	ss := make([][]byte, 10)
	for i := 0; i < len(ss); i++ {
		n := mrand.Intn(100)
		if n <= 0 {
			continue
		}
		ss[i] = RandomBytes(n)
	}

	sss := ConcatenateBytes(ss)
	h1 := Hash256NoError(ss...)
	h2 := Hash256NoError(sss)
	if bytes.Equal(h1, h2) {
		t.Logf("equal")
	} else {
		t.Errorf("not equal")
	}
}

func totestMerkleHash(t *testing.T, length int, hashFunc func([][]byte, int, *MerkleProofs) ([]byte, error)) error {
	hashList := make([][]byte, length)
	for i := 0; i < len(hashList); i++ {
		hashList[i] = RandomBytes(HashLength)
	}
	t.Logf("hashList: %x", hashList)

	i1 := length / 2
	p1 := NewMerkleProofs()
	root1, err := hashFunc(hashList, i1, p1)
	if err != nil {
		return err
	}
	t.Logf("Merkle hash root: %x, proof(%d) Len(%d): %s", root1, i1, p1.Len(), p1)

	i2 := length - 1
	p2 := NewMerkleProofs()
	root2, err := hashFunc(hashList, i2, p2)
	if err != nil {
		return err
	}
	t.Logf("Merkle hash root: %x, proof(%d) Len(%d): %s", root2, i2, p2.Len(), p2)

	if bytes.Equal(root1, root2) {
		t.Logf("2 root equals")
	} else {
		return fmt.Errorf("2 root not equal: %x <> %x", root1, root2)
	}

	verifier := func(index int, p *MerkleProofs, r []byte) error {
		v, err := p.Proof(BytesToHash(hashList[index]))
		if err != nil {
			return err
		}
		if bytes.Equal(v, r) {
			t.Logf("proof(%d) verified", index)
			return nil
		} else {
			return fmt.Errorf("proof(%d):%s verified failed", i1, p1)
		}
	}
	if err = verifier(i1, p1, root1); err != nil {
		return err
	}
	if err = verifier(i2, p2, root2); err != nil {
		return err
	}
	return nil
}

func TestMerkleHash_Full(t *testing.T) {
	if err := totestMerkleHash(t, 7, MerkleHashComplete); err != nil {
		t.Errorf("merkle(7)%v", err)
		return
	}
	if err := totestMerkleHash(t, 16, MerkleHashComplete); err != nil {
		t.Errorf("merkle(16)%v", err)
		return
	}
	if err := totestMerkleHash(t, 33, MerkleHashComplete); err != nil {
		t.Errorf("merkle(33)%v", err)
		return
	}
	if err := totestMerkleHash(t, 128, MerkleHashComplete); err != nil {
		t.Errorf("merkle(128)%v", err)
		return
	}
	if err := totestMerkleHash(t, 257, MerkleHashComplete); err != nil {
		t.Errorf("merkle(257)%v", err)
		return
	}
}

func TestMerkleHash_Half(t *testing.T) {
	if err := totestMerkleHash(t, 7, MerkleHash); err != nil {
		t.Errorf("merkle(7)%v", err)
		return
	}
	if err := totestMerkleHash(t, 16, MerkleHash); err != nil {
		t.Errorf("merkle(16)%v", err)
		return
	}
	if err := totestMerkleHash(t, 33, MerkleHash); err != nil {
		t.Errorf("merkle(33)%v", err)
		return
	}
	if err := totestMerkleHash(t, 128, MerkleHash); err != nil {
		t.Errorf("merkle(128)%v", err)
		return
	}
	if err := totestMerkleHash(t, 257, MerkleHash); err != nil {
		t.Errorf("merkle(257)%v", err)
		return
	}
}

func TestMoreTime_Equal(t *testing.T) {
	m := &MoreTime{
		Index: 1,
		Times: 1,
	}
	o := &MoreTime{
		Index: 1,
		Times: 1,
	}
	if (*m).Equal(*o) {
		t.Log(m, "==", o)
	} else {
		t.Fatal(m, "!=", o)
	}
}

func TestMoreTimes(t *testing.T) {
	mts0 := MoreTimes{{1, 1}, {2, 2}, {3, 3}}
	bs, err := rtl.Marshal(mts0)
	if err != nil {
		t.Fatal(err)
	}
	mts1 := make(MoreTimes, 0)
	if err := rtl.Unmarshal(bs, &mts1); err != nil {
		t.Fatal(err)
	}

	mts2 := mts1.Clone()
	mts1[2].Times++
	if mts1[2].Times == 4 {
		t.Logf("%v", mts1)
	} else {
		t.Fatalf("%v", mts1)
	}
	if mts2[2].Times == 3 {
		t.Logf("cloned: %v", mts2)
	} else {
		t.Fatalf("cloned: %v", mts2)
	}
}

func _codecMerkleProofs(mp *MerkleProofs) (int, error) {
	// encode
	bs, err := rtl.Marshal(mp)
	if err != nil {
		return 0, fmt.Errorf("encode failed: %v", err)
	}
	nmp := new(MerkleProofs)
	if err = rtl.Unmarshal(bs, nmp); err != nil {
		return 0, fmt.Errorf("decode failed: %v", err)
	}
	if !nmp.Equal(mp) {
		return 0, fmt.Errorf("not match, expecting:%s but:%s", mp, nmp)
	}
	return len(bs), nil
}

func TestRepeatedMerkleProofs(t *testing.T) {
	for i := 0; i < 10; i++ {
		mptimes := NewMerkleProofs()
		var hashs []Hash
		orders := big.NewInt(0)
		for j := 0; j < 50; j++ {
			h := BytesToHash(RandomBytes(HashLength))

			order := mrand.Int()%2 == 0
			mptimes.Append(h, order)
			hashs = append(hashs, h)
			if order {
				orders.SetBit(orders, len(hashs)-1, 1)
			}

			single := mrand.Int()
			times := 0
			if single%2 == 0 {
				times = mrand.Intn(10)
				for k := 0; k < times; k++ {
					order := mrand.Int()%2 == 0
					mptimes.Append(h, order)
					hashs = append(hashs, h)
					if order {
						orders.SetBit(orders, len(hashs)-1, 1)
					}
				}
			}
		}
		mpnotimes := &MerkleProofs{
			Hashs:   hashs,
			Paths:   orders,
			Repeats: nil,
		}

		if mptimes.Len() != mpnotimes.Len() {
			t.Fatalf("(%d) notimes len:%d times len:%d", i, mpnotimes.Len(), mptimes.Len())
		}
		if mptimes.Paths.Cmp(mpnotimes.Paths) != 0 {
			t.Fatalf("(%d) notimes path:%s times path:%s", i, mpnotimes.Paths, mptimes.Paths)
		}
		val := BytesToHash(RandomBytes(HashLength))
		mproot, err := mpnotimes.Proof(val)
		if err != nil {
			t.Fatalf("(%d) notimes.proof(%x) failed: %v", i, val[:], err)
		}
		timesroot, err := mptimes.Proof(val)
		if err != nil {
			t.Fatalf("(%d) times.proof(%x) failed: %v", i, val[:], err)
		}
		if bytes.Equal(mproot, timesroot) == false {
			t.Fatalf("(%d) notimes.root:%x times.root:%x", i, mproot, timesroot)
		}
		t.Logf("(%d) mp:%s\ntimes:%s check\n", i, mpnotimes.InfoString(0), mptimes.InfoString(0))

		// codec
		length, err := _codecMerkleProofs(mpnotimes)
		if err != nil {
			t.Fatalf("(%d) mp codec failed: %v", i, err)
		}
		timeLength, err := _codecMerkleProofs(mptimes)
		if err != nil {
			t.Fatalf("(%d) moretimes mp codec failed: %v", i, err)
		}
		if length < timeLength {
			t.Fatalf("(%d) mp:%d mptimes:%d", i, length, timeLength)
		} else {
			t.Logf("(%d) mp:%d mptimes:%d", i, length, timeLength)
		}
	}
}

func TestValuesToHashs(t *testing.T) {
	var slices [][]byte
	slices = append(slices, nil)
	slices = append(slices, RandomBytes(32))
	hashes, err := ValuesToHashs(slices)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", hashes)
	nilhash, _ := HashObject([]byte(nil))
	t.Logf("nilslice hash: %x", nilhash)
	h, _ := Hash256s([]byte{0x80})
	t.Logf("rtl.ZeroValue hash: %x", h)
	t.Logf("nilhash:%x emptyhash:%x", Hash256NoError([]byte(nil)), Hash256NoError([]byte("")))
}
