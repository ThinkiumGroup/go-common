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

package trie

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"

	common "github.com/ThinkiumGroup/go-common"
	"github.com/stephenfire/go-rtl"
	"golang.org/x/crypto/sha3"
)

type nodevalue2 struct {
	Value []byte
}

func (n nodevalue2) String() string {
	return hex.EncodeToString(n.Value)
}

type nodevalue []byte

func (n nodevalue) String() string {
	return string([]byte(hex.EncodeToString(n))[:10]) + "..."
}

func valueEncode(o interface{}, w io.Writer) error {
	buf := new(bytes.Buffer)
	err := rtl.Encode(o, buf)
	if err != nil {
		return err
	}
	bs := buf.Bytes()
	_, err = w.Write(bs)
	return err
}

func valueDecode(r io.Reader) (interface{}, error) {
	ret := nodevalue(make([]byte, 0))
	rr := &ret
	err := rtl.Decode(r, rr)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func randomBytes(length int) nodevalue {
	b := make([]byte, length)
	io.ReadFull(rand.Reader, b)
	return b
}

func createNode(gen uint64, withValue bool) *node {
	n := NewNodeWithFuncs(nil, gen, valueEncode, valueDecode, nil)
	if withValue {
		n.value = randomBytes(100)
	}
	return n
}

var (
	root    *node
	child1  *node
	child2  *node
	child3  *node
	child31 *node
	child32 *node
)

func init() {
	root = createNode(1, false)
	root.prefix = hexstringToPrefix([]byte("abc"))

	// child1.value.key = 0xab 0xcd 0xef
	child1 = createNode(2, true)
	child1.prefix = hexstringToPrefix([]byte("ef"))
	root.children[hexbyteToValuebyte('d')] = child1

	// child2.value.key = 0xab 0xc0 0x12
	child2 = createNode(3, true)
	child2.prefix = hexstringToPrefix([]byte("12"))
	root.children[hexbyteToValuebyte('0')] = child2

	child3 = createNode(4, false)
	child31 = createNode(4, true)
	child32 = createNode(4, true)
	child3.children[hexbyteToValuebyte('7')] = child31
	child3.children[hexbyteToValuebyte('F')] = child32
	root.children[hexbyteToValuebyte('4')] = child3
}

func TestNode(t *testing.T) {
	t.Logf("%v\n", root)

	h, err := root.HashValue()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(hex.EncodeToString(h))
	}

	t.Logf("%v\n", root)
}

func TestValueCodec(t *testing.T) {
	node1 := createNode(1, true)
	buf := new(bytes.Buffer)
	if err := node1.valueEncode(node1.value, buf); err != nil {
		t.Error("encode err:", err)
	}
	bs := buf.Bytes()
	node2 := createNode(2, false)
	node2value, err := node2.valueDecode(buf)
	if err == nil {
		if reflect.DeepEqual(node1.value, node2value) {
			t.Logf("%v->%x->%v", node1.value, bs, node2value)
		} else {
			t.Errorf("%v > %x > %v", node1.value, bs, node2value)
		}
	} else {
		t.Error("decode err:", err)
	}

	node3 := NewNode(nil, 1, reflect.TypeOf((*nodevalue2)(nil)).Elem())
	node3.value = nodevalue2{Value: make([]byte, 30)}
	io.ReadFull(rand.Reader, node3.value.(nodevalue2).Value)
	buf.Reset()
	if err := node3.valueEncode(node3.value, buf); err != nil {
		t.Error("encode err:", err)
	}
	bs = buf.Bytes()
	node4 := NewNode(nil, 2, reflect.TypeOf((*nodevalue2)(nil)).Elem())
	node4value, err := node4.valueDecode(buf)
	if err == nil {
		if reflect.DeepEqual(node3.value, node4value) {
			t.Logf("%s->%x->%s", node3.value, bs, node4value)
		} else {
			t.Errorf("%s > %x > %s", node3.value, bs, node4value)
		}
	} else {
		t.Error("decode err:", err)
	}

}

func printHeader(h *NodeHeader) *NodeHeader {
	fmt.Printf("%s\n", h)
	bs, err := rtl.Marshal(h)
	if err != nil {
		return nil
	}
	fmt.Printf("%X\n", bs)
	r := new(NodeHeader)
	if err := rtl.Unmarshal(bs, r); err != nil {
		return nil
	}
	return r
}

func TestEncodeHeader(t *testing.T) {
	h := newNodeHeader(root)
	H := printHeader(h)
	if reflect.DeepEqual(h, H) {
		t.Log("root check ok")
	} else {
		t.Error("root check failed")
	}

	h1 := newNodeHeader(child1)
	H1 := printHeader(h1)
	if reflect.DeepEqual(h1, H1) {
		t.Log("child1 check ok")
	} else {
		t.Error("child1 check failed")
	}

	h3 := newNodeHeader(child3)
	H3 := printHeader(h3)
	if reflect.DeepEqual(h3, H3) {
		t.Log("child3 check ok")
	} else {
		t.Error("child3 check failed")
	}
}

func hashequal(output string, inputs ...string) bool {
	h := sha3.New256()
	for i := 0; i < len(inputs); i++ {
		b, err := hex.DecodeString(inputs[i])
		if err != nil {
			panic(err)
		}
		h.Write(b)
	}
	hash := h.Sum(nil)
	o, err := hex.DecodeString(output)
	if err != nil {
		panic(err)
	}
	return bytes.Equal(hash, o)
}

func TestHash(t *testing.T) {
	t.Log(hashequal("a08b735fbf4ebcbe9aecd9e775a952cfec6bf97c7a7dedfbf45515e1b1ae1e90",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"93aad02fd077705a652199c2c13cd98d63fb45dd83671ecf7e94356ca8a77522",
	))
	t.Log(hashequal("d09a440de33a9a69ac5b5b1609264a24b331f3ea8d836eaff1f934f48c394a3e",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"b6c0ad83f7ce5689e451ef148623dc663b3de04020724067783fbbc4e1bfdcfd",
	))
	t.Log(hashequal("67b7a90478b7f848781bdc9e24bc7ab2712bdfaff7c1fa2ff348eb133e08c214",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"4a089b7ef2d08cbb11c3d6841558d7bdd8cb8102233f0b8085d4161bc9630665",
	))
	t.Log(hashequal("3238e8e67b65bca9266471479ec31cc725fab7dea16a0c9eda4809aa93fe5e61",
		"d09a440de33a9a69ac5b5b1609264a24b331f3ea8d836eaff1f934f48c394a3e",
		"67b7a90478b7f848781bdc9e24bc7ab2712bdfaff7c1fa2ff348eb133e08c214",
	))
	t.Log(hashequal("f952ceb4ba6acb8b54182dee463693451aa6c41684ed494209d0770bc621ed05",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		"029ee7192e6bcb94d5ad0893d079e75f72b2c2647aa81f79a780122607661f9f",
	))
	t.Log(hashequal("f31c4fce05a92ed3ca61e4933786bde88f523207ae60977fab6d4019992b5f13",
		"a08b735fbf4ebcbe9aecd9e775a952cfec6bf97c7a7dedfbf45515e1b1ae1e90",
		"3238e8e67b65bca9266471479ec31cc725fab7dea16a0c9eda4809aa93fe5e61",
		"f952ceb4ba6acb8b54182dee463693451aa6c41684ed494209d0770bc621ed05",
	))
}

func TestNodeOps(t *testing.T) {
	n := NewNodeWithFuncs(nil, 1, nil, nil, nil)
	n.setPrefix([]byte("1234567890"))
	t.Logf("%v", n)
	n.chopPrefixHead(1)
	t.Logf("%v", n)
	n.chopPrefixHead(0)
	t.Logf("%v", n)
	n.chopPrefixHead(100)
	t.Logf("%v", n)
	n.chopPrefixHead(9)
	t.Logf("%v", n)

	n.setPrefix([]byte("1234567890"))
	t.Logf("%v", n)
	n.chopPrefixTail(1)
	t.Logf("%v", n)
	n.chopPrefixTail(0)
	t.Logf("%v", n)
	n.chopPrefixTail(100)
	t.Logf("%v", n)
	n.chopPrefixTail(9)
	t.Logf("%v", n)
}

func TestOneValue(t *testing.T) {
	// bs := common.FromHex("400100d226f4ef37b7f90ba6240ed938fbe12ce05ef0b073099acf57c0598605f08473")
	// bs := common.FromHex("b0df000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002")
	// bs := common.FromHex("a0debbc715ae215aa6f55ea5de18e7f8c7496adbc6c689f13bea5ff897a6d0820000000000000000000000000000000000000000000000000000000000000001")
	bs := common.FromHex("b1d28d25424458d38d4859a1a74d3fa5cdd15d515d5b7eaecb8c04a97e0b7e0e31c27a2b46ee640b413bcd66a6cb187ce2b8218e")
	buf := rtl.NewValueReader(bytes.NewBuffer(bs), 256)
	n := &node{}
	if err := rtl.Decode(buf, n); err != nil {
		t.Errorf("err: %v", err)
	}
	t.Logf("%s", n)
}

func TestEmptyNodeHash(t *testing.T) {
	n := &node{}
	h, _ := n.HashValue()
	t.Logf("%X", h)
}

func TestNodeDecode(t *testing.T) {
	bs, _ := hex.DecodeString("80c0508253a214bbe0b77a32240bc47aa74188f8e66d0f459a8080677369fdf9ecd3")
	buf := rtl.NewValueReader(bytes.NewBuffer(bs), 256)
	node := new(node)
	if err := rtl.Decode(buf, node); err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("%v", node)
}
