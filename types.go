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
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"sync"

	"github.com/ThinkiumGroup/go-common/log"
	lru "github.com/hashicorp/golang-lru"
)

var (
	EmptyPlaceHolder     struct{} = struct{}{}
	EmptyByteSliceHolder []byte   = make([]byte, 0)

	BytesBufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	BigIntPool = sync.Pool{
		New: func() interface{} {
			return new(big.Int)
		},
	}

	ErrAlreadyInitialized  = errors.New("already initialized")
	ErrAlreadyStarted      = errors.New("already started")
	ErrAlreadyStopped      = errors.New("already stopped")
	ErrNeedInitialization  = errors.New("need initialization")
	ErrNotStarted          = errors.New("not started yet")
	ErrIllegalStatus       = errors.New("illegal status")
	ErrNoAdapter           = errors.New("no adapter")
	ErrInsufficientLength  = errors.New("insufficient length")
	ErrLength              = errors.New("length error")
	ErrNil                 = errors.New("nil value")
	ErrNotFound            = errors.New("not found")
	ErrDuplicated          = errors.New("duplicated")
	ErrIllegalParams       = errors.New("illegal parameters")
	ErrUnsupported         = errors.New("unsupported")
	ErrUnknown             = errors.New("unknown error")
	ErrAlreadyDone         = errors.New("already done, operation ignored")
	ErrReservedAddress     = errors.New("reserved address")
	ErrMissMatch           = errors.New("miss match")
	ErrInsufficientBalance = errors.New("insufficient balance for transfer")

	EmptyHash    = Hash{}
	NilHashSlice = []byte(nil)
	NilHash      = BytesToHash(NilHashSlice)
)

func init() {
	// Initialize the hash values of Nil according to RealCipher
	NilHashSlice = SystemHash256(nil)
	NilHash = BytesToHash(NilHashSlice)
	log.Debugf("NilHash set to: %s", NilHash)
}

// type NodeType string

type Service interface {
	String() string
	Init() error
	Start() error
	Close() error
}

type ServiceStatus byte

func (ss *ServiceStatus) CheckInit() error {
	switch *ss {
	case SSInitialized:
		return ErrAlreadyInitialized
	case SSStarted:
		return ErrAlreadyStarted
	}
	*ss = SSInitialized
	return nil
}

func (ss *ServiceStatus) CheckStart() error {
	if *ss != SSInitialized {
		return ErrNeedInitialization
	}
	*ss = SSStarted
	return nil
}

func (ss *ServiceStatus) CheckStop() error {
	switch *ss {
	case SSCreated, SSInitialized:
		return ErrNotStarted
	case SSStopped:
		return ErrAlreadyStopped
	}
	*ss = SSStopped
	return nil
}

type ServiceStateChanger interface {
	Initializer() error
	Starter() error
	Closer() error
}

func dummyFunc() error {
	return nil
}

type AbstractService struct {
	serviceStatus ServiceStatus
	serviceLocker sync.Mutex

	InitFunc  func() error
	StartFunc func() error
	CloseFunc func() error
}

func (s AbstractService) Copy() AbstractService {
	as := AbstractService{}
	as.serviceStatus = s.serviceStatus
	as.InitFunc = dummyFunc
	as.StartFunc = dummyFunc
	as.CloseFunc = dummyFunc
	return as
}

func (s *AbstractService) SetChanger(changer ServiceStateChanger) {
	s.InitFunc = changer.Initializer
	s.StartFunc = changer.Starter
	s.CloseFunc = changer.Closer
}

func (s *AbstractService) Init() error {
	s.serviceLocker.Lock()
	defer s.serviceLocker.Unlock()
	if err := s.serviceStatus.CheckInit(); err != nil {
		return err
	}

	if s.InitFunc != nil {
		if err := s.InitFunc(); err != nil {
			return err
		}
	}
	return nil
}

func (s *AbstractService) Start() error {
	s.serviceLocker.Lock()
	defer s.serviceLocker.Unlock()
	if err := s.serviceStatus.CheckStart(); err != nil {
		return err
	}

	if s.StartFunc != nil {
		if err := s.StartFunc(); err != nil {
			return err
		}
	}
	return nil
}

func (s *AbstractService) Close() error {
	s.serviceLocker.Lock()
	defer s.serviceLocker.Unlock()
	if err := s.serviceStatus.CheckStop(); err != nil {
		return err
	}

	if s.CloseFunc != nil {
		if err := s.CloseFunc(); err != nil {
			return err
		}
	}
	return nil
}

type DvppError struct {
	Message  string
	Embedded error
}

func NewDvppError(msg string, embeded error) DvppError {
	return DvppError{Message: msg, Embedded: embeded}
}

func (e DvppError) Error() string {
	return fmt.Sprintf("%s: %v", e.Message, e.Embedded)
}

type DvppFormatError struct {
	format string
	values []interface{}
}

func NewFormatError(format string, values ...interface{}) DvppFormatError {
	return DvppFormatError{format: format, values: values}
}

func (e DvppFormatError) Error() string {
	return fmt.Sprintf(e.format, e.values...)
}

func IntToBytes(n int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(n))
	return b
}

func BytesToUint32(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp uint32
	binary.Read(bytesBuffer, binary.BigEndian, &tmp)
	return tmp
}

type LruMap struct {
	Map *lru.Cache
}

func NewLruMap(size int) *LruMap {
	cache, err := lru.New(size)
	if err != nil {
		panic(err)
	}
	return &LruMap{Map: cache}
}

func (m *LruMap) Add(key interface{}, value interface{}) bool {
	if m.Map.Contains(key) {
		return false
	}
	m.Map.Add(key, value)
	return true
}

func (m *LruMap) Get(key interface{}) interface{} {
	v, ok := m.Map.Get(key)
	if !ok {
		return nil
	}
	return v
}

func (m *LruMap) Contains(key interface{}) bool {
	return m.Map.Contains(key)
}

func (m *LruMap) Remove(key interface{}) {
	m.Map.Remove(key)
}

func (m *LruMap) Clear() {
	m.Map.Purge()
}

type (
	// key pair
	Cipherer interface {
		Priv() []byte
		Pub() []byte
	}

	// account
	Identifier interface {
		Cipherer
		Address() Address
		AddressP() *Address
	}

	// node
	NodeIdentifier interface {
		Cipherer
		NodeID() NodeID
		NodeIDP() *NodeID
	}
)

func IdentifiersToNodeIDs(nis []NodeIdentifier) NodeIDs {
	if nis == nil {
		return nil
	}
	nids := make(NodeIDs, 0, len(nis))
	for _, ni := range nis {
		if ni == nil {
			continue
		}
		nids = append(nids, ni.NodeID())
	}
	return nids
}

type Infoer interface {
	InfoString(level IndentLevel) string
}

func InfoStringer(v reflect.Value, level IndentLevel) string {
	if !v.IsValid() {
		return "N/A"
	}
	o := v.Interface()
	switch obj := o.(type) {
	case Infoer:
		return obj.InfoString(level)
	case fmt.Stringer:
		return fmt.Sprintf("%s", obj.String())
	default:
		return "UKN"
	}
}

type IndentLevel int

func (l IndentLevel) IndentString() string {
	if l <= 0 {
		return ""
	}
	return strings.Repeat("\t", int(l))
}

func (l IndentLevel) InfoString(o interface{}) string {
	if o == nil {
		return "<nil>"
	}
	v := reflect.ValueOf(o)
	if !v.IsValid() {
		return "N/A"
	}
	kind := v.Kind()
	switch kind {
	case reflect.Array, reflect.Slice:
		indent := l.IndentString()
		if kind == reflect.Slice && v.IsNil() {
			return "<nil>"
		}
		next := l + 1
		nextIndent := next.IndentString()
		buf := new(bytes.Buffer)
		buf.WriteByte('[')
		if v.Len() > 0 {
			for i := 0; i < v.Len(); i++ {
				one := v.Index(i)
				buf.WriteString(fmt.Sprintf("\n%s%s,", nextIndent, InfoStringer(one, next)))
			}
			buf.WriteByte('\n')
			buf.WriteString(indent)
		}
		buf.WriteByte(']')
		return buf.String()
	default:
		return InfoStringer(v, l)
	}
}
