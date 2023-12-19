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
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
)

func startAndEnd(length, startPos, endPos int) (start, end int) {
	if startPos >= length {
		startPos = length - 1
	}
	if endPos < 0 {
		endPos = length
	}
	if endPos > length {
		endPos = length
	}
	if endPos <= startPos {
		endPos = startPos + 1
	}
	return startPos, endPos
}

func ForPrintSlice(s []byte, startPos int, endPos int) []byte {
	if s == nil {
		return []byte{}
	}
	l := len(s)
	startPos, endPos = startAndEnd(l, startPos, endPos)
	return s[startPos:endPos]
}

func ForPrintValue(val reflect.Value, startPos, endPos int) []byte {
	typ := val.Type()
	var s []byte
	switch typ.Kind() {
	case reflect.Ptr:
		if val.IsNil() {
			return []byte{}
		}
		return ForPrintValue(val.Elem(), startPos, endPos)
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			return []byte{}
		}
		startPos, endPos = startAndEnd(val.Len(), startPos, endPos)
		s = val.Slice(startPos, endPos).Bytes()
	case reflect.Slice:
		if val.IsNil() || typ.Elem().Kind() != reflect.Uint8 || val.Len() == 0 {
			return []byte{}
		}
		startPos, endPos = startAndEnd(val.Len(), startPos, endPos)
		s = val.Slice(startPos, endPos).Bytes()
	case reflect.String:
		startPos, endPos = startAndEnd(val.Len(), startPos, endPos)
		s = val.Slice(startPos, endPos).Bytes()
	default:
		return []byte{}
	}
	return s
}

func ForPrint(v interface{}, poss ...int) []byte {
	if v == nil {
		return []byte{}
	}
	val := reflect.ValueOf(v)
	startPos, endPos := 0, 5
	if len(poss) == 1 {
		startPos = poss[0]
		endPos = -1
	} else if len(poss) >= 2 {
		startPos = poss[0]
		endPos = poss[1]
	}
	return ForPrintValue(val, startPos, endPos)
}

func PrintBytesSlice(bss [][]byte, length int) string {
	buf := new(bytes.Buffer)
	buf.WriteByte('[')
	for i := 0; i < len(bss); i++ {
		if i > 0 {
			buf.WriteByte(',')
			buf.WriteByte(' ')
		}
		buf.Write([]byte(hex.EncodeToString(ForPrintSlice(bss[i], 0, length))))
	}
	buf.WriteByte(']')
	return buf.String()
}

func ForPrintSliceString(v interface{}, maxSize ...int) string {
	if v == nil {
		return ""
	}
	val := reflect.ValueOf(v)
	typ := val.Type()
	if typ.Kind() != reflect.Slice {
		return ""
	}
	if val.IsNil() || val.Len() == 0 {
		return "[]"
	}
	length := val.Len()
	size := length
	if len(maxSize) > 0 {
		if maxSize[0] < length && maxSize[0] > 0 {
			size = maxSize[0]
		}
	}
	return fmt.Sprintf("%s", val.Slice(0, size).Interface())
}

// FromHex returns the bytes represented by the hexadecimal string s.
// s may be prefixed with "0x".
func FromHex(s string) []byte {
	if len(s) > 1 {
		if s[0:2] == "0x" || s[0:2] == "0X" {
			s = s[2:]
		}
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return Hex2Bytes(s)
}

// CopyBytes returns an exact copy of the provided bytes.
func CopyBytes(b []byte) (copiedBytes []byte) {
	if b == nil {
		return nil
	}
	copiedBytes = make([]byte, len(b))
	if len(b) == 0 {
		return
	}
	copy(copiedBytes, b)
	return
}

// hasHexPrefix validates str begins with '0x' or '0X'.
func HasHexPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// isHexCharacter returns bool of c being a valid hexadecimal.
func IsHexCharacter(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

// IsHex validates whether each byte is valid hexadecimal string.
func IsHex(str string) bool {
	if len(str)%2 != 0 {
		return false
	}
	for _, c := range []byte(str) {
		if !IsHexCharacter(c) {
			return false
		}
	}
	return true
}

// Bytes2Hex returns the hexadecimal encoding of d.
func Bytes2Hex(d []byte) string {
	return hex.EncodeToString(d)
}

// Hex2Bytes returns the bytes represented by the hexadecimal string str.
func Hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

// Hex2BytesFixed returns bytes of a specified fixed length flen.
func Hex2BytesFixed(str string, flen int) []byte {
	h, _ := hex.DecodeString(str)
	if len(h) == flen {
		return h
	}
	if len(h) > flen {
		return h[len(h)-flen:]
	}
	hh := make([]byte, flen)
	copy(hh[flen-len(h):flen], h[:])
	return hh
}

// RightPadBytes zero-pads slice to the right up to length l.
func RightPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded, slice)

	return padded
}

// LeftPadBytes zero-pads slice to the left up to length l.
func LeftPadBytes(slice []byte, l int) []byte {
	if l <= len(slice) {
		return slice
	}

	padded := make([]byte, l)
	copy(padded[l-len(slice):], slice)

	return padded
}

// Divide bs into slices according to size, and each slice length is size
func SplitBytes(bs []byte, size int) ([][]byte, error) {
	if len(bs)%size != 0 {
		return nil, errors.New(fmt.Sprintf("input length illegal: (%d)%%(%d)!=0", len(bs), size))
	}
	r := make([][]byte, 0, len(bs)/size)
	for p := 0; p < len(bs); p += size {
		o := CopyBytes(bs[p : p+size])
		r = append(r, o)
	}
	return r, nil
}

// Join the slice array of the parameter to return a slice. Nil and empty are allowed. The returned slice is not nil
func ConcatenateBytes(bss [][]byte) []byte {
	size := 0
	for i := 0; i < len(bss); i++ {
		size += len(bss[i])
	}

	bs := make([]byte, size)
	p := 0
	for i := 0; i < len(bss); i++ {
		if len(bss[i]) <= 0 {
			continue
		}
		copy(bs[p:p+len(bss[i])], bss[i])
		p += len(bss[i])
	}
	return bs
}

func BytesIntersection(a, b [][]byte) [][]byte {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	x, y := a, b
	if len(a) < len(b) {
		x, y = b, a
	}
	m := make(map[string]struct{}, len(x))
	for _, bs := range x {
		m[string(bs)] = EmptyPlaceHolder
	}
	var r [][]byte
	for _, bs := range y {
		if _, exist := m[string(bs)]; exist {
			delete(m, string(bs))
			r = append(r, bs)
		}
	}
	return r
}

func BytesIntersectionMap(a map[string]struct{}, b [][]byte) [][]byte {
	rm := make(map[string]struct{})
	for _, bs := range b {
		if _, exist := a[string(bs)]; exist {
			rm[string(bs)] = struct{}{}
		}
	}
	r := make([][]byte, 0, len(rm))
	for bs, _ := range rm {
		r = append(r, []byte(bs))
	}
	return r
}

func CopyBytesSlice(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = CopyBytes(in[i])
	}
	return out
}

func BytesSliceEqual(a, b [][]byte) bool {
	if a == nil && b == nil {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if bytes.Equal(a[i], b[i]) == false {
			return false
		}
	}
	return true
}

// let b0.bit(0~7) and b1.bit(0~7) be bit(0~15), and returns bit(shifts, shifts+length)
// 0 <= shifts <= 7; 1<= length <= 8 default:8
// ShiftBytes(0xf0, 0xf, 3, 7) would be 0x7e
// ShiftBytes(0xf0, 0xf, 3) would be 0xfe
func ShiftBits(b0, b1 byte, shifts uint8, length ...uint8) byte {
	shifts = shifts & 0x7
	bitLength := uint8(8)
	if len(length) > 0 {
		if length[0] > 0 && length[0] < 8 {
			bitLength = length[0]
		}
	}
	r := b0
	if shifts == 0 {
		// r = b0
	} else {
		r = b0 >> shifts
		if bitLength+shifts > 8 {
			r |= b1 << (8 - shifts)
		}
	}
	if offset := 8 - bitLength; offset > 0 {
		rr := r << offset // clear top bits
		r = rr >> offset
	}
	return r
}

// cut bytes from bs, bits [from, to)
func SubBytes(bs []byte, from, size int) ([]byte, error) {
	if from < 0 || size <= 0 {
		return nil, errors.New("invalid bit parameters")
	}
	bsBitSize := len(bs) << 3
	if from >= bsBitSize {
		return nil, nil
	}
	if size+from > bsBitSize {
		size = bsBitSize - from
	}

	last := len(bs) - 1
	rssize := (size + 7) / 8

	rs := make([]byte, rssize)
	shiftBits := uint8(from % 8)
	for i := 0; i < size; i = i + 8 {
		p := last - (i+from)>>3
		pr := rssize - 1 - i>>3
		b1 := byte(0)
		if p > 0 {
			b1 = bs[p-1]
		}
		if size-i >= 8 {
			rs[pr] = ShiftBits(bs[p], b1, shiftBits)
		} else {
			rs[pr] = ShiftBits(bs[p], b1, shiftBits, uint8(size-i))
		}
	}
	return rs, nil
}

func DecodeHex(h string) ([]byte, error) {
	if HasHexPrefix(h) {
		return hex.DecodeString(h[2:])
	}
	return hex.DecodeString(h)
}
