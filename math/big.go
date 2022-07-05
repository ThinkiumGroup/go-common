// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package math provides integer math utilities.
package math

import (
	"fmt"
	"math"
	"math/big"
)

// Various big integer limit values.
var (
	tt255     = BigPow(2, 255)
	tt256     = BigPow(2, 256)
	tt256m1   = new(big.Int).Sub(tt256, big.NewInt(1))
	tt63      = BigPow(2, 63)
	MaxBig256 = new(big.Int).Set(tt256m1)
	MaxBig63  = new(big.Int).Sub(tt63, big.NewInt(1))

	Big1   = big.NewInt(1)
	Big2   = big.NewInt(2)
	Big3   = big.NewInt(3)
	Big0   = big.NewInt(0)
	Big32  = big.NewInt(32)
	Big256 = big.NewInt(256)
	Big257 = big.NewInt(257)

	Rat1 = big.NewRat(1, 1)
)

const (
	// number of bits in a big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in a big.Word
	wordBytes = wordBits / 8
)

// HexOrDecimal256 marshals big.Int as hex or decimal.
type HexOrDecimal256 big.Int

// UnmarshalText implements encoding.TextUnmarshaler.
func (i *HexOrDecimal256) UnmarshalText(input []byte) error {
	bigint, ok := ParseBig256(string(input))
	if !ok {
		return fmt.Errorf("invalid hex or decimal integer %q", input)
	}
	*i = HexOrDecimal256(*bigint)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (i *HexOrDecimal256) MarshalText() ([]byte, error) {
	if i == nil {
		return []byte("0x0"), nil
	}
	return []byte(fmt.Sprintf("%#x", (*big.Int)(i))), nil
}

// ParseBig256 parses s as a 256 bit integer in decimal or hexadecimal syntax.
// Leading zeros are accepted. The empty string parses as zero.
func ParseBig256(s string) (*big.Int, bool) {
	if s == "" {
		return new(big.Int), true
	}
	var bigint *big.Int
	var ok bool
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		bigint, ok = new(big.Int).SetString(s[2:], 16)
	} else {
		bigint, ok = new(big.Int).SetString(s, 10)
	}
	if ok && bigint.BitLen() > 256 {
		bigint, ok = nil, false
	}
	return bigint, ok
}

// MustParseBig256 parses s as a 256 bit big integer and panics if the string is invalid.
func MustParseBig256(s string) *big.Int {
	v, ok := ParseBig256(s)
	if !ok {
		panic("invalid 256 bit integer: " + s)
	}
	return v
}

// BigPow returns a ** b as a big integer.
func BigPow(a, b int64) *big.Int {
	r := big.NewInt(a)
	return r.Exp(r, big.NewInt(b), nil)
}

// BigMax returns the larger of x or y.
func BigMax(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return y
	}
	return x
}

// BigMin returns the smaller of x or y.
func BigMin(x, y *big.Int) *big.Int {
	if x.Cmp(y) > 0 {
		return y
	}
	return x
}

// FirstBitSet returns the index of the first 1 bit in v, counting from LSB.
func FirstBitSet(v *big.Int) int {
	for i := 0; i < v.BitLen(); i++ {
		if v.Bit(i) > 0 {
			return i
		}
	}
	return v.BitLen()
}

// PaddedBigBytes encodes a big integer as a big-endian byte slice. The length
// of the slice is at least n bytes.
func PaddedBigBytes(bigint *big.Int, n int) []byte {
	if bigint.BitLen()/8 >= n {
		return bigint.Bytes()
	}
	ret := make([]byte, n)
	ReadBits(bigint, ret)
	return ret
}

// bigEndianByteAt returns the byte at position n,
// in Big-Endian encoding
// So n==0 returns the least significant byte
func bigEndianByteAt(bigint *big.Int, n int) byte {
	words := bigint.Bits()
	// Check word-bucket the byte will reside in
	i := n / wordBytes
	if i >= len(words) {
		return byte(0)
	}
	word := words[i]
	// Offset of the byte
	shift := 8 * uint(n%wordBytes)

	return byte(word >> shift)
}

// Byte returns the byte at position n,
// with the supplied padlength in Little-Endian encoding.
// n==0 returns the MSB
// Example: bigint '5', padlength 32, n=31 => 5
func Byte(bigint *big.Int, padlength, n int) byte {
	if n >= padlength {
		return byte(0)
	}
	return bigEndianByteAt(bigint, padlength-1-n)
}

// ReadBits encodes the absolute value of bigint as big-endian bytes. Callers must ensure
// that buf has enough space. If buf is too short the result will be incomplete.
func ReadBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

// U256 encodes as a 256 bit two's complement number. This operation is destructive.
func U256(x *big.Int) *big.Int {
	return x.And(x, tt256m1)
}

// S256 interprets x as a two's complement number.
// x must not exceed 256 bits (the result is undefined if it does) and is not modified.
//
//   S256(0)        = 0
//   S256(1)        = 1
//   S256(2**255)   = -2**255
//   S256(2**256-1) = -1
func S256(x *big.Int) *big.Int {
	if x.Cmp(tt255) < 0 {
		return x
	}
	return new(big.Int).Sub(x, tt256)
}

// Exp implements exponentiation by squaring.
// Exp returns a newly-allocated big integer and does not change
// base or exponent. The result is truncated to 256 bits.
//
// Courtesy @karalabe and @chfast
func Exp(base, exponent *big.Int) *big.Int {
	result := big.NewInt(1)

	for _, word := range exponent.Bits() {
		for i := 0; i < wordBits; i++ {
			if word&1 == 1 {
				U256(result.Mul(result, base))
			}
			U256(base.Mul(base, base))
			word >>= 1
		}
	}
	return result
}

func BigStringForPrint(s string) string {
	l := len(s)
	if l <= 5 {
		return s
	}
	neg := false
	ss := []byte(s)
	if ss[0] == '-' {
		neg = true
		ss = ss[1:]
		l--
	} else if ss[0] == '+' {
		ss = ss[1:]
		l--
	}
	zeros := 0
	exp := l - 1
	i := l - 1
	for ; i >= 0; i-- {
		if ss[i] == '0' {
			zeros++
		} else {
			break
		}
	}
	var y []byte
	if l-zeros > 1 {
		y = make([]byte, l-zeros+1)
		y[0] = ss[0]
		y[1] = '.'
		copy(y[2:], ss[1:l-zeros])
		y = append(y, []byte(fmt.Sprintf("e%d", exp))...)
		if neg {
			y = append([]byte("-"), y...)
		}
	} else if l-zeros == 1 {
		y = append(y, ss[0])
		y = append(y, []byte(fmt.Sprintf("e%d", exp))...)
		if neg {
			y = append([]byte("-"), y...)
		}
	} else {
		y = []byte{'0'}
	}
	return string(y)
}

func BigIntForPrint(x *big.Int) string {
	if x == nil {
		return ""
	}
	s := x.String()
	return BigStringForPrint(s)
}

func BigForPrint(x *big.Int) string {
	if x == nil {
		return ""
	}
	s := x.String()
	ss := BigStringForPrint(s)
	if s == ss {
		return s
	}
	return s + " (" + ss + ")"
}

func BigRatForPrint(x *big.Rat) string {
	if x == nil {
		return ""
	}
	return x.RatString()
}

// r not bigger than 1
// x returns the smallest integer not less than i64*r
func Int64MulRat(i64 int64, r *big.Rat) (x int64) {
	rr := new(big.Rat).Mul(r, new(big.Rat).SetInt64(i64))
	x, _ = RatToInt64(rr)
	return x
}

func CopyBigInt(x *big.Int) *big.Int {
	if x == nil {
		return nil
	}
	return new(big.Int).Set(x)
}

func MustBigInt(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}

func MustPositiveInt(x *big.Int) *big.Int {
	if x == nil || x.Sign() <= 0 {
		return nil
	}
	return x
}

func MustCreatedBigInt(v *big.Int, isCreated bool) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	if isCreated {
		return v
	}
	return new(big.Int).Set(v)
}

func AddBigInt(base, delta *big.Int) *big.Int {
	if delta == nil {
		return base
	}
	if base == nil {
		base = new(big.Int).Set(delta)
	} else {
		base.Add(base, delta)
	}
	return base
}

func CopyBigRat(x *big.Rat) *big.Rat {
	if x == nil {
		return nil
	}
	return new(big.Rat).Set(x)
}

// return the smallest integer not less than r. If r is too large or divided by 0,
// nomeans is true, and x is meaningless
func RatToInt64(r *big.Rat) (x int64, nomeans bool) {
	f, _ := r.Float64()
	if math.IsNaN(f) || math.IsInf(f, 0) || f > float64(math.MaxInt64) || f < float64(math.MinInt64) {
		return 0, true
	}
	x = int64(f)
	if float64(x) < f {
		x += 1
	}
	return x, false
}

// lower round of r
func RatToInt64Floor(r *big.Rat) (x int64, nomeans bool) {
	f, _ := r.Float64()
	if math.IsNaN(f) || math.IsInf(f, 0) || f > float64(math.MaxInt64) || f < float64(math.MinInt64) {
		return 0, true
	}
	return int64(f), false
}

func CompareBigInt(a, b *big.Int) int {
	if a == b {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return a.Cmp(b)
}

func CompareBigRat(a, b *big.Rat) int {
	if a == b {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return a.Cmp(b)
}

type BigInt big.Int

func NewBigInt(a *big.Int) *BigInt {
	if a == nil {
		return nil
	}
	b := new(big.Int).Set(a)
	return (*BigInt)(b)
}

func (b *BigInt) Positive() bool {
	if b == nil || (*big.Int)(b).Sign() <= 0 {
		return false
	}
	return true
}

func (b *BigInt) Clone() *BigInt {
	return NewBigInt((*big.Int)(b))
}

func (b *BigInt) Int() *big.Int {
	return (*big.Int)(b)
}

func (b *BigInt) MustInt() *big.Int {
	if b == nil {
		return big.NewInt(0)
	}
	return (*big.Int)(b)
}

func (b *BigInt) Add(a *BigInt) *BigInt {
	if a == nil {
		return b
	}
	if b == nil {
		return (*BigInt)(new(big.Int).Set((*big.Int)(a)))
	}
	c := (*big.Int)(b)
	return (*BigInt)(c.Add(c, (*big.Int)(a)))
}

func (b *BigInt) AddInt(a *big.Int) *BigInt {
	if a == nil {
		return b
	}
	if b == nil {
		return (*BigInt)(new(big.Int).Set(a))
	} else {
		c := (*big.Int)(b)
		return (*BigInt)(c.Add(c, a))
	}
}

func (b *BigInt) SubInt(a *big.Int) *BigInt {
	if a == nil {
		return b
	}
	var c *big.Int
	if b == nil {
		c = big.NewInt(0)
	} else {
		c = (*big.Int)(b)
	}
	c.Sub(c, a)
	return (*BigInt)(c)
}

func (b *BigInt) Mul(a *big.Int) *BigInt {
	if b == nil {
		return nil
	}
	if a == nil || a.Sign() == 0 {
		return nil
	}
	c := (*big.Int)(b)
	return (*BigInt)(c.Mul(c, a))
}

func (b *BigInt) SetInt(a *big.Int) *BigInt {
	if a == nil {
		return nil
	}
	if b == nil {
		return (*BigInt)(new(big.Int).Set(a))
	}
	return (*BigInt)((*big.Int)(b).Set(a))
}

func (b *BigInt) Compare(o *BigInt) int {
	return CompareBigInt((*big.Int)(b), (*big.Int)(o))
}

func (b *BigInt) CompareInt(i *big.Int) int {
	return CompareBigInt((*big.Int)(b), i)
}

func (b *BigInt) MustPositive() *big.Int {
	if b.Positive() {
		return (*big.Int)(b)
	}
	return nil
}

func (b *BigInt) String() string {
	return BigIntForPrint((*big.Int)(b))
}
