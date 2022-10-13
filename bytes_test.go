package common

import (
	"bytes"
	"testing"
)

func TestShiftBits(t *testing.T) {
	tests := []struct {
		b0, b1 byte
		shifts uint8
		length uint8
		result byte
	}{
		{0xf0, 0xf, 3, 7, 0x7e},
		{0xf0, 0xf, 3, 8, 0xfe},
		{0xf0, 0xf, 3, 2, 0x2},
		{0xf0, 0xf, 1, 12, 0xf8},
		{0xf0, 0xf, 1, 8, 0xf8},
		{0xf0, 0xf, 7, 3, 0x7},
		{0xf0, 0xf, 7, 8, 0x1f},
		{0xf0, 0xf, 0, 8, 0xf0},
		{0xf0, 0xf, 0, 5, 0x10},
		{0xf0, 0xf, 0, 12, 0xf0},
	}

	for _, test := range tests {
		result := ShiftBits(test.b0, test.b1, test.shifts, test.length)
		if result == test.result {
			t.Logf("ShiftBits(0x%x, 0x%x, %d, %d)=0x%x check", test.b0, test.b1, test.shifts, test.length, result)
		} else {
			t.Fatalf("ShiftBits(0x%x, 0x%x, %d, %d)=0x%x expecting:0x%x", test.b0, test.b1, test.shifts, test.length, result, test.result)
		}
	}
}

func TestSubBytes(t *testing.T) {
	tests := []struct {
		bs         []byte
		from, size int
		rs         []byte
	}{
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 0, 20, []byte{0xd, 0xef, 0x21}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 0, 5, []byte{0x1}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 5, 11, []byte{0x7, 0x79}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 16, 7, []byte{0x4d}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 16, 16, []byte{0xab, 0xcd}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 7, 100, []byte{0x1, 0x57, 0x9b, 0xde}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 19, 3, []byte{0x1}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 19, 13, []byte{0x15, 0x79}},
		{[]byte{0xab, 0xcd, 0xef, 0x21}, 32, 13, []byte{}},
	}

	for _, test := range tests {
		rs, _ := SubBytes(test.bs, test.from, test.size)
		if bytes.Equal(test.rs, rs) {
			t.Logf("Sub(0x%x, %d, %d)=0x%x check", test.bs, test.from, test.size, rs)
		} else {
			t.Fatalf("Sub(0x%x, %d, %d)=0x%x expecting:0x%x", test.bs, test.from, test.size, rs, test.rs)
		}
	}
}