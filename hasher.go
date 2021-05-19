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
	"reflect"

	"github.com/stephenfire/go-rtl"
)

// If the object implements common.Hasher Interface, the HashValue() method is directly used
// to generate the hash value. Otherwise, hash will be performed after serializing the object
func HashObject(o interface{}) ([]byte, error) {
	if o == nil {
		return NilHashSlice, nil
	}
	v := reflect.ValueOf(o)
	if !v.IsValid() {
		return NilHashSlice, nil
	}

	switch val := o.(type) {
	case Hasher:
		return val.HashValue()
	default:
		hasher := RealCipher.Hasher()
		if err := rtl.Encode(val, hasher); err != nil {
			return nil, err
		}
		return hasher.Sum(nil), nil
	}
}

// Hash calculation after serializing objects
func EncodeAndHash(o interface{}) ([]byte, error) {
	if o == nil {
		return NilHashSlice, nil
	}
	v := reflect.ValueOf(o)
	if !v.IsValid() {
		return NilHashSlice, nil
	}

	hasher := RealCipher.Hasher()
	if err := rtl.Encode(o, hasher); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// Call the HashObject method and turn the result into a hash object. If there is an error,
// all 0 Hash object will be returned
func EncodeHash(v interface{}) Hash {
	bs, err := HashObject(v)
	if err != nil {
		return Hash{}
	}
	return BytesToHash(bs)
}
