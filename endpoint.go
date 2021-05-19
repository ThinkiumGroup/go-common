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

var (
	DefaultRpcEndpoint = Endpoint{NetType: "tcp", Address: DefaultRpcAddress}
)

type Endpoint struct {
	NetType string `yaml:"net" json:"net"`
	Address string `yaml:"addr" json:"addr"`
}

func (ep Endpoint) IsNil() bool {
	return ep.NetType == "" && ep.Address == ""
}

func (ep Endpoint) Network() string {
	return ep.NetType
}

func (ep Endpoint) String() string {
	return ep.Address
}
