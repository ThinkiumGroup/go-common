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

import "plugin"

func InitShareObject(sopath string) *plugin.Plugin {
	plug, err := plugin.Open(sopath)
	if err != nil {
		panic(err)
	}
	registerfunc, err := plug.Lookup("RegisterToSystem")
	if err == nil {
		// find the registration method to register
		registerfunc.(func())()
	}
	return plug
}

func InitSharedObjectWithError(sopath string) (*plugin.Plugin, error) {
	plug, err := plugin.Open(sopath)
	if err != nil {
		return nil, err
	}
	registerfunc, err := plug.Lookup("RegisterToSystem")
	if err == nil {
		// find the registration method to register
		registerfunc.(func())()
	}
	return plug, nil
}
