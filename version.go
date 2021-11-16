package common

import (
	"errors"
	"fmt"
)

type Version uint64

func (v Version) Major() uint64 {
	return uint64(v) / 1000000
}

func (v Version) Minor() uint64 {
	uv := uint64(v)
	return (uv - (uv/1000000)*1000000) / 1000
}

func (v Version) Patch() uint64 {
	uv := uint64(v)
	return uv - (uv/1000)*1000
}

func NewNodeVersion(major, minor, patch uint64) (Version, error) {
	if minor > 999 || patch > 999 || major > 999 {
		return 0, errors.New("out of range")
	}
	return Version(patch + minor*1000 + major*1000000), nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major(), v.Minor(), v.Patch())
}
