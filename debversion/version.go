// Package debversion parses and compares Debian package versions with
// dpkg's rules. It is a public package so that a control plane can compare
// installed versions with vendor data in the same way as the agent (ADR
// 0016: the contracts between the agent and a control plane are public).
package debversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is a Debian package version, split the way dpkg splits it:
// [epoch:]upstream[-revision]. See deb-version(7).
type Version struct {
	Epoch    uint32
	Upstream string
	Revision string
}

// ParseVersion parses s with dpkg's rules (lib/dpkg/parsehelp.c
// parseversion). It rejects what dpkg rejects as an error; dpkg's warnings
// (for example an upstream part that does not start with a digit) are
// accepted, because dpkg accepts them too.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, errors.New("version string is empty")
	}
	if strings.ContainsAny(s, " \t\n") {
		return Version{}, fmt.Errorf("version %q has embedded spaces", s)
	}
	var v Version
	rest := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if i == 0 {
			return Version{}, fmt.Errorf("version %q: epoch is empty", s)
		}
		e, err := strconv.ParseUint(s[:i], 10, 31)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: epoch is not a number or too large", s)
		}
		v.Epoch = uint32(e)
		rest = s[i+1:]
		if rest == "" {
			return Version{}, fmt.Errorf("version %q: nothing after colon", s)
		}
	}
	if i := strings.LastIndexByte(rest, '-'); i >= 0 {
		v.Revision = rest[i+1:]
		rest = rest[:i]
		if v.Revision == "" {
			return Version{}, fmt.Errorf("version %q: revision is empty", s)
		}
	}
	if rest == "" {
		return Version{}, fmt.Errorf("version %q: upstream version is empty", s)
	}
	v.Upstream = rest
	return v, nil
}

// String prints the version the way dpkg-query prints ${Version}
// (varbufversion with vdew_nonambig): the epoch is shown when it is
// non-zero, or when it is needed to parse the rest unambiguously.
func (v Version) String() string {
	var b strings.Builder
	if v.Epoch != 0 || strings.Contains(v.Upstream, ":") || strings.Contains(v.Revision, ":") {
		b.WriteString(strconv.FormatUint(uint64(v.Epoch), 10))
		b.WriteByte(':')
	}
	b.WriteString(v.Upstream)
	if v.Revision != "" {
		b.WriteByte('-')
		b.WriteString(v.Revision)
	}
	return b.String()
}

// Compare returns -1, 0, or 1 as a is older than, equal to, or newer than b,
// using dpkg's algorithm (lib/dpkg/version.c dpkg_version_compare).
func Compare(a, b Version) int {
	switch {
	case a.Epoch > b.Epoch:
		return 1
	case a.Epoch < b.Epoch:
		return -1
	}
	if r := verrevcmp(a.Upstream, b.Upstream); r != 0 {
		return r
	}
	return verrevcmp(a.Revision, b.Revision)
}

// order gives the sort weight of a non-digit character: '~' sorts before
// everything including the end of the string, letters before non-letters.
func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func verrevcmp(a, b string) int {
	at := func(s string, i int) byte {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := order(at(a, i)), order(at(b, j))
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for at(a, i) == '0' {
			i++
		}
		for at(b, j) == '0' {
			j++
		}
		for isDigit(at(a, i)) && isDigit(at(b, j)) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}
