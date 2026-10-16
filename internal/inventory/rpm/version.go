package rpm

import (
	"strconv"
	"strings"
)

// EVR is an rpm version: epoch, version, release. HasEpoch records whether
// the header carries an Epoch tag at all; rpm prints "0:" only then.
type EVR struct {
	Epoch    uint32
	HasEpoch bool
	Version  string
	Release  string
}

// String prints the version the way rpm's %{EVR} does.
func (v EVR) String() string {
	s := v.Version
	if v.Release != "" {
		s += "-" + v.Release
	}
	if v.HasEpoch {
		s = strconv.FormatUint(uint64(v.Epoch), 10) + ":" + s
	}
	return s
}

// ParseEVR splits [epoch:]version[-release]. It accepts what rpm's
// rpmverParse accepts; an epoch that is not a number is kept in the
// version string rather than rejected, as rpm does.
func ParseEVR(s string) EVR {
	var v EVR
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if e, err := strconv.ParseUint(s[:i], 10, 32); err == nil {
			v.Epoch, v.HasEpoch = uint32(e), true
			s = s[i+1:]
		}
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		v.Version, v.Release = s[:i], s[i+1:]
	} else {
		v.Version = s
	}
	return v
}

// Compare orders two versions as rpm does: epoch numerically (absent is
// 0), then version and release with Vercmp.
func Compare(a, b EVR) int {
	switch {
	case a.Epoch < b.Epoch:
		return -1
	case a.Epoch > b.Epoch:
		return 1
	}
	if c := Vercmp(a.Version, b.Version); c != 0 {
		return c
	}
	return Vercmp(a.Release, b.Release)
}

// Vercmp is rpmvercmp (lib/rpmvercmp.c): segments of digits compare
// numerically, segments of letters compare as strings, digits beat
// letters, "~" sorts before anything including the end of the string,
// and "^" sorts after the end of the string but before anything else.
func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case !ca:
				return 1
			case !cb:
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		sa, sb := a[si:i], b[sj:j]
		if sb == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	}
	return 1
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// SourceRPM splits a SOURCERPM value, "name-version-release.src.rpm",
// into its name and version-release. ok is false for anything else,
// including the "(none)" of gpg-pubkey entries.
func SourceRPM(s string) (name, vr string, ok bool) {
	base, found := strings.CutSuffix(s, ".src.rpm")
	if !found {
		if base, found = strings.CutSuffix(s, ".nosrc.rpm"); !found {
			return "", "", false
		}
	}
	r := strings.LastIndexByte(base, '-')
	if r <= 0 {
		return "", "", false
	}
	v := strings.LastIndexByte(base[:r], '-')
	if v <= 0 {
		return "", "", false
	}
	return base[:v], base[v+1:], true
}
