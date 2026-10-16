// Package rpm reads the rpm package database without running rpm.
//
// It opens rpmdb.sqlite (the only backend rpm 4.16 and later write by
// default; RHEL 9 and 10 and their rebuilds all use it), reads every
// header blob from the Packages table in header-number order, which is
// the order "rpm -qa" prints, and decodes the tags the inventory needs.
// It never writes, never takes rpm's lock, and never executes anything
// (ADR 0017). BerkeleyDB and NDB databases are detected and refused.
package rpm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Header tags (rpmtag.h). Only the ones the agent reads are listed.
const (
	tagI18NTable       = 100 // HEADERI18NTABLE: languages of i18n strings
	tagSigMD5          = 261 // SIGMD5: the "pkgid"
	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagSummary         = 1004
	tagBuildTime       = 1006
	tagInstallTime     = 1008
	tagSize            = 1009
	tagVendor          = 1011
	tagLicense         = 1014
	tagArch            = 1022
	tagSourceRPM       = 1044
	tagInstallTID      = 1128
	tagLongSize        = 5009
	tagModularityLabel = 5096

	// Region tags: a header's first entry may be one of these, marking
	// an immutable region. Entries after the region are later additions
	// (install time, signature results) and override earlier ones.
	tagHeaderImage      = 61
	tagHeaderSignatures = 62
	tagHeaderImmutable  = 63
)

// Tag data types (rpmtag.h).
const (
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9
)

// maxHeaderBytes is rpm's own limit on a header (lib/header.c).
const maxHeaderBytes = 256 << 20

// entry is one decoded tag.
type entry struct {
	typ   uint32
	count uint32
	data  []byte // exactly this tag's bytes
}

// header is a decoded header blob: tag number to entry.
type header map[int32]entry

var errMalformed = errors.New("malformed rpm header")

// parseHeader decodes a header blob as rpmdb stores it: an index length,
// a data length, the index, then the data. There is no magic in the
// stored form. Every offset is checked against the blob; a hostile or
// corrupt header yields an error, never a panic or an out-of-range read.
func parseHeader(blob []byte) (header, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("%w: %d bytes", errMalformed, len(blob))
	}
	il := int64(binary.BigEndian.Uint32(blob[0:4]))
	dl := int64(binary.BigEndian.Uint32(blob[4:8]))
	if il < 1 || dl < 0 || 8+16*il+dl > maxHeaderBytes || 8+16*il+dl != int64(len(blob)) {
		return nil, fmt.Errorf("%w: index %d, data %d, blob %d bytes", errMalformed, il, dl, len(blob))
	}
	index := blob[8 : 8+16*il]
	data := blob[8+16*il:]
	h := make(header, il)
	for i := int64(0); i < il; i++ {
		e := index[16*i : 16*i+16]
		tag := int32(binary.BigEndian.Uint32(e[0:4]))         //nolint:gosec // tags are signed in rpm's format
		off := int64(int32(binary.BigEndian.Uint32(e[8:12]))) //nolint:gosec // offsets are signed in rpm's format
		typ, count := binary.BigEndian.Uint32(e[4:8]), binary.BigEndian.Uint32(e[12:16])
		if i == 0 && (tag == tagHeaderImage || tag == tagHeaderSignatures || tag == tagHeaderImmutable) {
			continue // region marker; its data is a trailer, not a value
		}
		if off < 0 || off > dl {
			return nil, fmt.Errorf("%w: tag %d offset %d outside %d data bytes", errMalformed, tag, off, dl)
		}
		n, err := valueLength(typ, count, data[off:])
		if err != nil {
			return nil, fmt.Errorf("%w: tag %d: %w", errMalformed, tag, err)
		}
		h[tag] = entry{typ: typ, count: count, data: data[off : off+n]}
	}
	return h, nil
}

// valueLength returns how many bytes a value of the given type and count
// occupies at the start of data.
func valueLength(typ, count uint32, data []byte) (int64, error) {
	var size int64
	switch typ {
	case typeChar, typeInt8, typeBin:
		size = 1
	case typeInt16:
		size = 2
	case typeInt32:
		size = 4
	case typeInt64:
		size = 8
	case typeString:
		if count != 1 {
			return 0, fmt.Errorf("string with count %d", count)
		}
		return stringsLength(data, 1)
	case typeStringArray, typeI18NString:
		return stringsLength(data, count)
	default:
		return 0, fmt.Errorf("unknown type %d", typ)
	}
	n := size * int64(count)
	if n > int64(len(data)) {
		return 0, fmt.Errorf("%d bytes of type %d past the end of data", n, typ)
	}
	return n, nil
}

// stringsLength measures count NUL-terminated strings at the start of data.
func stringsLength(data []byte, count uint32) (int64, error) {
	var n int64
	for ; count > 0; count-- {
		i := indexNUL(data[n:])
		if i < 0 {
			return 0, errors.New("unterminated string")
		}
		n += int64(i) + 1
	}
	return n, nil
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// str returns a STRING tag, or the first element of a string array or
// i18n string. ok is false when the tag is absent or not a string.
func (h header) str(tag int32) (string, bool) {
	e, ok := h[tag]
	if !ok {
		return "", false
	}
	switch e.typ {
	case typeString, typeStringArray, typeI18NString:
		return string(e.data[:indexNUL(e.data)]), true
	}
	return "", false
}

// strs returns every element of a string-array tag.
func (h header) strs(tag int32) []string {
	e, ok := h[tag]
	if !ok || (e.typ != typeStringArray && e.typ != typeI18NString && e.typ != typeString) {
		return nil
	}
	out := make([]string, 0, e.count)
	d := e.data
	for len(d) > 0 {
		i := indexNUL(d)
		out = append(out, string(d[:i]))
		d = d[i+1:]
	}
	return out
}

// i18n returns an i18n string tag in the given language, falling back to
// the first entry the way rpm does when the language is not in the
// header's i18n table, and to "" when the tag is absent.
func (h header) i18n(tag int32, lang string) string {
	e, ok := h[tag]
	if !ok {
		return ""
	}
	if e.typ != typeI18NString {
		s, _ := h.str(tag)
		return s
	}
	all := h.strs(tag)
	if len(all) == 0 {
		return ""
	}
	for i, l := range h.strs(tagI18NTable) {
		if l == lang && i < len(all) {
			return all[i]
		}
	}
	return all[0]
}

// num returns an integer tag's first element as an unsigned 64-bit value.
// ok is false when the tag is absent or not an integer.
func (h header) num(tag int32) (uint64, bool) {
	e, ok := h[tag]
	if !ok || e.count == 0 {
		return 0, false
	}
	switch e.typ {
	case typeChar, typeInt8:
		return uint64(e.data[0]), true
	case typeInt16:
		return uint64(binary.BigEndian.Uint16(e.data)), true
	case typeInt32:
		return uint64(binary.BigEndian.Uint32(e.data)), true
	case typeInt64:
		return binary.BigEndian.Uint64(e.data), true
	}
	return 0, false
}

// bin returns a BIN tag's bytes.
func (h header) bin(tag int32) ([]byte, bool) {
	e, ok := h[tag]
	if !ok || e.typ != typeBin {
		return nil, false
	}
	return e.data, true
}
