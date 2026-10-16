package rpm

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// tagValue is one tag of a synthetic header.
type tagValue struct {
	tag  int32
	typ  uint32
	vals []string // strings for string types; decimal for integers; hex is not needed
	bin  []byte
}

// buildHeader encodes tags the way rpm stores headers in rpmdb: index
// length, data length, 16-byte index entries, then aligned data. When
// region is true the first entry is an immutable-region marker with a
// trailer, as every real header has.
func buildHeader(t *testing.T, region bool, tags ...tagValue) []byte {
	t.Helper()
	var index, data []byte
	add := func(tag int32, typ, count uint32, off int) {
		e := make([]byte, 16)
		binary.BigEndian.PutUint32(e[0:], uint32(tag))
		binary.BigEndian.PutUint32(e[4:], typ)
		binary.BigEndian.PutUint32(e[8:], uint32(off))
		binary.BigEndian.PutUint32(e[12:], count)
		index = append(index, e...)
	}
	if region {
		add(tagHeaderImmutable, typeBin, 16, 0)
		data = append(data, make([]byte, 16)...) // trailer; parseHeader ignores it
	}
	for _, tv := range tags {
		align := map[uint32]int{typeInt16: 2, typeInt32: 4, typeInt64: 8}[tv.typ]
		for align > 0 && len(data)%align != 0 {
			data = append(data, 0)
		}
		off := len(data)
		count := uint32(len(tv.vals))
		switch tv.typ {
		case typeString, typeStringArray, typeI18NString:
			for _, s := range tv.vals {
				data = append(data, s...)
				data = append(data, 0)
			}
		case typeInt32:
			for _, s := range tv.vals {
				var n uint32
				if _, err := fmtSscan(s, &n); err != nil {
					t.Fatal(err)
				}
				data = binary.BigEndian.AppendUint32(data, n)
			}
		case typeInt64:
			for _, s := range tv.vals {
				var n uint64
				if _, err := fmtSscan(s, &n); err != nil {
					t.Fatal(err)
				}
				data = binary.BigEndian.AppendUint64(data, n)
			}
		case typeBin:
			count = uint32(len(tv.bin))
			data = append(data, tv.bin...)
		default:
			t.Fatalf("unsupported type %d in test builder", tv.typ)
		}
		add(tv.tag, tv.typ, count, off)
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:], uint32(len(index)/16))
	binary.BigEndian.PutUint32(out[4:], uint32(len(data)))
	out = append(out, index...)
	return append(out, data...)
}

// samplePackage is a header shaped like a real one from AlmaLinux 9.
func samplePackage(t *testing.T) []byte {
	t.Helper()
	return buildHeader(t, true,
		tagValue{tag: tagI18NTable, typ: typeStringArray, vals: []string{"C", "de"}},
		tagValue{tag: tagName, typ: typeString, vals: []string{"bash"}},
		tagValue{tag: tagVersion, typ: typeString, vals: []string{"5.1.8"}},
		tagValue{tag: tagRelease, typ: typeString, vals: []string{"9.el9"}},
		tagValue{tag: tagEpoch, typ: typeInt32, vals: []string{"1"}},
		tagValue{tag: tagSummary, typ: typeI18NString, vals: []string{"The GNU Bourne Again shell", "Die GNU-Shell"}},
		tagValue{tag: tagBuildTime, typ: typeInt32, vals: []string{"1700000000"}},
		tagValue{tag: tagSize, typ: typeInt32, vals: []string{"7700000"}},
		tagValue{tag: tagArch, typ: typeString, vals: []string{"x86_64"}},
		tagValue{tag: tagSourceRPM, typ: typeString, vals: []string{"bash-5.1.8-9.el9.src.rpm"}},
		// Dribbles: added by rpm at install time, after the region.
		tagValue{tag: tagInstallTime, typ: typeInt32, vals: []string{"1786337864"}},
		tagValue{tag: tagInstallTID, typ: typeInt32, vals: []string{"1786337862"}},
		tagValue{tag: tagSigMD5, typ: typeBin, bin: []byte{0x6d, 0xab, 0xf1, 0xbe, 0x9c, 0x0b, 0xad, 0x3c, 0xff, 0x22, 0xde, 0x1e, 0xe5, 0xc4, 0xaa, 0x55}},
	)
}

// samplePubkey is shaped like a gpg-pubkey entry: no arch, no source,
// no epoch, no signature digest, a plain-string summary.
func samplePubkey(t *testing.T) []byte {
	t.Helper()
	return buildHeader(t, true,
		tagValue{tag: tagName, typ: typeString, vals: []string{"gpg-pubkey"}},
		tagValue{tag: tagVersion, typ: typeString, vals: []string{"b86b3716"}},
		tagValue{tag: tagRelease, typ: typeString, vals: []string{"61e69f29"}},
		tagValue{tag: tagSummary, typ: typeString, vals: []string{"AlmaLinux OS 9 <packager@almalinux.org> public key"}},
		tagValue{tag: tagSize, typ: typeInt32, vals: []string{"0"}},
		tagValue{tag: tagBuildTime, typ: typeInt32, vals: []string{"1642503977"}},
		tagValue{tag: tagInstallTime, typ: typeInt32, vals: []string{"1786338009"}},
	)
}

func TestParseHeader(t *testing.T) {
	h, err := parseHeader(samplePackage(t))
	if err != nil {
		t.Fatal(err)
	}
	p := fromHeader(7, h)
	if p.Name != "bash" || p.EVR.String() != "1:5.1.8-9.el9" || p.Arch != "x86_64" || p.Instance != 7 {
		t.Errorf("package: %+v", p)
	}
	if p.Summary != "The GNU Bourne Again shell" {
		t.Errorf("summary (C locale) = %q", p.Summary)
	}
	if s := h.i18n(tagSummary, "de"); s != "Die GNU-Shell" {
		t.Errorf("summary (de) = %q", s)
	}
	if p.SigMD5 != "6dabf1be9c0bad3cff22de1ee5c4aa55" || p.InstallTime.Unix() != 1786337864 || p.InstallTID != 1786337862 {
		t.Errorf("dribble tags: %+v", p)
	}
	if !p.HasSize || p.Size != 7700000 || p.BuildTime.Unix() != 1700000000 {
		t.Errorf("size/buildtime: %+v", p)
	}

	k := fromHeader(391, mustParse(t, samplePubkey(t)))
	if k.Name != "gpg-pubkey" || k.Arch != "" || k.SourceRPM != "" || k.EVR.HasEpoch || k.SigMD5 != "" {
		t.Errorf("pubkey: %+v", k)
	}
	if k.EVR.String() != "b86b3716-61e69f29" || k.Summary != "AlmaLinux OS 9 <packager@almalinux.org> public key" || !k.HasSize || k.Size != 0 {
		t.Errorf("pubkey fields: %+v", k)
	}
}

func mustParse(t *testing.T, blob []byte) header {
	t.Helper()
	h, err := parseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestParseHeaderNoRegion(t *testing.T) {
	h := mustParse(t, buildHeader(t, false, tagValue{tag: tagName, typ: typeString, vals: []string{"x"}}))
	if n, _ := h.str(tagName); n != "x" {
		t.Errorf("name = %q", n)
	}
}

func TestParseHeaderMalformed(t *testing.T) {
	good := samplePackage(t)
	cases := map[string][]byte{
		"empty":      {},
		"short":      good[:7],
		"truncated":  good[:len(good)-1],
		"extra byte": append(append([]byte{}, good...), 0),
		"zero index": func() []byte { b := append([]byte{}, good...); binary.BigEndian.PutUint32(b[0:], 0); return b }(),
		"huge index": func() []byte { b := append([]byte{}, good...); binary.BigEndian.PutUint32(b[0:], 1<<30); return b }(),
		"bad offset": func() []byte {
			b := append([]byte{}, good...)
			binary.BigEndian.PutUint32(b[8+16*2+8:], 1<<31)
			return b
		}(),
		"bad type":       func() []byte { b := append([]byte{}, good...); binary.BigEndian.PutUint32(b[8+16*2+4:], 99); return b }(),
		"string count 2": func() []byte { b := append([]byte{}, good...); binary.BigEndian.PutUint32(b[8+16*2+12:], 2); return b }(),
		"int past end": func() []byte {
			b := append([]byte{}, good...)
			binary.BigEndian.PutUint32(b[8+16*5+12:], 1<<20)
			return b
		}(),
	}
	for name, blob := range cases {
		if _, err := parseHeader(blob); !errors.Is(err, errMalformed) {
			t.Errorf("%s: err = %v, want malformed", name, err)
		}
	}
	// A string whose terminator is missing is rejected.
	one := buildHeader(t, false, tagValue{tag: tagName, typ: typeString, vals: []string{"x"}})
	one[len(one)-1] = 'x'
	if _, err := parseHeader(one); !errors.Is(err, errMalformed) {
		t.Errorf("unterminated string: %v", err)
	}
	// A 256 MiB claim must be rejected by arithmetic, not by allocation.
	b := append([]byte{}, good...)
	binary.BigEndian.PutUint32(b[4:], 0xffffffff)
	if _, err := parseHeader(b); !errors.Is(err, errMalformed) {
		t.Errorf("huge data length: %v", err)
	}
}

func TestAccessorsOnWrongTypes(t *testing.T) {
	h := mustParse(t, samplePackage(t))
	if _, ok := h.num(tagName); ok {
		t.Error("num() accepted a string tag")
	}
	if _, ok := h.str(tagEpoch); ok {
		t.Error("str() accepted an integer tag")
	}
	if _, ok := h.bin(tagName); ok {
		t.Error("bin() accepted a string tag")
	}
	if _, ok := h.str(9999); ok {
		t.Error("str() found an absent tag")
	}
	if got := h.strs(tagI18NTable); strings.Join(got, ",") != "C,de" {
		t.Errorf("strs = %v", got)
	}
}
