package sockdiag

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

func TestParseMsg(t *testing.T) {
	b := make([]byte, msgLen+12+8)
	b[0] = syscall.AF_INET6
	binary.BigEndian.PutUint16(b[4:], 443)
	copy(b[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.NativeEndian.PutUint32(b[64:], 33)
	// An attribute the parser skips, then INET_DIAG_CGROUP_ID.
	a := b[msgLen:]
	binary.NativeEndian.PutUint16(a, 5)
	binary.NativeEndian.PutUint16(a[2:], 1)
	a = a[8:]
	binary.NativeEndian.PutUint16(a, 12)
	binary.NativeEndian.PutUint16(a[2:], inetDiagCgroupID)
	binary.NativeEndian.PutUint64(a[4:], 4242)
	p, ok := parseMsg(b, "tcp")
	if !ok || p.Port != 443 || p.Addr != netip.MustParseAddr("2001:db8::1") || p.CgroupID != 4242 || p.UID != 33 || p.Loopback() {
		t.Fatalf("%+v %v", p, ok)
	}
	if _, ok := parseMsg(b[:msgLen-1], "tcp"); ok {
		t.Error("short message accepted")
	}
	b[0] = 99
	if _, ok := parseMsg(b, "tcp"); ok {
		t.Error("unknown family accepted")
	}
	// A bad attribute length ends the walk without a panic.
	binary.NativeEndian.PutUint16(b[msgLen:], 2)
	b[0] = syscall.AF_INET
	if _, ok := parseMsg(b, "tcp"); !ok {
		t.Error("message with a bad attribute rejected")
	}
}

// The live dump finds a socket this test opens on loopback.
func TestListeningLive(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = l.Close() }()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	socks, err := Listening()
	if err != nil {
		if strings.Contains(err.Error(), "not permitted") || strings.Contains(err.Error(), "not supported") {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	for _, s := range socks {
		if s.Proto == "tcp" && s.Port == port {
			if !s.Loopback() || s.CgroupID == 0 {
				t.Errorf("%+v", s)
			}
			return
		}
	}
	t.Errorf("port %d not in %d sockets", port, len(socks))
}
