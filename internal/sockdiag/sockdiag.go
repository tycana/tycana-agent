// Package sockdiag reads the listening sockets of a host and their
// cgroups from the kernel's socket diagnostics (sock_diag), without
// privilege (tycana-hq ADR 0029). It opens one NETLINK_SOCK_DIAG socket,
// sends SOCK_DIAG_BY_FAMILY dump requests, and reads the answers; it
// never sends SOCK_DESTROY or any other request. It also maps cgroup ids
// to paths by reading the cgroup v2 tree. tools/nowrite allows this
// package, and only it besides internal/hostexec and internal/filetime,
// to import syscall and golang.org/x/sys/unix.
package sockdiag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Socket is one listening socket from the kernel's socket diagnostics.
type Socket struct {
	// Proto is "tcp" (state LISTEN) or "udp" (unconnected).
	Proto string     `json:"proto"`
	Addr  netip.Addr `json:"addr"`
	Port  uint16     `json:"port"`
	// CgroupID is the cgroup v2 id of the socket (INET_DIAG_CGROUP_ID,
	// Linux 5.7): the inode number of the cgroup's directory. 0 when the
	// kernel did not send it.
	CgroupID uint64 `json:"-"`
	UID      uint32 `json:"-"`
}

// Loopback reports whether only the host itself can reach the socket.
func (s Socket) Loopback() bool { return s.Addr.Unmap().IsLoopback() }

// Linux constants that x/sys/unix does not name.
const (
	inetDiagCgroupID = 21   // INET_DIAG_CGROUP_ID, include/uapi/linux/inet_diag.h
	tcpListen        = 10   // TCP_LISTEN
	tcpClose         = 7    // TCP_CLOSE: an unconnected UDP socket
	reqLen           = 56   // sizeof(struct inet_diag_req_v2)
	msgLen           = 72   // sizeof(struct inet_diag_msg)
	nlmFDumpIntr     = 0x10 // NLM_F_DUMP_INTR
)

var errInterrupted = errors.New("sock_diag: dump interrupted")

// maxSockets bounds what one dump may return. A host with more listening
// sockets than this gets an error, not a partial list.
const maxSockets = 65536

// Listening asks the kernel for every listening TCP socket and every
// unconnected UDP socket, IPv4 and IPv6, with their cgroups. It opens one
// NETLINK_SOCK_DIAG socket, which needs AF_NETLINK in the unit's
// RestrictAddressFamilies= (tycana-hq ADR 0029) and no capability: the
// kernel gives every user the dump. It sends only SOCK_DIAG_BY_FAMILY
// dump requests and changes nothing.
func Listening() ([]Socket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag: bind: %w", err)
	}
	var out []Socket
	seq := uint32(1)
	for _, q := range []struct {
		proto  string
		ipProt uint8
		states uint32
	}{
		{"tcp", syscall.IPPROTO_TCP, 1 << tcpListen},
		{"udp", syscall.IPPROTO_UDP, 1 << tcpClose},
	} {
		for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
			got, err := dump(fd, seq, fam, q.ipProt, q.states, q.proto)
			// A dump that the kernel marks interrupted (the socket table
			// changed during it) is asked again, at most twice.
			for try := 0; errors.Is(err, errInterrupted) && try < 2; try++ {
				seq++
				got, err = dump(fd, seq, fam, q.ipProt, q.states, q.proto)
			}
			if err != nil {
				return nil, err
			}
			out = append(out, got...)
			if len(out) > maxSockets {
				return nil, fmt.Errorf("sock_diag: more than %d sockets", maxSockets)
			}
			seq++
		}
	}
	return out, nil
}

func dump(fd int, seq uint32, family, proto uint8, states uint32, name string) ([]Socket, error) {
	req := make([]byte, syscall.NLMSG_HDRLEN+reqLen)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], syscall.NLMSG_HDRLEN+reqLen)
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	ne.PutUint32(req[8:], seq)
	r := req[syscall.NLMSG_HDRLEN:]
	r[0], r[1] = family, proto
	ne.PutUint32(r[4:], states)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag: send: %w", err)
	}
	buf := make([]byte, os.Getpagesize()*8)
	var out []Socket
	interrupted := false
	for {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("sock_diag: receive: %w", err)
		}
		// Only the kernel (port id 0) answers; anything else is ignored.
		if sa, ok := from.(*syscall.SockaddrNetlink); !ok || sa.Pid != 0 {
			continue
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("sock_diag: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			if m.Header.Flags&nlmFDumpIntr != 0 {
				interrupted = true
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				if interrupted {
					return nil, errInterrupted
				}
				return out, nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if e := int32(ne.Uint32(m.Data)); e < 0 { //nolint:gosec // errno is a negative int32
						return nil, fmt.Errorf("sock_diag: %w", syscall.Errno(uint32(-e)))
					}
				}
				return out, nil
			}
			s, ok := parseMsg(m.Data, name)
			if ok && (name != "udp" || s.dport == 0) {
				out = append(out, s.Socket)
			}
			if len(out) > maxSockets {
				return nil, errors.New("sock_diag: too many sockets")
			}
		}
	}
}

type parsed struct {
	Socket
	dport uint16
}

// parseMsg reads one struct inet_diag_msg and its attributes.
func parseMsg(b []byte, proto string) (parsed, bool) {
	if len(b) < msgLen {
		return parsed{}, false
	}
	var p parsed
	p.Proto = proto
	// struct inet_diag_sockid: ports and addresses in network order.
	p.Port = binary.BigEndian.Uint16(b[4:])
	p.dport = binary.BigEndian.Uint16(b[6:])
	switch b[0] {
	case syscall.AF_INET:
		p.Addr = netip.AddrFrom4([4]byte(b[8:12]))
	case syscall.AF_INET6:
		p.Addr = netip.AddrFrom16([16]byte(b[8:24]))
	default:
		return parsed{}, false
	}
	p.UID = binary.NativeEndian.Uint32(b[64:68])
	for a := b[msgLen:]; len(a) >= 4; { //nolint:gosec // len(b) >= msgLen is checked above
		l := int(binary.NativeEndian.Uint16(a[0:2]))
		t := binary.NativeEndian.Uint16(a[2:4]) & 0x3fff // without NLA_F_NESTED, NLA_F_NET_BYTEORDER
		if l < 4 || l > len(a) {
			break
		}
		if t == inetDiagCgroupID && l >= 12 {
			p.CgroupID = binary.NativeEndian.Uint64(a[4:12])
		}
		a = a[min(len(a), (l+3)&^3):]
	}
	return p, true
}
