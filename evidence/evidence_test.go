package evidence

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type body struct {
	Packages int `json:"packages"`
}

// chain makes n signed records with k, as the store does.
func chain(t *testing.T, k *Key, n int, version ...string) [][]byte {
	t.Helper()
	var out [][]byte
	prev := ""
	for i := range n {
		h := Header{
			Record: RecordInfo{Type: TypeHostInventory, Sequence: uint64(i + 1), Previous: prev,
				Created: time.Date(2026, 10, 17, 10, i, 0, 0, time.UTC), Cycle: uint64(i + 1)},
			Host:  HostInfo{ID: "h1", Hostname: "web-03", OS: "ubuntu", OSVersion: "24.04"},
			Agent: AgentInfo{Version: "test", BinarySHA256: "00", SelfCheck: "none"},
		}
		if len(version) > 0 {
			h.Agent.Version = version[0]
		}
		p, err := NewStatement(h, k.PublicDER, body{Packages: 700 + i})
		if err != nil {
			t.Fatal(err)
		}
		e, err := k.Sign(p)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw)
		prev = Digest(p)
	}
	return out
}

func keys(t *testing.T, ks ...*Key) (map[string]*ecdsa.PublicKey, map[string][]byte) {
	t.Helper()
	pubs, ders := map[string]*ecdsa.PublicKey{}, map[string][]byte{}
	for _, k := range ks {
		p, der, err := ParsePublic(k.PublicPEM())
		if err != nil {
			t.Fatal(err)
		}
		pubs[k.ID], ders[k.ID] = p, der
	}
	return pubs, ders
}

func TestSignVerifyAndChain(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := k.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivate(pem)
	if err != nil || k2.ID != k.ID {
		t.Fatalf("private key round trip: %v", err)
	}
	raws := chain(t, k, 4)
	pubs, ders := keys(t, k)
	r := VerifyChain(raws, pubs, ders)
	if !r.OK() || r.Records != 4 || r.First != 1 || r.Last != 4 {
		t.Fatalf("good chain: %+v", r)
	}
	c, err := Open(raws[0], pubs, ders)
	if err != nil {
		t.Fatal(err)
	}
	var full struct {
		Header
		body
	}
	if err := json.Unmarshal(c.Statement.Predicate, &full); err != nil || full.Packages != 700 || full.Record.Sequence != 1 {
		t.Errorf("predicate: %v %+v", err, full)
	}

	// A removed record is a break.
	r = VerifyChain([][]byte{raws[0], raws[1], raws[3]}, pubs, ders)
	if r.OK() || len(r.Breaks) != 1 || !strings.Contains(r.Breaks[0], "sequence 4 follows 2") {
		t.Errorf("gap: %+v", r)
	}
	// A record from another chain with the right sequence is a break.
	other := chain(t, k, 3, "other")
	r = VerifyChain([][]byte{raws[0], raws[1], other[2]}, pubs, ders)
	if r.OK() || len(r.Breaks) != 1 || !strings.Contains(r.Breaks[0], "previous") {
		t.Errorf("spliced: %+v", r)
	}
	// One changed byte in the payload fails the signature.
	var e Envelope
	_ = json.Unmarshal(raws[2], &e)
	p, _ := base64.StdEncoding.DecodeString(e.Payload)
	p[len(p)-3] ^= 1
	e.Payload = base64.StdEncoding.EncodeToString(p)
	bad, _ := e.Marshal()
	if _, err := Open(bad, pubs, ders); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered payload: %v", err)
	}
	r = VerifyChain([][]byte{raws[0], raws[1], bad, raws[3]}, pubs, ders)
	if r.OK() || len(r.Invalid) != 1 {
		t.Errorf("tampered in chain: %+v", r)
	}
	// A record signed by an unknown key does not verify.
	k3, _ := NewKey()
	if _, err := Open(chain(t, k3, 1)[0], pubs, ders); !errors.Is(err, ErrSignature) {
		t.Errorf("unknown key: %v", err)
	}
}

func TestSubjectMustNameSigningKey(t *testing.T) {
	k, _ := NewKey()
	other, _ := NewKey()
	h := Header{Record: RecordInfo{Type: TypeHostInventory, Sequence: 1}, Host: HostInfo{ID: "h1"}}
	p, _ := NewStatement(h, other.PublicDER, body{})
	e, _ := k.Sign(p)
	raw, _ := e.Marshal()
	pubs, ders := keys(t, k)
	if _, err := Open(raw, pubs, ders); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Errorf("got %v", err)
	}
}

func TestPAE(t *testing.T) {
	// The example of the DSSE specification (protocol.md).
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Errorf("got %q", got)
	}
}

// The value was checked once against systemd-id128 machine-id
// --app-specific on a Fedora 44 host (2026-10-17) with that host's own
// machine id; this vector uses a made-up machine id.
func TestAppSpecificID(t *testing.T) {
	var mid, app [16]byte
	for i := range mid {
		mid[i] = byte(i)
	}
	a, _ := hex.DecodeString("8356524ea4d3427190b05a578bcee252")
	copy(app[:], a)
	got := AppSpecificID(mid, app)
	if want := "4198e61979cd44a2a3ba6167207fe705"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
