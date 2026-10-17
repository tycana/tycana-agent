package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// BundleFormat names the export format.
const BundleFormat = "tycana-evidence-bundle/v0.1"

// Bundle is "tycana evidence export": the records of one host and the
// public keys that signed them. A record is its DSSE envelope as the
// store holds it.
type Bundle struct {
	Format   string            `json:"format"`
	Exported time.Time         `json:"exported"`
	Keys     []BundleKey       `json:"keys"`
	Records  []json.RawMessage `json:"records"`
}

// BundleKey is one public key, PEM.
type BundleKey struct {
	KeyID     string `json:"keyid"`
	PublicKey string `json:"public_key"`
}

const maxBundle = 1 << 30

// ReadBundle parses a bundle. Unknown fields are errors.
func ReadBundle(r io.Reader) (*Bundle, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBundle {
		return nil, errors.New("evidence: bundle larger than 1 GiB")
	}
	var bd Bundle
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bd); err != nil {
		return nil, fmt.Errorf("evidence: bundle: %w", err)
	}
	if bd.Format != BundleFormat {
		return nil, fmt.Errorf("evidence: bundle format %q, want %q", bd.Format, BundleFormat)
	}
	return &bd, nil
}

// KeySource says where the verifier's keys came from.
type KeySource string

const (
	// KeysFromBundle means the keys came with the records; nothing
	// outside the bundle vouches for them.
	KeysFromBundle KeySource = "bundle"
	// KeyPinned means the verifier gave the key.
	KeyPinned KeySource = "pinned"
)

// Verify checks every record and the chain. With pinned (a PEM or DER
// public key) only that key is trusted; otherwise the bundle's keys are.
func (b *Bundle) Verify(pinned []byte) (ChainReport, KeySource, []string, error) {
	pubs, ders := map[string]*ecdsa.PublicKey{}, map[string][]byte{}
	src := KeysFromBundle
	add := func(raw []byte, declared string) error {
		p, der, err := ParsePublic(raw)
		if err != nil {
			return err
		}
		id := KeyID(der)
		if declared != "" && declared != id {
			return fmt.Errorf("evidence: key declared as %s is %s", declared, id)
		}
		pubs[id], ders[id] = p, der
		return nil
	}
	if pinned != nil {
		src = KeyPinned
		if err := add(pinned, ""); err != nil {
			return ChainReport{}, src, nil, err
		}
	} else {
		for _, k := range b.Keys {
			if err := add([]byte(k.PublicKey), k.KeyID); err != nil {
				return ChainReport{}, src, nil, err
			}
		}
	}
	ids := make([]string, 0, len(pubs))
	for id := range pubs {
		ids = append(ids, id)
	}
	raws := make([][]byte, len(b.Records))
	for i, r := range b.Records {
		raws[i] = r
	}
	return VerifyChain(raws, pubs, ders), src, ids, nil
}
