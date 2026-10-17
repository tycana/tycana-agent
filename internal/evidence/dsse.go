// Package evidence makes and checks the agent's signed records (ADR 0011,
// tycana-hq ADR 0025): in-toto Statements v1 in DSSE envelopes, signed
// with the host's ECDSA P-256 key, and chained: each record names the
// SHA-256 of the previous record's payload (the signed Statement bytes).
//
// The package does no I/O. internal/state keeps the key and the record
// files; the commands read them.
package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
)

// PayloadType is the DSSE payload type of an in-toto Statement.
const PayloadType = "application/vnd.in-toto+json"

// Envelope is a DSSE v1 envelope in its JSON form.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature: ASN.1 DER ECDSA over SHA-256 of the
// pre-authentication encoding, base64.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE is DSSE's pre-authentication encoding of a payload.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Key is the host's signing key.
type Key struct {
	priv *ecdsa.PrivateKey
	// ID is the hex SHA-256 of the public key's SubjectPublicKeyInfo DER.
	ID string
	// PublicDER is the public key's SubjectPublicKeyInfo DER.
	PublicDER []byte
}

// NewKey makes a P-256 key.
func NewKey() (*Key, error) {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return fromPrivate(p)
}

func fromPrivate(p *ecdsa.PrivateKey) (*Key, error) {
	der, err := x509.MarshalPKIXPublicKey(&p.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Key{priv: p, ID: KeyID(der), PublicDER: der}, nil
}

// KeyID is the hex SHA-256 of a SubjectPublicKeyInfo DER.
func KeyID(spki []byte) string {
	s := sha256.Sum256(spki)
	return hex.EncodeToString(s[:])
}

// MarshalPrivate returns the private key as PKCS#8 PEM.
func (k *Key) MarshalPrivate() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicPEM returns the public key as PEM ("PUBLIC KEY").
func (k *Key) PublicPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: k.PublicDER})
}

// ParseError is a key file that does not parse.
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return "evidence: " + e.Msg }

// ParsePrivate reads a PKCS#8 PEM P-256 key. A key that does not parse
// is a *ParseError.
func ParsePrivate(b []byte) (*Key, error) {
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, &ParseError{"key is not one PKCS#8 PEM block"}
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, &ParseError{err.Error()}
	}
	p, ok := k.(*ecdsa.PrivateKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, &ParseError{"key is not ECDSA P-256"}
	}
	return fromPrivate(p)
}

// ParsePublic reads a PEM or DER SubjectPublicKeyInfo P-256 key.
func ParsePublic(b []byte) (*ecdsa.PublicKey, []byte, error) {
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		if blk.Type != "PUBLIC KEY" {
			return nil, nil, fmt.Errorf("evidence: PEM block %q, want PUBLIC KEY", blk.Type)
		}
		der = blk.Bytes
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, err
	}
	p, ok := k.(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, nil, errors.New("evidence: public key is not ECDSA P-256")
	}
	return p, der, nil
}

// Sign wraps payload in a signed envelope.
func (k *Key) Sign(payload []byte) (*Envelope, error) {
	h := sha256.Sum256(PAE(PayloadType, payload))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, h[:])
	if err != nil {
		return nil, err
	}
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// ErrSignature is a signature that does not verify.
var ErrSignature = errors.New("evidence: signature does not verify")

// Verify checks that one signature by pub (SPKI DER) is valid and returns
// the payload. Signatures by other keys are ignored; at least one must be
// by pub.
func (e *Envelope) Verify(pub *ecdsa.PublicKey, spki []byte) ([]byte, error) {
	if e.PayloadType != PayloadType {
		return nil, fmt.Errorf("evidence: payload type %q", e.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("evidence: payload: %w", err)
	}
	h := sha256.Sum256(PAE(e.PayloadType, payload))
	id := KeyID(spki)
	for _, s := range e.Signatures {
		if s.KeyID != id {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			continue
		}
		if ecdsa.VerifyASN1(pub, h[:], sig) {
			return payload, nil
		}
	}
	return nil, ErrSignature
}

// Marshal is the file form of an envelope: compact JSON and a newline.
func (e *Envelope) Marshal() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Digest is "sha256:" and the hex SHA-256 of b.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
