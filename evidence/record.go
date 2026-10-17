package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StatementType is the in-toto Statement v1 type.
const StatementType = "https://in-toto.io/Statement/v1"

// Record types and their predicate types.
const (
	TypeHostInventory  = "host-inventory"
	TypeHostAssessment = "host-assessment"
	predicateBase      = "https://tycana.ai/attestations/"
	predicateVersion   = "/v0.1"
)

// PredicateType returns the predicate type URI of a record type.
func PredicateType(recordType string) string {
	return predicateBase + recordType + predicateVersion
}

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Subject is an in-toto resource descriptor.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Header is the part of every predicate that the chain and a verifier
// read.
type Header struct {
	Record RecordInfo `json:"record"`
	Host   HostInfo   `json:"host"`
	Agent  AgentInfo  `json:"agent"`
	// Errors names each collector that failed in this cycle. A record
	// with errors is incomplete, and says so.
	Errors []CollectError `json:"errors,omitempty"`
	// Halted is set on the records of the first cycle after a halt: the
	// operator's halt file stopped the agent between From and To (the
	// first and the last cycle that saw it). It tells a halt from an
	// agent that did not run (Mark, 2026-10-17, ADR 0025).
	Halted *Halt `json:"halted,omitempty"`
	// Operator is what the operator states about the host in the
	// agent's configuration (tycana-hq ADR 0031). It is the operator's
	// statement, signed as given; the agent did not observe it.
	Operator *Operator `json:"operator,omitempty"`
}

// Operator is the operator's statement about a host.
type Operator struct {
	// Tags are key=value pairs: the well-known keys "owner", "client",
	// and "internet" ("yes" or "no"), and any others.
	Tags map[string]string `json:"tags,omitempty"`
}

// Halt is a period in which the halt file stopped the agent.
type Halt struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// RecordInfo places a record in the host's chain.
type RecordInfo struct {
	Type     string `json:"type"`
	Sequence uint64 `json:"sequence"`
	// Previous is Digest of the previous record's payload; empty for
	// the first record of a store.
	Previous string `json:"previous,omitempty"`
	// PreviousKeyID is set when the previous record was signed by a
	// different key: the key was lost or replaced.
	PreviousKeyID string    `json:"previous_key_id,omitempty"`
	Created       time.Time `json:"created"`
	// Cycle groups the records of one collection.
	Cycle uint64 `json:"cycle"`
}

// HostInfo identifies the host.
type HostInfo struct {
	// ID is systemd's application-specific machine id for Tycana.
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	BootID    string `json:"boot_id,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
}

// AgentInfo identifies the agent binary that made the record.
type AgentInfo struct {
	Version      string `json:"version"`
	Commit       string `json:"commit,omitempty"`
	BinarySHA256 string `json:"binary_sha256"`
	// SelfCheck is how the binary was checked at start: package:dpkg,
	// package:rpm, previous-record, or none.
	SelfCheck string `json:"self_check"`
}

// CollectError is one collector that failed.
type CollectError struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

// SubjectName is the in-toto subject name of a host.
func SubjectName(hostID string) string { return "tycana-host:" + hostID }

// NewStatement builds the payload of one record. body holds the
// record's own fields; they are merged after the header's.
func NewStatement(h Header, spki []byte, body any) ([]byte, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	bb, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	pred := hb
	if len(bb) > 2 && bb[0] == '{' {
		// Concatenate the two objects: header fields, then body fields.
		pred = append(append(hb[:len(hb)-1:len(hb)-1], ','), bb[1:]...)
	}
	return json.Marshal(Statement{
		Type:          StatementType,
		Subject:       []Subject{{Name: SubjectName(h.Host.ID), Digest: map[string]string{"sha256": KeyID(spki)}}},
		PredicateType: PredicateType(h.Record.Type),
		Predicate:     pred,
	})
}

// Checked is one record after verification.
type Checked struct {
	Header    Header
	Statement Statement
	Payload   []byte
	KeyID     string
}

// Open verifies an envelope with one of keys (keyed by key id) and parses
// its Statement and header. It checks that the subject names the signing
// key and that the predicate type matches the record type.
func Open(raw []byte, keys map[string]*ecdsa.PublicKey, ders map[string][]byte) (*Checked, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("evidence: envelope: %w", err)
	}
	var payload []byte
	var keyID string
	for _, s := range e.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok {
			continue
		}
		p, err := e.Verify(pub, ders[s.KeyID])
		if err == nil {
			payload, keyID = p, s.KeyID
			break
		}
	}
	if payload == nil {
		return nil, ErrSignature
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("evidence: statement: %w", err)
	}
	var h Header
	if err := json.Unmarshal(st.Predicate, &h); err != nil {
		return nil, fmt.Errorf("evidence: predicate: %w", err)
	}
	switch {
	case st.Type != StatementType:
		return nil, fmt.Errorf("evidence: statement type %q", st.Type)
	case st.PredicateType != PredicateType(h.Record.Type):
		return nil, fmt.Errorf("evidence: predicate type %q for record type %q", st.PredicateType, h.Record.Type)
	case len(st.Subject) != 1 || st.Subject[0].Name != SubjectName(h.Host.ID) || st.Subject[0].Digest["sha256"] != keyID:
		return nil, errors.New("evidence: subject does not name this host and its signing key")
	}
	return &Checked{Header: h, Statement: st, Payload: payload, KeyID: keyID}, nil
}

// ChainReport is the outcome of checking a sequence of records.
type ChainReport struct {
	Records int `json:"records"`
	// First and Last are the sequence numbers held.
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
	// Breaks lists every place where the chain does not continue: a
	// missing sequence number, a wrong previous digest, or a key change.
	Breaks []string `json:"breaks,omitempty"`
	// Invalid lists records whose signature or form failed.
	Invalid []string  `json:"invalid,omitempty"`
	Hosts   []string  `json:"hosts,omitempty"`
	From    time.Time `json:"from,omitzero"`
	To      time.Time `json:"to,omitzero"`
}

// OK reports whether every record verified and the chain has no break.
func (r *ChainReport) OK() bool { return r.Records > 0 && len(r.Breaks) == 0 && len(r.Invalid) == 0 }

// VerifyChain checks records in sequence order. A key change is a break
// even when the record names the previous key: the verifier holds no
// proof that the old key handed over to the new one.
func VerifyChain(raws [][]byte, keys map[string]*ecdsa.PublicKey, ders map[string][]byte) ChainReport {
	var r ChainReport
	var prev *Checked
	hosts := map[string]bool{}
	for i, raw := range raws {
		c, err := Open(raw, keys, ders)
		if err != nil {
			r.Invalid = append(r.Invalid, fmt.Sprintf("record %d in the bundle: %v", i+1, err))
			prev = nil
			continue
		}
		r.Records++
		h := c.Header.Record
		if !hosts[c.Header.Host.ID] {
			hosts[c.Header.Host.ID] = true
			r.Hosts = append(r.Hosts, c.Header.Host.ID)
		}
		if r.Records == 1 {
			r.First, r.From = h.Sequence, h.Created
		}
		r.Last, r.To = h.Sequence, h.Created
		if prev != nil {
			p := prev.Header.Record
			switch {
			case h.Sequence != p.Sequence+1:
				r.Breaks = append(r.Breaks, fmt.Sprintf("sequence %d follows %d", h.Sequence, p.Sequence))
			case h.Previous != Digest(prev.Payload):
				r.Breaks = append(r.Breaks, fmt.Sprintf("record %d does not name record %d as previous", h.Sequence, p.Sequence))
			case c.KeyID != prev.KeyID:
				r.Breaks = append(r.Breaks, fmt.Sprintf("record %d is signed by a new key %s", h.Sequence, short(c.KeyID)))
			case h.Created.Before(p.Created):
				r.Breaks = append(r.Breaks, fmt.Sprintf("record %d is older than record %d", h.Sequence, p.Sequence))
			}
		}
		prev = c
	}
	if len(r.Hosts) > 1 {
		r.Breaks = append(r.Breaks, fmt.Sprintf("records of %d hosts", len(r.Hosts)))
	}
	return r
}

func short(id string) string {
	if len(id) > 16 {
		return id[:16]
	}
	return id
}

// AppSpecificID is systemd's sd_id128_get_machine_app_specific: HMAC-SHA256
// of app keyed with the machine id, first 16 bytes, made a version 4
// UUID, in lower-case hex without dashes.
func AppSpecificID(machineID, app [16]byte) string {
	sum := hmacSHA256(machineID[:], app[:])
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return hex.EncodeToString(id[:])
}
