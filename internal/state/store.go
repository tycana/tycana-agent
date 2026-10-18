package state

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"tycana.ai/agent/evidence"
)

// DefaultDir is the unit's StateDirectory.
const DefaultDir = "/var/lib/tycanad"

const (
	keyDir     = "key"
	keyFile    = "host.key"
	pubFile    = "host.pub"
	publicDir  = "public"
	recordsDir = "records"
	maxRecord  = 64 << 20
)

// Store is the state directory.
type Store struct {
	dir string
}

// Open opens the state directory, and makes its key and records
// directories (mode 0700) when they are absent. dir itself must exist:
// systemd makes it for the unit.
func Open(dir string) (*Store, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("state: %s is not a directory", dir)
	}
	for _, d := range []string{keyDir, recordsDir} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

// Reader opens an existing state directory to read only. It makes
// nothing.
func Reader(dir string) *Store { return &Store{dir: dir} }

// Dir is the state directory.
func (s *Store) Dir() string { return s.dir }

// Key reads the host key. It returns fs.ErrNotExist when there is none.
func (s *Store) Key() (*evidence.Key, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, keyDir, keyFile))
	if err != nil {
		return nil, err
	}
	return evidence.ParsePrivate(b)
}

// PublicKey reads the host's public key PEM.
func (s *Store) PublicKey() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, keyDir, pubFile))
}

// PublicKeys reads every public key the store has made, by key id.
func (s *Store) PublicKeys() (map[string][]byte, error) {
	dir := filepath.Join(s.dir, keyDir, publicDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".pub")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a file of the store's key directory
		if err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, nil
}

// CreateKey makes a new host key and keeps it (private 0600, public
// 0644, both in the 0700 key directory). An existing key is replaced
// only when replace is true.
func (s *Store) CreateKey(replace bool) (*evidence.Key, error) {
	path := filepath.Join(s.dir, keyDir, keyFile)
	if _, err := os.Lstat(path); err == nil && !replace {
		return nil, fmt.Errorf("state: %s exists", path)
	}
	k, err := evidence.NewKey()
	if err != nil {
		return nil, err
	}
	priv, err := k.MarshalPrivate()
	if err != nil {
		return nil, err
	}
	// Every public key stays, so that a bundle can verify records
	// signed before a new key.
	if err := os.Mkdir(filepath.Join(s.dir, keyDir, publicDir), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := s.write(filepath.Join(s.dir, keyDir, publicDir), k.ID+".pub", k.PublicPEM(), 0o644); err != nil {
		return nil, err
	}
	if err := s.write(filepath.Join(s.dir, keyDir), pubFile, k.PublicPEM(), 0o644); err != nil {
		return nil, err
	}
	if err := s.write(filepath.Join(s.dir, keyDir), keyFile, priv, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// Record is one record file in the store.
type Record struct {
	Sequence uint64
	Type     string
	Path     string
}

// Records are kept gzipped: an inventory of 2,587 packages is 1.58 MB
// as JSON and 0.29 MB gzipped (Fedora 44, 2026-10-17). The chain hashes
// the decoded payload, so the file form does not matter to it.
var recordRE = regexp.MustCompile(`^([0-9]{10})\.([a-z-]+)\.json\.gz$`)

// Records lists the records in sequence order. Other files are ignored.
func (s *Store) Records() ([]Record, error) {
	ents, err := os.ReadDir(filepath.Join(s.dir, recordsDir))
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range ents {
		m := recordRE.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		n, _ := strconv.ParseUint(m[1], 10, 64)
		out = append(out, Record{Sequence: n, Type: m[2], Path: filepath.Join(s.dir, recordsDir, e.Name())})
	}
	slices.SortFunc(out, func(a, b Record) int {
		switch {
		case a.Sequence < b.Sequence:
			return -1
		case a.Sequence > b.Sequence:
			return 1
		}
		return 0
	})
	return out, nil
}

// ReadRecord reads one record: the envelope JSON, at most 64 MiB once
// decompressed.
func ReadRecord(r Record) ([]byte, error) {
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("state: %s is not a regular file", r.Path)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("state: %s: %w", r.Path, err)
	}
	b, err := io.ReadAll(io.LimitReader(zr, maxRecord+1))
	if err != nil {
		return nil, fmt.Errorf("state: %s: %w", r.Path, err)
	}
	if len(b) > maxRecord {
		return nil, fmt.Errorf("state: %s is larger than 64 MiB", r.Path)
	}
	return b, nil
}

// Append keeps a new record. It never replaces one: a sequence number
// that exists is an error.
func (s *Store) Append(seq uint64, typ string, raw []byte) error {
	name := fmt.Sprintf("%010d.%s.json.gz", seq, typ)
	if !recordRE.MatchString(name) {
		return fmt.Errorf("state: record name %q is not valid", name)
	}
	recs, err := s.Records()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(recs, func(r Record) bool { return r.Sequence == seq }) {
		return fmt.Errorf("state: record %d exists", seq)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return s.write(filepath.Join(s.dir, recordsDir), name, buf.Bytes(), 0o600)
}

// Remove deletes one record (retention).
func (s *Store) Remove(r Record) error {
	if filepath.Dir(r.Path) != filepath.Join(s.dir, recordsDir) || !recordRE.MatchString(filepath.Base(r.Path)) {
		return fmt.Errorf("state: %s is not a record of this store", r.Path)
	}
	return os.Remove(r.Path)
}

// write puts data in dir/name atomically: a temporary file in dir,
// synced, renamed over name, and the directory synced.
func (s *Store) write(dir, name string, data []byte, mode os.FileMode) (err error) {
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // a directory of the store
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

const haltFile = "halt.json"

// HaltMarker reads the halt marker: when the agent first and last saw
// the halt file. It returns nil when there is none.
func (s *Store) HaltMarker() (*evidence.Halt, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, haltFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var h evidence.Halt
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("state: %s: %w", haltFile, err)
	}
	return &h, nil
}

// SetHaltMarker keeps the halt marker.
func (s *Store) SetHaltMarker(h evidence.Halt) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return s.write(s.dir, haltFile, b, 0o600)
}

// ClearHaltMarker removes the halt marker.
func (s *Store) ClearHaltMarker() error {
	err := os.Remove(filepath.Join(s.dir, haltFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

const overrunFile = "cycle-limit.json"

// Overrun is a run of cycles that did not finish within the cycle time
// limit (tycana-hq ADR 0025 item 7). The agent keeps it before it exits,
// and the next record carries it as an error.
type Overrun struct {
	// First and Last are the start times of the first and the last cycle
	// that did not finish.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Count int       `json:"count"`
	// Step is the collector that was running at the limit.
	Step string `json:"step,omitempty"`
}

// Message is the error text of the next record.
func (o Overrun) Message(limit time.Duration) string {
	m := fmt.Sprintf("%d cycle(s) did not finish within %s (started %s", o.Count, limit, o.First.Format(time.RFC3339))
	if o.Count > 1 {
		m += " to " + o.Last.Format(time.RFC3339)
	}
	m += "); the agent stopped and started again"
	if o.Step != "" {
		m += "; the step at the limit: " + o.Step
	}
	return m
}

// OverrunMarker reads the cycle-limit marker. It returns nil when there
// is none.
func (s *Store) OverrunMarker() (*Overrun, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, overrunFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o Overrun
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("state: %s: %w", overrunFile, err)
	}
	return &o, nil
}

// SetOverrunMarker keeps the cycle-limit marker.
func (s *Store) SetOverrunMarker(o Overrun) error {
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return s.write(s.dir, overrunFile, b, 0o600)
}

// ClearOverrunMarker removes the cycle-limit marker.
func (s *Store) ClearOverrunMarker() error {
	err := os.Remove(filepath.Join(s.dir, overrunFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
