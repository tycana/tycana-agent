package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
)

// fixture is everything a baseline run read from a host, so a lab run can
// be replayed in tests (testdata/lab/*/baseline-*.json.gz).
type fixture struct {
	OS            string                       `json:"os"`
	PackageFormat string                       `json:"package_format"`
	Packages      map[string][]string          `json:"packages"`
	Units         map[string]map[string]string `json:"units"`
	Wanted        []string                     `json:"wanted"`
	Mounts        []Mount                      `json:"mounts"`
	OverflowUID   uint32                       `json:"overflow_uid"`
	OverflowGID   uint32                       `json:"overflow_gid"`
	UserNS        bool                         `json:"user_ns"`
	Sandboxed     bool                         `json:"sandboxed"`
	Container     bool                         `json:"container"`
	Stats         map[string]fixStat           `json:"stats"`
	Files         map[string]fixFile           `json:"files"`
	Dirs          map[string]fixDir            `json:"dirs"`
}

type fixStat struct {
	Meta *Meta  `json:"meta,omitempty"`
	Err  string `json:"err,omitempty"`
}

type fixFile struct {
	Data []byte `json:"data,omitempty"`
	Err  string `json:"err,omitempty"`
}

type fixDir struct {
	Names []string `json:"names,omitempty"`
	Err   string   `json:"err,omitempty"`
}

func errKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrNotExist):
		return "notexist"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	}
	return err.Error()
}

func kindErr(op, path, kind string) error {
	switch kind {
	case "":
		return nil
	case "notexist":
		return &fs.PathError{Op: op, Path: path, Err: fs.ErrNotExist}
	case "permission":
		return &fs.PathError{Op: op, Path: path, Err: fs.ErrPermission}
	}
	return &fs.PathError{Op: op, Path: path, Err: errors.New(kind)}
}

// scrubRE matches the lab user's name in passwd and group lines.
var scrubRE = regexp.MustCompile(`\b` + regexp.QuoteMeta(os.Getenv("TYCANA_CAPTURE_SCRUB")) + `\b`)

// record wraps h so that every read lands in a fixture.
func record(h *Host, osName string) (*Host, *fixture) {
	f := &fixture{
		OS: osName, PackageFormat: h.PackageFormat, Packages: h.Packages, Units: h.Units,
		Wanted: h.Wanted, Mounts: h.Mounts, OverflowUID: h.OverflowUID, OverflowGID: h.OverflowGID,
		UserNS: h.UserNS, Sandboxed: h.Sandboxed, Container: h.Container,
		Stats: map[string]fixStat{}, Files: map[string]fixFile{}, Dirs: map[string]fixDir{},
	}
	r := *h
	r.Stat = func(p string) (Meta, error) {
		m, err := h.Stat(p)
		s := fixStat{Err: errKind(err)}
		if err == nil {
			s.Meta = &m
		}
		f.Stats[p] = s
		return m, err
	}
	r.ReadFile = func(p string) ([]byte, error) {
		b, err := h.ReadFile(p)
		data := b
		if os.Getenv("TYCANA_CAPTURE_SCRUB") != "" && (p == "/etc/passwd" || p == "/etc/group") {
			data = scrubRE.ReplaceAll(b, []byte("operator"))
		}
		f.Files[p] = fixFile{Data: data, Err: errKind(err)}
		return b, err
	}
	r.ReadDir = func(p string) ([]fs.DirEntry, error) {
		ents, err := h.ReadDir(p)
		d := fixDir{Err: errKind(err)}
		for _, e := range ents {
			d.Names = append(d.Names, e.Name())
		}
		f.Dirs[p] = d
		return ents, err
	}
	return &r, f
}

// replay builds a Host from a fixture. A read the fixture lacks is an
// error, so a test notices when a check reads something new.
func replay(f *fixture) *Host {
	return &Host{
		Root: "/", PackageFormat: f.PackageFormat, Packages: f.Packages, Units: f.Units,
		Wanted: f.Wanted, Mounts: f.Mounts, OverflowUID: f.OverflowUID, OverflowGID: f.OverflowGID,
		UserNS: f.UserNS, Sandboxed: f.Sandboxed, Container: f.Container,
		Stat: func(p string) (Meta, error) {
			s, ok := f.Stats[p]
			if !ok {
				return Meta{}, fmt.Errorf("fixture has no stat of %s", p)
			}
			if s.Meta == nil {
				return Meta{}, kindErr("lstat", p, s.Err)
			}
			return *s.Meta, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			x, ok := f.Files[p]
			if !ok {
				return nil, fmt.Errorf("fixture has no content of %s", p)
			}
			return x.Data, kindErr("open", p, x.Err)
		},
		ReadDir: func(p string) ([]fs.DirEntry, error) {
			d, ok := f.Dirs[p]
			if !ok {
				return nil, fmt.Errorf("fixture has no listing of %s", p)
			}
			var out []fs.DirEntry
			for _, n := range slices.Sorted(slices.Values(d.Names)) {
				out = append(out, nameEntry(n))
			}
			return out, kindErr("readdir", p, d.Err)
		},
	}
}

// nameEntry is a DirEntry that knows only its name; the checks stat each
// entry themselves.
type nameEntry string

func (n nameEntry) Name() string               { return string(n) }
func (n nameEntry) IsDir() bool                { return false }
func (n nameEntry) Type() fs.FileMode          { return 0 }
func (n nameEntry) Info() (fs.FileInfo, error) { return nil, errors.New("not recorded") }
