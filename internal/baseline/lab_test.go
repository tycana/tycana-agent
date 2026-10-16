package baseline

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"tycana.ai/agent/internal/inventory"
)

// TestLabCapture is a lab tool, not a test. Cross-compiled with
// "go test -c" and run on a lab VM with TYCANA_CAPTURE_BASELINE=1, it
// evaluates the host's preset and prints a gzipped fixture of everything
// it read. TYCANA_CAPTURE_SCRUB names the lab user, replaced by
// "operator" in /etc/passwd and /etc/group.
func TestLabCapture(t *testing.T) {
	if os.Getenv("TYCANA_CAPTURE_BASELINE") == "" {
		t.Skip("lab capture only: set TYCANA_CAPTURE_BASELINE=1")
	}
	snap, _, err := inventory.Collect("/", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := PresetFor(snap.OS.ID, snap.OS.VersionID)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Collect(context.Background(), b, snap)
	if err != nil {
		t.Fatal(err)
	}
	rh, fx := record(h, snap.OS.ID+" "+snap.OS.VersionID)
	Evaluate(b, rh, nil, 0, time.Now())
	zw := gzip.NewWriter(os.Stdout)
	if err := json.NewEncoder(zw).Encode(fx); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// The lab cases: a fixture captured on a lab VM, and OpenSCAP's results
// for the same ComplianceAsCode commit and profile on the same VM state
// (baseline-openscap.tsv: rule id, result).
var labCases = []struct {
	vm, preset string
}{
	{"alma9", "almalinux9-level1-server"},
	{"debian12", "debian12-level1-server"},
	{"ubuntu2404", "ubuntu2404-level1-server"},
	// Known-bad: six settings broken by hand on the same VM (MANIFEST).
	{"ubuntu2404-bad", "ubuntu2404-level1-server"},
}

// TestLabAgreesWithOpenSCAP is the M3 promise: on the lab VMs, a check
// the agent evaluates gives OpenSCAP's verdict. Run as root (the same view
// as OpenSCAP) every evaluated check must agree. Run inside the tycanad
// sandbox a check may be unknown, but never fail where OpenSCAP passes
// (a false finding) or pass where OpenSCAP fails.
func TestLabAgreesWithOpenSCAP(t *testing.T) {
	ps, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*Baseline{}
	for _, p := range ps {
		byName[p.Name] = p
	}
	for _, c := range labCases {
		dir := filepath.Join("..", "..", "testdata", "lab", c.vm)
		oracle := readOracle(t, filepath.Join(dir, "baseline-openscap.tsv"))
		b := byName[c.preset]
		for _, view := range []string{"root", "sandbox"} {
			t.Run(c.vm+"/"+view, func(t *testing.T) {
				fx := readFixture(t, filepath.Join(dir, "baseline-"+view+".json.gz"))
				r := Evaluate(b, replay(fx), nil, 0, time.Now())
				counts := map[Status]int{}
				for _, res := range r.Results {
					counts[res.Status]++
					want, ok := oracle[res.ID]
					if !ok {
						t.Errorf("%s: no OpenSCAP result", res.ID)
						continue
					}
					got := map[Status]string{Pass: "pass", Fail: "fail", NotApplicable: "notapplicable"}[res.Status]
					switch {
					case res.Status == Error:
						t.Errorf("%s: content error: %s", res.ID, res.Reason)
					case res.Status == Unknown && view == "root":
						t.Errorf("%s: unknown as root: %s", res.ID, res.Reason)
					case res.Status == Unknown:
					case got != want:
						t.Errorf("%s: %s, OpenSCAP %s (%s)", res.ID, got, want, res.Reason)
					}
				}
				t.Logf("%s %s: %v, %d not covered", c.vm, view, counts, len(r.NotCovered))
			})
		}
	}
}

func readOracle(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if id, res, ok := strings.Cut(sc.Text(), "\t"); ok {
			out[id] = res
		}
	}
	return out
}

func readFixture(t *testing.T, path string) *fixture {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var fx fixture
	if err := json.NewDecoder(zr).Decode(&fx); err != nil {
		t.Fatal(err)
	}
	return &fx
}

// Fable review, 2026-10-16: /etc/ssh is readable in the unit, so the
// presets must never read a host key's content, only its mode and owner.
func TestNoHostKeyContentRead(t *testing.T) {
	keyRE := regexp.MustCompile(`^/etc/ssh/.*_key(\.pub)?$`)
	for _, c := range labCases {
		for _, view := range []string{"root", "sandbox"} {
			fx := readFixture(t, filepath.Join("..", "..", "testdata", "lab", c.vm, "baseline-"+view+".json.gz"))
			for p := range fx.Files {
				if keyRE.MatchString(p) {
					t.Errorf("%s %s: read the content of %s", c.vm, view, p)
				}
			}
		}
	}
}
