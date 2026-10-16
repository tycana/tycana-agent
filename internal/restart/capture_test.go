package restart

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestLabCapture is a lab tool, not a test. Cross-compiled with
// "go test -c" and run on a lab VM with TYCANA_CAPTURE_EXECS set to a
// comma-separated list of programs, it prints the Programs and Files of a
// Snapshot for them. It rebuilds the closure half of a snapshot for units
// that are no longer running, such as a ground truth captured before a
// reboot.
func TestLabCapture(t *testing.T) {
	execs := os.Getenv("TYCANA_CAPTURE_EXECS")
	if execs == "" {
		t.Skip("lab capture only: set TYCANA_CAPTURE_EXECS")
	}
	r := NewResolver("/")
	progs, files := map[string]Program{}, map[string]FileTime{}
	for _, e := range strings.Split(execs, ",") {
		addProgram(r, e, progs, files)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(Snapshot{Programs: progs, Files: files}); err != nil {
		t.Fatal(err)
	}
}
