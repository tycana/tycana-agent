package buildinfo

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestGetHasRuntimeFields(t *testing.T) {
	i := Get()
	if i.Version == "" || i.GoVersion == "" || i.OS == "" || i.Arch == "" {
		t.Fatalf("missing fields: %+v", i)
	}
}

func TestWriteText(t *testing.T) {
	var b bytes.Buffer
	i := Info{Version: "1.2.3", Commit: "0123456789abcdef", Date: "2026-10-15T00:00:00Z", GoVersion: "go1.27", OS: "linux", Arch: "amd64"}
	if err := i.Write(&b, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"tycana 1.2.3", "0123456789ab", "2026-10-15", "linux/amd64"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0123456789abc") {
		t.Errorf("commit not truncated to 12:\n%s", out)
	}
}

func TestWriteJSON(t *testing.T) {
	var b bytes.Buffer
	i := Info{Version: "1.2.3", GoVersion: "go1.27", OS: "linux", Arch: "arm64"}
	if err := i.Write(&b, true); err != nil {
		t.Fatal(err)
	}
	var got Info
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b.String())
	}
	if got != i {
		t.Errorf("round trip mismatch: %+v != %+v", got, i)
	}
}
