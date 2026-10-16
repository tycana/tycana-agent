// Package buildinfo reports what this binary is, so an operator can match a
// running agent to a signed release (see VERIFY.md).
package buildinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Set by the linker at release time (see .goreleaser.yaml). Development builds
// fall back to module metadata from the Go toolchain.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info describes one build of the agent.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"go"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Modified  bool   `json:"modified,omitempty"`
}

// Get returns build information for the running binary.
func Get() Info {
	i := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" {
					i.Commit = s.Value
				}
			case "vcs.time":
				if i.Date == "" {
					i.Date = s.Value
				}
			case "vcs.modified":
				i.Modified = s.Value == "true"
			}
		}
	}
	return i
}

// Write prints the info as text or JSON.
func (i Info) Write(w io.Writer, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(i)
	}
	commit := i.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	if i.Modified {
		commit += " (modified)"
	}
	_, err := fmt.Fprintf(w, "tycana %s\n  commit  %s\n  built   %s\n  go      %s %s/%s\n",
		i.Version, commit, orUnknown(i.Date), i.GoVersion, i.OS, i.Arch)
	return err
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
