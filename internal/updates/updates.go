// Package updates reports the updates waiting on a host, as the host's own
// package manager computes them: apt's simulation and policy, dnf's
// check-update and updateinfo. It runs those tools only through
// internal/hostexec, read-only verbs only (ADR 0017), and never guesses an
// answer the package manager did not give.
package updates

import (
	"context"
	"strings"

	"tycana.ai/agent/internal/hostexec"
)

// Schema names the report format. Bump it on any incompatible change.
const Schema = "tycana.updates/v0"

// State says what will happen to a pending update.
type State string

// The states of a pending update.
const (
	// Upgrade: a plain upgrade ("apt-get upgrade", "dnf upgrade") installs it.
	Upgrade State = "upgrade"
	// DistUpgrade: apt keeps it back, because the new version needs new
	// packages or removals; only "apt-get dist-upgrade" installs it.
	DistUpgrade State = "dist-upgrade"
	// New: a package not installed today that the upgrade pulls in.
	New State = "new"
	// Phased: the distribution releases it to a share of hosts at a time,
	// and this host is not in that share yet.
	Phased State = "phased"
	// Held: the operator put a hold on the package.
	Held State = "held"
)

// Report is the set of updates waiting on one host.
type Report struct {
	Schema   string    `json:"schema"`
	Manager  string    `json:"manager"` // "apt" or "dnf"
	Updates  []Update  `json:"updates"`
	Removals []Removal `json:"removals,omitempty"`
}

// Update is one package with a newer version available.
type Update struct {
	Name      string   `json:"name"`
	Arch      string   `json:"arch"`
	Installed string   `json:"installed,omitempty"` // empty for State New
	Candidate string   `json:"candidate"`
	State     State    `json:"state"`
	Security  bool     `json:"security"`
	Origins   []Origin `json:"origins,omitempty"`
	// PhasedPercent is the share of hosts the update is released to, when
	// the distribution phases it.
	PhasedPercent int `json:"phased_percent,omitempty"`
}

// Origin is one archive that offers the candidate version.
type Origin struct {
	Label string `json:"label,omitempty"` // "Ubuntu", "Debian-Security"
	Suite string `json:"suite"`           // "noble-security", "bookworm-updates"
}

// Removal is a package the full upgrade would remove.
type Removal struct {
	Name      string `json:"name"`
	Arch      string `json:"arch,omitempty"`
	Installed string `json:"installed"`
}

// runner is hostexec.Run; tests replace it.
type runner func(ctx context.Context, id hostexec.ID, extra ...string) (hostexec.Result, error)

// isSecuritySuite reports a security pocket: "noble-security",
// "stable-security", "noble-apps-security" (Ubuntu Pro).
func isSecuritySuite(s string) bool { return strings.HasSuffix(s, "-security") }
