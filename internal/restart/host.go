package restart

import "time"

// HostState is the restart state of the host as a whole (ADR 0020): the
// main result, which a restart of the listed units or a reboot clears.
type HostState struct {
	// State is "restart-needed" when a unit is inferred or possible,
	// "unknown" when a unit has no start time and none is inferred or
	// possible, and "current" otherwise. The kernel is judged apart.
	State    string `json:"state"`
	Inferred int    `json:"inferred"`
	Possible int    `json:"possible"`
	Unknown  int    `json:"unknown"`
	// LatestChange is the newest package change on the host.
	LatestChange time.Time `json:"latest_change,omitzero"`
	// PackageData is false for snapshots without package change times:
	// then "none" means only "no evidence".
	PackageData bool `json:"package_data"`
}

// Host sums the findings into the host state.
func Host(s Snapshot, r Report) HostState {
	h := HostState{PackageData: len(s.Packages) > 0}
	for _, c := range s.Packages {
		if c.Changed.After(h.LatestChange) {
			h.LatestChange = c.Changed
		}
	}
	for _, f := range r.Findings {
		switch f.Status {
		case Inferred:
			h.Inferred++
		case Possible:
			h.Possible++
		case Unknown:
			h.Unknown++
		}
	}
	switch {
	case h.Inferred+h.Possible > 0:
		h.State = "restart-needed"
	case h.Unknown > 0 || !h.PackageData:
		h.State = "unknown"
	default:
		h.State = "current"
	}
	return h
}
