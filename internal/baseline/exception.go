package baseline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"go.yaml.in/yaml/v3"
)

// Exception takes one check out of the score, with a reason (spec §4,
// ADR 0015). In M3 exceptions come from a local file; the control plane
// owns them later.
type Exception struct {
	Check    string `yaml:"check" json:"check"`
	Reason   string `yaml:"reason" json:"reason"`
	Owner    string `yaml:"owner" json:"owner"`
	Approver string `yaml:"approver,omitempty" json:"approver,omitempty"`
	// Expires is a date (2027-01-31). An expired exception no longer
	// applies, and the check counts again.
	Expires string   `yaml:"expires" json:"expires"`
	Tickets []string `yaml:"tickets,omitempty" json:"tickets,omitempty"`
}

// ExceptionFile is the local exceptions file.
type ExceptionFile struct {
	Version    int         `yaml:"version"`
	Exceptions []Exception `yaml:"exceptions"`
}

// LoadExceptions reads an exceptions file. Each exception needs a check,
// a reason, an owner, and an expiry date; an exception without them is
// an error, not ignored.
func LoadExceptions(r io.Reader) ([]Exception, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, errors.New("exceptions file larger than 4 MiB")
	}
	var f ExceptionFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("exceptions: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("exceptions: version %d not supported (want 1)", f.Version)
	}
	seen := map[string]bool{}
	for i, e := range f.Exceptions {
		switch {
		case e.Check == "":
			return nil, fmt.Errorf("exceptions: item %d has no check", i+1)
		case e.Reason == "":
			return nil, fmt.Errorf("exceptions: %s has no reason", e.Check)
		case e.Owner == "":
			return nil, fmt.Errorf("exceptions: %s has no owner", e.Check)
		case seen[e.Check]:
			return nil, fmt.Errorf("exceptions: %s is listed twice", e.Check)
		}
		if _, err := time.Parse(time.DateOnly, e.Expires); err != nil {
			return nil, fmt.Errorf("exceptions: %s: expires must be a date like 2027-01-31", e.Check)
		}
		seen[e.Check] = true
	}
	return f.Exceptions, nil
}

// applyExceptions marks the results that a current exception covers. An
// exception expires at the end of its date, in UTC.
func applyExceptions(results []Result, exc []Exception, now time.Time) {
	by := map[string]Exception{}
	for _, e := range exc {
		by[e.Check] = e
	}
	for i := range results {
		e, ok := by[results[i].ID]
		if !ok {
			continue
		}
		end, _ := time.Parse(time.DateOnly, e.Expires)
		if !now.Before(end.AddDate(0, 0, 1)) {
			continue
		}
		results[i].Found = results[i].Status
		results[i].Status = Excepted
		results[i].Exception = &e
	}
}
