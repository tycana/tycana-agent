package baseline

import (
	"fmt"
	"time"
)

// Status is the verdict for one check on one host.
//
// Only Fail lowers the score. A check the agent could not evaluate is
// never counted as failed: NotApplicable, Unknown, and Error are each
// reported with a reason, and an auditor sees how many there were.
type Status string

const (
	// Pass means the host meets the check.
	Pass Status = "pass"
	// Fail means the agent read the host and it does not meet the check.
	Fail Status = "fail"
	// NotApplicable means a condition in the check's "when" list does not
	// hold on this host (for example, the package is not installed).
	NotApplicable Status = "not_applicable"
	// Unknown means the agent could not read what the check needs: the
	// file is unreadable to its unprivileged user, the sandbox hides it,
	// or the host reports an owner the agent cannot see through.
	Unknown Status = "unknown"
	// Error means the check itself is faulty: a content bug, such as a
	// value that does not parse or a variable that has no value. It says
	// nothing about the host.
	Error Status = "error"
	// Excepted means an exception covers the check. The result the agent
	// found is kept in Result.Found.
	Excepted Status = "excepted"
)

// Result is one check's verdict.
type Result struct {
	ID       string              `json:"id"`
	Title    string              `json:"title"`
	Severity string              `json:"severity,omitempty"`
	Refs     map[string][]string `json:"refs,omitempty"`
	Status   Status              `json:"status"`
	// Reason says why, in one line: what was found against what was
	// expected, or what could not be read.
	Reason string `json:"reason,omitempty"`
	// Found is the status before an exception applied.
	Found     Status     `json:"found,omitempty"`
	Exception *Exception `json:"exception,omitempty"`
}

// Report is the outcome of one baseline on one host.
type Report struct {
	Baseline  string    `json:"baseline"`
	Title     string    `json:"title"`
	Source    Source    `json:"source"`
	Collected time.Time `json:"collected"`
	Results   []Result  `json:"results"`
	// NotCovered lists the source rules this baseline does not evaluate.
	NotCovered []Uncovered `json:"not_covered,omitempty"`
	Score      Score       `json:"score"`
}

// Score is passed checks over evaluated checks, with the coverage of the
// source profile beside it. Evaluated means Pass or Fail. Excepted,
// not-applicable, unknown, and faulty checks are outside both numbers and
// counted separately. Percent is not a compliance score for the profile:
// it says nothing about the NotCovered rules, so a report must show
// Coverage with it (Mark, 2026-10-16).
type Score struct {
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Excepted      int `json:"excepted"`
	NotApplicable int `json:"not_applicable"`
	Unknown       int `json:"unknown"`
	Errors        int `json:"errors"`
	NotCovered    int `json:"not_covered"`
	// Rules is the number of rules in the source profile: the checks
	// of the baseline plus NotCovered.
	Rules int `json:"rules"`
	// Coverage is checks / Rules * 100, rounded down to one decimal
	// place. It counts profile rules, not benchmark recommendations; one
	// recommendation can need several rules, so coverage of the benchmark
	// is lower (47-49% for the M3 presets, measured 2026-10-16).
	Coverage float64 `json:"coverage_percent"`
	// Percent is Passed / (Passed + Failed) * 100, rounded down to one
	// decimal place. It is 0 when nothing was evaluated.
	Percent float64 `json:"percent"`
	// Target is the policy's target percent (default 95, spec §4).
	Target float64 `json:"target"`
	// Met is Percent >= Target, and false when nothing was evaluated.
	Met bool `json:"met"`
}

// DefaultTarget is the target score without a policy (Mark, 2026-10-15:
// operators aim at 93 to 97 percent, not 100).
const DefaultTarget = 95

func score(results []Result, notCovered int, target float64) Score {
	s := Score{NotCovered: notCovered, Rules: len(results) + notCovered, Target: target}
	if s.Rules > 0 {
		s.Coverage = float64(len(results)*1000/s.Rules) / 10
	}
	for _, r := range results {
		switch r.Status {
		case Pass:
			s.Passed++
		case Fail:
			s.Failed++
		case Excepted:
			s.Excepted++
		case NotApplicable:
			s.NotApplicable++
		case Unknown:
			s.Unknown++
		case Error:
			s.Errors++
		default:
			panic(fmt.Sprintf("baseline: result %q has status %q", r.ID, r.Status))
		}
	}
	if n := s.Passed + s.Failed; n > 0 {
		// Round down so that 94.96 never shows as a met 95.0.
		s.Percent = float64(s.Passed*1000/n) / 10
		s.Met = s.Percent >= s.Target
	}
	return s
}
