package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"tycana.ai/agent/internal/baseline"
)

func TestWriteBaselineText(t *testing.T) {
	r := baseline.Report{
		Title:  "Ubuntu 24.04 level 1 server baseline",
		Source: baseline.Source{Project: "ComplianceAsCode", Commit: "4ab60a5b8964df4c49ddf751e491d97157f19b64", Product: "ubuntu2404", License: "BSD-3-Clause"},
		Results: []baseline.Result{
			{ID: "a_pass", Status: baseline.Pass},
			{ID: "b_fail", Status: baseline.Fail, Severity: "medium", Reason: "/etc/passwd is 0666"},
			{ID: "a_low", Status: baseline.Fail, Severity: "low", Reason: "x"},
			{ID: "z_high", Status: baseline.Fail, Severity: "high", Reason: "y"},
			{ID: "c_unknown", Status: baseline.Unknown, Reason: "not readable without privilege"},
			{ID: "d_exc", Status: baseline.Excepted, Found: baseline.Fail,
				Exception: &baseline.Exception{Reason: "legacy app", Owner: "ops", Expires: "2027-01-31"}},
		},
		Score: baseline.Score{Passed: 1, Failed: 1, Unknown: 1, Excepted: 1, NotCovered: 150, Rules: 156, Coverage: 3.8, Percent: 50, Target: 95},
	}
	var out bytes.Buffer
	if err := writeBaselineText(&out, r, false); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"Ubuntu 24.04 level 1 server baseline: partial assessment. Tycana has checks for 6 of the 156 rules in the source profile (3.8%); 150 rules are not checked.\n",
		"Score of the checked rules: 50.0% (1 of 2 evaluated checks pass), below the 95% target.\n",
		"1 excepted, 0 not applicable, 1 unknown",
		"150 source rules not covered",
		"ComplianceAsCode 4ab60a5b8964 (ubuntu2404)",
		"legacy app (owner ops, until 2027-01-31; found fail)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "a_pass") {
		t.Error("passed checks listed without --all")
	}
	order := []int{strings.Index(s, "z_high"), strings.Index(s, "b_fail"), strings.Index(s, "a_low"), strings.Index(s, "c_unknown")}
	if !slices.IsSorted(order) {
		t.Errorf("want failed checks first, worst severity first:\n%s", s)
	}
}
