package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBenchmark(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yml")
	const doc = `
levels:
  - id: l1_server
  - id: l2_server
    inherits_from: [l1_server]
controls:
  - id: "1"
    title: Section
    controls:
      - id: "1.1"
        title: Ensure a (Automated)
        levels: [l1_server]
        rules: [rule_b, rule_a, var_x=1, rule_a]
      - id: "1.2"
        title: Ensure b (Manual)
        levels: [l1_server]
        rules: [rule_c]
      - id: "1.3"
        title: Ensure c (Automated)
        levels: [l2_server]
        rules: [rule_d]
      - id: "1.4"
        title: Ensure d (Automated)
        levels: [l1_server]
`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	bm, err := benchmark(p, "l1_server")
	if err != nil {
		t.Fatal(err)
	}
	if bm.Automated != 2 || !reflect.DeepEqual(bm.Recommendations, [][]string{{"rule_a", "rule_b"}}) {
		t.Errorf("l1: got %+v", bm)
	}
	bm, err = benchmark(p, "l2_server")
	if err != nil {
		t.Fatal(err)
	}
	if bm.Automated != 3 || len(bm.Recommendations) != 2 {
		t.Errorf("l2: got %+v", bm)
	}
	if _, err := benchmark(p, "l3"); err == nil {
		t.Error("unknown level accepted")
	}
}
