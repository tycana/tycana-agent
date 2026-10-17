// Package agent is tycanad's loop (tycana-hq ADR 0025): at each cycle it
// collects the host's state, signs a host-inventory and a host-assessment
// record with the host key, and keeps them in the state directory. It
// honours the local halt file and checks its own binary at start.
package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// ConfigPath is the agent's configuration file. /etc/tycana is
// root-owned; the file holds no secret, so the CLI reads the tags from it.
const ConfigPath = "/etc/tycana/tycanad.yaml"

// Config is /etc/tycana/tycanad.yaml. Every field is optional.
type Config struct {
	// Interval is the time between cycles.
	Interval Duration `yaml:"interval"`
	// RetentionDays is how long records stay in the state directory.
	// The newest MinRecords records are always kept.
	RetentionDays int `yaml:"retention_days"`
	// Exceptions is a baseline exceptions file (version 1).
	Exceptions string `yaml:"exceptions"`
	// BaselineTarget is the target percent of the score of the checked
	// rules (0: the default, 95).
	BaselineTarget float64 `yaml:"baseline_target"`
	// Tags are the operator's key=value statements about the host
	// (tycana-hq ADR 0031): "owner", "client", "internet" (yes or no),
	// and others. The agent signs them in each record as given and
	// never infers them.
	Tags map[string]string `yaml:"tags"`
}

// Defaults: one cycle each hour, 30 days of records on the host (Mark,
// 2026-10-17, tycana-hq old inbox item 1.1, answer 2 A). Older evidence
// lives in the exports the operator keeps.
const (
	DefaultInterval      = time.Hour
	DefaultRetentionDays = 30
	// MinInterval and MinRecords bound a hostile or mistaken
	// configuration (Fable review of ADR 0025).
	MinInterval = 5 * time.Minute
	MinRecords  = 50
)

// Duration is a time.Duration written as "1h" or "90m".
type Duration time.Duration

// UnmarshalYAML reads a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

const maxConfig = 64 << 10

// LoadConfig reads the configuration. A missing file gives the defaults.
// Unknown fields are errors.
func LoadConfig(path string) (Config, error) {
	c := Config{}
	f, err := os.Open(path) //nolint:gosec // the unit's fixed configuration path
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return c.withDefaults()
	case err != nil:
		return c, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return c, err
	}
	if len(b) > maxConfig {
		return c, fmt.Errorf("%s is larger than 64 KiB", path)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c.withDefaults()
}

func (c Config) withDefaults() (Config, error) {
	if c.Interval == 0 {
		c.Interval = Duration(DefaultInterval)
	}
	if time.Duration(c.Interval) < MinInterval {
		return c, fmt.Errorf("interval %s is less than %s", time.Duration(c.Interval), MinInterval)
	}
	switch {
	case c.RetentionDays == 0:
		c.RetentionDays = DefaultRetentionDays
	case c.RetentionDays < 0:
		return c, fmt.Errorf("retention_days %d is negative", c.RetentionDays)
	}
	if c.BaselineTarget < 0 || c.BaselineTarget > 100 {
		return c, fmt.Errorf("baseline_target %v is not a percent", c.BaselineTarget)
	}
	if err := checkTags(c.Tags); err != nil {
		return c, err
	}
	return c, nil
}

// Limits of the tags: a tag is data from the operator, shown and never
// interpreted, and it goes into every record.
const (
	MaxTags     = 16
	MaxTagValue = 128
)

var tagKey = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,31}$`)

func checkTags(tags map[string]string) error {
	if len(tags) > MaxTags {
		return fmt.Errorf("tags: %d tags, at most %d", len(tags), MaxTags)
	}
	for k, v := range tags {
		if !tagKey.MatchString(k) {
			return fmt.Errorf("tags: key %q: use 1 to 32 characters a-z, 0-9, _ . -, starting with a letter", k)
		}
		if len(v) > MaxTagValue || !utf8.ValidString(v) {
			return fmt.Errorf("tags: %s: the value is longer than %d bytes or not UTF-8", k, MaxTagValue)
		}
		for _, r := range v {
			if !unicode.IsPrint(r) {
				return fmt.Errorf("tags: %s: the value has a control character", k)
			}
		}
		if k == "internet" && v != "yes" && v != "no" {
			return fmt.Errorf("tags: internet is %q; use yes or no", v)
		}
	}
	return nil
}
