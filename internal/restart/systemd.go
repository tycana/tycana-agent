package restart

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Unit is one running service or scope as systemd reports it. All
// strings are data from the host.
type Unit struct {
	ID string `json:"id"`
	// MainPID is the service's main process; 0 for scopes.
	MainPID int `json:"main_pid,omitempty"`
	// Start is when the main process started (a service) or when the
	// scope became active (a scope).
	Start time.Time `json:"start"`
	// Exec is the program of the first ExecStart= line.
	Exec string `json:"exec,omitempty"`
	// Service is the PAM service of a login session scope, from logind:
	// "sshd", "login", "gdm-password".
	Service string `json:"service,omitempty"`
}

// systemdTime is "--timestamp=us+utc": "Fri 2026-10-16 17:02:06.510786 UTC".
const systemdTime = "Mon 2006-01-02 15:04:05.000000 MST"

// parseShow parses "systemctl show" output for several units: blocks of
// Key=Value lines separated by blank lines.
func parseShow(b []byte) ([]Unit, error) {
	var units []Unit
	for _, block := range blocks(b) {
		var u Unit
		var execStart, active time.Time
		for k, v := range block {
			var err error
			switch k {
			case "Id":
				u.ID = v
			case "MainPID":
				u.MainPID, err = strconv.Atoi(v)
			case "ExecMainStartTimestamp":
				execStart, err = parseTime(v)
			case "ActiveEnterTimestamp":
				active, err = parseTime(v)
			case "ExecStart":
				u.Exec = execPath(v)
			}
			if err != nil {
				return nil, fmt.Errorf("restart: %s of %q: %w", k, block["Id"], err)
			}
		}
		if u.ID == "" {
			return nil, fmt.Errorf("restart: systemctl show block without Id")
		}
		u.Start = execStart
		if strings.HasSuffix(u.ID, ".scope") {
			u.Start = active
		}
		units = append(units, u)
	}
	return units, nil
}

func parseTime(v string) (time.Time, error) {
	if v == "" || v == "n/a" {
		return time.Time{}, nil
	}
	t, err := time.Parse(systemdTime, v)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// execPath takes the program from an ExecStart= value:
// "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ... }". Only an
// absolute path without control characters is accepted.
func execPath(v string) string {
	_, rest, ok := strings.Cut(v, "path=")
	if !ok {
		return ""
	}
	p, _, _ := strings.Cut(rest, " ; ")
	if !strings.HasPrefix(p, "/") || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	return p
}

// parseSessions parses "loginctl show-session -p Id,Service,Scope" into
// scope name -> PAM service.
func parseSessions(b []byte) map[string]string {
	m := map[string]string{}
	for _, block := range blocks(b) {
		if block["Scope"] != "" {
			m[block["Scope"]] = block["Service"]
		}
	}
	return m
}

// blocks splits Key=Value output into one map per blank-line-separated
// block. The first "=" separates key and value.
func blocks(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// sessionID returns "4" for "session-4.scope".
func sessionID(scope string) (string, bool) {
	id, ok := strings.CutPrefix(scope, "session-")
	if !ok {
		return "", false
	}
	return strings.CutSuffix(id, ".scope")
}
