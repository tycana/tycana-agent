package restart

import (
	"testing"
	"time"
)

const showOutput = `MainPID=741
ExecMainStartTimestamp=Fri 2026-10-16 14:16:20.123456 UTC
ActiveEnterTimestamp=Fri 2026-10-16 14:16:21.000000 UTC
ExecStart={ path=/usr/lib/systemd/systemd-logind ; argv[]=/usr/lib/systemd/systemd-logind ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Id=systemd-logind.service

MainPID=0
ExecMainStartTimestamp=
ActiveEnterTimestamp=Fri 2026-10-16 14:16:22.712800 UTC
ExecStart=
Id=session-4.scope

MainPID=99
ExecMainStartTimestamp=n/a
ExecStart={ path=relative/evil ; argv[]=x }
Id=odd.service
`

func TestParseShow(t *testing.T) {
	units, err := parseShow([]byte(showOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 3 {
		t.Fatalf("%d units", len(units))
	}
	l := units[0]
	if l.ID != "systemd-logind.service" || l.MainPID != 741 || l.Exec != "/usr/lib/systemd/systemd-logind" ||
		!l.Start.Equal(time.Date(2026, 10, 16, 14, 16, 20, 123456000, time.UTC)) {
		t.Errorf("service: %+v", l)
	}
	s := units[1]
	if s.ID != "session-4.scope" || !s.Start.Equal(time.Date(2026, 10, 16, 14, 16, 22, 712800000, time.UTC)) {
		t.Errorf("scope start is ActiveEnterTimestamp: %+v", s)
	}
	if o := units[2]; o.Exec != "" || !o.Start.IsZero() {
		t.Errorf("relative ExecStart and n/a time: %+v", o)
	}
	if _, err := parseShow([]byte("MainPID=x\nId=a.service\n")); err == nil {
		t.Error("bad MainPID accepted")
	}
	if _, err := parseShow([]byte("MainPID=1\n")); err == nil {
		t.Error("block without Id accepted")
	}
}

func TestParseSessions(t *testing.T) {
	got := parseSessions([]byte("Id=4\nService=sshd\nScope=session-4.scope\n\nId=c1\nService=gdm-password\nScope=session-c1.scope\n"))
	if got["session-4.scope"] != "sshd" || got["session-c1.scope"] != "gdm-password" || len(got) != 2 {
		t.Errorf("%v", got)
	}
	if id, ok := sessionID("session-c1.scope"); !ok || id != "c1" {
		t.Errorf("sessionID: %q %v", id, ok)
	}
	if _, ok := sessionID("init.scope"); ok {
		t.Error("init.scope is not a session")
	}
}

func TestAnalyze(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 14, 16, 20, 0, time.UTC)
	before, after := t0.Add(-time.Hour), t0.Add(time.Hour)
	snap := Snapshot{
		Units: []Unit{
			{ID: "stale.service", MainPID: 1, Start: t0, Exec: "/bin/stale"},
			{ID: "fresh.service", MainPID: 2, Start: t0, Exec: "/bin/fresh"},
			{ID: "script.service", MainPID: 3, Start: t0, Exec: "/bin/script"},
			{ID: "script-stale.service", MainPID: 4, Start: t0, Exec: "/bin/script-stale"},
			{ID: "partial.service", MainPID: 5, Start: t0, Exec: "/bin/partial"},
			{ID: "unreadable.service", MainPID: 6, Start: t0, Exec: "/bin/gone"},
			{ID: "nomain.service", Start: t0, Exec: "/bin/fresh"},
			{ID: "nostart.service", MainPID: 7, Exec: "/bin/fresh"},
			{ID: "session-4.scope", Start: t0, Service: "sshd"},
			{ID: "session-c1.scope", Start: t0, Service: "gdm-password"},
			{ID: "init.scope", Start: t0},
			{ID: "docker-abc.scope", Start: t0},
		},
		Programs: map[string]Program{
			"/bin/stale":        {Path: "/bin/stale", Closure: []string{"/bin/stale", "/lib/new.so"}},
			"/bin/fresh":        {Path: "/bin/fresh", Closure: []string{"/bin/fresh", "/lib/old.so"}},
			"/bin/script":       {Path: "/bin/script", Interpreter: "/bin/py", Closure: []string{"/bin/py", "/lib/old.so"}},
			"/bin/script-stale": {Path: "/bin/script-stale", Interpreter: "/bin/py", Closure: []string{"/bin/py", "/lib/new.so"}},
			"/bin/partial":      {Path: "/bin/partial", Closure: []string{"/bin/partial"}, Unresolved: []string{"libx.so.1"}},
			"/bin/gone":         {Error: "no such file"},
			"/usr/sbin/sshd":    {Path: "/usr/sbin/sshd", Closure: []string{"/usr/sbin/sshd", "/lib/new.so"}},
		},
		Files: map[string]FileTime{
			"/bin/stale": {Time: before}, "/bin/fresh": {Time: before}, "/bin/py": {Time: before},
			"/bin/partial": {Time: before}, "/usr/sbin/sshd": {Time: before},
			"/lib/new.so": {Time: after}, "/lib/old.so": {Time: before},
		},
		SSHProgram: "/usr/sbin/sshd",
	}
	want := map[string]Status{
		"stale.service":        Inferred,
		"fresh.service":        None,
		"script.service":       Unknown,
		"script-stale.service": Inferred,
		"partial.service":      Unknown,
		"unreadable.service":   Unknown,
		"nomain.service":       Unknown,
		"nostart.service":      Unknown,
		"session-4.scope":      Inferred,
		"session-c1.scope":     Unknown,
		"init.scope":           Unknown,
		"docker-abc.scope":     Unknown,
	}
	r := Analyze(snap)
	if len(r.Findings) != len(want) {
		t.Fatalf("%d findings", len(r.Findings))
	}
	for _, f := range r.Findings {
		if f.Status != want[f.Unit] {
			t.Errorf("%s: %s (%s), want %s", f.Unit, f.Status, f.Reason, want[f.Unit])
		}
		if f.Status == Unknown && f.Reason == "" {
			t.Errorf("%s: unknown without a reason", f.Unit)
		}
		if f.Status == Inferred && (len(f.Replaced) != 1 || f.Replaced[0].Path != "/lib/new.so") {
			t.Errorf("%s: replaced %v", f.Unit, f.Replaced)
		}
	}
}
