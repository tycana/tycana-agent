package hostexec

import (
	"fmt"
	"regexp"
	"time"
)

// ID names a registered command.
type ID string

// The registered commands. Each is a simulation or a query.
const (
	// AptSimulateUpgrade lists what "apt-get upgrade" would do, including
	// updates deferred by phasing and packages kept back.
	AptSimulateUpgrade ID = "apt-simulate-upgrade"
	// AptSimulateDistUpgrade lists what "apt-get dist-upgrade" would do.
	AptSimulateDistUpgrade ID = "apt-simulate-dist-upgrade"
	// AptCachePolicy prints candidate versions, origins, and pins for the
	// named packages, or the source priorities when none is named.
	AptCachePolicy ID = "apt-cache-policy"
	// DnfCheckUpdate lists available updates from the system metadata
	// cache. Exit status 100 means updates exist.
	DnfCheckUpdate ID = "dnf-check-update"
	// DnfUpdateinfo lists the advisories for available updates from the
	// system metadata cache.
	DnfUpdateinfo ID = "dnf-updateinfo"
	// SystemctlShowRunning prints, for every running service and scope,
	// its name, main PID, the start time of its main process or scope,
	// and its ExecStart= program. Times are UTC with microseconds.
	SystemctlShowRunning ID = "systemctl-show-running"
	// LoginctlShowSession prints the PAM service and scope of the named
	// login sessions.
	LoginctlShowSession ID = "loginctl-show-session"
	// AptConfigDump prints apt's merged configuration, which holds the
	// settings of unattended-upgrades and APT::Periodic.
	AptConfigDump ID = "apt-config-dump"
	// SystemctlShowUpdaterTimers prints the state and next run of the
	// timers that start unattended-upgrades and dnf-automatic.
	SystemctlShowUpdaterTimers ID = "systemctl-show-updater-timers"
	// SystemctlShowUnits prints the load, activation, and unit-file state
	// of the named units, and for mount units where and with which
	// options they are mounted. systemd answers from the host's mount
	// table, not from the caller's mount namespace. A name systemd has not
	// loaded makes PID 1 read its unit file into memory; nothing is
	// written and nothing starts (the M2 timer query does the same).
	SystemctlShowUnits ID = "systemctl-show-units"
	// SystemctlListDependencies prints every unit multi-user.target
	// depends on, recursively, one per line.
	SystemctlListDependencies ID = "systemctl-list-dependencies"
)

// UpdaterTimers are the timers SystemctlShowUpdaterTimers reports, in
// order.
var UpdaterTimers = []string{
	"apt-daily.timer", "apt-daily-upgrade.timer",
	"dnf-automatic.timer", "dnf-automatic-install.timer",
	"dnf-automatic-download.timer", "dnf-automatic-notifyonly.timer",
}

// aptOpts keeps apt from taking the lock and from writing its binary
// caches when a run would otherwise regenerate them.
//
// It also points apt's chroot test at false. apt skips phased-update
// rules when /usr/bin/ischroot does not answer "not a chroot", and in the
// unit's mount namespace ischroot answers "cannot tell" (exit 2). The
// sandboxed agent then reported phased updates as installable that the
// host itself defers (tycana-ubuntu2404, 2026-10-16: 48 against 44). apt's
// separate container test, /run/systemd/container, still applies.
var aptOpts = []string{
	"-o", "Debug::NoLocking=true",
	"-o", "Dir::Cache::pkgcache=",
	"-o", "Dir::Cache::srcpkgcache=",
	"-o", "Dir::Bin::ischroot=/usr/bin/false",
}

var registry = map[ID]Spec{
	AptSimulateUpgrade: {
		Paths: []string{"/usr/bin/apt-get"},
		Args:  append(append([]string{"--simulate", "--quiet"}, aptOpts...), "upgrade"),
	},
	AptSimulateDistUpgrade: {
		Paths: []string{"/usr/bin/apt-get"},
		Args:  append(append([]string{"--simulate", "--quiet"}, aptOpts...), "dist-upgrade"),
	},
	AptCachePolicy: {
		Paths: []string{"/usr/bin/apt-cache"},
		Args:  append(append([]string{}, aptOpts...), "policy"),
		Extra: packageNames(debName),
	},
	DnfCheckUpdate: {
		Paths:         []string{"/usr/bin/dnf"},
		Args:          []string{"--cacheonly", "--quiet", "check-update"},
		OKExit:        []int{100},
		ScratchVarTmp: true,
	},
	DnfUpdateinfo: {
		Paths:         []string{"/usr/bin/dnf"},
		Args:          []string{"--cacheonly", "--quiet", "updateinfo", "list", "--available"},
		ScratchVarTmp: true,
	},
	SystemctlShowRunning: {
		Paths: []string{"/usr/bin/systemctl", "/bin/systemctl"},
		Args: []string{"show", "--no-pager", "--timestamp=us+utc",
			"--type=service,scope", "--state=running",
			"--property=Id,MainPID,ExecMainStartTimestamp,ActiveEnterTimestamp,ExecStart",
			"*"},
		Timeout: 30 * time.Second,
	},
	AptConfigDump: {
		Paths:   []string{"/usr/bin/apt-config"},
		Args:    []string{"dump"},
		Timeout: 30 * time.Second,
	},
	SystemctlShowUpdaterTimers: {
		Paths: []string{"/usr/bin/systemctl", "/bin/systemctl"},
		Args: append([]string{"show", "--no-pager", "--timestamp=us+utc",
			"--property=Id,LoadState,UnitFileState,ActiveState,NextElapseUSecRealtime,LastTriggerUSec"},
			UpdaterTimers...),
		Timeout: 30 * time.Second,
	},
	SystemctlShowUnits: {
		Paths: []string{"/usr/bin/systemctl", "/bin/systemctl"},
		// "--" ends the options: a unit name can never become one.
		Args: []string{"show", "--no-pager",
			"--property=Id,LoadState,ActiveState,SubState,UnitFileState,Where,What,Options,Type",
			"--"},
		Extra:   unitNames,
		Timeout: 30 * time.Second,
	},
	SystemctlListDependencies: {
		Paths:   []string{"/usr/bin/systemctl", "/bin/systemctl"},
		Args:    []string{"list-dependencies", "--plain", "--no-pager", "--all", "multi-user.target"},
		Timeout: 30 * time.Second,
	},
	LoginctlShowSession: {
		Paths: []string{"/usr/bin/loginctl", "/bin/loginctl"},
		// loginctl, unlike systemctl, ignores a comma list after --property.
		Args:    []string{"show-session", "--no-pager", "--property=Id", "--property=Service", "--property=Scope"},
		Extra:   sessionIDs,
		Timeout: 30 * time.Second,
	},
}

// Package-name grammars. A name never starts with "-", so it cannot be
// read as an option.
var (
	// debName is a Debian package name with an optional architecture.
	debName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+(:[a-z0-9-]+)?$`)
	// unitName is a systemd unit name of the types baseline checks read.
	// It cannot start with "-".
	unitName = regexp.MustCompile(`^[A-Za-z0-9_:@][A-Za-z0-9_:@.\\-]{0,250}\.(service|socket|mount|timer|target)$`)
	// sessionID is a logind session id: "4", "c2", "12".
	sessionID = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
)

// maxSessions bounds one loginctl call.
const maxSessions = 1000

func sessionIDs(ids []string) error {
	if len(ids) > maxSessions {
		return fmt.Errorf("hostexec: %d session ids, at most %d", len(ids), maxSessions)
	}
	for _, id := range ids {
		if !sessionID.MatchString(id) {
			return fmt.Errorf("hostexec: %q is not a session id", id)
		}
	}
	return nil
}

// maxUnits bounds one systemctl call; callers batch above it.
const maxUnits = 500

func unitNames(names []string) error {
	if len(names) == 0 || len(names) > maxUnits {
		return fmt.Errorf("hostexec: %d unit names, want 1 to %d", len(names), maxUnits)
	}
	for _, n := range names {
		// "-.mount" is the root file system's unit, the one name that
		// starts with "-"; Args ends with "--", so it cannot be an option.
		if n != "-.mount" && !unitName.MatchString(n) {
			return fmt.Errorf("hostexec: %q is not a unit name", n)
		}
	}
	return nil
}

// maxNames bounds one call; callers batch above it.
const maxNames = 2000

func packageNames(re *regexp.Regexp) func([]string) error {
	return func(names []string) error {
		if len(names) > maxNames {
			return fmt.Errorf("hostexec: %d package names, at most %d", len(names), maxNames)
		}
		for _, n := range names {
			if !re.MatchString(n) {
				return fmt.Errorf("hostexec: %q is not a package name", n)
			}
		}
		return nil
	}
}
