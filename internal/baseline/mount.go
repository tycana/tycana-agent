package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"
)

// MountCheck is ComplianceAsCode's mount_option template:
//
//	PASS = (RT_OK or not RT_EXISTS) and (FS_OK or (MustExist and not FS_EXISTS))
//
// RT is the running mount table; RT_OK means Option is in the options of
// every mount at Path. FS is the first /etc/fstab line for Path; FS_OK
// means its options field contains Option. With MustExist false (the
// /dev/shm rules) the path must have an fstab line.
//
// The agent cannot read the host's mount table directly inside the
// tycanad unit: the sandbox remounts everything with more options
// (nosuid, ro) and binds a private /tmp and /var/tmp. It reads instead
// systemd's mount units, which describe the host's table, and falls back
// to its own table only where that is sound: systemd adds options, never
// removes them, so an option absent there is absent on the host.
type MountCheck struct {
	Path      string `yaml:"path"`
	Option    string `yaml:"option"`
	MustExist bool   `yaml:"must_exist"`
	// ExcludeFSType skips mounts and fstab lines of this type (prefix
	// match on fstab, as the OVAL's negative lookahead does).
	ExcludeFSType string `yaml:"exclude_fs_type,omitempty"`
}

var mountOptionRE = regexp.MustCompile(`^[a-z0-9_]+(=[A-Za-z0-9_.,:-]+)?$`)

func (m *MountCheck) validate() error {
	if !path.IsAbs(m.Path) || path.Clean(m.Path) != m.Path {
		return fmt.Errorf("mount: path %q is not clean and absolute", m.Path)
	}
	if !mountOptionRE.MatchString(m.Option) {
		return fmt.Errorf("mount: option %q is not valid", m.Option)
	}
	return nil
}

func (m *MountCheck) eval(h *Host) (bool, string, error) {
	fsLine, err := fstabLine(h, m.Path, true, m.ExcludeFSType)
	if err != nil {
		return false, "", err
	}
	switch {
	case fsLine == nil && !m.MustExist:
		return false, m.Path + " has no /etc/fstab line", nil
	case fsLine != nil && !regexp.MustCompile(regexp.QuoteMeta(m.Option)).MatchString(fsLine.options):
		return false, fmt.Sprintf("/etc/fstab mounts %s with %s, without %s", m.Path, fsLine.options, m.Option), nil
	}
	rt := hostMount(h, m.Path)
	if !rt.mounted {
		return true, m.Path + " is not mounted; " + fstabWhy(fsLine, m.Option), nil
	}
	if m.ExcludeFSType != "" && rt.fsType == m.ExcludeFSType {
		return true, m.Path + " is " + m.ExcludeFSType + " (excluded)", nil
	}
	for _, opts := range rt.options {
		if !slices.Contains(opts, m.Option) {
			return false, fmt.Sprintf("%s is mounted without %s (%s)", m.Path, m.Option, strings.Join(opts, ",")), nil
		}
	}
	if !rt.certain {
		return false, "", unknownf("%s shows %s only in the agent's sandbox, which adds mount options; systemd has no unit for it", m.Path, m.Option)
	}
	return true, fmt.Sprintf("%s is mounted with %s; %s", m.Path, m.Option, fstabWhy(fsLine, m.Option)), nil
}

func fstabWhy(l *fstabEntry, opt string) string {
	if l == nil {
		return "no /etc/fstab line"
	}
	return "/etc/fstab has " + opt
}

type fstabEntry struct{ fsType, options string }

// fstabLine returns the first /etc/fstab line for mp. strict is the
// mount_option pattern, which skips lines whose first field starts with
// "#"; the platform pattern (mount[...]) does not, so a commented line
// counts there.
func fstabLine(h *Host, mp string, strict bool, exclude string) (*fstabEntry, error) {
	b, err := h.ReadFile("/etc/fstab")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	first := `[\S]+`
	if strict {
		// PCRE "(?!#)[\S]+" after "^[\s]*": the first field cannot
		// start with "#".
		first = `[^#\s][\S]*`
	}
	re := regexp.MustCompile(`(?m)^[\s]*` + first + `[\s]+` + regexp.QuoteMeta(mp) + `[\s]+([\S]+)[\s]+([\S]+)`)
	for _, sm := range re.FindAllSubmatch(b, -1) {
		if exclude != "" && strings.HasPrefix(string(sm[1]), exclude) {
			continue
		}
		return &fstabEntry{fsType: string(sm[1]), options: string(sm[2])}, nil
	}
	return nil, nil
}

// hostView is the host's mount at one path, as far as the agent can tell.
type hostView struct {
	mounted bool
	fsType  string
	// options holds one option list per mount at the path (mounts can
	// stack); the OVAL requires the option in every one.
	options [][]string
	// certain is false when the options come from the sandbox's table,
	// where an option may have been added.
	certain bool
}

// sandboxRoots are the roots of mounts systemd makes for the unit's own
// namespace: PrivateTmp binds and InaccessiblePaths.
var sandboxRoots = []string{"/systemd-private-", "/tmp/systemd-private-", "/var/tmp/systemd-private-", "/systemd/inaccessible/"}

func hostMount(h *Host, mp string) hostView {
	if u, ok := h.Units[mountUnit(mp)]; ok && u["LoadState"] != "not-found" {
		if u["ActiveState"] == "active" && u["Where"] == mp {
			return hostView{mounted: true, fsType: u["Type"], options: [][]string{strings.Split(u["Options"], ",")}, certain: true}
		}
		return hostView{}
	}
	v := hostView{certain: !h.Sandboxed}
	for i := range h.Mounts {
		mt := &h.Mounts[i]
		if mt.Target != mp || sandboxMount(mt) {
			continue
		}
		v.mounted, v.fsType = true, mt.FSType
		v.options = append(v.options, mt.Options)
	}
	// A path systemd tracks has a unit; only API file systems such as
	// /dev/shm are absent from its units and mounted here.
	return v
}

func sandboxMount(mt *Mount) bool {
	return slices.ContainsFunc(sandboxRoots, func(r string) bool { return strings.HasPrefix(mt.Root, r) })
}

// sandboxed reports whether the mount table is a systemd sandbox's: it
// has a PrivateTmp bind or an InaccessiblePaths mount.
func sandboxed(ms []Mount) bool {
	return slices.ContainsFunc(ms, func(m Mount) bool { return sandboxMount(&m) })
}
