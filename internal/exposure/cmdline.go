package exposure

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"unicode"
	"unicode/utf8"

	"tycana.ai/agent/internal/restart"
)

// maxCmdline bounds the read of one command line: argv[0] is a path, and
// PATH_MAX is 4096.
const maxCmdline = 4096

// mainProgram returns argv[0] of process pid from proc, and its canonical
// path, when argv[0] is an absolute, clean path to a regular file
// (tycana-hq ADR 0032). It reads at most maxCmdline bytes and returns
// nothing else of the command line: arguments can carry secrets, and the
// caller never sees them. Needs ProtectProc=default; under
// ProtectProc=invisible other users' processes are not visible.
func mainProgram(proc string, r *restart.Resolver, pid int) (argv0, canon string, ok bool) {
	if pid <= 0 {
		return "", "", false
	}
	f, err := os.Open(filepath.Join(proc, strconv.Itoa(pid), "cmdline")) //nolint:gosec // /proc/<pid>/cmdline of a unit's main process
	if err != nil {
		return "", "", false
	}
	buf := make([]byte, maxCmdline)
	n, err := io.ReadFull(f, buf)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", "", false
	}
	i := bytes.IndexByte(buf[:n], 0)
	if i < 0 {
		// No NUL: a process that rewrote its title, or a path longer
		// than PATH_MAX. Neither names a file.
		return "", "", false
	}
	a := string(buf[:i])
	if a == "" || a[0] != '/' || path.Clean(a) != a || !printable(a) {
		return "", "", false
	}
	c, err := r.Canonical(a)
	if err != nil {
		return "", "", false
	}
	st, err := os.Stat(r.Host(c))
	if err != nil || !st.Mode().IsRegular() {
		return "", "", false
	}
	return a, c, true
}

// printable is true for valid UTF-8 without control characters: argv[0]
// goes into a signed record and onto terminals.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
