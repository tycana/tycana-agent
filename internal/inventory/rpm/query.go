package rpm

import (
	"bufio"
	"io"
	"strconv"
)

// QueryFormat is the rpm --queryformat that WriteQuery reproduces byte
// for byte. Lab checks and golden tests compare against
//
//	LC_ALL=C rpm -qa --qf "$QueryFormat"
//
// run on the same host. LC_ALL=C selects the untranslated summary. Tabs
// separate fields; every field but the summary is free of tabs and
// newlines by rpm's own rules.
const QueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{SIZE}\t%{SIGMD5}\t%{SUMMARY}\n`

// none is what rpm prints for a tag the header does not have.
const none = "(none)"

// WriteQuery writes one line per package in QueryFormat, in database
// order.
func (db *Database) WriteQuery(w io.Writer) error {
	bw := bufio.NewWriter(w)
	for _, p := range db.Packages {
		for i, s := range []string{
			orNone(p.Name), strconv.FormatUint(uint64(p.EVR.Epoch), 10), orNone(p.EVR.Version), orNone(p.EVR.Release),
			orNone(p.Arch), orNone(p.SourceRPM), unixOrNone(p.InstallTime), unixOrNone(p.BuildTime),
			sizeOrNone(p), orNone(p.SigMD5), orNone(p.Summary),
		} {
			if i > 0 {
				_ = bw.WriteByte('\t')
			}
			_, _ = bw.WriteString(s)
		}
		_ = bw.WriteByte('\n')
	}
	return bw.Flush()
}

func orNone(s string) string {
	if s == "" {
		return none
	}
	return s
}

func unixOrNone(t interface {
	IsZero() bool
	Unix() int64
}) string {
	if t.IsZero() {
		return none
	}
	return strconv.FormatInt(t.Unix(), 10)
}

func sizeOrNone(p Package) string {
	if !p.HasSize {
		return none
	}
	return strconv.FormatUint(p.Size, 10)
}
