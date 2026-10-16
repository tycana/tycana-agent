package dpkg

import (
	"bufio"
	"io"
)

// QueryFormat is the dpkg-query --showformat that WriteQuery reproduces
// byte for byte. Lab checks and golden tests compare against
//
//	dpkg-query -W -f="$QueryFormat"
//
// run on the same host. Tabs separate fields; every field but the summary
// is free of tabs and newlines by dpkg's own syntax rules.
const QueryFormat = `${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${binary:Summary}\n`

// WriteQuery writes one line per package in QueryFormat.
func (db *Database) WriteQuery(w io.Writer) error {
	bw := bufio.NewWriter(w)
	for _, p := range db.Packages {
		for i, s := range []string{
			p.StatusAbbrev(), db.BinaryPackage(p), versionField(p.Version), p.Architecture,
			p.SourceName, versionField(p.SourceVersion), p.Summary,
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

// versionField prints a version as dpkg-query does, which is the empty
// string when the package has none.
func versionField(v Version) string {
	if v.Upstream == "" {
		return ""
	}
	return v.String()
}
