package rpm

import "strings"

// SourceRPM splits a SOURCERPM value, "name-version-release.src.rpm",
// into its name and version-release. ok is false for anything else,
// including the "(none)" of gpg-pubkey entries.
func SourceRPM(s string) (name, vr string, ok bool) {
	base, found := strings.CutSuffix(s, ".src.rpm")
	if !found {
		if base, found = strings.CutSuffix(s, ".nosrc.rpm"); !found {
			return "", "", false
		}
	}
	r := strings.LastIndexByte(base, '-')
	if r <= 0 {
		return "", "", false
	}
	v := strings.LastIndexByte(base[:r], '-')
	if v <= 0 {
		return "", "", false
	}
	return base[:v], base[v+1:], true
}
