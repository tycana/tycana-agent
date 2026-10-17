// Package state owns the agent's only writable location: its own state
// directory (StateDirectory=tycanad, ADR 0009). It keeps the host key and
// the signed records (tycana-hq ADR 0025). Nothing outside this package
// may create, modify, or delete a file; tools/nowrite enforces that at CI
// time. Host state is never written here or anywhere.
package state
