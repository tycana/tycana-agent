// Package state will own the agent's only writable location: its own state
// directory (StateDirectory=tycanad, ADR 0009). It is empty in M0. Nothing
// outside this package may create, modify, or delete a file; tools/nowrite
// enforces that at CI time. Host state is never written here or anywhere.
package state
