# Hold-out: PostgreSQL with PL/Python after a Python update, tycana-alma9, 2026-10-16

A hold-out case: chosen by the Fable review of backlog item B1 as a class the agent's
rules had never seen, and measured before any rule was written for it.

From the staged state, as root: `dnf install postgresql-server postgresql-plpython3`,
`postgresql-setup --initdb`, start postgresql. One client session ran
`CREATE EXTENSION plpython3u`, a `DO LANGUAGE plpython3u` block, and `pg_sleep(1800)`,
so its backend (pid 2742) kept `plpython3.so` and `libpython3.9.so.1.0` mapped. Then
only `dnf upgrade python3 python3-libs` (3.9.25-7.el9_8.2 to .3); nothing restarted.
`/usr/bin/postgres` links no libpython. The VM was then restored from the Lima snapshot
`staged-2026-10-16`.

- `deleted-maps.tsv`: root, after the update. Stale: postgresql.service (the backend)
  and tuned.service.
- `before-fix/snapshot.json`: the agent before it knew PostgreSQL's library directory.
  postgresql.service was "none": a silent miss.
- `snapshot.json`: the agent with `/usr/lib64/pgsql` watched, same state.
  postgresql.service is "possible", the only one; tuned is "inferred".

Same-UID probe on the same state: a process in the tycanad sandbox with `User=postgres`
and `PrivateUsers=no` read `/proc/2742/maps` and saw the five deleted libpython mappings,
with no capability. With `PrivateUsers=yes` the backend was not visible.

Captured again at 19:00 UTC with package change times (ADR 0020), from the same snapshot
and the same steps: `snapshot.json` and `deleted-maps.tsv` now hold that capture.
`TestLabHoldoutsWithoutModuleRules` removes the PostgreSQL module evidence and still finds
postgresql "possible", from the package rule alone.
