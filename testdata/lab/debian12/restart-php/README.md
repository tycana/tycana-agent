# Hold-out: PHP-FPM after a libcurl update, tycana-debian12, 2026-10-16

A hold-out case: chosen by the Fable review of backlog item B1 as a class the agent's
rules had never seen, and measured before any rule was written for it.

From the staged state, as root: `apt-get install --no-upgrade php8.2-fpm php8.2-curl`,
then `apt-get install --reinstall libcurl4`; nothing restarted. `/usr/sbin/php-fpm8.2`
links no libcurl; PHP's `curl.so` extension, which PHP opens at run time, does. The VM
was then restored from the Lima snapshot `staged-2026-10-16`.

- `before-fix/snapshot.json`: the agent before it knew PHP's extension directory.
  php8.2-fpm.service was "none" while root saw three php-fpm processes map the deleted
  libcurl: a silent miss.
- The same state was then built again for the agent with PHP's extension directory
  (`internal/restart/modules.go`, programDirs): `snapshot.json` and `deleted-maps.tsv`
  (root, same moment). php8.2-fpm.service is "possible", the only one.

Captured a third time at 18:59 UTC with package change times (ADR 0020), from the same
snapshot and the same steps: `snapshot.json` and `deleted-maps.tsv` now hold that capture.
`TestLabHoldoutsWithoutModuleRules` removes the PHP module evidence and still finds
php8.2-fpm "possible", from the package rule alone.
