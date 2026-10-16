package state

import "os"

func f() { _ = os.WriteFile("/var/lib/tycanad/x", nil, 0o600) }
