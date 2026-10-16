package bad

import (
	"os"
	stdos "os"
	"os/exec"
)

func f() {
	_ = os.WriteFile("/etc/motd", nil, 0o644)
	_ = stdos.Remove("/etc/motd")
	_ = exec.Command("apt-get", "install", "-y", "nginx")
	_ = os.Getenv("HOME") // fine
}
