package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, os.Getenv("HOME"))
	_, _ = os.ReadFile("/etc/os-release")
	_, _ = os.Open("/x")
}
