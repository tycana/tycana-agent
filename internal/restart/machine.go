package restart

import (
	"debug/elf"
	"runtime"
)

// nativeMachine is the ELF machine of this build, used for the default
// library directories when no program fixes one.
var nativeMachine = map[string]elf.Machine{
	"amd64": elf.EM_X86_64,
	"arm64": elf.EM_AARCH64,
}[runtime.GOARCH]
