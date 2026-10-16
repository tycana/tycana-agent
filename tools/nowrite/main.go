// Command nowrite is the source-level guard for ADR 0017: the agent never
// changes a host. It parses every Go file in the module and rejects
// filesystem-mutating calls, process execution, and raw syscalls outside
// the two packages allowed to have them:
//
//   - internal/state    may create and modify files in the agent's own state dir
//   - internal/hostexec may run host commands through the hardened wrapper
//
// Test files are exempt (they write fixtures under t.TempDir). The check is
// syntactic and alias-aware but not type-aware; it is a tripwire, not a
// proof. Run it from the module root: go run ./tools/nowrite
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// allowed maps a package directory (relative to the module root) to the
// imports it may use.
var allowed = map[string]map[string]bool{
	"internal/state":    {"os": true},
	"internal/hostexec": {"os": true, "os/exec": true, "syscall": true, "golang.org/x/sys/unix": true},
}

// forbiddenOS lists os.* functions that mutate the filesystem.
var forbiddenOS = map[string]bool{
	"WriteFile": true, "Create": true, "CreateTemp": true, "OpenFile": true,
	"Remove": true, "RemoveAll": true, "Mkdir": true, "MkdirAll": true, "MkdirTemp": true,
	"Chmod": true, "Chown": true, "Lchown": true, "Chtimes": true,
	"Rename": true, "Symlink": true, "Link": true, "Truncate": true,
	"NewFile": true, "Setenv": false, // Setenv is process-local; permitted
}

// forbiddenImports are never acceptable outside their allowed package.
var forbiddenImports = map[string]string{
	"os/exec":               "process execution belongs in internal/hostexec",
	"syscall":               "raw syscalls belong in internal/hostexec",
	"golang.org/x/sys/unix": "raw syscalls belong in internal/hostexec",
	"io/ioutil":             "deprecated; and it hides file writes",
	"os/signal":             "", // allowed everywhere; listed to document the decision
}

type finding struct {
	pos token.Position
	msg string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	findings, err := scan(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nowrite:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Printf("%s: %s\n", f.pos, f.msg)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "nowrite: %d violation(s) of the observe-only contract (ADR 0017)\n", len(findings))
		os.Exit(1)
	}
	fmt.Println("nowrite: ok, no host-mutating calls outside internal/state and internal/hostexec")
}

func scan(root string) ([]finding, error) {
	var findings []finding
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", ".git", "vendor", "dist":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		pkgDir := filepath.ToSlash(filepath.Dir(rel))
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		findings = append(findings, checkFile(fset, f, pkgDir)...)
		return nil
	})
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i].pos, findings[j].pos
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Line < b.Line
	})
	return findings, err
}

func checkFile(fset *token.FileSet, f *ast.File, pkgDir string) []finding {
	var out []finding
	perms := allowed[pkgDir]
	osNames := map[string]bool{} // local names bound to the "os" package

	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		local := filepath.Base(path)
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if path == "os" {
			osNames[local] = true
		}
		if why, bad := forbiddenImports[path]; bad && why != "" && !perms[path] {
			out = append(out, finding{fset.Position(imp.Pos()), fmt.Sprintf("import %q: %s", path, why)})
		}
	}
	if perms["os"] {
		return out // state and hostexec may mutate their own files
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !osNames[id.Name] {
			return true
		}
		if forbiddenOS[sel.Sel.Name] {
			out = append(out, finding{fset.Position(sel.Pos()),
				fmt.Sprintf("os.%s mutates the filesystem; only internal/state may do that", sel.Sel.Name)})
		}
		return true
	})
	return out
}
