//go:build ignore

// pre-commit runs the same checks as CI: go vet, go test, and golangci-lint.
// Invoked by .git/hooks/pre-commit via `go run scripts/pre-commit.go`.
//
// Install golangci-lint (required):
//
//	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gopath returns the GOPATH as reported by `go env GOPATH`.
func gopath() string {
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// resolve returns the full path to a binary, preferring GOPATH/bin over PATH.
func resolve(name string) string {
	if gp := gopath(); gp != "" {
		candidate := filepath.Join(gp, "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return name // fall back to PATH lookup
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	checks := [][]string{
		{"go", "vet", "./..."},
		{"go", "test", "./..."},
		{resolve("golangci-lint"), "run", "./..."},
	}

	for _, args := range checks {
		fmt.Printf("pre-commit: %s %s\n", filepath.Base(args[0]), args[1])
		if err := run(args...); err != nil {
			fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
			os.Exit(1)
		}
	}
}
