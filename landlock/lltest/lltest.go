// Package lltest has helpers for Landlock-enabled tests.
package lltest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// RunInSubprocess runs the given test function in a subprocess
// and forwards its output.
func RunInSubprocess(t *testing.T, f func()) {
	t.Helper()

	if IsRunningInSubprocess() {
		f()
		return
	}

	args := append(os.Args[1:], "-test.run="+regexp.QuoteMeta(t.Name())+"$")

	// Make sure that the parent process cleans up the actual TempDir.
	// If the child process uses t.TempDir(), it'll create it in $TMPDIR.
	t.Setenv("TMPDIR", t.TempDir())

	t.Setenv("IS_SUBPROCESS", "yes")
	buf, err := exec.Command(os.Args[0], args...).Output()

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("Could not execute test in subprocess: %v", err)
	}

	lines := strings.Split(string(buf), "\n")
	for _, l := range lines {
		if l == "FAIL" {
			defer func() { t.Error("Test failed in subprocess") }()
			continue
		}
		if strings.HasPrefix(l, "--- SKIP") {
			defer func() { t.Skip("Test skipped in subprocess") }()
			continue
		}
		if strings.HasPrefix(l, "===") || strings.HasPrefix(l, "---") || l == "PASS" || l == "" {
			continue
		}
		fmt.Println(l)
	}
}

// TempDir is a replacement for t.TempDir() to be used in Landlock tests.
// If we were using t.TempDir(), the test framework would try to remove it
// after the test, even in Landlocked subprocess tests where this fails.
//
// TODO: It would be nicer if all tests could just use t.TempDir()
// without the test framework trying to delete these later in the subprocesses.
func TempDir(t testing.TB) string {
	t.Helper()

	if IsRunningInSubprocess() {
		dir, err := os.MkdirTemp("", "LandlockTestTempDir")
		if err != nil {
			t.Fatalf("os.MkdirTemp: %v", err)
		}
		return dir
	}
	return t.TempDir()
}

// RequireABI skips the test if the kernel does not provide the given ABI version.
func RequireABI(t testing.TB, want int) {
	t.Helper()

	if v, err := ll.LandlockGetABIVersion(); err != nil || v < want {
		t.Skipf("Requires Landlock >= V%v, got V%v (err=%v)", want, v, err)
	}
}

func IsRunningInSubprocess() bool {
	return os.Getenv("IS_SUBPROCESS") != ""
}
