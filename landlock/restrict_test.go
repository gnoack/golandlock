//go:build linux

package landlock_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/lltest"
	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

func TestRestrictPaths(t *testing.T) {
	// On kernels before 5.19.8, some refer cases returned EXDEV
	// which now return EACCES.
	exdevBefore5198 := syscall.EXDEV
	if major, minor, patch := OSRelease(t); 1000*1000*major+1000*minor+patch >= 5019008 {
		exdevBefore5198 = syscall.EACCES
	}

	for _, tt := range []struct {
		Name            string
		EnableLandlock  func(dir, fpath string) error
		RequiredABI     int
		WantOpenErr     error
		WantReadDirErr  error
		WantCreateErr   error
		WantMkdirErr    error
		WantUnlinkErr   error
		WantMkfifoErr   error
		WantReferErr    error
		WantTruncateErr error
	}{
		{
			Name:        "EverythingForbidden",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths()
			},
			WantOpenErr:     syscall.EACCES,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "ROFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(fpath))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWFilesPermissionsOnFile",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(fpath))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   nil,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "ROFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.ROFiles(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWFilesPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWFiles(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   nil,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RODirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RODirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsPermissionsOnDir",
			RequiredABI: 1,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V1.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsWithRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir).WithRefer())
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    nil,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsWithoutRefer",
			RequiredABI: 2,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V2.RestrictPaths(landlock.RWDirs(dir) /* without refer */)
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "RWDirsV3",
			RequiredABI: 3,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V3.RestrictPaths(landlock.RWDirs(dir))
			},
			WantOpenErr:     nil,
			WantReadDirErr:  nil,
			WantCreateErr:   nil,
			WantMkdirErr:    nil,
			WantUnlinkErr:   nil,
			WantMkfifoErr:   nil,
			WantReferErr:    syscall.EXDEV,
			WantTruncateErr: nil,
		},
		{
			Name:        "EverythingForbiddenV3",
			RequiredABI: 3,
			EnableLandlock: func(dir, fpath string) error {
				return landlock.V3.RestrictPaths()
			},
			WantOpenErr:     syscall.EACCES,
			WantReadDirErr:  syscall.EACCES,
			WantCreateErr:   syscall.EACCES,
			WantMkdirErr:    syscall.EACCES,
			WantUnlinkErr:   syscall.EACCES,
			WantMkfifoErr:   syscall.EACCES,
			WantReferErr:    exdevBefore5198,
			WantTruncateErr: syscall.EACCES,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, tt.RequiredABI)

				dir := lltest.TempDir(t)
				fpath := filepath.Join(dir, "lolcat.txt")
				MustWriteFile(t, fpath)
				renameMeFpath := filepath.Join(dir, "renameme.txt")
				MustWriteFile(t, renameMeFpath)
				dstDirPath := filepath.Join(dir, "dst")
				MustMkdir(t, dstDirPath)

				err := tt.EnableLandlock(dir, fpath)
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				if err := openForRead(fpath); !errEqual(err, tt.WantOpenErr) {
					t.Errorf("openForRead(%q) = «%v», want «%v»", fpath, err, tt.WantOpenErr)
				}

				if _, err := os.ReadDir(dir); !errEqual(err, tt.WantReadDirErr) {
					t.Errorf("os.ReadDir(%q) = «%v», want «%v»", dir, err, tt.WantReadDirErr)
				}

				if err := openForWrite(fpath); !errEqual(err, tt.WantCreateErr) {
					t.Errorf("os.Create(%q) = «%v», want «%v»", fpath, err, tt.WantCreateErr)
				}

				if err := os.Truncate(fpath, 3); !errEqual(err, tt.WantTruncateErr) {
					t.Errorf("os.Truncate(%q, ...) = «%v», want «%v»", fpath, err, tt.WantTruncateErr)
				}

				subdirPath := filepath.Join(dir, "subdir")
				if err := os.Mkdir(subdirPath, 0600); !errEqual(err, tt.WantMkdirErr) {
					t.Errorf("os.Mkdir(%q) = «%v», want «%v»", subdirPath, err, tt.WantMkdirErr)
				}

				if err := os.Remove(fpath); !errEqual(err, tt.WantUnlinkErr) {
					t.Errorf("os.Remove(%q) = «%v», want «%v»", fpath, err, tt.WantUnlinkErr)
				}

				fifoPath := filepath.Join(dir, "fifo")
				if err := unix.Mkfifo(fifoPath, 0600); !errEqual(err, tt.WantMkfifoErr) {
					t.Errorf("os.Mkfifo(%q, ...) = «%v», want «%v»", fifoPath, err, tt.WantMkfifoErr)
				}

				dstFpath := filepath.Join(dstDirPath, "target.txt")
				if err := os.Rename(renameMeFpath, dstFpath); !errEqual(err, tt.WantReferErr) {
					t.Errorf("os.Rename(%q, %q) = «%v», want «%v»", renameMeFpath, dstFpath, err, tt.WantReferErr)
				}
			})
		})
	}
}

func openForRead(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func openForWrite(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func TestRestrictNet(t *testing.T) {
	const (
		cPort = 4242
		bPort = 4343
	)

	for _, tt := range []struct {
		Name           string
		EnableLandlock func() error
		RequiredABI    int
		WantConnectErr error
		WantBindErr    error
	}{
		{
			Name:        "ABITooOld",
			RequiredABI: 3,
			EnableLandlock: func() error {
				return landlock.V3.RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "ABITooOldWithDowngrade",
			RequiredABI: 3,
			EnableLandlock: func() error {
				return landlock.V3.BestEffort().RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "RestrictingPathsShouldNotBreakNetworking",
			RequiredABI: 1,
			EnableLandlock: func() error {
				return landlock.V4.BestEffort().RestrictPaths(
					landlock.ROFiles("/etc/hosts"),
				)
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "RestrictingBindButConnectShouldWork",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.AccessNetSet(ll.AccessNetBindTCP),
				).RestrictNet()
			},
			WantConnectErr: nil,
			WantBindErr:    syscall.EACCES,
		},
		{
			Name:        "RestrictingConnectButBindShouldWork",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.AccessNetSet(ll.AccessNetConnectTCP),
				).RestrictNet()
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitTheConnectPort",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(landlock.ConnectTCP(cPort))
			},
			WantConnectErr: nil,
			WantBindErr:    syscall.EACCES,
		},
		{
			Name:        "PermitTheBindPort",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(landlock.BindTCP(bPort))
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitBothPorts",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(
					landlock.BindTCP(bPort),
					landlock.ConnectTCP(cPort),
				)
			},
			WantConnectErr: nil,
			WantBindErr:    nil,
		},
		{
			Name:        "PermitTheWrongPorts",
			RequiredABI: 4,
			EnableLandlock: func() error {
				return landlock.V4.RestrictNet(
					landlock.BindTCP(bPort+1),
					landlock.ConnectTCP(cPort+1),
				)
			},
			WantConnectErr: syscall.EACCES,
			WantBindErr:    syscall.EACCES,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, tt.RequiredABI)

				// Set up a service that we can dial for the test.
				runBackgroundService(t, "tcp", fmt.Sprintf("localhost:%v", cPort))

				err := tt.EnableLandlock()
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				if err := tryDial(cPort); !errEqual(err, tt.WantConnectErr) {
					t.Errorf("net.Dial(tcp, localhost:%v) = «%v»; want «%v»", cPort, err, tt.WantConnectErr)
				}
				if err := tryListen(bPort); !errEqual(err, tt.WantBindErr) {
					t.Errorf("net.Listen(tcp, localhost:%v) = «%v»; want «%v»", bPort, err, tt.WantBindErr)
				}
			})
		})
	}
}

func runBackgroundService(t *testing.T, network, addr string) {
	l, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("net.Listen: Failed to set up local service to connect to: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				// Return on error (e.g. if l gets closed asynchronously)
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
}

func tryDial(port int) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%v", port))
	if err == nil {
		conn.Close()
	}
	return err
}

func tryListen(port int) error {
	conn, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", port))
	if err == nil {
		conn.Close()
	}
	return err
}

func TestIoctlDev(t *testing.T) {
	const (
		path     = "/dev/zero"
		FIONREAD = 0x541b
	)
	for _, tt := range []struct {
		Name    string
		Rule    landlock.Rule
		WantErr error
	}{
		{
			Name:    "WithoutIoctlDev",
			Rule:    landlock.RWFiles(path),
			WantErr: syscall.EACCES,
		},
		{
			Name: "WithIoctlDev",
			Rule: landlock.RWFiles(path).WithIoctlDev(),
			// ENOTTY means that the IOCTL was dispatched
			// to device.  (Would be nicer to find an
			// IOCTL that returns success here, but the
			// available devices on qemu are limited.)
			WantErr: syscall.ENOTTY,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, 5)

				err := landlock.V5.BestEffort().RestrictPaths(tt.Rule)
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				f, err := os.Open(path)
				if err != nil {
					t.Fatalf("os.Open(%q): %v", path, err)
				}
				defer func() { f.Close() }()

				_, err = unix.IoctlGetInt(int(f.Fd()), FIONREAD)
				if !errEqual(err, tt.WantErr) {
					t.Errorf("ioctl(%v, FIONREAD): got err «%v», want «%v»", f, err, tt.WantErr)
				}
			})
		})
	}
}

func TestRestrictScoped(t *testing.T) {
	const name = "@abstract/go-landlock/test"

	// Bring up an abstract Unix Domain Socket service in the
	// parent process, which the subprocesses can dial.
	if !lltest.IsRunningInSubprocess() {
		ls, err := net.Listen("unix", name)
		if err != nil {
			t.Fatalf("net.Listen(unix:%q): %v", name, err)
		}
		defer ls.Close()
	}

	for _, tt := range []struct {
		Name           string
		EnableLandlock func() error
		RequiredABI    int
		WantDialErr    error
		WantKillErr    error
	}{
		{
			Name:           "Unrestricted",
			RequiredABI:    0,
			EnableLandlock: func() error { return nil },
		},
		{
			Name:        "RestrictAbstractUnixSockets",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.ScopedSet(ll.ScopeAbstractUnixSocket),
				).Restrict()
			},
			WantDialErr: syscall.EPERM,
		},
		{
			Name:        "RestrictSignal",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.MustConfig(
					landlock.ScopedSet(ll.ScopeSignal),
				).Restrict()
			},
			WantKillErr: syscall.EPERM,
		},
		{
			Name:        "RestrictAll",
			RequiredABI: 6,
			EnableLandlock: func() error {
				return landlock.V6.RestrictScoped()
			},
			WantDialErr: syscall.EPERM,
			WantKillErr: syscall.EPERM,
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			lltest.RunInSubprocess(t, func() {
				lltest.RequireABI(t, tt.RequiredABI)

				err := tt.EnableLandlock()
				if err != nil {
					t.Fatalf("Enabling Landlock: %v", err)
				}

				cs, err := net.Dial("unix", name)
				if want := tt.WantDialErr; !errEqual(err, want) {
					t.Errorf("Dial(unix:%q): err=%q, want %q", name, err, want)
				}
				if err == nil {
					defer cs.Close()
				}

				killErr := syscall.Kill(os.Getppid(), syscall.SIGUSR1)
				if want := tt.WantKillErr; killErr != want {
					t.Errorf("Kill(ppid, USR1): err=%q, want %q", killErr, want)
				}
			})
		})
	}
}

func errEqual(got, want error) bool {
	if got == nil && want == nil {
		return true
	}
	return errors.Is(got, want)
}

func OSRelease(t testing.TB) (major, minor, patch int) {
	t.Helper()

	var buf unix.Utsname
	if err := unix.Uname(&buf); err != nil {
		t.Fatalf("Uname: %v", err)
	}
	release := string(buf.Release[:bytes.IndexByte(buf.Release[:], 0)])
	release, _, _ = strings.Cut(release, "-")
	release, _, _ = strings.Cut(release, "+")

	parts := strings.SplitN(release, ".", 4)
	if len(parts) < 3 {
		t.Fatalf("Invalid release format %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[0], err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[1], err)
	}
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", parts[2], err)
	}
	return major, minor, patch
}
