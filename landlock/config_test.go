package landlock

import (
	"fmt"
	"testing"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestConfigString(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want string
	}{
		{
			cfg:  Config{handledAccessFS: 0, handledAccessNet: 0},
			want: "{Landlock V0; FS: ∅; Net: ∅; Scoped: ∅}",
		},
		{
			cfg:  Config{handledAccessFS: ll.AccessFSWriteFile},
			want: "{Landlock V1; FS: {write_file}; Net: ∅; Scoped: ∅}",
		},
		{
			cfg:  Config{handledAccessNet: ll.AccessNetBindTCP},
			want: "{Landlock V4; FS: ∅; Net: {bind_tcp}; Scoped: ∅}",
		},
		{
			cfg:  V1,
			want: "{Landlock V1; FS: all; Net: ∅; Scoped: ∅}",
		},
		{
			cfg:  V1.BestEffort(),
			want: "{Landlock V1; FS: all; Net: ∅; Scoped: ∅ (best effort)}",
		},
		{
			cfg:  Config{handledAccessFS: 1 << 63},
			want: "{Landlock V???; FS: {1<<63}; Net: ∅; Scoped: ∅}",
		},
	} {
		got := tc.cfg.String()
		if got != tc.want {
			t.Errorf("cfg.String() = %q, want %q", got, tc.want)
		}
	}
}

func TestNewConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []any
		want Config
	}{
		{
			name: "fs_write_file",
			args: []any{AccessFSSet(ll.AccessFSWriteFile)},
			want: Config{handledAccessFS: ll.AccessFSWriteFile},
		},
		{
			name: "fs_refer",
			args: []any{AccessFSSet(ll.AccessFSRefer)},
			want: Config{handledAccessFS: ll.AccessFSRefer},
		},
		{
			name: "net_bind",
			args: []any{AccessNetSet(ll.AccessNetBindTCP)},
			want: Config{handledAccessNet: ll.AccessNetBindTCP},
		},
		{
			name: "scoped_signal",
			args: []any{ScopedSet(ll.ScopeSignal)},
			want: Config{scoped: ll.ScopeSignal},
		},
		{
			name: "christmas_tree",
			args: []any{
				AccessFSSet(ll.AccessFSReadDir | ll.AccessFSReadFile),
				AccessNetSet(ll.AccessNetBindTCP | ll.AccessNetConnectTCP),
				ScopedSet(ll.ScopeSignal | ll.ScopeAbstractUnixSocket),
			},
			want: Config{
				handledAccessFS:  ll.AccessFSReadDir | ll.AccessFSReadFile,
				handledAccessNet: ll.AccessNetBindTCP | ll.AccessNetConnectTCP,
				scoped:           ll.ScopeSignal | ll.ScopeAbstractUnixSocket,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(tt.args...)
			if err != nil {
				t.Errorf("NewConfig(): expected success, got %v", err)
			}
			if *cfg != tt.want {
				t.Errorf("cfg = %v, want %v", cfg, tt.want)
			}
		})
	}
}

func TestNewConfigEmpty(t *testing.T) {
	// Constructing an empty config is a bit pointless, but should work.
	c, err := NewConfig()
	if err != nil {
		t.Errorf("NewConfig(): expected success, got %v", err)
	}
	want := AccessFSSet(0)
	if c.handledAccessFS != want {
		t.Errorf("c.handledAccessFS = %v, want %v", c.handledAccessFS, want)
	}
}

func TestNewConfigFailures(t *testing.T) {
	for _, args := range [][]interface{}{
		{ll.AccessFSWriteFile},
		{123},
		{"a string"},
		{"foo", 42},
		// May not specify two AccessFSSets
		{AccessFSSet(ll.AccessFSWriteFile), AccessFSSet(ll.AccessFSReadFile)},
		// May not specify an unsupported AccessFSSet value
		{AccessFSSet(1 << 16)},
		{AccessFSSet(1 << 63)},
	} {
		_, err := NewConfig(args...)
		if err == nil {
			t.Errorf("NewConfig(%v) success, expected error", args)
		}
	}
}

func TestCompatibleWithABI(t *testing.T) {
	for i, abi := range abiInfos {
		cfg := abi.asConfig()
		t.Run(fmt.Sprintf("V%v", i), func(t *testing.T) {
			for j := 0; j < i; j++ {
				if cfg.compatibleWithABI(abiInfos[j]) {
					t.Errorf("cfg.compatibleWithABI(abiInfos[%v]) = true, want false", j)
				}
			}
			for j := i; j < len(abiInfos); j++ {
				if !cfg.compatibleWithABI(abiInfos[j]) {
					t.Errorf("cfg.compatibleWithABI(abiInfos[%v]) = false, want true", j)
				}
			}
		})
	}
}

func TestRestrictTo(t *testing.T) {
	for i, abi := range abiInfos {
		cfg := abi.asConfig()
		t.Run(fmt.Sprintf("V%v", i), func(t *testing.T) {
			for j := 0; j < len(abiInfos); j++ {
				compatCfg := cfg.restrictTo(abiInfos[j])
				if !compatCfg.compatibleWithABI(abiInfos[j]) {
					t.Errorf("compatCfg.compatibleWithABI(abiInfos[%v]) = false, want true", j)
				}
			}
		})
	}
}
