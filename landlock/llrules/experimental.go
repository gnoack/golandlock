// Package llrules implements commonly used groups of Landlock rules.
//
// This package is *experimental*.
package llrules

import "github.com/landlock-lsm/go-landlock/landlock"

func DNS() landlock.Rule {
	// UDP is not restrictable yet, but it can be added here once
	// Landlock can do that.
	return landlock.CompositeRule(landlock.ConnectTCP(53), dnsFiles())
}

func dnsFiles() landlock.Rule {
	return landlock.ROFiles(
		"/etc/hosts",
		"/etc/resolv.conf",
	).IgnoreIfMissing()
}

func SharedLibraries() landlock.Rule {
	// XXX: How does the linker look up this list of paths?
	// XXX: Use more specific rulesets.
	return landlock.RODirs(
		"/lib",
		"/lib32",
		"/lib64",
		"/usr/lib",
		"/usr/lib32",
		"/usr/lib64",
	).IgnoreIfMissing()
}
