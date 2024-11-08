// landlock-restrict-scoped executes a process with Landlock scope restrictions
//
// This is an example tool which does not provide backwards
// compatibility guarantees.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func usage() {
	var (
		out  = flag.CommandLine.Output()
		name = os.Args[0]
	)
	fmt.Fprintf(out, "Usage of %s:\n", name)
	flag.PrintDefaults()
	fmt.Fprintf(out, "\nExample usages:\n")
	fmt.Fprintf(out, "  %s -- /usr/bin/kill -USR1 $$\n", name)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	var cmd []string
	if flag.NArg() > 1 {
		cmd = flag.Args()
	} else {
		log.Println("missing command to call, using /bin/bash")
		cmd = []string{"/bin/bash"}
	}

	if err := landlock.V6.RestrictScoped(); err != nil {
		log.Fatalf("landlock RestrictScoped: %v", err)
	}

	log.Printf("Starting %v", cmd)
	if err := syscall.Exec(cmd[0], cmd, os.Environ()); err != nil {
		log.Fatalf("execve: %v", err)
	}
}
