// Package landlock restricts a Go program's ability to use files.
//
// The following invocation will restrict all goroutines so that they
// can only read from /usr, /bin and /tmp, and only write to /tmp:
//
//     err := landlock.V2.BestEffort().RestrictPaths(
//         landlock.RODirs("/usr", "/bin"),
//         landlock.RWDirs("/tmp"),
//     )
//
// This will restrict file access using Landlock V2, if available. If
// unavailable, it will attempt using earlier Landlock versions than
// the one requested. If no Landlock version is available, it will
// still succeed, without restricting file accesses.
//
// More possible invocations
//
// landlock.V2.RestrictPaths(...) enforces the given rules using the
// capabilities of Landlock V2, but returns an error if that is not
// available.
//
// Landlock ABI versioning
//
// Callers need to identify at which ABI level they want to use
// Landlock and call RestrictPaths on the corresponding ABI constant.
//
// When new Landlock versions become available in landlock, users
// will need to upgrade their usages manually to higher Landlock
// versions, as there is a risk that new Landlock versions will break
// operations that their programs rely on.
//
// Graceful degradation on older kernels
//
// Programs that get run on different kernel versions will want to use
// the Config.BestEffort() method to gracefully degrade to using the
// best available Landlock version on the current kernel.
//
// Current limitations
//
// Enabling Landlock implicitly turns off the following file system
// features:
//
// - File reparenting: renaming or linking a file to a different parent directory is denied,
//   unless it is explicitly enabled on both directories with the "Refer" access modifier,
//   and the new target directory does not grant the file additional rights through its
//   Landlock access rules.
//
// - Filesystem topology modification: arbitrary mounts are always denied.
//
// These are Landlock limitations that will be resolved in future
// versions. See
// https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#current-limitations
//
// Multithreading Limitations
//
// This warning only applies to programs using cgo and linking C
// libraries that start OS threads through means other than
// pthread_create() before landlock is called:
//
// When using cgo, the landlock package relies on libpsx in order to
// apply the rules across all OS threads, (rather than just the ones
// managed by the Go runtime). psx achieves this by wrapping the
// C-level phtread_create() API which is very commonly used on Unix to
// start threads. However, C libraries calling clone(2) through other
// means before landlock is called might still create threads that
// won't have Landlock protections.
package landlock
