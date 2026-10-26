//go:build linux

package supervisor

// fdDir is where Linux exposes the descriptor table of a process.
func fdDir() string { return "/proc/self/fd" }
