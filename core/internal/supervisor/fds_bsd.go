//go:build darwin || freebsd || netbsd || openbsd

package supervisor

// fdDir is where macOS and the BSDs expose the descriptor table of a process.
func fdDir() string { return "/dev/fd" }
