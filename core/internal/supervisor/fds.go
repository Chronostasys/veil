package supervisor

import (
	"os"

	"veil/internal/logx"
)

// logLevel maps a configuration string to a logger level.
func logLevel(s string) logx.Level { return logx.ParseLevel(s) }

// countFDs returns the number of open file descriptors, or 0 when the platform
// does not expose it cheaply. It is used as a leak signal in the health block.
func countFDs() int {
	entries, err := os.ReadDir(fdDir())
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		n++
	}
	return n
}
