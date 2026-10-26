//go:build !linux

package main

import "fmt"
import "os"

// hilogWrite is a no-op on desktop builds (stdout stands in for hilog).
func hilogWrite(level, line string) {
	fmt.Fprintln(os.Stdout, line)
}
