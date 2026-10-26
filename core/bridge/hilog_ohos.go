//go:build linux

package main

/*
#include <stdlib.h>
extern void veil_hilog(int level, const char *msg);
*/
import "C"
import "unsafe"

// hilogWrite forwards one line to HarmonyOS hilog (implemented in the NAPI shim).
func hilogWrite(level, line string) {
	cs := C.CString(line)
	if cs == nil {
		return
	}
	lv := C.int(4)
	switch level {
	case "debug":
		lv = 3
	case "warn":
		lv = 5
	case "error":
		lv = 6
	}
	C.veil_hilog(lv, cs)
	C.free(unsafe.Pointer(cs))
}
