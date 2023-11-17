package main

import (
	"syscall"
	"unsafe"

	ghostevasion "github.com/BlackShell256/GhostEvasion/pkg/GhostEvasion"
)

var (
	kernel32      = ghostevasion.NewLazyDLL("shell32")
	ShellExecuteW = kernel32.NewProc("ShellExecuteW")
)

func main() {
	s, err := syscall.UTF16PtrFromString("notepad.exe")
	if err != nil {
		panic(err)
	}
	_, err = ShellExecuteW.Call(
		0,
		0,
		uintptr(unsafe.Pointer(s)),
		0,
		0,
		1,
	)
	if err != nil {
		panic(err)
	}
}
