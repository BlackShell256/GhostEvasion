package ghostevasion

import "golang.org/x/sys/windows"

func getModule(i int) (start uintptr, size uintptr, modulepath *nTUnicodeString)

type nTUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func (s nTUnicodeString) String() string {
	return windows.UTF16PtrToString(s.Buffer)
}

func hgSyscall(callid uint16, argh ...uintptr) (errcode uint32)
