# GhostEvasion
Syscalld Indirectas, GetModuleHandle y GetProcessAddres personalizado para la evasión.


## Uso
https://github.com/BlackShell256/GhostEvasion/tree/main/example
```
package main

import (
  "crypto/sha1"
  "encoding/hex"
   ghostevasion "github.com/BlackShell256/GhostEvasion/pkg/GhostEvasion"
)

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

func main() {
	newWhisper := ghostevasion.Whisper(hash)

	NtAllocateVirtualMemory, err := newWhisper.GetSysid("1021ddc2cb8b096b")
	if err != nil {
		panic(err)
	}
	println(NtAllocateVirtualMemory.Id)
}
```

### Creditos
Gracias por sus proyectos

@timwhitez
@C-Sto

