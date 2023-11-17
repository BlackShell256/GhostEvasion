TEXT ·getModule(SB), $0-32
	MOVQ 0x60(GS), AX
	BYTE $0x90			
	MOVQ 0x18(AX),AX
	BYTE $0x90			

	MOVQ 0x20(AX),AX
	BYTE $0x90			

	XORQ R10,R10
startloop:
	CMPQ R10,i+0(FP)
	BYTE $0x90			
	JE endloop
	BYTE $0x90			
	MOVQ (AX),AX
	BYTE $0x90			
	INCQ R10
	JMP startloop
endloop:
	MOVQ 0x30(AX),CX
	BYTE $0x90			
	MOVQ CX, size+16(FP)
	BYTE $0x90			


	MOVQ 0x20(AX),CX
	BYTE $0x90			
    MOVQ CX, start+8(FP)
    BYTE $0x90			


	MOVQ AX,CX
	BYTE $0x90			
	ADDQ $0x38,CX
	BYTE $0x90			
	MOVQ CX, modulepath+24(FP)
	RET

#define maxargs 18
TEXT ·hgSyscall(SB), $0-56
	BYTE $0x90			
	XORQ AX,AX
	BYTE $0x90			
	MOVW callid+0(FP), AX
	BYTE $0x90			
	PUSHQ CX
	BYTE $0x90			
	MOVQ argh_len+16(FP),CX
	BYTE $0x90		
	MOVQ argh_base+8(FP),SI
	BYTE $0x90			
	MOVQ	0x30(GS), DI
	BYTE $0x90			
	MOVL	$0, 0x68(DI)
	BYTE $0x90			
	SUBQ	$(maxargs*8), SP	
	BYTE $0x90			
	CMPL CX, $0
	JLE callz

	CMPL	CX, $4
	BYTE $0x90			
	JLE	loadregs
	CMPL	CX, $maxargs
	BYTE $0x90			
	JLE	2(PC)
	INT	$3			
	BYTE $0x90			
	MOVQ	SP, DI
	BYTE $0x90			
	CLD
	BYTE $0x90			
	REP; MOVSQ
	BYTE $0x90			
	MOVQ	SP, SI
	BYTE $0x90			
loadregs:
	SUBQ	$8, SP
	BYTE $0x90			
	MOVQ	8(SI), DX
	BYTE $0x90			

	MOVQ	24(SI), R9
	BYTE $0x90			

	MOVQ	0(SI), CX
	BYTE $0x90			

	MOVQ	16(SI), R8
	BYTE $0x90			

	MOVQ	CX, X0
	BYTE $0x90			
	MOVQ	DX, X1
	BYTE $0x90			
	MOVQ	R8, X2
	BYTE $0x90			
	MOVQ	R9, X3
	BYTE $0x90			
	MOVQ CX, R10
	BYTE $0x90			
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET
	PUSHQ CX
callz:
	MOVQ CX, R10
	BYTE $0x90			
	SYSCALL
	ADDQ	$((maxargs)*8), SP
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	RET

