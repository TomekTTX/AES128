.code

shiftRows PROC
	push	rbp
	mov	rbp, rsp

	rol	dword ptr [rcx + 4], 8
	rol	dword ptr [rcx + 8], 16
	ror	dword ptr [rcx + 12], 8

	pop	rbp
	ret
shiftRows ENDP

shiftRowsReverse PROC
	push	rbp
	mov	rbp, rsp

	ror	dword ptr [rcx + 4], 8
	ror	dword ptr [rcx + 8], 16
	rol	dword ptr [rcx + 12], 8

	pop	rbp
	ret
shiftRowsReverse ENDP

; XOR 128 bits of arg1 with arg2
xor128 PROC
	push	rbp
	mov	rbp, rsp

	movdqu  xmm0, [rdx]
	movdqu  xmm1, [rcx]
	xorps	xmm0, xmm1
	movdqu  [rcx], xmm0

	pop	rbp
	ret
xor128 ENDP

END
