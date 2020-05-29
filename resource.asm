.code

shiftRows PROC
	push	rbp
	mov		rbp, rsp

	rol		dword ptr [rcx + 4], 8
	rol		dword ptr [rcx + 8], 16
	ror		dword ptr [rcx + 12], 8

	pop		rbp
	ret
shiftRows ENDP

shiftRowsReverse PROC
	push	rbp
	mov		rbp, rsp

	ror		dword ptr [rcx + 4], 8
	ror		dword ptr [rcx + 8], 16
	rol		dword ptr [rcx + 12], 8

	pop		rbp
	ret
shiftRowsReverse ENDP

; XOR 128 bits of arg1 with arg2
xor128 PROC
	push	rbp
	mov		rbp, rsp

	movdqu  xmm0, [rdx]
	movdqu  xmm1, [rcx]
	xorps	xmm0, xmm1
	movdqu  [rcx], xmm0

	pop		rbp
	ret
xor128 ENDP

END







mc_matrix	db	2,3,1,1,
				1,2,3,1,
				1,1,2,3,
				3,1,1,2,

matrMul PROC
	push	rbp
	mov		rbp, rsp
	push	rsi
	push	rbx

	mov		rsi, offset mc_matrix
	xor		rdx, rdx

	mov		r8, 4
outer:
	mov		r9, 4
	mov		ebx, [rsi][4 * r8 - 4]
	mov		rax, [rcx]
inner:
	mul		bl
	xor		dl, al
	rol		eax, 16
	rol		ebx, 8

	dec		r9
	jnz		inner

	rol		rdx, 16
	dec		r8
	jnz		outer

	ror		rdx, 16
	mov		[rcx], rdx

	pop		rbx
	pop		rsi
	pop		rbp
	ret
matrMul ENDP