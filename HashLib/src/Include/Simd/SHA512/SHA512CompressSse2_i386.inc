// SHA-512 SSE2 implementation (IA-32), derived from OpenSSL's sha512-586
// (CRYPTOGAMS). The 64-bit state and message schedule are held in xmm0-xmm7 (low
// 64 bits) and computed entirely in SSE2 (paddq/psrlq/psllq/pxor), so the whole
// hash runs in the vector unit - avoiding IA-32's 32-bit-GPR bottleneck.
// Expects (after HlpSimdProc4Begin_i386): ebx = state, esi = data, edi = numblocks,
//   eax = K512 ptr (80 UInt64). HlpSimdProc4Begin pushes ebx/esi/edi; ebp is pushed
//   here as the K512 walk pointer; state is loaded into xmm0-xmm7.

  push   ebp
  mov    ebp, eax
  mov    eax, edi
  mov    edi, esi
  mov    esi, ebx
  mov    ebx, esp
  sub    esp, $10
  and    esp, $FFFFFFC0
  shl    eax, $7
  add    eax, edi
  mov    dword [esp], esi
  mov    dword [esp + $4], edi
  mov    dword [esp + $8], eax
  mov    dword [esp + $C], ebx
  movq   xmm0, qword [esi]
  movq   xmm1, qword [esi + $8]
  movq   xmm2, qword [esi + $10]
  movq   xmm3, qword [esi + $18]
  movq   xmm4, qword [esi + $20]
  movq   xmm5, qword [esi + $28]
  movq   xmm6, qword [esi + $30]
  movq   xmm7, qword [esi + $38]
  sub    esp, $50
  jmp @loop

@loop:
  movq   qword [esp + $8], xmm1
  movq   qword [esp + $10], xmm2
  movq   qword [esp + $18], xmm3
  movq   qword [esp + $28], xmm5
  movq   qword [esp + $30], xmm6
  pxor   xmm2, xmm1
  movq   qword [esp + $38], xmm7
  movdqa xmm3, xmm0
  mov    eax, dword [edi]
  mov    ebx, dword [edi + $4]
  add    edi, $8
  mov    edx, $F
  bswap  eax
  bswap  ebx
  jmp @rounds_00_14

@rounds_00_14:
  movd   xmm1, eax
  mov    eax, dword [edi]
  movd   xmm7, ebx
  mov    ebx, dword [edi + $4]
  add    edi, $8
  bswap  eax
  bswap  ebx
  punpckldq xmm7, xmm1
  movdqa xmm1, xmm4
  pxor   xmm5, xmm6
  psrlq  xmm1, $E
  movq   qword [esp + $20], xmm4
  pand   xmm5, xmm4
  psllq  xmm4, $17
  movdqa xmm0, xmm3
  movq   qword [esp + $48], xmm7
  movdqa xmm3, xmm1
  psrlq  xmm1, $4
  pxor   xmm5, xmm6
  pxor   xmm3, xmm4
  psllq  xmm4, $17
  pxor   xmm3, xmm1
  movq   qword [esp], xmm0
  paddq  xmm7, xmm5
  pxor   xmm3, xmm4
  psrlq  xmm1, $17
  movq   xmm5, qword [esp + $38]
  paddq  xmm7, xmm5
  pxor   xmm3, xmm1
  psllq  xmm4, $4
  movq   xmm1, qword [ebp + $0]
  paddq  xmm7, xmm1
  pxor   xmm3, xmm4
  movq   xmm4, qword [esp + $18]
  paddq  xmm3, xmm7
  movdqa xmm5, xmm0
  psrlq  xmm5, $1C
  paddq  xmm4, xmm3
  movdqa xmm6, xmm0
  movdqa xmm7, xmm5
  psllq  xmm6, $19
  movq   xmm1, qword [esp + $8]
  psrlq  xmm5, $6
  pxor   xmm7, xmm6
  sub    esp, $8
  psllq  xmm6, $5
  pxor   xmm7, xmm5
  pxor   xmm0, xmm1
  psrlq  xmm5, $5
  pxor   xmm7, xmm6
  pand   xmm2, xmm0
  psllq  xmm6, $6
  pxor   xmm7, xmm5
  pxor   xmm2, xmm1
  pxor   xmm6, xmm7
  movq   xmm5, qword [esp + $28]
  paddq  xmm3, xmm2
  movdqa xmm2, xmm0
  add    ebp, $8
  paddq  xmm3, xmm6
  movq   xmm6, qword [esp + $30]
  dec    edx
  jnz @rounds_00_14
  movd   xmm1, eax
  movd   xmm7, ebx
  punpckldq xmm7, xmm1
  movdqa xmm1, xmm4
  pxor   xmm5, xmm6
  psrlq  xmm1, $E
  movq   qword [esp + $20], xmm4
  pand   xmm5, xmm4
  psllq  xmm4, $17
  movdqa xmm0, xmm3
  movq   qword [esp + $48], xmm7
  movdqa xmm3, xmm1
  psrlq  xmm1, $4
  pxor   xmm5, xmm6
  pxor   xmm3, xmm4
  psllq  xmm4, $17
  pxor   xmm3, xmm1
  movq   qword [esp], xmm0
  paddq  xmm7, xmm5
  pxor   xmm3, xmm4
  psrlq  xmm1, $17
  movq   xmm5, qword [esp + $38]
  paddq  xmm7, xmm5
  pxor   xmm3, xmm1
  psllq  xmm4, $4
  movq   xmm1, qword [ebp + $0]
  paddq  xmm7, xmm1
  pxor   xmm3, xmm4
  movq   xmm4, qword [esp + $18]
  paddq  xmm3, xmm7
  movdqa xmm5, xmm0
  psrlq  xmm5, $1C
  paddq  xmm4, xmm3
  movdqa xmm6, xmm0
  movdqa xmm7, xmm5
  psllq  xmm6, $19
  movq   xmm1, qword [esp + $8]
  psrlq  xmm5, $6
  pxor   xmm7, xmm6
  sub    esp, $8
  psllq  xmm6, $5
  pxor   xmm7, xmm5
  pxor   xmm0, xmm1
  psrlq  xmm5, $5
  pxor   xmm7, xmm6
  pand   xmm2, xmm0
  psllq  xmm6, $6
  pxor   xmm7, xmm5
  pxor   xmm2, xmm1
  pxor   xmm6, xmm7
  movq   xmm7, qword [esp + $C0]
  paddq  xmm3, xmm2
  movdqa xmm2, xmm0
  add    ebp, $8
  paddq  xmm3, xmm6
  pxor   xmm0, xmm0
  mov    edx, $20
  jmp @rounds_16_79

@rounds_16_79:
  movq   xmm5, qword [esp + $58]
  movdqa xmm1, xmm7
  psrlq  xmm7, $1
  movdqa xmm6, xmm5
  psrlq  xmm5, $6
  psllq  xmm1, $38
  paddq  xmm0, xmm3
  movdqa xmm3, xmm7
  psrlq  xmm7, $6
  pxor   xmm3, xmm1
  psllq  xmm1, $7
  pxor   xmm3, xmm7
  psrlq  xmm7, $1
  pxor   xmm3, xmm1
  movdqa xmm1, xmm5
  psrlq  xmm5, $D
  pxor   xmm7, xmm3
  psllq  xmm6, $3
  pxor   xmm1, xmm5
  movq   xmm3, qword [esp + $C8]
  paddq  xmm7, xmm3
  pxor   xmm1, xmm6
  psrlq  xmm5, $2A
  movq   xmm3, qword [esp + $80]
  paddq  xmm7, xmm3
  pxor   xmm1, xmm5
  psllq  xmm6, $2A
  movq   xmm5, qword [esp + $28]
  pxor   xmm1, xmm6
  movq   xmm6, qword [esp + $30]
  paddq  xmm7, xmm1
  movdqa xmm1, xmm4
  pxor   xmm5, xmm6
  psrlq  xmm1, $E
  movq   qword [esp + $20], xmm4
  pand   xmm5, xmm4
  psllq  xmm4, $17
  movq   qword [esp + $48], xmm7
  movdqa xmm3, xmm1
  psrlq  xmm1, $4
  pxor   xmm5, xmm6
  pxor   xmm3, xmm4
  psllq  xmm4, $17
  pxor   xmm3, xmm1
  movq   qword [esp], xmm0
  paddq  xmm7, xmm5
  pxor   xmm3, xmm4
  psrlq  xmm1, $17
  movq   xmm5, qword [esp + $38]
  paddq  xmm7, xmm5
  pxor   xmm3, xmm1
  psllq  xmm4, $4
  movq   xmm1, qword [ebp + $0]
  paddq  xmm7, xmm1
  pxor   xmm3, xmm4
  movq   xmm4, qword [esp + $18]
  paddq  xmm3, xmm7
  movdqa xmm5, xmm0
  psrlq  xmm5, $1C
  paddq  xmm4, xmm3
  movdqa xmm6, xmm0
  movdqa xmm7, xmm5
  psllq  xmm6, $19
  movq   xmm1, qword [esp + $8]
  psrlq  xmm5, $6
  pxor   xmm7, xmm6
  sub    esp, $8
  psllq  xmm6, $5
  pxor   xmm7, xmm5
  pxor   xmm0, xmm1
  psrlq  xmm5, $5
  pxor   xmm7, xmm6
  pand   xmm2, xmm0
  psllq  xmm6, $6
  pxor   xmm7, xmm5
  pxor   xmm2, xmm1
  pxor   xmm6, xmm7
  movq   xmm7, qword [esp + $C0]
  paddq  xmm2, xmm6
  add    ebp, $8
  movq   xmm5, qword [esp + $58]
  movdqa xmm1, xmm7
  psrlq  xmm7, $1
  movdqa xmm6, xmm5
  psrlq  xmm5, $6
  psllq  xmm1, $38
  paddq  xmm2, xmm3
  movdqa xmm3, xmm7
  psrlq  xmm7, $6
  pxor   xmm3, xmm1
  psllq  xmm1, $7
  pxor   xmm3, xmm7
  psrlq  xmm7, $1
  pxor   xmm3, xmm1
  movdqa xmm1, xmm5
  psrlq  xmm5, $D
  pxor   xmm7, xmm3
  psllq  xmm6, $3
  pxor   xmm1, xmm5
  movq   xmm3, qword [esp + $C8]
  paddq  xmm7, xmm3
  pxor   xmm1, xmm6
  psrlq  xmm5, $2A
  movq   xmm3, qword [esp + $80]
  paddq  xmm7, xmm3
  pxor   xmm1, xmm5
  psllq  xmm6, $2A
  movq   xmm5, qword [esp + $28]
  pxor   xmm1, xmm6
  movq   xmm6, qword [esp + $30]
  paddq  xmm7, xmm1
  movdqa xmm1, xmm4
  pxor   xmm5, xmm6
  psrlq  xmm1, $E
  movq   qword [esp + $20], xmm4
  pand   xmm5, xmm4
  psllq  xmm4, $17
  movq   qword [esp + $48], xmm7
  movdqa xmm3, xmm1
  psrlq  xmm1, $4
  pxor   xmm5, xmm6
  pxor   xmm3, xmm4
  psllq  xmm4, $17
  pxor   xmm3, xmm1
  movq   qword [esp], xmm2
  paddq  xmm7, xmm5
  pxor   xmm3, xmm4
  psrlq  xmm1, $17
  movq   xmm5, qword [esp + $38]
  paddq  xmm7, xmm5
  pxor   xmm3, xmm1
  psllq  xmm4, $4
  movq   xmm1, qword [ebp + $0]
  paddq  xmm7, xmm1
  pxor   xmm3, xmm4
  movq   xmm4, qword [esp + $18]
  paddq  xmm3, xmm7
  movdqa xmm5, xmm2
  psrlq  xmm5, $1C
  paddq  xmm4, xmm3
  movdqa xmm6, xmm2
  movdqa xmm7, xmm5
  psllq  xmm6, $19
  movq   xmm1, qword [esp + $8]
  psrlq  xmm5, $6
  pxor   xmm7, xmm6
  sub    esp, $8
  psllq  xmm6, $5
  pxor   xmm7, xmm5
  pxor   xmm2, xmm1
  psrlq  xmm5, $5
  pxor   xmm7, xmm6
  pand   xmm0, xmm2
  psllq  xmm6, $6
  pxor   xmm7, xmm5
  pxor   xmm0, xmm1
  pxor   xmm6, xmm7
  movq   xmm7, qword [esp + $C0]
  paddq  xmm0, xmm6
  add    ebp, $8
  dec    edx
  jnz @rounds_16_79
  paddq  xmm0, xmm3
  movq   xmm1, qword [esp + $8]
  movq   xmm3, qword [esp + $18]
  movq   xmm5, qword [esp + $28]
  movq   xmm6, qword [esp + $30]
  movq   xmm7, qword [esp + $38]
  pxor   xmm2, xmm1
  sub    esp, $8
  movq   qword [esp], xmm7
  movq   xmm7, qword [esi]
  paddq  xmm0, xmm7
  movq   qword [esi], xmm0
  movq   xmm0, qword [esi + $8]
  paddq  xmm1, xmm0
  movq   qword [esi + $8], xmm1
  movq   xmm0, qword [esi + $10]
  paddq  xmm2, xmm0
  movq   qword [esi + $10], xmm2
  movq   xmm0, qword [esi + $18]
  paddq  xmm3, xmm0
  movq   qword [esi + $18], xmm3
  movq   xmm0, qword [esi + $20]
  paddq  xmm4, xmm0
  movq   qword [esi + $20], xmm4
  movq   xmm0, qword [esi + $28]
  paddq  xmm5, xmm0
  movq   qword [esi + $28], xmm5
  movq   xmm0, qword [esi + $30]
  paddq  xmm6, xmm0
  movq   qword [esi + $30], xmm6
  movq   xmm7, qword [esp]
  add    esp, $8
  movq   xmm0, qword [esi + $38]
  paddq  xmm7, xmm0
  movq   qword [esi + $38], xmm7
  mov    eax, $280
  movq   xmm0, qword [esi]
  lea    esp, [esp + eax*1]
  sub    ebp, eax
  cmp    edi, dword [esp + $58]
  jb @loop
  mov    esp, dword [esp + $5C]
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
