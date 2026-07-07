// SHA-1 SSE2 SIMD-schedule implementation (IA-32), derived from OpenSSL's
// sha1-586 (CRYPTOGAMS) SSSE3 kernel. The message schedule runs in SSE2
// (pxor/pshufd/psrldq/pslldq) interleaved with the GPR compression rounds.
// OpenSSL's only SSSE3-only op is the pshufb input byte-swap, emulated in SSE2 as
// psrlw/psllw/por + pshuflw/pshufhw (the freed byte-swap-mask register xmm6 is the
// scratch); the W-schedule uses no palignr.
// Expects (after SimdProc4Begin_i386): ebx = state, esi = data, edi = numblocks,
//   eax = doubled-K_SHA1 ptr (read at a 32-byte stride so the duplicated halves
//   are skipped; see K_SHA1_Doubled). SimdProc4Begin pushes ebx/esi/edi; ebp is
//   pushed here as the K pointer, then reused as the data pointer and for the
//   state writeback.

  push   ebp
  mov    ebp, eax

  movdqu xmm7, oword [ebp + $0]
  movdqu xmm0, oword [ebp + $20]
  movdqu xmm1, oword [ebp + $40]
  movdqu xmm2, oword [ebp + $60]
  movdqu xmm6, oword [ebp + $80]
  mov    edx, edi
  mov    edi, ebx
  mov    ebp, esi
  mov    esi, esp
  sub    esp, $D0
  and    esp, $FFFFFFC0
  movdqa oword [esp + $70], xmm0
  movdqa oword [esp + $80], xmm1
  movdqa oword [esp + $90], xmm2
  shl    edx, $6
  movdqa oword [esp + $A0], xmm7
  add    edx, ebp
  movdqa oword [esp + $B0], xmm6
  add    ebp, $40
  mov    dword [esp + $C0], edi
  mov    dword [esp + $C4], ebp
  mov    dword [esp + $C8], edx
  mov    dword [esp + $CC], esi
  mov    eax, dword [edi]
  mov    ebx, dword [edi + $4]
  mov    ecx, dword [edi + $8]
  mov    edx, dword [edi + $C]
  mov    edi, dword [edi + $10]
  mov    esi, ebx
  movdqu xmm0, oword [ebp - $40]
  movdqu xmm1, oword [ebp - $30]
  movdqu xmm2, oword [ebp - $20]
  movdqu xmm3, oword [ebp - $10]
  movdqa xmm6, xmm0
  psrlw  xmm6, $8
  psllw  xmm0, $8
  por    xmm0, xmm6
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqa xmm6, xmm1
  psrlw  xmm6, $8
  psllw  xmm1, $8
  por    xmm1, xmm6
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqa xmm6, xmm2
  psrlw  xmm6, $8
  psllw  xmm2, $8
  por    xmm2, xmm6
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  movdqa oword [esp + $60], xmm7
  movdqa xmm6, xmm3
  psrlw  xmm6, $8
  psllw  xmm3, $8
  por    xmm3, xmm6
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd  xmm0, xmm7
  paddd  xmm1, xmm7
  paddd  xmm2, xmm7
  movdqa oword [esp], xmm0
  psubd  xmm0, xmm7
  movdqa oword [esp + $10], xmm1
  psubd  xmm1, xmm7
  movdqa oword [esp + $20], xmm2
  mov    ebp, ecx
  psubd  xmm2, xmm7
  xor    ebp, edx
  pshufd xmm4, xmm0, $EE
  and    esi, ebp
  jmp @block_loop

@block_loop:
  ror    ebx, $2
  xor    esi, edx
  mov    ebp, eax
  punpcklqdq xmm4, xmm1
  movdqa xmm6, xmm3
  add    edi, dword [esp]
  xor    ebx, ecx
  paddd  xmm7, xmm3
  movdqa oword [esp + $40], xmm0
  rol    eax, $5
  add    edi, esi
  psrldq xmm6, $4
  and    ebp, ebx
  xor    ebx, ecx
  pxor   xmm4, xmm0
  add    edi, eax
  ror    eax, $7
  pxor   xmm6, xmm2
  xor    ebp, ecx
  mov    esi, edi
  add    edx, dword [esp + $4]
  pxor   xmm4, xmm6
  xor    eax, ebx
  rol    edi, $5
  movdqa oword [esp + $30], xmm7
  add    edx, ebp
  and    esi, eax
  movdqa xmm0, xmm4
  xor    eax, ebx
  add    edx, edi
  ror    edi, $7
  movdqa xmm6, xmm4
  xor    esi, ebx
  pslldq xmm0, $C
  paddd  xmm4, xmm4
  mov    ebp, edx
  add    ecx, dword [esp + $8]
  psrld  xmm6, $1F
  xor    edi, eax
  rol    edx, $5
  movdqa xmm7, xmm0
  add    ecx, esi
  and    ebp, edi
  xor    edi, eax
  psrld  xmm0, $1E
  add    ecx, edx
  ror    edx, $7
  por    xmm4, xmm6
  xor    ebp, eax
  mov    esi, ecx
  add    ebx, dword [esp + $C]
  pslld  xmm7, $2
  xor    edx, edi
  rol    ecx, $5
  pxor   xmm4, xmm0
  movdqa xmm0, oword [esp + $60]
  add    ebx, ebp
  and    esi, edx
  pxor   xmm4, xmm7
  pshufd xmm5, xmm1, $EE
  xor    edx, edi
  add    ebx, ecx
  ror    ecx, $7
  xor    esi, edi
  mov    ebp, ebx
  punpcklqdq xmm5, xmm2
  movdqa xmm7, xmm4
  add    eax, dword [esp + $10]
  xor    ecx, edx
  paddd  xmm0, xmm4
  movdqa oword [esp + $50], xmm1
  rol    ebx, $5
  add    eax, esi
  psrldq xmm7, $4
  and    ebp, ecx
  xor    ecx, edx
  pxor   xmm5, xmm1
  add    eax, ebx
  ror    ebx, $7
  pxor   xmm7, xmm3
  xor    ebp, edx
  mov    esi, eax
  add    edi, dword [esp + $14]
  pxor   xmm5, xmm7
  xor    ebx, ecx
  rol    eax, $5
  movdqa oword [esp], xmm0
  add    edi, ebp
  and    esi, ebx
  movdqa xmm1, xmm5
  xor    ebx, ecx
  add    edi, eax
  ror    eax, $7
  movdqa xmm7, xmm5
  xor    esi, ecx
  pslldq xmm1, $C
  paddd  xmm5, xmm5
  mov    ebp, edi
  add    edx, dword [esp + $18]
  psrld  xmm7, $1F
  xor    eax, ebx
  rol    edi, $5
  movdqa xmm0, xmm1
  add    edx, esi
  and    ebp, eax
  xor    eax, ebx
  psrld  xmm1, $1E
  add    edx, edi
  ror    edi, $7
  por    xmm5, xmm7
  xor    ebp, ebx
  mov    esi, edx
  add    ecx, dword [esp + $1C]
  pslld  xmm0, $2
  xor    edi, eax
  rol    edx, $5
  pxor   xmm5, xmm1
  movdqa xmm1, oword [esp + $70]
  add    ecx, ebp
  and    esi, edi
  pxor   xmm5, xmm0
  pshufd xmm6, xmm2, $EE
  xor    edi, eax
  add    ecx, edx
  ror    edx, $7
  xor    esi, eax
  mov    ebp, ecx
  punpcklqdq xmm6, xmm3
  movdqa xmm0, xmm5
  add    ebx, dword [esp + $20]
  xor    edx, edi
  paddd  xmm1, xmm5
  movdqa oword [esp + $60], xmm2
  rol    ecx, $5
  add    ebx, esi
  psrldq xmm0, $4
  and    ebp, edx
  xor    edx, edi
  pxor   xmm6, xmm2
  add    ebx, ecx
  ror    ecx, $7
  pxor   xmm0, xmm4
  xor    ebp, edi
  mov    esi, ebx
  add    eax, dword [esp + $24]
  pxor   xmm6, xmm0
  xor    ecx, edx
  rol    ebx, $5
  movdqa oword [esp + $10], xmm1
  add    eax, ebp
  and    esi, ecx
  movdqa xmm2, xmm6
  xor    ecx, edx
  add    eax, ebx
  ror    ebx, $7
  movdqa xmm0, xmm6
  xor    esi, edx
  pslldq xmm2, $C
  paddd  xmm6, xmm6
  mov    ebp, eax
  add    edi, dword [esp + $28]
  psrld  xmm0, $1F
  xor    ebx, ecx
  rol    eax, $5
  movdqa xmm1, xmm2
  add    edi, esi
  and    ebp, ebx
  xor    ebx, ecx
  psrld  xmm2, $1E
  add    edi, eax
  ror    eax, $7
  por    xmm6, xmm0
  xor    ebp, ecx
  movdqa xmm0, oword [esp + $40]
  mov    esi, edi
  add    edx, dword [esp + $2C]
  pslld  xmm1, $2
  xor    eax, ebx
  rol    edi, $5
  pxor   xmm6, xmm2
  movdqa xmm2, oword [esp + $70]
  add    edx, ebp
  and    esi, eax
  pxor   xmm6, xmm1
  pshufd xmm7, xmm3, $EE
  xor    eax, ebx
  add    edx, edi
  ror    edi, $7
  xor    esi, ebx
  mov    ebp, edx
  punpcklqdq xmm7, xmm4
  movdqa xmm1, xmm6
  add    ecx, dword [esp + $30]
  xor    edi, eax
  paddd  xmm2, xmm6
  movdqa oword [esp + $40], xmm3
  rol    edx, $5
  add    ecx, esi
  psrldq xmm1, $4
  and    ebp, edi
  xor    edi, eax
  pxor   xmm7, xmm3
  add    ecx, edx
  ror    edx, $7
  pxor   xmm1, xmm5
  xor    ebp, eax
  mov    esi, ecx
  add    ebx, dword [esp + $34]
  pxor   xmm7, xmm1
  xor    edx, edi
  rol    ecx, $5
  movdqa oword [esp + $20], xmm2
  add    ebx, ebp
  and    esi, edx
  movdqa xmm3, xmm7
  xor    edx, edi
  add    ebx, ecx
  ror    ecx, $7
  movdqa xmm1, xmm7
  xor    esi, edi
  pslldq xmm3, $C
  paddd  xmm7, xmm7
  mov    ebp, ebx
  add    eax, dword [esp + $38]
  psrld  xmm1, $1F
  xor    ecx, edx
  rol    ebx, $5
  movdqa xmm2, xmm3
  add    eax, esi
  and    ebp, ecx
  xor    ecx, edx
  psrld  xmm3, $1E
  add    eax, ebx
  ror    ebx, $7
  por    xmm7, xmm1
  xor    ebp, edx
  movdqa xmm1, oword [esp + $50]
  mov    esi, eax
  add    edi, dword [esp + $3C]
  pslld  xmm2, $2
  xor    ebx, ecx
  rol    eax, $5
  pxor   xmm7, xmm3
  movdqa xmm3, oword [esp + $70]
  add    edi, ebp
  and    esi, ebx
  pxor   xmm7, xmm2
  pshufd xmm2, xmm6, $EE
  xor    ebx, ecx
  add    edi, eax
  ror    eax, $7
  pxor   xmm0, xmm4
  punpcklqdq xmm2, xmm7
  xor    esi, ecx
  mov    ebp, edi
  add    edx, dword [esp]
  pxor   xmm0, xmm1
  movdqa oword [esp + $50], xmm4
  xor    eax, ebx
  rol    edi, $5
  movdqa xmm4, xmm3
  add    edx, esi
  paddd  xmm3, xmm7
  and    ebp, eax
  pxor   xmm0, xmm2
  xor    eax, ebx
  add    edx, edi
  ror    edi, $7
  xor    ebp, ebx
  movdqa xmm2, xmm0
  movdqa oword [esp + $30], xmm3
  mov    esi, edx
  add    ecx, dword [esp + $4]
  xor    edi, eax
  rol    edx, $5
  pslld  xmm0, $2
  add    ecx, ebp
  and    esi, edi
  psrld  xmm2, $1E
  xor    edi, eax
  add    ecx, edx
  ror    edx, $7
  xor    esi, eax
  mov    ebp, ecx
  add    ebx, dword [esp + $8]
  xor    edx, edi
  rol    ecx, $5
  por    xmm0, xmm2
  add    ebx, esi
  and    ebp, edx
  movdqa xmm2, oword [esp + $60]
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword [esp + $C]
  xor    ebp, edi
  mov    esi, ebx
  pshufd xmm3, xmm7, $EE
  rol    ebx, $5
  add    eax, ebp
  xor    esi, edx
  ror    ecx, $7
  add    eax, ebx
  add    edi, dword [esp + $10]
  pxor   xmm1, xmm5
  punpcklqdq xmm3, xmm0
  xor    esi, ecx
  mov    ebp, eax
  rol    eax, $5
  pxor   xmm1, xmm2
  movdqa oword [esp + $60], xmm5
  add    edi, esi
  xor    ebp, ecx
  movdqa xmm5, xmm4
  ror    ebx, $7
  paddd  xmm4, xmm0
  add    edi, eax
  pxor   xmm1, xmm3
  add    edx, dword [esp + $14]
  xor    ebp, ebx
  mov    esi, edi
  rol    edi, $5
  movdqa xmm3, xmm1
  movdqa oword [esp], xmm4
  add    edx, ebp
  xor    esi, ebx
  ror    eax, $7
  add    edx, edi
  pslld  xmm1, $2
  add    ecx, dword [esp + $18]
  xor    esi, eax
  psrld  xmm3, $1E
  mov    ebp, edx
  rol    edx, $5
  add    ecx, esi
  xor    ebp, eax
  ror    edi, $7
  add    ecx, edx
  por    xmm1, xmm3
  add    ebx, dword [esp + $1C]
  xor    ebp, edi
  movdqa xmm3, oword [esp + $40]
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, ebp
  xor    esi, edi
  ror    edx, $7
  pshufd xmm4, xmm0, $EE
  add    ebx, ecx
  add    eax, dword [esp + $20]
  pxor   xmm2, xmm6
  punpcklqdq xmm4, xmm1
  xor    esi, edx
  mov    ebp, ebx
  rol    ebx, $5
  pxor   xmm2, xmm3
  movdqa oword [esp + $40], xmm6
  add    eax, esi
  xor    ebp, edx
  movdqa xmm6, oword [esp + $80]
  ror    ecx, $7
  paddd  xmm5, xmm1
  add    eax, ebx
  pxor   xmm2, xmm4
  add    edi, dword [esp + $24]
  xor    ebp, ecx
  mov    esi, eax
  rol    eax, $5
  movdqa xmm4, xmm2
  movdqa oword [esp + $10], xmm5
  add    edi, ebp
  xor    esi, ecx
  ror    ebx, $7
  add    edi, eax
  pslld  xmm2, $2
  add    edx, dword [esp + $28]
  xor    esi, ebx
  psrld  xmm4, $1E
  mov    ebp, edi
  rol    edi, $5
  add    edx, esi
  xor    ebp, ebx
  ror    eax, $7
  add    edx, edi
  por    xmm2, xmm4
  add    ecx, dword [esp + $2C]
  xor    ebp, eax
  movdqa xmm4, oword [esp + $50]
  mov    esi, edx
  rol    edx, $5
  add    ecx, ebp
  xor    esi, eax
  ror    edi, $7
  pshufd xmm5, xmm1, $EE
  add    ecx, edx
  add    ebx, dword [esp + $30]
  pxor   xmm3, xmm7
  punpcklqdq xmm5, xmm2
  xor    esi, edi
  mov    ebp, ecx
  rol    ecx, $5
  pxor   xmm3, xmm4
  movdqa oword [esp + $50], xmm7
  add    ebx, esi
  xor    ebp, edi
  movdqa xmm7, xmm6
  ror    edx, $7
  paddd  xmm6, xmm2
  add    ebx, ecx
  pxor   xmm3, xmm5
  add    eax, dword [esp + $34]
  xor    ebp, edx
  mov    esi, ebx
  rol    ebx, $5
  movdqa xmm5, xmm3
  movdqa oword [esp + $20], xmm6
  add    eax, ebp
  xor    esi, edx
  ror    ecx, $7
  add    eax, ebx
  pslld  xmm3, $2
  add    edi, dword [esp + $38]
  xor    esi, ecx
  psrld  xmm5, $1E
  mov    ebp, eax
  rol    eax, $5
  add    edi, esi
  xor    ebp, ecx
  ror    ebx, $7
  add    edi, eax
  por    xmm3, xmm5
  add    edx, dword [esp + $3C]
  xor    ebp, ebx
  movdqa xmm5, oword [esp + $60]
  mov    esi, edi
  rol    edi, $5
  add    edx, ebp
  xor    esi, ebx
  ror    eax, $7
  pshufd xmm6, xmm2, $EE
  add    edx, edi
  add    ecx, dword [esp]
  pxor   xmm4, xmm0
  punpcklqdq xmm6, xmm3
  xor    esi, eax
  mov    ebp, edx
  rol    edx, $5
  pxor   xmm4, xmm5
  movdqa oword [esp + $60], xmm0
  add    ecx, esi
  xor    ebp, eax
  movdqa xmm0, xmm7
  ror    edi, $7
  paddd  xmm7, xmm3
  add    ecx, edx
  pxor   xmm4, xmm6
  add    ebx, dword [esp + $4]
  xor    ebp, edi
  mov    esi, ecx
  rol    ecx, $5
  movdqa xmm6, xmm4
  movdqa oword [esp + $30], xmm7
  add    ebx, ebp
  xor    esi, edi
  ror    edx, $7
  add    ebx, ecx
  pslld  xmm4, $2
  add    eax, dword [esp + $8]
  xor    esi, edx
  psrld  xmm6, $1E
  mov    ebp, ebx
  rol    ebx, $5
  add    eax, esi
  xor    ebp, edx
  ror    ecx, $7
  add    eax, ebx
  por    xmm4, xmm6
  add    edi, dword [esp + $C]
  xor    ebp, ecx
  movdqa xmm6, oword [esp + $40]
  mov    esi, eax
  rol    eax, $5
  add    edi, ebp
  xor    esi, ecx
  ror    ebx, $7
  pshufd xmm7, xmm3, $EE
  add    edi, eax
  add    edx, dword [esp + $10]
  pxor   xmm5, xmm1
  punpcklqdq xmm7, xmm4
  xor    esi, ebx
  mov    ebp, edi
  rol    edi, $5
  pxor   xmm5, xmm6
  movdqa oword [esp + $40], xmm1
  add    edx, esi
  xor    ebp, ebx
  movdqa xmm1, xmm0
  ror    eax, $7
  paddd  xmm0, xmm4
  add    edx, edi
  pxor   xmm5, xmm7
  add    ecx, dword [esp + $14]
  xor    ebp, eax
  mov    esi, edx
  rol    edx, $5
  movdqa xmm7, xmm5
  movdqa oword [esp], xmm0
  add    ecx, ebp
  xor    esi, eax
  ror    edi, $7
  add    ecx, edx
  pslld  xmm5, $2
  add    ebx, dword [esp + $18]
  xor    esi, edi
  psrld  xmm7, $1E
  mov    ebp, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edi
  ror    edx, $7
  add    ebx, ecx
  por    xmm5, xmm7
  add    eax, dword [esp + $1C]
  movdqa xmm7, oword [esp + $50]
  ror    ecx, $7
  mov    esi, ebx
  xor    ebp, edx
  rol    ebx, $5
  pshufd xmm0, xmm4, $EE
  add    eax, ebp
  xor    esi, ecx
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword [esp + $20]
  pxor   xmm6, xmm2
  punpcklqdq xmm0, xmm5
  and    esi, ecx
  xor    ecx, edx
  ror    ebx, $7
  pxor   xmm6, xmm7
  movdqa oword [esp + $50], xmm2
  mov    ebp, eax
  xor    esi, ecx
  rol    eax, $5
  movdqa xmm2, xmm1
  add    edi, esi
  paddd  xmm1, xmm5
  xor    ebp, ebx
  pxor   xmm6, xmm0
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword [esp + $24]
  and    ebp, ebx
  movdqa xmm0, xmm6
  movdqa oword [esp + $10], xmm1
  xor    ebx, ecx
  ror    eax, $7
  mov    esi, edi
  xor    ebp, ebx
  rol    edi, $5
  pslld  xmm6, $2
  add    edx, ebp
  xor    esi, eax
  psrld  xmm0, $1E
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword [esp + $28]
  and    esi, eax
  xor    eax, ebx
  ror    edi, $7
  por    xmm6, xmm0
  mov    ebp, edx
  xor    esi, eax
  movdqa xmm0, oword [esp + $60]
  rol    edx, $5
  add    ecx, esi
  xor    ebp, edi
  xor    edi, eax
  add    ecx, edx
  pshufd xmm1, xmm5, $EE
  add    ebx, dword [esp + $2C]
  and    ebp, edi
  xor    edi, eax
  ror    edx, $7
  mov    esi, ecx
  xor    ebp, edi
  rol    ecx, $5
  add    ebx, ebp
  xor    esi, edx
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword [esp + $30]
  pxor   xmm7, xmm3
  punpcklqdq xmm1, xmm6
  and    esi, edx
  xor    edx, edi
  ror    ecx, $7
  pxor   xmm7, xmm0
  movdqa oword [esp + $60], xmm3
  mov    ebp, ebx
  xor    esi, edx
  rol    ebx, $5
  movdqa xmm3, oword [esp + $90]
  add    eax, esi
  paddd  xmm2, xmm6
  xor    ebp, ecx
  pxor   xmm7, xmm1
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword [esp + $34]
  and    ebp, ecx
  movdqa xmm1, xmm7
  movdqa oword [esp + $20], xmm2
  xor    ecx, edx
  ror    ebx, $7
  mov    esi, eax
  xor    ebp, ecx
  rol    eax, $5
  pslld  xmm7, $2
  add    edi, ebp
  xor    esi, ebx
  psrld  xmm1, $1E
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword [esp + $38]
  and    esi, ebx
  xor    ebx, ecx
  ror    eax, $7
  por    xmm7, xmm1
  mov    ebp, edi
  xor    esi, ebx
  movdqa xmm1, oword [esp + $40]
  rol    edi, $5
  add    edx, esi
  xor    ebp, eax
  xor    eax, ebx
  add    edx, edi
  pshufd xmm2, xmm6, $EE
  add    ecx, dword [esp + $3C]
  and    ebp, eax
  xor    eax, ebx
  ror    edi, $7
  mov    esi, edx
  xor    ebp, eax
  rol    edx, $5
  add    ecx, ebp
  xor    esi, edi
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword [esp]
  pxor   xmm0, xmm4
  punpcklqdq xmm2, xmm7
  and    esi, edi
  xor    edi, eax
  ror    edx, $7
  pxor   xmm0, xmm1
  movdqa oword [esp + $40], xmm4
  mov    ebp, ecx
  xor    esi, edi
  rol    ecx, $5
  movdqa xmm4, xmm3
  add    ebx, esi
  paddd  xmm3, xmm7
  xor    ebp, edx
  pxor   xmm0, xmm2
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword [esp + $4]
  and    ebp, edx
  movdqa xmm2, xmm0
  movdqa oword [esp + $30], xmm3
  xor    edx, edi
  ror    ecx, $7
  mov    esi, ebx
  xor    ebp, edx
  rol    ebx, $5
  pslld  xmm0, $2
  add    eax, ebp
  xor    esi, ecx
  psrld  xmm2, $1E
  xor    ecx, edx
  add    eax, ebx
  add    edi, dword [esp + $8]
  and    esi, ecx
  xor    ecx, edx
  ror    ebx, $7
  por    xmm0, xmm2
  mov    ebp, eax
  xor    esi, ecx
  movdqa xmm2, oword [esp + $50]
  rol    eax, $5
  add    edi, esi
  xor    ebp, ebx
  xor    ebx, ecx
  add    edi, eax
  pshufd xmm3, xmm7, $EE
  add    edx, dword [esp + $C]
  and    ebp, ebx
  xor    ebx, ecx
  ror    eax, $7
  mov    esi, edi
  xor    ebp, ebx
  rol    edi, $5
  add    edx, ebp
  xor    esi, eax
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword [esp + $10]
  pxor   xmm1, xmm5
  punpcklqdq xmm3, xmm0
  and    esi, eax
  xor    eax, ebx
  ror    edi, $7
  pxor   xmm1, xmm2
  movdqa oword [esp + $50], xmm5
  mov    ebp, edx
  xor    esi, eax
  rol    edx, $5
  movdqa xmm5, xmm4
  add    ecx, esi
  paddd  xmm4, xmm0
  xor    ebp, edi
  pxor   xmm1, xmm3
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword [esp + $14]
  and    ebp, edi
  movdqa xmm3, xmm1
  movdqa oword [esp], xmm4
  xor    edi, eax
  ror    edx, $7
  mov    esi, ecx
  xor    ebp, edi
  rol    ecx, $5
  pslld  xmm1, $2
  add    ebx, ebp
  xor    esi, edx
  psrld  xmm3, $1E
  xor    edx, edi
  add    ebx, ecx
  add    eax, dword [esp + $18]
  and    esi, edx
  xor    edx, edi
  ror    ecx, $7
  por    xmm1, xmm3
  mov    ebp, ebx
  xor    esi, edx
  movdqa xmm3, oword [esp + $60]
  rol    ebx, $5
  add    eax, esi
  xor    ebp, ecx
  xor    ecx, edx
  add    eax, ebx
  pshufd xmm4, xmm0, $EE
  add    edi, dword [esp + $1C]
  and    ebp, ecx
  xor    ecx, edx
  ror    ebx, $7
  mov    esi, eax
  xor    ebp, ecx
  rol    eax, $5
  add    edi, ebp
  xor    esi, ebx
  xor    ebx, ecx
  add    edi, eax
  add    edx, dword [esp + $20]
  pxor   xmm2, xmm6
  punpcklqdq xmm4, xmm1
  and    esi, ebx
  xor    ebx, ecx
  ror    eax, $7
  pxor   xmm2, xmm3
  movdqa oword [esp + $60], xmm6
  mov    ebp, edi
  xor    esi, ebx
  rol    edi, $5
  movdqa xmm6, xmm5
  add    edx, esi
  paddd  xmm5, xmm1
  xor    ebp, eax
  pxor   xmm2, xmm4
  xor    eax, ebx
  add    edx, edi
  add    ecx, dword [esp + $24]
  and    ebp, eax
  movdqa xmm4, xmm2
  movdqa oword [esp + $10], xmm5
  xor    eax, ebx
  ror    edi, $7
  mov    esi, edx
  xor    ebp, eax
  rol    edx, $5
  pslld  xmm2, $2
  add    ecx, ebp
  xor    esi, edi
  psrld  xmm4, $1E
  xor    edi, eax
  add    ecx, edx
  add    ebx, dword [esp + $28]
  and    esi, edi
  xor    edi, eax
  ror    edx, $7
  por    xmm2, xmm4
  mov    ebp, ecx
  xor    esi, edi
  movdqa xmm4, oword [esp + $40]
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edx
  xor    edx, edi
  add    ebx, ecx
  pshufd xmm5, xmm1, $EE
  add    eax, dword [esp + $2C]
  and    ebp, edx
  xor    edx, edi
  ror    ecx, $7
  mov    esi, ebx
  xor    ebp, edx
  rol    ebx, $5
  add    eax, ebp
  xor    esi, edx
  add    eax, ebx
  add    edi, dword [esp + $30]
  pxor   xmm3, xmm7
  punpcklqdq xmm5, xmm2
  xor    esi, ecx
  mov    ebp, eax
  rol    eax, $5
  pxor   xmm3, xmm4
  movdqa oword [esp + $40], xmm7
  add    edi, esi
  xor    ebp, ecx
  movdqa xmm7, xmm6
  ror    ebx, $7
  paddd  xmm6, xmm2
  add    edi, eax
  pxor   xmm3, xmm5
  add    edx, dword [esp + $34]
  xor    ebp, ebx
  mov    esi, edi
  rol    edi, $5
  movdqa xmm5, xmm3
  movdqa oword [esp + $20], xmm6
  add    edx, ebp
  xor    esi, ebx
  ror    eax, $7
  add    edx, edi
  pslld  xmm3, $2
  add    ecx, dword [esp + $38]
  xor    esi, eax
  psrld  xmm5, $1E
  mov    ebp, edx
  rol    edx, $5
  add    ecx, esi
  xor    ebp, eax
  ror    edi, $7
  add    ecx, edx
  por    xmm3, xmm5
  add    ebx, dword [esp + $3C]
  xor    ebp, edi
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, ebp
  xor    esi, edi
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [esp]
  xor    esi, edx
  mov    ebp, ebx
  rol    ebx, $5
  add    eax, esi
  xor    ebp, edx
  ror    ecx, $7
  paddd  xmm7, xmm3
  add    eax, ebx
  add    edi, dword [esp + $4]
  xor    ebp, ecx
  mov    esi, eax
  movdqa oword [esp + $30], xmm7
  rol    eax, $5
  add    edi, ebp
  xor    esi, ecx
  ror    ebx, $7
  add    edi, eax
  add    edx, dword [esp + $8]
  xor    esi, ebx
  mov    ebp, edi
  rol    edi, $5
  add    edx, esi
  xor    ebp, ebx
  ror    eax, $7
  add    edx, edi
  add    ecx, dword [esp + $C]
  xor    ebp, eax
  mov    esi, edx
  rol    edx, $5
  add    ecx, ebp
  xor    esi, eax
  ror    edi, $7
  add    ecx, edx
  mov    ebp, dword [esp + $C4]
  cmp    ebp, dword [esp + $C8]
  je @done
  movdqa xmm7, oword [esp + $A0]
  movdqa xmm6, oword [esp + $B0]
  movdqu xmm0, oword [ebp + $0]
  movdqu xmm1, oword [ebp + $10]
  movdqu xmm2, oword [ebp + $20]
  movdqu xmm3, oword [ebp + $30]
  add    ebp, $40
  movdqa xmm6, xmm0
  psrlw  xmm6, $8
  psllw  xmm0, $8
  por    xmm0, xmm6
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  mov    dword [esp + $C4], ebp
  movdqa oword [esp + $60], xmm7
  add    ebx, dword [esp + $10]
  xor    esi, edi
  mov    ebp, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edi
  ror    edx, $7
  movdqa xmm6, xmm1
  psrlw  xmm6, $8
  psllw  xmm1, $8
  por    xmm1, xmm6
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  add    ebx, ecx
  add    eax, dword [esp + $14]
  xor    ebp, edx
  mov    esi, ebx
  paddd  xmm0, xmm7
  rol    ebx, $5
  add    eax, ebp
  xor    esi, edx
  ror    ecx, $7
  movdqa oword [esp], xmm0
  add    eax, ebx
  add    edi, dword [esp + $18]
  xor    esi, ecx
  mov    ebp, eax
  psubd  xmm0, xmm7
  rol    eax, $5
  add    edi, esi
  xor    ebp, ecx
  ror    ebx, $7
  add    edi, eax
  add    edx, dword [esp + $1C]
  xor    ebp, ebx
  mov    esi, edi
  rol    edi, $5
  add    edx, ebp
  xor    esi, ebx
  ror    eax, $7
  add    edx, edi
  add    ecx, dword [esp + $20]
  xor    esi, eax
  mov    ebp, edx
  rol    edx, $5
  add    ecx, esi
  xor    ebp, eax
  ror    edi, $7
  movdqa xmm6, xmm2
  psrlw  xmm6, $8
  psllw  xmm2, $8
  por    xmm2, xmm6
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  add    ecx, edx
  add    ebx, dword [esp + $24]
  xor    ebp, edi
  mov    esi, ecx
  paddd  xmm1, xmm7
  rol    ecx, $5
  add    ebx, ebp
  xor    esi, edi
  ror    edx, $7
  movdqa oword [esp + $10], xmm1
  add    ebx, ecx
  add    eax, dword [esp + $28]
  xor    esi, edx
  mov    ebp, ebx
  psubd  xmm1, xmm7
  rol    ebx, $5
  add    eax, esi
  xor    ebp, edx
  ror    ecx, $7
  add    eax, ebx
  add    edi, dword [esp + $2C]
  xor    ebp, ecx
  mov    esi, eax
  rol    eax, $5
  add    edi, ebp
  xor    esi, ecx
  ror    ebx, $7
  add    edi, eax
  add    edx, dword [esp + $30]
  xor    esi, ebx
  mov    ebp, edi
  rol    edi, $5
  add    edx, esi
  xor    ebp, ebx
  ror    eax, $7
  movdqa xmm6, xmm3
  psrlw  xmm6, $8
  psllw  xmm3, $8
  por    xmm3, xmm6
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  add    edx, edi
  add    ecx, dword [esp + $34]
  xor    ebp, eax
  mov    esi, edx
  paddd  xmm2, xmm7
  rol    edx, $5
  add    ecx, ebp
  xor    esi, eax
  ror    edi, $7
  movdqa oword [esp + $20], xmm2
  add    ecx, edx
  add    ebx, dword [esp + $38]
  xor    esi, edi
  mov    ebp, ecx
  psubd  xmm2, xmm7
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edi
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [esp + $3C]
  xor    ebp, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, ebp
  ror    ecx, $7
  add    eax, ebx
  mov    ebp, dword [esp + $C0]
  add    eax, dword [ebp + $0]
  add    esi, dword [ebp + $4]
  add    ecx, dword [ebp + $8]
  mov    dword [ebp + $0], eax
  add    edx, dword [ebp + $C]
  mov    dword [ebp + $4], esi
  add    edi, dword [ebp + $10]
  mov    dword [ebp + $8], ecx
  mov    ebx, ecx
  mov    dword [ebp + $C], edx
  xor    ebx, edx
  mov    dword [ebp + $10], edi
  mov    ebp, esi
  pshufd xmm4, xmm0, $EE
  and    esi, ebx
  mov    ebx, ebp
  jmp @block_loop

@done:
  add    ebx, dword [esp + $10]
  xor    esi, edi
  mov    ebp, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edi
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [esp + $14]
  xor    ebp, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, ebp
  xor    esi, edx
  ror    ecx, $7
  add    eax, ebx
  add    edi, dword [esp + $18]
  xor    esi, ecx
  mov    ebp, eax
  rol    eax, $5
  add    edi, esi
  xor    ebp, ecx
  ror    ebx, $7
  add    edi, eax
  add    edx, dword [esp + $1C]
  xor    ebp, ebx
  mov    esi, edi
  rol    edi, $5
  add    edx, ebp
  xor    esi, ebx
  ror    eax, $7
  add    edx, edi
  add    ecx, dword [esp + $20]
  xor    esi, eax
  mov    ebp, edx
  rol    edx, $5
  add    ecx, esi
  xor    ebp, eax
  ror    edi, $7
  add    ecx, edx
  add    ebx, dword [esp + $24]
  xor    ebp, edi
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, ebp
  xor    esi, edi
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [esp + $28]
  xor    esi, edx
  mov    ebp, ebx
  rol    ebx, $5
  add    eax, esi
  xor    ebp, edx
  ror    ecx, $7
  add    eax, ebx
  add    edi, dword [esp + $2C]
  xor    ebp, ecx
  mov    esi, eax
  rol    eax, $5
  add    edi, ebp
  xor    esi, ecx
  ror    ebx, $7
  add    edi, eax
  add    edx, dword [esp + $30]
  xor    esi, ebx
  mov    ebp, edi
  rol    edi, $5
  add    edx, esi
  xor    ebp, ebx
  ror    eax, $7
  add    edx, edi
  add    ecx, dword [esp + $34]
  xor    ebp, eax
  mov    esi, edx
  rol    edx, $5
  add    ecx, ebp
  xor    esi, eax
  ror    edi, $7
  add    ecx, edx
  add    ebx, dword [esp + $38]
  xor    esi, edi
  mov    ebp, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    ebp, edi
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [esp + $3C]
  xor    ebp, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, ebp
  ror    ecx, $7
  add    eax, ebx
  mov    ebp, dword [esp + $C0]
  add    eax, dword [ebp + $0]
  mov    esp, dword [esp + $CC]
  add    esi, dword [ebp + $4]
  add    ecx, dword [ebp + $8]
  mov    dword [ebp + $0], eax
  add    edx, dword [ebp + $C]
  mov    dword [ebp + $4], esi
  add    edi, dword [ebp + $10]
  mov    dword [ebp + $8], ecx
  mov    dword [ebp + $C], edx
  mov    dword [ebp + $10], edi
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
