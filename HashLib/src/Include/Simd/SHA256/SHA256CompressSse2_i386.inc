// SHA-256 SSE2 SIMD-schedule implementation (IA-32), derived from OpenSSL's
// sha256-586 (CRYPTOGAMS) SSSE3 kernel. The message schedule runs in SSE2
// (paddd/psrld/pslld/pxor/pshufd/psrldq/pslldq) interleaved with the GPR
// compression rounds; the 32-bit state lives in eax/ebx/ecx plus the local frame
// (IA-32 has too few GPRs to keep all eight in registers). OpenSSL's two SSSE3-only
// ops are emulated in SSE2: the pshufb dword byte-swap becomes psrlw/psllw/por +
// pshuflw/pshufhw, and palignr becomes psrldq/pslldq/por.
// Expects (after SimdProc4Begin_i386): ebx = state, esi = data, edi = numblocks,
//   eax = doubled-K256 ptr (read at a 32-byte stride so the duplicated halves are
//   skipped; see K256_Doubled). SimdProc4Begin pushes ebx/esi/edi; ebp is pushed
//   here as the K256 walk pointer; state loads into eax/ebx/ecx and the frame.

  push   ebp
  mov    ebp, eax
  mov    eax, edi
  mov    edi, esi
  mov    esi, ebx
  mov    ebx, esp
  sub    esp, $10
  and    esp, $FFFFFFC0
  shl    eax, $6
  add    eax, edi
  mov    dword [esp], esi
  mov    dword [esp + $4], edi
  mov    dword [esp + $8], eax
  mov    dword [esp + $C], ebx
  lea    esp, [esp - $60]
  mov    eax, dword [esi]
  mov    ebx, dword [esi + $4]
  mov    ecx, dword [esi + $8]
  mov    edi, dword [esi + $C]
  mov    dword [esp + $4], ebx
  xor    ebx, ecx
  mov    dword [esp + $8], ecx
  mov    dword [esp + $C], edi
  mov    edx, dword [esi + $10]
  mov    edi, dword [esi + $14]
  mov    ecx, dword [esi + $18]
  mov    esi, dword [esi + $1C]
  mov    dword [esp + $14], edi
  mov    edi, dword [esp + $64]
  mov    dword [esp + $18], ecx
  mov    dword [esp + $1C], esi
  jmp @block_loop

@block_loop:
  movdqu xmm0, oword [edi]
  movdqu xmm1, oword [edi + $10]
  movdqu xmm2, oword [edi + $20]
  movdqu xmm3, oword [edi + $30]
  add    edi, $40
  movdqa xmm4, xmm0
  psrlw  xmm4, $8
  psllw  xmm0, $8
  por    xmm0, xmm4
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  mov    dword [esp + $64], edi
  movdqa xmm4, xmm1
  psrlw  xmm4, $8
  psllw  xmm1, $8
  por    xmm1, xmm4
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqu xmm4, oword [ebp + $0]
  movdqa xmm5, xmm2
  psrlw  xmm5, $8
  psllw  xmm2, $8
  por    xmm2, xmm5
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  movdqu xmm5, oword [ebp + $20]
  paddd  xmm4, xmm0
  movdqa xmm6, xmm3
  psrlw  xmm6, $8
  psllw  xmm3, $8
  por    xmm3, xmm6
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  movdqu xmm6, oword [ebp + $40]
  paddd  xmm5, xmm1
  movdqu xmm7, oword [ebp + $60]
  movdqa oword [esp + $20], xmm4
  paddd  xmm6, xmm2
  movdqa oword [esp + $30], xmm5
  paddd  xmm7, xmm3
  movdqa oword [esp + $40], xmm6
  movdqa oword [esp + $50], xmm7
  jmp @sched_loop

@sched_loop:
  add    ebp, $80
  mov    ecx, edx
  movdqa xmm4, xmm1
  ror    edx, $E
  mov    esi, dword [esp + $14]
  movdqa xmm7, xmm3
  xor    edx, ecx
  mov    edi, dword [esp + $18]
  movdqa xmm5, xmm0
  psrldq xmm5, $4
  pslldq xmm4, $C
  por    xmm4, xmm5
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  movdqa xmm5, xmm2
  psrldq xmm5, $4
  pslldq xmm7, $C
  por    xmm7, xmm5
  mov    dword [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  movdqa xmm5, xmm4
  ror    edx, $6
  mov    ecx, eax
  movdqa xmm6, xmm4
  add    edx, edi
  mov    edi, dword [esp + $4]
  psrld  xmm4, $3
  mov    esi, eax
  ror    ecx, $9
  paddd  xmm0, xmm7
  mov    dword [esp], eax
  xor    ecx, eax
  psrld  xmm6, $7
  xor    eax, edi
  add    edx, dword [esp + $1C]
  ror    ecx, $B
  and    ebx, eax
  pshufd xmm7, xmm3, $FA
  xor    ecx, esi
  add    edx, dword [esp + $20]
  pslld  xmm5, $E
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm4, xmm6
  add    ebx, edx
  add    edx, dword [esp + $C]
  psrld  xmm6, $B
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm4, xmm5
  mov    esi, dword [esp + $10]
  xor    edx, ecx
  pslld  xmm5, $B
  mov    edi, dword [esp + $14]
  xor    esi, edi
  ror    edx, $5
  pxor   xmm4, xmm6
  and    esi, ecx
  mov    dword [esp + $C], ecx
  movdqa xmm6, xmm7
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  pxor   xmm4, xmm5
  mov    ecx, ebx
  add    edx, edi
  psrld  xmm7, $A
  mov    edi, dword [esp]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm0, xmm4
  mov    dword [esp + $1C], ebx
  xor    ecx, ebx
  psrlq  xmm6, $11
  xor    ebx, edi
  add    edx, dword [esp + $18]
  ror    ecx, $B
  pxor   xmm7, xmm6
  and    eax, ebx
  xor    ecx, esi
  psrlq  xmm6, $2
  add    edx, dword [esp + $24]
  xor    eax, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    eax, edx
  add    edx, dword [esp + $8]
  pshufd xmm7, xmm7, $80
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $C]
  xor    edx, ecx
  mov    edi, dword [esp + $10]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  psrldq xmm7, $8
  mov    dword [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  paddd  xmm0, xmm7
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $1C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $18], eax
  pshufd xmm7, xmm0, $50
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $14]
  movdqa xmm6, xmm7
  ror    ecx, $B
  psrld  xmm7, $A
  and    ebx, eax
  psrlq  xmm6, $11
  xor    ecx, esi
  add    edx, dword [esp + $28]
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    ebx, edx
  add    edx, dword [esp + $4]
  psrlq  xmm6, $2
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm7, xmm6
  mov    esi, dword [esp + $8]
  xor    edx, ecx
  mov    edi, dword [esp + $C]
  pshufd xmm7, xmm7, $8
  xor    esi, edi
  ror    edx, $5
  movdqu xmm6, oword [ebp + $0]
  and    esi, ecx
  mov    dword [esp + $4], ecx
  pslldq xmm7, $8
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $18]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm0, xmm7
  mov    dword [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $10]
  paddd  xmm6, xmm0
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $2C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp]
  add    eax, ecx
  movdqa oword [esp + $20], xmm6
  mov    ecx, edx
  movdqa xmm4, xmm2
  ror    edx, $E
  mov    esi, dword [esp + $4]
  movdqa xmm7, xmm0
  xor    edx, ecx
  mov    edi, dword [esp + $8]
  movdqa xmm5, xmm1
  psrldq xmm5, $4
  pslldq xmm4, $C
  por    xmm4, xmm5
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  movdqa xmm5, xmm3
  psrldq xmm5, $4
  pslldq xmm7, $C
  por    xmm7, xmm5
  mov    dword [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  movdqa xmm5, xmm4
  ror    edx, $6
  mov    ecx, eax
  movdqa xmm6, xmm4
  add    edx, edi
  mov    edi, dword [esp + $14]
  psrld  xmm4, $3
  mov    esi, eax
  ror    ecx, $9
  paddd  xmm1, xmm7
  mov    dword [esp + $10], eax
  xor    ecx, eax
  psrld  xmm6, $7
  xor    eax, edi
  add    edx, dword [esp + $C]
  ror    ecx, $B
  and    ebx, eax
  pshufd xmm7, xmm0, $FA
  xor    ecx, esi
  add    edx, dword [esp + $30]
  pslld  xmm5, $E
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm4, xmm6
  add    ebx, edx
  add    edx, dword [esp + $1C]
  psrld  xmm6, $B
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm4, xmm5
  mov    esi, dword [esp]
  xor    edx, ecx
  pslld  xmm5, $B
  mov    edi, dword [esp + $4]
  xor    esi, edi
  ror    edx, $5
  pxor   xmm4, xmm6
  and    esi, ecx
  mov    dword [esp + $1C], ecx
  movdqa xmm6, xmm7
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  pxor   xmm4, xmm5
  mov    ecx, ebx
  add    edx, edi
  psrld  xmm7, $A
  mov    edi, dword [esp + $10]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm1, xmm4
  mov    dword [esp + $C], ebx
  xor    ecx, ebx
  psrlq  xmm6, $11
  xor    ebx, edi
  add    edx, dword [esp + $8]
  ror    ecx, $B
  pxor   xmm7, xmm6
  and    eax, ebx
  xor    ecx, esi
  psrlq  xmm6, $2
  add    edx, dword [esp + $34]
  xor    eax, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    eax, edx
  add    edx, dword [esp + $18]
  pshufd xmm7, xmm7, $80
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $1C]
  xor    edx, ecx
  mov    edi, dword [esp]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  psrldq xmm7, $8
  mov    dword [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  paddd  xmm1, xmm7
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $8], eax
  pshufd xmm7, xmm1, $50
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $4]
  movdqa xmm6, xmm7
  ror    ecx, $B
  psrld  xmm7, $A
  and    ebx, eax
  psrlq  xmm6, $11
  xor    ecx, esi
  add    edx, dword [esp + $38]
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    ebx, edx
  add    edx, dword [esp + $14]
  psrlq  xmm6, $2
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm7, xmm6
  mov    esi, dword [esp + $18]
  xor    edx, ecx
  mov    edi, dword [esp + $1C]
  pshufd xmm7, xmm7, $8
  xor    esi, edi
  ror    edx, $5
  movdqu xmm6, oword [ebp + $20]
  and    esi, ecx
  mov    dword [esp + $14], ecx
  pslldq xmm7, $8
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $8]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm1, xmm7
  mov    dword [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp]
  paddd  xmm6, xmm1
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $3C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $10]
  add    eax, ecx
  movdqa oword [esp + $30], xmm6
  mov    ecx, edx
  movdqa xmm4, xmm3
  ror    edx, $E
  mov    esi, dword [esp + $14]
  movdqa xmm7, xmm1
  xor    edx, ecx
  mov    edi, dword [esp + $18]
  movdqa xmm5, xmm2
  psrldq xmm5, $4
  pslldq xmm4, $C
  por    xmm4, xmm5
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  movdqa xmm5, xmm0
  psrldq xmm5, $4
  pslldq xmm7, $C
  por    xmm7, xmm5
  mov    dword [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  movdqa xmm5, xmm4
  ror    edx, $6
  mov    ecx, eax
  movdqa xmm6, xmm4
  add    edx, edi
  mov    edi, dword [esp + $4]
  psrld  xmm4, $3
  mov    esi, eax
  ror    ecx, $9
  paddd  xmm2, xmm7
  mov    dword [esp], eax
  xor    ecx, eax
  psrld  xmm6, $7
  xor    eax, edi
  add    edx, dword [esp + $1C]
  ror    ecx, $B
  and    ebx, eax
  pshufd xmm7, xmm1, $FA
  xor    ecx, esi
  add    edx, dword [esp + $40]
  pslld  xmm5, $E
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm4, xmm6
  add    ebx, edx
  add    edx, dword [esp + $C]
  psrld  xmm6, $B
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm4, xmm5
  mov    esi, dword [esp + $10]
  xor    edx, ecx
  pslld  xmm5, $B
  mov    edi, dword [esp + $14]
  xor    esi, edi
  ror    edx, $5
  pxor   xmm4, xmm6
  and    esi, ecx
  mov    dword [esp + $C], ecx
  movdqa xmm6, xmm7
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  pxor   xmm4, xmm5
  mov    ecx, ebx
  add    edx, edi
  psrld  xmm7, $A
  mov    edi, dword [esp]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm2, xmm4
  mov    dword [esp + $1C], ebx
  xor    ecx, ebx
  psrlq  xmm6, $11
  xor    ebx, edi
  add    edx, dword [esp + $18]
  ror    ecx, $B
  pxor   xmm7, xmm6
  and    eax, ebx
  xor    ecx, esi
  psrlq  xmm6, $2
  add    edx, dword [esp + $44]
  xor    eax, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    eax, edx
  add    edx, dword [esp + $8]
  pshufd xmm7, xmm7, $80
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $C]
  xor    edx, ecx
  mov    edi, dword [esp + $10]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  psrldq xmm7, $8
  mov    dword [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  paddd  xmm2, xmm7
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $1C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $18], eax
  pshufd xmm7, xmm2, $50
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $14]
  movdqa xmm6, xmm7
  ror    ecx, $B
  psrld  xmm7, $A
  and    ebx, eax
  psrlq  xmm6, $11
  xor    ecx, esi
  add    edx, dword [esp + $48]
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    ebx, edx
  add    edx, dword [esp + $4]
  psrlq  xmm6, $2
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm7, xmm6
  mov    esi, dword [esp + $8]
  xor    edx, ecx
  mov    edi, dword [esp + $C]
  pshufd xmm7, xmm7, $8
  xor    esi, edi
  ror    edx, $5
  movdqu xmm6, oword [ebp + $40]
  and    esi, ecx
  mov    dword [esp + $4], ecx
  pslldq xmm7, $8
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $18]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm2, xmm7
  mov    dword [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $10]
  paddd  xmm6, xmm2
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $4C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp]
  add    eax, ecx
  movdqa oword [esp + $40], xmm6
  mov    ecx, edx
  movdqa xmm4, xmm0
  ror    edx, $E
  mov    esi, dword [esp + $4]
  movdqa xmm7, xmm2
  xor    edx, ecx
  mov    edi, dword [esp + $8]
  movdqa xmm5, xmm3
  psrldq xmm5, $4
  pslldq xmm4, $C
  por    xmm4, xmm5
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  movdqa xmm5, xmm1
  psrldq xmm5, $4
  pslldq xmm7, $C
  por    xmm7, xmm5
  mov    dword [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  movdqa xmm5, xmm4
  ror    edx, $6
  mov    ecx, eax
  movdqa xmm6, xmm4
  add    edx, edi
  mov    edi, dword [esp + $14]
  psrld  xmm4, $3
  mov    esi, eax
  ror    ecx, $9
  paddd  xmm3, xmm7
  mov    dword [esp + $10], eax
  xor    ecx, eax
  psrld  xmm6, $7
  xor    eax, edi
  add    edx, dword [esp + $C]
  ror    ecx, $B
  and    ebx, eax
  pshufd xmm7, xmm2, $FA
  xor    ecx, esi
  add    edx, dword [esp + $50]
  pslld  xmm5, $E
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm4, xmm6
  add    ebx, edx
  add    edx, dword [esp + $1C]
  psrld  xmm6, $B
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm4, xmm5
  mov    esi, dword [esp]
  xor    edx, ecx
  pslld  xmm5, $B
  mov    edi, dword [esp + $4]
  xor    esi, edi
  ror    edx, $5
  pxor   xmm4, xmm6
  and    esi, ecx
  mov    dword [esp + $1C], ecx
  movdqa xmm6, xmm7
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  pxor   xmm4, xmm5
  mov    ecx, ebx
  add    edx, edi
  psrld  xmm7, $A
  mov    edi, dword [esp + $10]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm3, xmm4
  mov    dword [esp + $C], ebx
  xor    ecx, ebx
  psrlq  xmm6, $11
  xor    ebx, edi
  add    edx, dword [esp + $8]
  ror    ecx, $B
  pxor   xmm7, xmm6
  and    eax, ebx
  xor    ecx, esi
  psrlq  xmm6, $2
  add    edx, dword [esp + $54]
  xor    eax, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    eax, edx
  add    edx, dword [esp + $18]
  pshufd xmm7, xmm7, $80
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $1C]
  xor    edx, ecx
  mov    edi, dword [esp]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  psrldq xmm7, $8
  mov    dword [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  paddd  xmm3, xmm7
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $8], eax
  pshufd xmm7, xmm3, $50
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $4]
  movdqa xmm6, xmm7
  ror    ecx, $B
  psrld  xmm7, $A
  and    ebx, eax
  psrlq  xmm6, $11
  xor    ecx, esi
  add    edx, dword [esp + $58]
  xor    ebx, edi
  ror    ecx, $2
  pxor   xmm7, xmm6
  add    ebx, edx
  add    edx, dword [esp + $14]
  psrlq  xmm6, $2
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  pxor   xmm7, xmm6
  mov    esi, dword [esp + $18]
  xor    edx, ecx
  mov    edi, dword [esp + $1C]
  pshufd xmm7, xmm7, $8
  xor    esi, edi
  ror    edx, $5
  movdqu xmm6, oword [ebp + $60]
  and    esi, ecx
  mov    dword [esp + $14], ecx
  pslldq xmm7, $8
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $8]
  mov    esi, ebx
  ror    ecx, $9
  paddd  xmm3, xmm7
  mov    dword [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp]
  paddd  xmm6, xmm3
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $5C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $10]
  add    eax, ecx
  movdqa oword [esp + $50], xmm6
  cmp    dword [ebp + $80], $10203
  jne @sched_loop
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $14]
  xor    edx, ecx
  mov    edi, dword [esp + $18]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $4]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $1C]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $20]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $C]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $10]
  xor    edx, ecx
  mov    edi, dword [esp + $14]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $C], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $1C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $18]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $24]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $8]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $C]
  xor    edx, ecx
  mov    edi, dword [esp + $10]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $1C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $18], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $14]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $28]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $4]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $8]
  xor    edx, ecx
  mov    edi, dword [esp + $C]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $18]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $10]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $2C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $4]
  xor    edx, ecx
  mov    edi, dword [esp + $8]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $14]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $10], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $C]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $30]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $1C]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp]
  xor    edx, ecx
  mov    edi, dword [esp + $4]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $1C], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $10]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $8]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $34]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $18]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $1C]
  xor    edx, ecx
  mov    edi, dword [esp]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $8], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $4]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $38]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $14]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $18]
  xor    edx, ecx
  mov    edi, dword [esp + $1C]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $8]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $3C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $10]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $14]
  xor    edx, ecx
  mov    edi, dword [esp + $18]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $10], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $4]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $1C]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $40]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $C]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $10]
  xor    edx, ecx
  mov    edi, dword [esp + $14]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $C], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $1C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $18]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $44]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $8]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $C]
  xor    edx, ecx
  mov    edi, dword [esp + $10]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $8], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $1C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $18], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $14]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $48]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $4]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $8]
  xor    edx, ecx
  mov    edi, dword [esp + $C]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $4], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $18]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $14], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $10]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $4C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $4]
  xor    edx, ecx
  mov    edi, dword [esp + $8]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $14]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $10], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $C]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $50]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $1C]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp]
  xor    edx, ecx
  mov    edi, dword [esp + $4]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $1C], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $10]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $C], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp + $8]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $54]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $18]
  add    eax, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $1C]
  xor    edx, ecx
  mov    edi, dword [esp]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $18], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, eax
  add    edx, edi
  mov    edi, dword [esp + $C]
  mov    esi, eax
  ror    ecx, $9
  mov    dword [esp + $8], eax
  xor    ecx, eax
  xor    eax, edi
  add    edx, dword [esp + $4]
  ror    ecx, $B
  and    ebx, eax
  xor    ecx, esi
  add    edx, dword [esp + $58]
  xor    ebx, edi
  ror    ecx, $2
  add    ebx, edx
  add    edx, dword [esp + $14]
  add    ebx, ecx
  mov    ecx, edx
  ror    edx, $E
  mov    esi, dword [esp + $18]
  xor    edx, ecx
  mov    edi, dword [esp + $1C]
  xor    esi, edi
  ror    edx, $5
  and    esi, ecx
  mov    dword [esp + $14], ecx
  xor    edx, ecx
  xor    edi, esi
  ror    edx, $6
  mov    ecx, ebx
  add    edx, edi
  mov    edi, dword [esp + $8]
  mov    esi, ebx
  ror    ecx, $9
  mov    dword [esp + $4], ebx
  xor    ecx, ebx
  xor    ebx, edi
  add    edx, dword [esp]
  ror    ecx, $B
  and    eax, ebx
  xor    ecx, esi
  add    edx, dword [esp + $5C]
  xor    eax, edi
  ror    ecx, $2
  add    eax, edx
  add    edx, dword [esp + $10]
  add    eax, ecx
  mov    esi, dword [esp + $60]
  xor    ebx, edi
  mov    ecx, dword [esp + $C]
  add    eax, dword [esi]
  add    ebx, dword [esi + $4]
  add    edi, dword [esi + $8]
  add    ecx, dword [esi + $C]
  mov    dword [esi], eax
  mov    dword [esi + $4], ebx
  mov    dword [esi + $8], edi
  mov    dword [esi + $C], ecx
  mov    dword [esp + $4], ebx
  xor    ebx, edi
  mov    dword [esp + $8], edi
  mov    dword [esp + $C], ecx
  mov    edi, dword [esp + $14]
  mov    ecx, dword [esp + $18]
  add    edx, dword [esi + $10]
  add    edi, dword [esi + $14]
  add    ecx, dword [esi + $18]
  mov    dword [esi + $10], edx
  mov    dword [esi + $14], edi
  mov    dword [esp + $14], edi
  mov    edi, dword [esp + $1C]
  mov    dword [esi + $18], ecx
  add    edi, dword [esi + $1C]
  mov    dword [esp + $18], ecx
  mov    dword [esi + $1C], edi
  mov    dword [esp + $1C], edi
  mov    edi, dword [esp + $64]
  sub    ebp, $180
  cmp    edi, dword [esp + $68]
  jb @block_loop
  mov    esp, dword [esp + $6C]
  pop    ebp
  pop    edi
  pop    esi
  pop    ebx
