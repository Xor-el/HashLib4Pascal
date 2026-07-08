// SHA-1 SSE2 SIMD-schedule implementation, derived from OpenSSL's SHA-1 SSSE3
// kernel in sha1-x86_64.pl (CRYPTOGAMS). The message schedule runs in SSE2
// (pxor/pshufd/psrldq/pslldq) interleaved with the GPR compression rounds, so the
// vector and integer units run in parallel. OpenSSL's only SSSE3-only op here is
// the pshufb input byte-swap, which is emulated in SSE2 (psrlw/psllw/por +
// pshuflw/pshufhw; xmm12 is a free scratch); the W-schedule uses no palignr. The
// appended masks go unused - the byte-swap is computed, not shuffled.
// Expects MS x64 ABI (after HlpSimdProc4Begin): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = doubled-K_SHA1 ptr (read 128-bit at a 32-byte stride,
//   r14 = K + 64, so the duplicated halves are skipped; see K_SHA1_Doubled).
//
// MS x64 non-volatile saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore
// include (no-op on SysV); rbx, rbp, rdi, rsi, r12-r14 in the local frame; r11
// holds the caller rsp across the kernel for the unwind.

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  mov    r11, rsp
  push   r9
  push   rbx
  push   rbp
  push   r12
  push   r13
  push   r14
  push   rdi
  push   rsi
  mov    rdi, rcx
  mov    rsi, rdx
  mov    rdx, r8
  lea    rsp, [rsp - $A0]
  and    rsp, $FFFFFFFFFFFFFFC0
  mov    r8, rdi
  mov    r9, rsi
  mov    r10, rdx
  shl    r10, $6
  add    r10, r9
  mov    r14, qword [r11 - $8]
  add    r14, $40
  mov    eax, dword [r8]
  mov    ebx, dword [r8 + $4]
  mov    ecx, dword [r8 + $8]
  mov    edx, dword [r8 + $C]
  mov    esi, ebx
  mov    ebp, dword [r8 + $10]
  mov    edi, ecx
  xor    edi, edx
  and    esi, edi
  movdqu xmm6, oword [r14 + $40]
  movdqu xmm9, oword [r14 - $40]
  movdqu xmm0, oword [r9]
  movdqu xmm1, oword [r9 + $10]
  movdqu xmm2, oword [r9 + $20]
  movdqu xmm3, oword [r9 + $30]
  movdqa xmm12, xmm0
  psrlw  xmm12, $8
  psllw  xmm0, $8
  por    xmm0, xmm12
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqa xmm12, xmm1
  psrlw  xmm12, $8
  psllw  xmm1, $8
  por    xmm1, xmm12
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqa xmm12, xmm2
  psrlw  xmm12, $8
  psllw  xmm2, $8
  por    xmm2, xmm12
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  add    r9, $40
  paddd  xmm0, xmm9
  movdqa xmm12, xmm3
  psrlw  xmm12, $8
  psllw  xmm3, $8
  por    xmm3, xmm12
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd  xmm1, xmm9
  paddd  xmm2, xmm9
  movdqa oword [rsp], xmm0
  psubd  xmm0, xmm9
  movdqa oword [rsp + $10], xmm1
  psubd  xmm1, xmm9
  movdqa oword [rsp + $20], xmm2
  psubd  xmm2, xmm9
  jmp @block_loop

@block_loop:
  ror    ebx, $2
  pshufd xmm4, xmm0, $EE
  xor    esi, edx
  movdqa xmm8, xmm3
  paddd  xmm9, xmm3
  mov    edi, eax
  add    ebp, dword [rsp]
  punpcklqdq xmm4, xmm1
  xor    ebx, ecx
  rol    eax, $5
  add    ebp, esi
  psrldq xmm8, $4
  and    edi, ebx
  xor    ebx, ecx
  pxor   xmm4, xmm0
  add    ebp, eax
  ror    eax, $7
  pxor   xmm8, xmm2
  xor    edi, ecx
  mov    esi, ebp
  add    edx, dword [rsp + $4]
  pxor   xmm4, xmm8
  xor    eax, ebx
  rol    ebp, $5
  movdqa oword [rsp + $30], xmm9
  add    edx, edi
  and    esi, eax
  movdqa xmm10, xmm4
  xor    eax, ebx
  add    edx, ebp
  ror    ebp, $7
  movdqa xmm8, xmm4
  xor    esi, ebx
  pslldq xmm10, $C
  paddd  xmm4, xmm4
  mov    edi, edx
  add    ecx, dword [rsp + $8]
  psrld  xmm8, $1F
  xor    ebp, eax
  rol    edx, $5
  add    ecx, esi
  movdqa xmm9, xmm10
  and    edi, ebp
  xor    ebp, eax
  psrld  xmm10, $1E
  add    ecx, edx
  ror    edx, $7
  por    xmm4, xmm8
  xor    edi, eax
  mov    esi, ecx
  add    ebx, dword [rsp + $C]
  pslld  xmm9, $2
  pxor   xmm4, xmm10
  xor    edx, ebp
  movdqu xmm10, oword [r14 - $40]
  rol    ecx, $5
  add    ebx, edi
  and    esi, edx
  pxor   xmm4, xmm9
  xor    edx, ebp
  add    ebx, ecx
  ror    ecx, $7
  pshufd xmm5, xmm1, $EE
  xor    esi, ebp
  movdqa xmm9, xmm4
  paddd  xmm10, xmm4
  mov    edi, ebx
  add    eax, dword [rsp + $10]
  punpcklqdq xmm5, xmm2
  xor    ecx, edx
  rol    ebx, $5
  add    eax, esi
  psrldq xmm9, $4
  and    edi, ecx
  xor    ecx, edx
  pxor   xmm5, xmm1
  add    eax, ebx
  ror    ebx, $7
  pxor   xmm9, xmm3
  xor    edi, edx
  mov    esi, eax
  add    ebp, dword [rsp + $14]
  pxor   xmm5, xmm9
  xor    ebx, ecx
  rol    eax, $5
  movdqa oword [rsp], xmm10
  add    ebp, edi
  and    esi, ebx
  movdqa xmm8, xmm5
  xor    ebx, ecx
  add    ebp, eax
  ror    eax, $7
  movdqa xmm9, xmm5
  xor    esi, ecx
  pslldq xmm8, $C
  paddd  xmm5, xmm5
  mov    edi, ebp
  add    edx, dword [rsp + $18]
  psrld  xmm9, $1F
  xor    eax, ebx
  rol    ebp, $5
  add    edx, esi
  movdqa xmm10, xmm8
  and    edi, eax
  xor    eax, ebx
  psrld  xmm8, $1E
  add    edx, ebp
  ror    ebp, $7
  por    xmm5, xmm9
  xor    edi, ebx
  mov    esi, edx
  add    ecx, dword [rsp + $1C]
  pslld  xmm10, $2
  pxor   xmm5, xmm8
  xor    ebp, eax
  movdqu xmm8, oword [r14 - $20]
  rol    edx, $5
  add    ecx, edi
  and    esi, ebp
  pxor   xmm5, xmm10
  xor    ebp, eax
  add    ecx, edx
  ror    edx, $7
  pshufd xmm6, xmm2, $EE
  xor    esi, eax
  movdqa xmm10, xmm5
  paddd  xmm8, xmm5
  mov    edi, ecx
  add    ebx, dword [rsp + $20]
  punpcklqdq xmm6, xmm3
  xor    edx, ebp
  rol    ecx, $5
  add    ebx, esi
  psrldq xmm10, $4
  and    edi, edx
  xor    edx, ebp
  pxor   xmm6, xmm2
  add    ebx, ecx
  ror    ecx, $7
  pxor   xmm10, xmm4
  xor    edi, ebp
  mov    esi, ebx
  add    eax, dword [rsp + $24]
  pxor   xmm6, xmm10
  xor    ecx, edx
  rol    ebx, $5
  movdqa oword [rsp + $10], xmm8
  add    eax, edi
  and    esi, ecx
  movdqa xmm9, xmm6
  xor    ecx, edx
  add    eax, ebx
  ror    ebx, $7
  movdqa xmm10, xmm6
  xor    esi, edx
  pslldq xmm9, $C
  paddd  xmm6, xmm6
  mov    edi, eax
  add    ebp, dword [rsp + $28]
  psrld  xmm10, $1F
  xor    ebx, ecx
  rol    eax, $5
  add    ebp, esi
  movdqa xmm8, xmm9
  and    edi, ebx
  xor    ebx, ecx
  psrld  xmm9, $1E
  add    ebp, eax
  ror    eax, $7
  por    xmm6, xmm10
  xor    edi, ecx
  mov    esi, ebp
  add    edx, dword [rsp + $2C]
  pslld  xmm8, $2
  pxor   xmm6, xmm9
  xor    eax, ebx
  movdqu xmm9, oword [r14 - $20]
  rol    ebp, $5
  add    edx, edi
  and    esi, eax
  pxor   xmm6, xmm8
  xor    eax, ebx
  add    edx, ebp
  ror    ebp, $7
  pshufd xmm7, xmm3, $EE
  xor    esi, ebx
  movdqa xmm8, xmm6
  paddd  xmm9, xmm6
  mov    edi, edx
  add    ecx, dword [rsp + $30]
  punpcklqdq xmm7, xmm4
  xor    ebp, eax
  rol    edx, $5
  add    ecx, esi
  psrldq xmm8, $4
  and    edi, ebp
  xor    ebp, eax
  pxor   xmm7, xmm3
  add    ecx, edx
  ror    edx, $7
  pxor   xmm8, xmm5
  xor    edi, eax
  mov    esi, ecx
  add    ebx, dword [rsp + $34]
  pxor   xmm7, xmm8
  xor    edx, ebp
  rol    ecx, $5
  movdqa oword [rsp + $20], xmm9
  add    ebx, edi
  and    esi, edx
  movdqa xmm10, xmm7
  xor    edx, ebp
  add    ebx, ecx
  ror    ecx, $7
  movdqa xmm8, xmm7
  xor    esi, ebp
  pslldq xmm10, $C
  paddd  xmm7, xmm7
  mov    edi, ebx
  add    eax, dword [rsp + $38]
  psrld  xmm8, $1F
  xor    ecx, edx
  rol    ebx, $5
  add    eax, esi
  movdqa xmm9, xmm10
  and    edi, ecx
  xor    ecx, edx
  psrld  xmm10, $1E
  add    eax, ebx
  ror    ebx, $7
  por    xmm7, xmm8
  xor    edi, edx
  mov    esi, eax
  add    ebp, dword [rsp + $3C]
  pslld  xmm9, $2
  pxor   xmm7, xmm10
  xor    ebx, ecx
  movdqu xmm10, oword [r14 - $20]
  rol    eax, $5
  add    ebp, edi
  and    esi, ebx
  pxor   xmm7, xmm9
  pshufd xmm9, xmm6, $EE
  xor    ebx, ecx
  add    ebp, eax
  ror    eax, $7
  pxor   xmm0, xmm4
  xor    esi, ecx
  mov    edi, ebp
  add    edx, dword [rsp]
  punpcklqdq xmm9, xmm7
  xor    eax, ebx
  rol    ebp, $5
  pxor   xmm0, xmm1
  add    edx, esi
  and    edi, eax
  movdqa xmm8, xmm10
  xor    eax, ebx
  paddd  xmm10, xmm7
  add    edx, ebp
  pxor   xmm0, xmm9
  ror    ebp, $7
  xor    edi, ebx
  mov    esi, edx
  add    ecx, dword [rsp + $4]
  movdqa xmm9, xmm0
  xor    ebp, eax
  rol    edx, $5
  movdqa oword [rsp + $30], xmm10
  add    ecx, edi
  and    esi, ebp
  xor    ebp, eax
  pslld  xmm0, $2
  add    ecx, edx
  ror    edx, $7
  psrld  xmm9, $1E
  xor    esi, eax
  mov    edi, ecx
  add    ebx, dword [rsp + $8]
  por    xmm0, xmm9
  xor    edx, ebp
  rol    ecx, $5
  pshufd xmm10, xmm7, $EE
  add    ebx, esi
  and    edi, edx
  xor    edx, ebp
  add    ebx, ecx
  add    eax, dword [rsp + $C]
  xor    edi, ebp
  mov    esi, ebx
  rol    ebx, $5
  add    eax, edi
  xor    esi, edx
  ror    ecx, $7
  add    eax, ebx
  pxor   xmm1, xmm5
  add    ebp, dword [rsp + $10]
  xor    esi, ecx
  punpcklqdq xmm10, xmm0
  mov    edi, eax
  rol    eax, $5
  pxor   xmm1, xmm2
  add    ebp, esi
  xor    edi, ecx
  movdqa xmm9, xmm8
  ror    ebx, $7
  paddd  xmm8, xmm0
  add    ebp, eax
  pxor   xmm1, xmm10
  add    edx, dword [rsp + $14]
  xor    edi, ebx
  mov    esi, ebp
  rol    ebp, $5
  movdqa xmm10, xmm1
  add    edx, edi
  xor    esi, ebx
  movdqa oword [rsp], xmm8
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $18]
  pslld  xmm1, $2
  xor    esi, eax
  mov    edi, edx
  psrld  xmm10, $1E
  rol    edx, $5
  add    ecx, esi
  xor    edi, eax
  ror    ebp, $7
  por    xmm1, xmm10
  add    ecx, edx
  add    ebx, dword [rsp + $1C]
  pshufd xmm8, xmm0, $EE
  xor    edi, ebp
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, edi
  xor    esi, ebp
  ror    edx, $7
  add    ebx, ecx
  pxor   xmm2, xmm6
  add    eax, dword [rsp + $20]
  xor    esi, edx
  punpcklqdq xmm8, xmm1
  mov    edi, ebx
  rol    ebx, $5
  pxor   xmm2, xmm3
  add    eax, esi
  xor    edi, edx
  movdqu xmm10, oword [r14]
  ror    ecx, $7
  paddd  xmm9, xmm1
  add    eax, ebx
  pxor   xmm2, xmm8
  add    ebp, dword [rsp + $24]
  xor    edi, ecx
  mov    esi, eax
  rol    eax, $5
  movdqa xmm8, xmm2
  add    ebp, edi
  xor    esi, ecx
  movdqa oword [rsp + $10], xmm9
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $28]
  pslld  xmm2, $2
  xor    esi, ebx
  mov    edi, ebp
  psrld  xmm8, $1E
  rol    ebp, $5
  add    edx, esi
  xor    edi, ebx
  ror    eax, $7
  por    xmm2, xmm8
  add    edx, ebp
  add    ecx, dword [rsp + $2C]
  pshufd xmm9, xmm1, $EE
  xor    edi, eax
  mov    esi, edx
  rol    edx, $5
  add    ecx, edi
  xor    esi, eax
  ror    ebp, $7
  add    ecx, edx
  pxor   xmm3, xmm7
  add    ebx, dword [rsp + $30]
  xor    esi, ebp
  punpcklqdq xmm9, xmm2
  mov    edi, ecx
  rol    ecx, $5
  pxor   xmm3, xmm4
  add    ebx, esi
  xor    edi, ebp
  movdqa xmm8, xmm10
  ror    edx, $7
  paddd  xmm10, xmm2
  add    ebx, ecx
  pxor   xmm3, xmm9
  add    eax, dword [rsp + $34]
  xor    edi, edx
  mov    esi, ebx
  rol    ebx, $5
  movdqa xmm9, xmm3
  add    eax, edi
  xor    esi, edx
  movdqa oword [rsp + $20], xmm10
  ror    ecx, $7
  add    eax, ebx
  add    ebp, dword [rsp + $38]
  pslld  xmm3, $2
  xor    esi, ecx
  mov    edi, eax
  psrld  xmm9, $1E
  rol    eax, $5
  add    ebp, esi
  xor    edi, ecx
  ror    ebx, $7
  por    xmm3, xmm9
  add    ebp, eax
  add    edx, dword [rsp + $3C]
  pshufd xmm10, xmm2, $EE
  xor    edi, ebx
  mov    esi, ebp
  rol    ebp, $5
  add    edx, edi
  xor    esi, ebx
  ror    eax, $7
  add    edx, ebp
  pxor   xmm4, xmm0
  add    ecx, dword [rsp]
  xor    esi, eax
  punpcklqdq xmm10, xmm3
  mov    edi, edx
  rol    edx, $5
  pxor   xmm4, xmm5
  add    ecx, esi
  xor    edi, eax
  movdqa xmm9, xmm8
  ror    ebp, $7
  paddd  xmm8, xmm3
  add    ecx, edx
  pxor   xmm4, xmm10
  add    ebx, dword [rsp + $4]
  xor    edi, ebp
  mov    esi, ecx
  rol    ecx, $5
  movdqa xmm10, xmm4
  add    ebx, edi
  xor    esi, ebp
  movdqa oword [rsp + $30], xmm8
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp + $8]
  pslld  xmm4, $2
  xor    esi, edx
  mov    edi, ebx
  psrld  xmm10, $1E
  rol    ebx, $5
  add    eax, esi
  xor    edi, edx
  ror    ecx, $7
  por    xmm4, xmm10
  add    eax, ebx
  add    ebp, dword [rsp + $C]
  pshufd xmm8, xmm3, $EE
  xor    edi, ecx
  mov    esi, eax
  rol    eax, $5
  add    ebp, edi
  xor    esi, ecx
  ror    ebx, $7
  add    ebp, eax
  pxor   xmm5, xmm1
  add    edx, dword [rsp + $10]
  xor    esi, ebx
  punpcklqdq xmm8, xmm4
  mov    edi, ebp
  rol    ebp, $5
  pxor   xmm5, xmm6
  add    edx, esi
  xor    edi, ebx
  movdqa xmm10, xmm9
  ror    eax, $7
  paddd  xmm9, xmm4
  add    edx, ebp
  pxor   xmm5, xmm8
  add    ecx, dword [rsp + $14]
  xor    edi, eax
  mov    esi, edx
  rol    edx, $5
  movdqa xmm8, xmm5
  add    ecx, edi
  xor    esi, eax
  movdqa oword [rsp], xmm9
  ror    ebp, $7
  add    ecx, edx
  add    ebx, dword [rsp + $18]
  pslld  xmm5, $2
  xor    esi, ebp
  mov    edi, ecx
  psrld  xmm8, $1E
  rol    ecx, $5
  add    ebx, esi
  xor    edi, ebp
  ror    edx, $7
  por    xmm5, xmm8
  add    ebx, ecx
  add    eax, dword [rsp + $1C]
  pshufd xmm9, xmm4, $EE
  ror    ecx, $7
  mov    esi, ebx
  xor    edi, edx
  rol    ebx, $5
  add    eax, edi
  xor    esi, ecx
  xor    ecx, edx
  add    eax, ebx
  pxor   xmm6, xmm2
  add    ebp, dword [rsp + $20]
  and    esi, ecx
  xor    ecx, edx
  ror    ebx, $7
  punpcklqdq xmm9, xmm5
  mov    edi, eax
  xor    esi, ecx
  pxor   xmm6, xmm7
  rol    eax, $5
  add    ebp, esi
  movdqa xmm8, xmm10
  xor    edi, ebx
  paddd  xmm10, xmm5
  xor    ebx, ecx
  pxor   xmm6, xmm9
  add    ebp, eax
  add    edx, dword [rsp + $24]
  and    edi, ebx
  xor    ebx, ecx
  ror    eax, $7
  movdqa xmm9, xmm6
  mov    esi, ebp
  xor    edi, ebx
  movdqa oword [rsp + $10], xmm10
  rol    ebp, $5
  add    edx, edi
  xor    esi, eax
  pslld  xmm6, $2
  xor    eax, ebx
  add    edx, ebp
  psrld  xmm9, $1E
  add    ecx, dword [rsp + $28]
  and    esi, eax
  xor    eax, ebx
  por    xmm6, xmm9
  ror    ebp, $7
  mov    edi, edx
  xor    esi, eax
  rol    edx, $5
  pshufd xmm10, xmm5, $EE
  add    ecx, esi
  xor    edi, ebp
  xor    ebp, eax
  add    ecx, edx
  add    ebx, dword [rsp + $2C]
  and    edi, ebp
  xor    ebp, eax
  ror    edx, $7
  mov    esi, ecx
  xor    edi, ebp
  rol    ecx, $5
  add    ebx, edi
  xor    esi, edx
  xor    edx, ebp
  add    ebx, ecx
  pxor   xmm7, xmm3
  add    eax, dword [rsp + $30]
  and    esi, edx
  xor    edx, ebp
  ror    ecx, $7
  punpcklqdq xmm10, xmm6
  mov    edi, ebx
  xor    esi, edx
  pxor   xmm7, xmm0
  rol    ebx, $5
  add    eax, esi
  movdqu xmm9, oword [r14 + $20]
  xor    edi, ecx
  paddd  xmm8, xmm6
  xor    ecx, edx
  pxor   xmm7, xmm10
  add    eax, ebx
  add    ebp, dword [rsp + $34]
  and    edi, ecx
  xor    ecx, edx
  ror    ebx, $7
  movdqa xmm10, xmm7
  mov    esi, eax
  xor    edi, ecx
  movdqa oword [rsp + $20], xmm8
  rol    eax, $5
  add    ebp, edi
  xor    esi, ebx
  pslld  xmm7, $2
  xor    ebx, ecx
  add    ebp, eax
  psrld  xmm10, $1E
  add    edx, dword [rsp + $38]
  and    esi, ebx
  xor    ebx, ecx
  por    xmm7, xmm10
  ror    eax, $7
  mov    edi, ebp
  xor    esi, ebx
  rol    ebp, $5
  pshufd xmm8, xmm6, $EE
  add    edx, esi
  xor    edi, eax
  xor    eax, ebx
  add    edx, ebp
  add    ecx, dword [rsp + $3C]
  and    edi, eax
  xor    eax, ebx
  ror    ebp, $7
  mov    esi, edx
  xor    edi, eax
  rol    edx, $5
  add    ecx, edi
  xor    esi, ebp
  xor    ebp, eax
  add    ecx, edx
  pxor   xmm0, xmm4
  add    ebx, dword [rsp]
  and    esi, ebp
  xor    ebp, eax
  ror    edx, $7
  punpcklqdq xmm8, xmm7
  mov    edi, ecx
  xor    esi, ebp
  pxor   xmm0, xmm1
  rol    ecx, $5
  add    ebx, esi
  movdqa xmm10, xmm9
  xor    edi, edx
  paddd  xmm9, xmm7
  xor    edx, ebp
  pxor   xmm0, xmm8
  add    ebx, ecx
  add    eax, dword [rsp + $4]
  and    edi, edx
  xor    edx, ebp
  ror    ecx, $7
  movdqa xmm8, xmm0
  mov    esi, ebx
  xor    edi, edx
  movdqa oword [rsp + $30], xmm9
  rol    ebx, $5
  add    eax, edi
  xor    esi, ecx
  pslld  xmm0, $2
  xor    ecx, edx
  add    eax, ebx
  psrld  xmm8, $1E
  add    ebp, dword [rsp + $8]
  and    esi, ecx
  xor    ecx, edx
  por    xmm0, xmm8
  ror    ebx, $7
  mov    edi, eax
  xor    esi, ecx
  rol    eax, $5
  pshufd xmm9, xmm7, $EE
  add    ebp, esi
  xor    edi, ebx
  xor    ebx, ecx
  add    ebp, eax
  add    edx, dword [rsp + $C]
  and    edi, ebx
  xor    ebx, ecx
  ror    eax, $7
  mov    esi, ebp
  xor    edi, ebx
  rol    ebp, $5
  add    edx, edi
  xor    esi, eax
  xor    eax, ebx
  add    edx, ebp
  pxor   xmm1, xmm5
  add    ecx, dword [rsp + $10]
  and    esi, eax
  xor    eax, ebx
  ror    ebp, $7
  punpcklqdq xmm9, xmm0
  mov    edi, edx
  xor    esi, eax
  pxor   xmm1, xmm2
  rol    edx, $5
  add    ecx, esi
  movdqa xmm8, xmm10
  xor    edi, ebp
  paddd  xmm10, xmm0
  xor    ebp, eax
  pxor   xmm1, xmm9
  add    ecx, edx
  add    ebx, dword [rsp + $14]
  and    edi, ebp
  xor    ebp, eax
  ror    edx, $7
  movdqa xmm9, xmm1
  mov    esi, ecx
  xor    edi, ebp
  movdqa oword [rsp], xmm10
  rol    ecx, $5
  add    ebx, edi
  xor    esi, edx
  pslld  xmm1, $2
  xor    edx, ebp
  add    ebx, ecx
  psrld  xmm9, $1E
  add    eax, dword [rsp + $18]
  and    esi, edx
  xor    edx, ebp
  por    xmm1, xmm9
  ror    ecx, $7
  mov    edi, ebx
  xor    esi, edx
  rol    ebx, $5
  pshufd xmm10, xmm0, $EE
  add    eax, esi
  xor    edi, ecx
  xor    ecx, edx
  add    eax, ebx
  add    ebp, dword [rsp + $1C]
  and    edi, ecx
  xor    ecx, edx
  ror    ebx, $7
  mov    esi, eax
  xor    edi, ecx
  rol    eax, $5
  add    ebp, edi
  xor    esi, ebx
  xor    ebx, ecx
  add    ebp, eax
  pxor   xmm2, xmm6
  add    edx, dword [rsp + $20]
  and    esi, ebx
  xor    ebx, ecx
  ror    eax, $7
  punpcklqdq xmm10, xmm1
  mov    edi, ebp
  xor    esi, ebx
  pxor   xmm2, xmm3
  rol    ebp, $5
  add    edx, esi
  movdqa xmm9, xmm8
  xor    edi, eax
  paddd  xmm8, xmm1
  xor    eax, ebx
  pxor   xmm2, xmm10
  add    edx, ebp
  add    ecx, dword [rsp + $24]
  and    edi, eax
  xor    eax, ebx
  ror    ebp, $7
  movdqa xmm10, xmm2
  mov    esi, edx
  xor    edi, eax
  movdqa oword [rsp + $10], xmm8
  rol    edx, $5
  add    ecx, edi
  xor    esi, ebp
  pslld  xmm2, $2
  xor    ebp, eax
  add    ecx, edx
  psrld  xmm10, $1E
  add    ebx, dword [rsp + $28]
  and    esi, ebp
  xor    ebp, eax
  por    xmm2, xmm10
  ror    edx, $7
  mov    edi, ecx
  xor    esi, ebp
  rol    ecx, $5
  pshufd xmm8, xmm1, $EE
  add    ebx, esi
  xor    edi, edx
  xor    edx, ebp
  add    ebx, ecx
  add    eax, dword [rsp + $2C]
  and    edi, edx
  xor    edx, ebp
  ror    ecx, $7
  mov    esi, ebx
  xor    edi, edx
  rol    ebx, $5
  add    eax, edi
  xor    esi, edx
  add    eax, ebx
  pxor   xmm3, xmm7
  add    ebp, dword [rsp + $30]
  xor    esi, ecx
  punpcklqdq xmm8, xmm2
  mov    edi, eax
  rol    eax, $5
  pxor   xmm3, xmm4
  add    ebp, esi
  xor    edi, ecx
  movdqa xmm10, xmm9
  ror    ebx, $7
  paddd  xmm9, xmm2
  add    ebp, eax
  pxor   xmm3, xmm8
  add    edx, dword [rsp + $34]
  xor    edi, ebx
  mov    esi, ebp
  rol    ebp, $5
  movdqa xmm8, xmm3
  add    edx, edi
  xor    esi, ebx
  movdqa oword [rsp + $20], xmm9
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $38]
  pslld  xmm3, $2
  xor    esi, eax
  mov    edi, edx
  psrld  xmm8, $1E
  rol    edx, $5
  add    ecx, esi
  xor    edi, eax
  ror    ebp, $7
  por    xmm3, xmm8
  add    ecx, edx
  add    ebx, dword [rsp + $3C]
  xor    edi, ebp
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, edi
  xor    esi, ebp
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp]
  xor    esi, edx
  mov    edi, ebx
  rol    ebx, $5
  paddd  xmm10, xmm3
  add    eax, esi
  xor    edi, edx
  movdqa oword [rsp + $30], xmm10
  ror    ecx, $7
  add    eax, ebx
  add    ebp, dword [rsp + $4]
  xor    edi, ecx
  mov    esi, eax
  rol    eax, $5
  add    ebp, edi
  xor    esi, ecx
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $8]
  xor    esi, ebx
  mov    edi, ebp
  rol    ebp, $5
  add    edx, esi
  xor    edi, ebx
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $C]
  xor    edi, eax
  mov    esi, edx
  rol    edx, $5
  add    ecx, edi
  xor    esi, eax
  ror    ebp, $7
  add    ecx, edx
  cmp    r9, r10
  je @done
  movdqu xmm6, oword [r14 + $40]
  movdqu xmm9, oword [r14 - $40]
  movdqu xmm0, oword [r9]
  movdqu xmm1, oword [r9 + $10]
  movdqu xmm2, oword [r9 + $20]
  movdqu xmm3, oword [r9 + $30]
  movdqa xmm12, xmm0
  psrlw  xmm12, $8
  psllw  xmm0, $8
  por    xmm0, xmm12
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  add    r9, $40
  add    ebx, dword [rsp + $10]
  xor    esi, ebp
  mov    edi, ecx
  movdqa xmm12, xmm1
  psrlw  xmm12, $8
  psllw  xmm1, $8
  por    xmm1, xmm12
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  rol    ecx, $5
  add    ebx, esi
  xor    edi, ebp
  ror    edx, $7
  paddd  xmm0, xmm9
  add    ebx, ecx
  add    eax, dword [rsp + $14]
  xor    edi, edx
  mov    esi, ebx
  movdqa oword [rsp], xmm0
  rol    ebx, $5
  add    eax, edi
  xor    esi, edx
  ror    ecx, $7
  psubd  xmm0, xmm9
  add    eax, ebx
  add    ebp, dword [rsp + $18]
  xor    esi, ecx
  mov    edi, eax
  rol    eax, $5
  add    ebp, esi
  xor    edi, ecx
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $1C]
  xor    edi, ebx
  mov    esi, ebp
  rol    ebp, $5
  add    edx, edi
  xor    esi, ebx
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $20]
  xor    esi, eax
  mov    edi, edx
  movdqa xmm12, xmm2
  psrlw  xmm12, $8
  psllw  xmm2, $8
  por    xmm2, xmm12
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  rol    edx, $5
  add    ecx, esi
  xor    edi, eax
  ror    ebp, $7
  paddd  xmm1, xmm9
  add    ecx, edx
  add    ebx, dword [rsp + $24]
  xor    edi, ebp
  mov    esi, ecx
  movdqa oword [rsp + $10], xmm1
  rol    ecx, $5
  add    ebx, edi
  xor    esi, ebp
  ror    edx, $7
  psubd  xmm1, xmm9
  add    ebx, ecx
  add    eax, dword [rsp + $28]
  xor    esi, edx
  mov    edi, ebx
  rol    ebx, $5
  add    eax, esi
  xor    edi, edx
  ror    ecx, $7
  add    eax, ebx
  add    ebp, dword [rsp + $2C]
  xor    edi, ecx
  mov    esi, eax
  rol    eax, $5
  add    ebp, edi
  xor    esi, ecx
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $30]
  xor    esi, ebx
  mov    edi, ebp
  movdqa xmm12, xmm3
  psrlw  xmm12, $8
  psllw  xmm3, $8
  por    xmm3, xmm12
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  rol    ebp, $5
  add    edx, esi
  xor    edi, ebx
  ror    eax, $7
  paddd  xmm2, xmm9
  add    edx, ebp
  add    ecx, dword [rsp + $34]
  xor    edi, eax
  mov    esi, edx
  movdqa oword [rsp + $20], xmm2
  rol    edx, $5
  add    ecx, edi
  xor    esi, eax
  ror    ebp, $7
  psubd  xmm2, xmm9
  add    ecx, edx
  add    ebx, dword [rsp + $38]
  xor    esi, ebp
  mov    edi, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    edi, ebp
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp + $3C]
  xor    edi, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, edi
  ror    ecx, $7
  add    eax, ebx
  add    eax, dword [r8]
  add    esi, dword [r8 + $4]
  add    ecx, dword [r8 + $8]
  add    edx, dword [r8 + $C]
  mov    dword [r8], eax
  add    ebp, dword [r8 + $10]
  mov    dword [r8 + $4], esi
  mov    ebx, esi
  mov    dword [r8 + $8], ecx
  mov    edi, ecx
  mov    dword [r8 + $C], edx
  xor    edi, edx
  mov    dword [r8 + $10], ebp
  and    esi, edi
  jmp @block_loop

@done:
  add    ebx, dword [rsp + $10]
  xor    esi, ebp
  mov    edi, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    edi, ebp
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp + $14]
  xor    edi, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, edi
  xor    esi, edx
  ror    ecx, $7
  add    eax, ebx
  add    ebp, dword [rsp + $18]
  xor    esi, ecx
  mov    edi, eax
  rol    eax, $5
  add    ebp, esi
  xor    edi, ecx
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $1C]
  xor    edi, ebx
  mov    esi, ebp
  rol    ebp, $5
  add    edx, edi
  xor    esi, ebx
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $20]
  xor    esi, eax
  mov    edi, edx
  rol    edx, $5
  add    ecx, esi
  xor    edi, eax
  ror    ebp, $7
  add    ecx, edx
  add    ebx, dword [rsp + $24]
  xor    edi, ebp
  mov    esi, ecx
  rol    ecx, $5
  add    ebx, edi
  xor    esi, ebp
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp + $28]
  xor    esi, edx
  mov    edi, ebx
  rol    ebx, $5
  add    eax, esi
  xor    edi, edx
  ror    ecx, $7
  add    eax, ebx
  add    ebp, dword [rsp + $2C]
  xor    edi, ecx
  mov    esi, eax
  rol    eax, $5
  add    ebp, edi
  xor    esi, ecx
  ror    ebx, $7
  add    ebp, eax
  add    edx, dword [rsp + $30]
  xor    esi, ebx
  mov    edi, ebp
  rol    ebp, $5
  add    edx, esi
  xor    edi, ebx
  ror    eax, $7
  add    edx, ebp
  add    ecx, dword [rsp + $34]
  xor    edi, eax
  mov    esi, edx
  rol    edx, $5
  add    ecx, edi
  xor    esi, eax
  ror    ebp, $7
  add    ecx, edx
  add    ebx, dword [rsp + $38]
  xor    esi, ebp
  mov    edi, ecx
  rol    ecx, $5
  add    ebx, esi
  xor    edi, ebp
  ror    edx, $7
  add    ebx, ecx
  add    eax, dword [rsp + $3C]
  xor    edi, edx
  mov    esi, ebx
  rol    ebx, $5
  add    eax, edi
  ror    ecx, $7
  add    eax, ebx
  add    eax, dword [r8]
  add    esi, dword [r8 + $4]
  add    ecx, dword [r8 + $8]
  mov    dword [r8], eax
  add    edx, dword [r8 + $C]
  mov    dword [r8 + $4], esi
  add    ebp, dword [r8 + $10]
  mov    dword [r8 + $8], ecx
  mov    dword [r8 + $C], edx
  mov    dword [r8 + $10], ebp
  mov    rsi, qword [r11 - $40]
  mov    rdi, qword [r11 - $38]
  mov    r14, qword [r11 - $30]
  mov    r13, qword [r11 - $28]
  mov    r12, qword [r11 - $20]
  mov    rbp, qword [r11 - $18]
  mov    rbx, qword [r11 - $10]
  lea    rsp, [r11]

  {$I ..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
