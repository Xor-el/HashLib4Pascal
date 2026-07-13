// SSE2 implementation of SHA-256 compress (SIMD schedule). The message
// schedule runs in SSE2 (paddd/psrld/pslld/pxor/pshufd) interleaved with
// the GPR compression rounds, so the vector and integer units run in
// parallel. The original's two SSSE3-only ops are emulated in SSE2: the
// pshufb dword byte-swap becomes psrlw/psllw/por + pshuflw/pshufhw, and
// palignr becomes psrldq/pslldq/por (xmm8 is a free scratch).
// ABI (after HlpSimdProc4Begin_x86_64.inc): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = doubled-K256 ptr (read at a 32-byte stride so the
//   duplicated halves are skipped; see K256_Doubled). No byte-swap mask
//   table is needed - the swap is computed, not shuffled.
// Saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore include
//   (no-op on SysV); rbx, rbp, rdi, rsi, r12-r15 in the local frame.
// Reference: OpenSSL CRYPTOGAMS sha512-x86_64.pl (SHA-256 SSSE3 kernel).

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  mov    rax, rsp
  push   r9
  push   rbx
  push   rbp
  push   rsi
  push   rdi
  push   r12
  push   r13
  push   r14
  push   r15
  mov    rdi, rcx
  mov    rsi, rdx
  mov    edx, r8d
  shl    rdx, $4
  sub    rsp, $A0
  lea    rdx, [rsi + rdx*4]
  and    rsp, $FFFFFFFFFFFFFFC0
  mov    qword [rsp + $40], rdi
  mov    qword [rsp + $48], rsi
  mov    qword [rsp + $50], rdx
  mov    qword [rsp + $58], rax

@prologue:
  mov    eax, dword [rdi]
  mov    ebx, dword [rdi + $4]
  mov    ecx, dword [rdi + $8]
  mov    edx, dword [rdi + $C]
  mov    r8d, dword [rdi + $10]
  mov    r9d, dword [rdi + $14]
  mov    r10d, dword [rdi + $18]
  mov    r11d, dword [rdi + $1C]
  jmp @block_loop

@block_loop:
  movdqu xmm0, oword [rsi]
  movdqu xmm1, oword [rsi + $10]
  movdqu xmm2, oword [rsi + $20]
  movdqa xmm8, xmm0
  psrlw  xmm8, $8
  psllw  xmm0, $8
  por    xmm0, xmm8
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqu xmm3, oword [rsi + $30]
  mov    rbp, qword [rsp + $58]
  mov    rbp, qword [rbp - $8]
  movdqa xmm8, xmm1
  psrlw  xmm8, $8
  psllw  xmm1, $8
  por    xmm1, xmm8
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqu xmm4, oword [rbp + $0]
  movdqu xmm5, oword [rbp + $20]
  movdqa xmm8, xmm2
  psrlw  xmm8, $8
  psllw  xmm2, $8
  por    xmm2, xmm8
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  paddd  xmm4, xmm0
  movdqu xmm6, oword [rbp + $40]
  movdqa xmm8, xmm3
  psrlw  xmm8, $8
  psllw  xmm3, $8
  por    xmm3, xmm8
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  movdqu xmm7, oword [rbp + $60]
  paddd  xmm5, xmm1
  paddd  xmm6, xmm2
  paddd  xmm7, xmm3
  movdqa oword [rsp], xmm4
  mov    r14d, eax
  movdqa oword [rsp + $10], xmm5
  mov    edi, ebx
  movdqa oword [rsp + $20], xmm6
  xor    edi, ecx
  movdqa oword [rsp + $30], xmm7
  mov    r13d, r8d
  jmp @sched_loop

@sched_loop:
  sub    rbp, $FFFFFFFFFFFFFF80
  ror    r13d, $E
  movdqa xmm4, xmm1
  mov    eax, r14d
  mov    r12d, r9d
  movdqa xmm7, xmm3
  ror    r14d, $9
  xor    r13d, r8d
  xor    r12d, r10d
  ror    r13d, $5
  xor    r14d, eax
  movdqa xmm8, xmm0
  psrldq xmm8, $4
  pslldq xmm4, $C
  por    xmm4, xmm8
  and    r12d, r8d
  xor    r13d, r8d
  movdqa xmm8, xmm2
  psrldq xmm8, $4
  pslldq xmm7, $C
  por    xmm7, xmm8
  add    r11d, dword [rsp]
  mov    r15d, eax
  xor    r12d, r10d
  ror    r14d, $B
  movdqa xmm5, xmm4
  xor    r15d, ebx
  add    r11d, r12d
  movdqa xmm6, xmm4
  ror    r13d, $6
  and    edi, r15d
  psrld  xmm4, $3
  xor    r14d, eax
  add    r11d, r13d
  xor    edi, ebx
  paddd  xmm0, xmm7
  ror    r14d, $2
  add    edx, r11d
  psrld  xmm6, $7
  add    r11d, edi
  mov    r13d, edx
  pshufd xmm7, xmm3, $FA
  add    r14d, r11d
  ror    r13d, $E
  pslld  xmm5, $E
  mov    r11d, r14d
  mov    r12d, r8d
  pxor   xmm4, xmm6
  ror    r14d, $9
  xor    r13d, edx
  xor    r12d, r9d
  ror    r13d, $5
  psrld  xmm6, $B
  xor    r14d, r11d
  pxor   xmm4, xmm5
  and    r12d, edx
  xor    r13d, edx
  pslld  xmm5, $B
  add    r10d, dword [rsp + $4]
  mov    edi, r11d
  pxor   xmm4, xmm6
  xor    r12d, r9d
  ror    r14d, $B
  movdqa xmm6, xmm7
  xor    edi, eax
  add    r10d, r12d
  pxor   xmm4, xmm5
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r11d
  psrld  xmm7, $A
  add    r10d, r13d
  xor    r15d, eax
  paddd  xmm0, xmm4
  ror    r14d, $2
  add    ecx, r10d
  psrlq  xmm6, $11
  add    r10d, r15d
  mov    r13d, ecx
  add    r14d, r10d
  pxor   xmm7, xmm6
  ror    r13d, $E
  mov    r10d, r14d
  mov    r12d, edx
  ror    r14d, $9
  psrlq  xmm6, $2
  xor    r13d, ecx
  xor    r12d, r8d
  pxor   xmm7, xmm6
  ror    r13d, $5
  xor    r14d, r10d
  and    r12d, ecx
  pshufd xmm7, xmm7, $80
  xor    r13d, ecx
  add    r9d, dword [rsp + $8]
  mov    r15d, r10d
  psrldq xmm7, $8
  xor    r12d, r8d
  ror    r14d, $B
  xor    r15d, r11d
  add    r9d, r12d
  ror    r13d, $6
  paddd  xmm0, xmm7
  and    edi, r15d
  xor    r14d, r10d
  add    r9d, r13d
  pshufd xmm7, xmm0, $50
  xor    edi, r11d
  ror    r14d, $2
  add    ebx, r9d
  movdqa xmm6, xmm7
  add    r9d, edi
  mov    r13d, ebx
  psrld  xmm7, $A
  add    r14d, r9d
  ror    r13d, $E
  psrlq  xmm6, $11
  mov    r9d, r14d
  mov    r12d, ecx
  pxor   xmm7, xmm6
  ror    r14d, $9
  xor    r13d, ebx
  xor    r12d, edx
  ror    r13d, $5
  xor    r14d, r9d
  psrlq  xmm6, $2
  and    r12d, ebx
  xor    r13d, ebx
  add    r8d, dword [rsp + $C]
  pxor   xmm7, xmm6
  mov    edi, r9d
  xor    r12d, edx
  ror    r14d, $B
  pshufd xmm7, xmm7, $8
  xor    edi, r10d
  add    r8d, r12d
  movdqu xmm6, oword [rbp + $0]
  ror    r13d, $6
  and    r15d, edi
  pslldq xmm7, $8
  xor    r14d, r9d
  add    r8d, r13d
  xor    r15d, r10d
  paddd  xmm0, xmm7
  ror    r14d, $2
  add    eax, r8d
  add    r8d, r15d
  paddd  xmm6, xmm0
  mov    r13d, eax
  add    r14d, r8d
  movdqa oword [rsp], xmm6
  ror    r13d, $E
  movdqa xmm4, xmm2
  mov    r8d, r14d
  mov    r12d, ebx
  movdqa xmm7, xmm0
  ror    r14d, $9
  xor    r13d, eax
  xor    r12d, ecx
  ror    r13d, $5
  xor    r14d, r8d
  movdqa xmm8, xmm1
  psrldq xmm8, $4
  pslldq xmm4, $C
  por    xmm4, xmm8
  and    r12d, eax
  xor    r13d, eax
  movdqa xmm8, xmm3
  psrldq xmm8, $4
  pslldq xmm7, $C
  por    xmm7, xmm8
  add    edx, dword [rsp + $10]
  mov    r15d, r8d
  xor    r12d, ecx
  ror    r14d, $B
  movdqa xmm5, xmm4
  xor    r15d, r9d
  add    edx, r12d
  movdqa xmm6, xmm4
  ror    r13d, $6
  and    edi, r15d
  psrld  xmm4, $3
  xor    r14d, r8d
  add    edx, r13d
  xor    edi, r9d
  paddd  xmm1, xmm7
  ror    r14d, $2
  add    r11d, edx
  psrld  xmm6, $7
  add    edx, edi
  mov    r13d, r11d
  pshufd xmm7, xmm0, $FA
  add    r14d, edx
  ror    r13d, $E
  pslld  xmm5, $E
  mov    edx, r14d
  mov    r12d, eax
  pxor   xmm4, xmm6
  ror    r14d, $9
  xor    r13d, r11d
  xor    r12d, ebx
  ror    r13d, $5
  psrld  xmm6, $B
  xor    r14d, edx
  pxor   xmm4, xmm5
  and    r12d, r11d
  xor    r13d, r11d
  pslld  xmm5, $B
  add    ecx, dword [rsp + $14]
  mov    edi, edx
  pxor   xmm4, xmm6
  xor    r12d, ebx
  ror    r14d, $B
  movdqa xmm6, xmm7
  xor    edi, r8d
  add    ecx, r12d
  pxor   xmm4, xmm5
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, edx
  psrld  xmm7, $A
  add    ecx, r13d
  xor    r15d, r8d
  paddd  xmm1, xmm4
  ror    r14d, $2
  add    r10d, ecx
  psrlq  xmm6, $11
  add    ecx, r15d
  mov    r13d, r10d
  add    r14d, ecx
  pxor   xmm7, xmm6
  ror    r13d, $E
  mov    ecx, r14d
  mov    r12d, r11d
  ror    r14d, $9
  psrlq  xmm6, $2
  xor    r13d, r10d
  xor    r12d, eax
  pxor   xmm7, xmm6
  ror    r13d, $5
  xor    r14d, ecx
  and    r12d, r10d
  pshufd xmm7, xmm7, $80
  xor    r13d, r10d
  add    ebx, dword [rsp + $18]
  mov    r15d, ecx
  psrldq xmm7, $8
  xor    r12d, eax
  ror    r14d, $B
  xor    r15d, edx
  add    ebx, r12d
  ror    r13d, $6
  paddd  xmm1, xmm7
  and    edi, r15d
  xor    r14d, ecx
  add    ebx, r13d
  pshufd xmm7, xmm1, $50
  xor    edi, edx
  ror    r14d, $2
  add    r9d, ebx
  movdqa xmm6, xmm7
  add    ebx, edi
  mov    r13d, r9d
  psrld  xmm7, $A
  add    r14d, ebx
  ror    r13d, $E
  psrlq  xmm6, $11
  mov    ebx, r14d
  mov    r12d, r10d
  pxor   xmm7, xmm6
  ror    r14d, $9
  xor    r13d, r9d
  xor    r12d, r11d
  ror    r13d, $5
  xor    r14d, ebx
  psrlq  xmm6, $2
  and    r12d, r9d
  xor    r13d, r9d
  add    eax, dword [rsp + $1C]
  pxor   xmm7, xmm6
  mov    edi, ebx
  xor    r12d, r11d
  ror    r14d, $B
  pshufd xmm7, xmm7, $8
  xor    edi, ecx
  add    eax, r12d
  movdqu xmm6, oword [rbp + $20]
  ror    r13d, $6
  and    r15d, edi
  pslldq xmm7, $8
  xor    r14d, ebx
  add    eax, r13d
  xor    r15d, ecx
  paddd  xmm1, xmm7
  ror    r14d, $2
  add    r8d, eax
  add    eax, r15d
  paddd  xmm6, xmm1
  mov    r13d, r8d
  add    r14d, eax
  movdqa oword [rsp + $10], xmm6
  ror    r13d, $E
  movdqa xmm4, xmm3
  mov    eax, r14d
  mov    r12d, r9d
  movdqa xmm7, xmm1
  ror    r14d, $9
  xor    r13d, r8d
  xor    r12d, r10d
  ror    r13d, $5
  xor    r14d, eax
  movdqa xmm8, xmm2
  psrldq xmm8, $4
  pslldq xmm4, $C
  por    xmm4, xmm8
  and    r12d, r8d
  xor    r13d, r8d
  movdqa xmm8, xmm0
  psrldq xmm8, $4
  pslldq xmm7, $C
  por    xmm7, xmm8
  add    r11d, dword [rsp + $20]
  mov    r15d, eax
  xor    r12d, r10d
  ror    r14d, $B
  movdqa xmm5, xmm4
  xor    r15d, ebx
  add    r11d, r12d
  movdqa xmm6, xmm4
  ror    r13d, $6
  and    edi, r15d
  psrld  xmm4, $3
  xor    r14d, eax
  add    r11d, r13d
  xor    edi, ebx
  paddd  xmm2, xmm7
  ror    r14d, $2
  add    edx, r11d
  psrld  xmm6, $7
  add    r11d, edi
  mov    r13d, edx
  pshufd xmm7, xmm1, $FA
  add    r14d, r11d
  ror    r13d, $E
  pslld  xmm5, $E
  mov    r11d, r14d
  mov    r12d, r8d
  pxor   xmm4, xmm6
  ror    r14d, $9
  xor    r13d, edx
  xor    r12d, r9d
  ror    r13d, $5
  psrld  xmm6, $B
  xor    r14d, r11d
  pxor   xmm4, xmm5
  and    r12d, edx
  xor    r13d, edx
  pslld  xmm5, $B
  add    r10d, dword [rsp + $24]
  mov    edi, r11d
  pxor   xmm4, xmm6
  xor    r12d, r9d
  ror    r14d, $B
  movdqa xmm6, xmm7
  xor    edi, eax
  add    r10d, r12d
  pxor   xmm4, xmm5
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r11d
  psrld  xmm7, $A
  add    r10d, r13d
  xor    r15d, eax
  paddd  xmm2, xmm4
  ror    r14d, $2
  add    ecx, r10d
  psrlq  xmm6, $11
  add    r10d, r15d
  mov    r13d, ecx
  add    r14d, r10d
  pxor   xmm7, xmm6
  ror    r13d, $E
  mov    r10d, r14d
  mov    r12d, edx
  ror    r14d, $9
  psrlq  xmm6, $2
  xor    r13d, ecx
  xor    r12d, r8d
  pxor   xmm7, xmm6
  ror    r13d, $5
  xor    r14d, r10d
  and    r12d, ecx
  pshufd xmm7, xmm7, $80
  xor    r13d, ecx
  add    r9d, dword [rsp + $28]
  mov    r15d, r10d
  psrldq xmm7, $8
  xor    r12d, r8d
  ror    r14d, $B
  xor    r15d, r11d
  add    r9d, r12d
  ror    r13d, $6
  paddd  xmm2, xmm7
  and    edi, r15d
  xor    r14d, r10d
  add    r9d, r13d
  pshufd xmm7, xmm2, $50
  xor    edi, r11d
  ror    r14d, $2
  add    ebx, r9d
  movdqa xmm6, xmm7
  add    r9d, edi
  mov    r13d, ebx
  psrld  xmm7, $A
  add    r14d, r9d
  ror    r13d, $E
  psrlq  xmm6, $11
  mov    r9d, r14d
  mov    r12d, ecx
  pxor   xmm7, xmm6
  ror    r14d, $9
  xor    r13d, ebx
  xor    r12d, edx
  ror    r13d, $5
  xor    r14d, r9d
  psrlq  xmm6, $2
  and    r12d, ebx
  xor    r13d, ebx
  add    r8d, dword [rsp + $2C]
  pxor   xmm7, xmm6
  mov    edi, r9d
  xor    r12d, edx
  ror    r14d, $B
  pshufd xmm7, xmm7, $8
  xor    edi, r10d
  add    r8d, r12d
  movdqu xmm6, oword [rbp + $40]
  ror    r13d, $6
  and    r15d, edi
  pslldq xmm7, $8
  xor    r14d, r9d
  add    r8d, r13d
  xor    r15d, r10d
  paddd  xmm2, xmm7
  ror    r14d, $2
  add    eax, r8d
  add    r8d, r15d
  paddd  xmm6, xmm2
  mov    r13d, eax
  add    r14d, r8d
  movdqa oword [rsp + $20], xmm6
  ror    r13d, $E
  movdqa xmm4, xmm0
  mov    r8d, r14d
  mov    r12d, ebx
  movdqa xmm7, xmm2
  ror    r14d, $9
  xor    r13d, eax
  xor    r12d, ecx
  ror    r13d, $5
  xor    r14d, r8d
  movdqa xmm8, xmm3
  psrldq xmm8, $4
  pslldq xmm4, $C
  por    xmm4, xmm8
  and    r12d, eax
  xor    r13d, eax
  movdqa xmm8, xmm1
  psrldq xmm8, $4
  pslldq xmm7, $C
  por    xmm7, xmm8
  add    edx, dword [rsp + $30]
  mov    r15d, r8d
  xor    r12d, ecx
  ror    r14d, $B
  movdqa xmm5, xmm4
  xor    r15d, r9d
  add    edx, r12d
  movdqa xmm6, xmm4
  ror    r13d, $6
  and    edi, r15d
  psrld  xmm4, $3
  xor    r14d, r8d
  add    edx, r13d
  xor    edi, r9d
  paddd  xmm3, xmm7
  ror    r14d, $2
  add    r11d, edx
  psrld  xmm6, $7
  add    edx, edi
  mov    r13d, r11d
  pshufd xmm7, xmm2, $FA
  add    r14d, edx
  ror    r13d, $E
  pslld  xmm5, $E
  mov    edx, r14d
  mov    r12d, eax
  pxor   xmm4, xmm6
  ror    r14d, $9
  xor    r13d, r11d
  xor    r12d, ebx
  ror    r13d, $5
  psrld  xmm6, $B
  xor    r14d, edx
  pxor   xmm4, xmm5
  and    r12d, r11d
  xor    r13d, r11d
  pslld  xmm5, $B
  add    ecx, dword [rsp + $34]
  mov    edi, edx
  pxor   xmm4, xmm6
  xor    r12d, ebx
  ror    r14d, $B
  movdqa xmm6, xmm7
  xor    edi, r8d
  add    ecx, r12d
  pxor   xmm4, xmm5
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, edx
  psrld  xmm7, $A
  add    ecx, r13d
  xor    r15d, r8d
  paddd  xmm3, xmm4
  ror    r14d, $2
  add    r10d, ecx
  psrlq  xmm6, $11
  add    ecx, r15d
  mov    r13d, r10d
  add    r14d, ecx
  pxor   xmm7, xmm6
  ror    r13d, $E
  mov    ecx, r14d
  mov    r12d, r11d
  ror    r14d, $9
  psrlq  xmm6, $2
  xor    r13d, r10d
  xor    r12d, eax
  pxor   xmm7, xmm6
  ror    r13d, $5
  xor    r14d, ecx
  and    r12d, r10d
  pshufd xmm7, xmm7, $80
  xor    r13d, r10d
  add    ebx, dword [rsp + $38]
  mov    r15d, ecx
  psrldq xmm7, $8
  xor    r12d, eax
  ror    r14d, $B
  xor    r15d, edx
  add    ebx, r12d
  ror    r13d, $6
  paddd  xmm3, xmm7
  and    edi, r15d
  xor    r14d, ecx
  add    ebx, r13d
  pshufd xmm7, xmm3, $50
  xor    edi, edx
  ror    r14d, $2
  add    r9d, ebx
  movdqa xmm6, xmm7
  add    ebx, edi
  mov    r13d, r9d
  psrld  xmm7, $A
  add    r14d, ebx
  ror    r13d, $E
  psrlq  xmm6, $11
  mov    ebx, r14d
  mov    r12d, r10d
  pxor   xmm7, xmm6
  ror    r14d, $9
  xor    r13d, r9d
  xor    r12d, r11d
  ror    r13d, $5
  xor    r14d, ebx
  psrlq  xmm6, $2
  and    r12d, r9d
  xor    r13d, r9d
  add    eax, dword [rsp + $3C]
  pxor   xmm7, xmm6
  mov    edi, ebx
  xor    r12d, r11d
  ror    r14d, $B
  pshufd xmm7, xmm7, $8
  xor    edi, ecx
  add    eax, r12d
  movdqu xmm6, oword [rbp + $60]
  ror    r13d, $6
  and    r15d, edi
  pslldq xmm7, $8
  xor    r14d, ebx
  add    eax, r13d
  xor    r15d, ecx
  paddd  xmm3, xmm7
  ror    r14d, $2
  add    r8d, eax
  add    eax, r15d
  paddd  xmm6, xmm3
  mov    r13d, r8d
  add    r14d, eax
  movdqa oword [rsp + $30], xmm6
  cmp    byte [rbp + $83], $0
  jne @sched_loop
  ror    r13d, $E
  mov    eax, r14d
  mov    r12d, r9d
  ror    r14d, $9
  xor    r13d, r8d
  xor    r12d, r10d
  ror    r13d, $5
  xor    r14d, eax
  and    r12d, r8d
  xor    r13d, r8d
  add    r11d, dword [rsp]
  mov    r15d, eax
  xor    r12d, r10d
  ror    r14d, $B
  xor    r15d, ebx
  add    r11d, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, eax
  add    r11d, r13d
  xor    edi, ebx
  ror    r14d, $2
  add    edx, r11d
  add    r11d, edi
  mov    r13d, edx
  add    r14d, r11d
  ror    r13d, $E
  mov    r11d, r14d
  mov    r12d, r8d
  ror    r14d, $9
  xor    r13d, edx
  xor    r12d, r9d
  ror    r13d, $5
  xor    r14d, r11d
  and    r12d, edx
  xor    r13d, edx
  add    r10d, dword [rsp + $4]
  mov    edi, r11d
  xor    r12d, r9d
  ror    r14d, $B
  xor    edi, eax
  add    r10d, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r11d
  add    r10d, r13d
  xor    r15d, eax
  ror    r14d, $2
  add    ecx, r10d
  add    r10d, r15d
  mov    r13d, ecx
  add    r14d, r10d
  ror    r13d, $E
  mov    r10d, r14d
  mov    r12d, edx
  ror    r14d, $9
  xor    r13d, ecx
  xor    r12d, r8d
  ror    r13d, $5
  xor    r14d, r10d
  and    r12d, ecx
  xor    r13d, ecx
  add    r9d, dword [rsp + $8]
  mov    r15d, r10d
  xor    r12d, r8d
  ror    r14d, $B
  xor    r15d, r11d
  add    r9d, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, r10d
  add    r9d, r13d
  xor    edi, r11d
  ror    r14d, $2
  add    ebx, r9d
  add    r9d, edi
  mov    r13d, ebx
  add    r14d, r9d
  ror    r13d, $E
  mov    r9d, r14d
  mov    r12d, ecx
  ror    r14d, $9
  xor    r13d, ebx
  xor    r12d, edx
  ror    r13d, $5
  xor    r14d, r9d
  and    r12d, ebx
  xor    r13d, ebx
  add    r8d, dword [rsp + $C]
  mov    edi, r9d
  xor    r12d, edx
  ror    r14d, $B
  xor    edi, r10d
  add    r8d, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r9d
  add    r8d, r13d
  xor    r15d, r10d
  ror    r14d, $2
  add    eax, r8d
  add    r8d, r15d
  mov    r13d, eax
  add    r14d, r8d
  ror    r13d, $E
  mov    r8d, r14d
  mov    r12d, ebx
  ror    r14d, $9
  xor    r13d, eax
  xor    r12d, ecx
  ror    r13d, $5
  xor    r14d, r8d
  and    r12d, eax
  xor    r13d, eax
  add    edx, dword [rsp + $10]
  mov    r15d, r8d
  xor    r12d, ecx
  ror    r14d, $B
  xor    r15d, r9d
  add    edx, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, r8d
  add    edx, r13d
  xor    edi, r9d
  ror    r14d, $2
  add    r11d, edx
  add    edx, edi
  mov    r13d, r11d
  add    r14d, edx
  ror    r13d, $E
  mov    edx, r14d
  mov    r12d, eax
  ror    r14d, $9
  xor    r13d, r11d
  xor    r12d, ebx
  ror    r13d, $5
  xor    r14d, edx
  and    r12d, r11d
  xor    r13d, r11d
  add    ecx, dword [rsp + $14]
  mov    edi, edx
  xor    r12d, ebx
  ror    r14d, $B
  xor    edi, r8d
  add    ecx, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, edx
  add    ecx, r13d
  xor    r15d, r8d
  ror    r14d, $2
  add    r10d, ecx
  add    ecx, r15d
  mov    r13d, r10d
  add    r14d, ecx
  ror    r13d, $E
  mov    ecx, r14d
  mov    r12d, r11d
  ror    r14d, $9
  xor    r13d, r10d
  xor    r12d, eax
  ror    r13d, $5
  xor    r14d, ecx
  and    r12d, r10d
  xor    r13d, r10d
  add    ebx, dword [rsp + $18]
  mov    r15d, ecx
  xor    r12d, eax
  ror    r14d, $B
  xor    r15d, edx
  add    ebx, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, ecx
  add    ebx, r13d
  xor    edi, edx
  ror    r14d, $2
  add    r9d, ebx
  add    ebx, edi
  mov    r13d, r9d
  add    r14d, ebx
  ror    r13d, $E
  mov    ebx, r14d
  mov    r12d, r10d
  ror    r14d, $9
  xor    r13d, r9d
  xor    r12d, r11d
  ror    r13d, $5
  xor    r14d, ebx
  and    r12d, r9d
  xor    r13d, r9d
  add    eax, dword [rsp + $1C]
  mov    edi, ebx
  xor    r12d, r11d
  ror    r14d, $B
  xor    edi, ecx
  add    eax, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, ebx
  add    eax, r13d
  xor    r15d, ecx
  ror    r14d, $2
  add    r8d, eax
  add    eax, r15d
  mov    r13d, r8d
  add    r14d, eax
  ror    r13d, $E
  mov    eax, r14d
  mov    r12d, r9d
  ror    r14d, $9
  xor    r13d, r8d
  xor    r12d, r10d
  ror    r13d, $5
  xor    r14d, eax
  and    r12d, r8d
  xor    r13d, r8d
  add    r11d, dword [rsp + $20]
  mov    r15d, eax
  xor    r12d, r10d
  ror    r14d, $B
  xor    r15d, ebx
  add    r11d, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, eax
  add    r11d, r13d
  xor    edi, ebx
  ror    r14d, $2
  add    edx, r11d
  add    r11d, edi
  mov    r13d, edx
  add    r14d, r11d
  ror    r13d, $E
  mov    r11d, r14d
  mov    r12d, r8d
  ror    r14d, $9
  xor    r13d, edx
  xor    r12d, r9d
  ror    r13d, $5
  xor    r14d, r11d
  and    r12d, edx
  xor    r13d, edx
  add    r10d, dword [rsp + $24]
  mov    edi, r11d
  xor    r12d, r9d
  ror    r14d, $B
  xor    edi, eax
  add    r10d, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r11d
  add    r10d, r13d
  xor    r15d, eax
  ror    r14d, $2
  add    ecx, r10d
  add    r10d, r15d
  mov    r13d, ecx
  add    r14d, r10d
  ror    r13d, $E
  mov    r10d, r14d
  mov    r12d, edx
  ror    r14d, $9
  xor    r13d, ecx
  xor    r12d, r8d
  ror    r13d, $5
  xor    r14d, r10d
  and    r12d, ecx
  xor    r13d, ecx
  add    r9d, dword [rsp + $28]
  mov    r15d, r10d
  xor    r12d, r8d
  ror    r14d, $B
  xor    r15d, r11d
  add    r9d, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, r10d
  add    r9d, r13d
  xor    edi, r11d
  ror    r14d, $2
  add    ebx, r9d
  add    r9d, edi
  mov    r13d, ebx
  add    r14d, r9d
  ror    r13d, $E
  mov    r9d, r14d
  mov    r12d, ecx
  ror    r14d, $9
  xor    r13d, ebx
  xor    r12d, edx
  ror    r13d, $5
  xor    r14d, r9d
  and    r12d, ebx
  xor    r13d, ebx
  add    r8d, dword [rsp + $2C]
  mov    edi, r9d
  xor    r12d, edx
  ror    r14d, $B
  xor    edi, r10d
  add    r8d, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, r9d
  add    r8d, r13d
  xor    r15d, r10d
  ror    r14d, $2
  add    eax, r8d
  add    r8d, r15d
  mov    r13d, eax
  add    r14d, r8d
  ror    r13d, $E
  mov    r8d, r14d
  mov    r12d, ebx
  ror    r14d, $9
  xor    r13d, eax
  xor    r12d, ecx
  ror    r13d, $5
  xor    r14d, r8d
  and    r12d, eax
  xor    r13d, eax
  add    edx, dword [rsp + $30]
  mov    r15d, r8d
  xor    r12d, ecx
  ror    r14d, $B
  xor    r15d, r9d
  add    edx, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, r8d
  add    edx, r13d
  xor    edi, r9d
  ror    r14d, $2
  add    r11d, edx
  add    edx, edi
  mov    r13d, r11d
  add    r14d, edx
  ror    r13d, $E
  mov    edx, r14d
  mov    r12d, eax
  ror    r14d, $9
  xor    r13d, r11d
  xor    r12d, ebx
  ror    r13d, $5
  xor    r14d, edx
  and    r12d, r11d
  xor    r13d, r11d
  add    ecx, dword [rsp + $34]
  mov    edi, edx
  xor    r12d, ebx
  ror    r14d, $B
  xor    edi, r8d
  add    ecx, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, edx
  add    ecx, r13d
  xor    r15d, r8d
  ror    r14d, $2
  add    r10d, ecx
  add    ecx, r15d
  mov    r13d, r10d
  add    r14d, ecx
  ror    r13d, $E
  mov    ecx, r14d
  mov    r12d, r11d
  ror    r14d, $9
  xor    r13d, r10d
  xor    r12d, eax
  ror    r13d, $5
  xor    r14d, ecx
  and    r12d, r10d
  xor    r13d, r10d
  add    ebx, dword [rsp + $38]
  mov    r15d, ecx
  xor    r12d, eax
  ror    r14d, $B
  xor    r15d, edx
  add    ebx, r12d
  ror    r13d, $6
  and    edi, r15d
  xor    r14d, ecx
  add    ebx, r13d
  xor    edi, edx
  ror    r14d, $2
  add    r9d, ebx
  add    ebx, edi
  mov    r13d, r9d
  add    r14d, ebx
  ror    r13d, $E
  mov    ebx, r14d
  mov    r12d, r10d
  ror    r14d, $9
  xor    r13d, r9d
  xor    r12d, r11d
  ror    r13d, $5
  xor    r14d, ebx
  and    r12d, r9d
  xor    r13d, r9d
  add    eax, dword [rsp + $3C]
  mov    edi, ebx
  xor    r12d, r11d
  ror    r14d, $B
  xor    edi, ecx
  add    eax, r12d
  ror    r13d, $6
  and    r15d, edi
  xor    r14d, ebx
  add    eax, r13d
  xor    r15d, ecx
  ror    r14d, $2
  add    r8d, eax
  add    eax, r15d
  mov    r13d, r8d
  add    r14d, eax
  mov    rdi, qword [rsp + $40]
  mov    eax, r14d
  add    eax, dword [rdi]
  lea    rsi, [rsi + $40]
  add    ebx, dword [rdi + $4]
  add    ecx, dword [rdi + $8]
  add    edx, dword [rdi + $C]
  add    r8d, dword [rdi + $10]
  add    r9d, dword [rdi + $14]
  add    r10d, dword [rdi + $18]
  add    r11d, dword [rdi + $1C]
  cmp    rsi, qword [rsp + $50]
  mov    dword [rdi], eax
  mov    dword [rdi + $4], ebx
  mov    dword [rdi + $8], ecx
  mov    dword [rdi + $C], edx
  mov    dword [rdi + $10], r8d
  mov    dword [rdi + $14], r9d
  mov    dword [rdi + $18], r10d
  mov    dword [rdi + $1C], r11d
  jb @block_loop
  mov    rsi, qword [rsp + $58]
  mov    r15, qword [rsi - $48]
  mov    r14, qword [rsi - $40]
  mov    r13, qword [rsi - $38]
  mov    r12, qword [rsi - $30]
  mov    rdi, qword [rsi - $28]
  mov    rbp, qword [rsi - $18]
  mov    rbx, qword [rsi - $10]
  mov    rax, qword [rsi - $20]
  lea    rsp, [rsi]
  mov    rsi, rax

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
