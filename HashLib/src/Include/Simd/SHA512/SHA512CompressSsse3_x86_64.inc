// SHA-512 SSSE3 implementation with a SIMD message schedule; SSE2 sibling:
// SHA512CompressSse2_x86_64.inc. The sigma schedule runs in 128-bit SIMD and
// is interleaved with the 64-bit GPR compression rounds, so the vector and
// integer units run in parallel. Unlike the SSE2 sibling the big-endian input
// byte-swaps are real pshufb (db-encoded for broad assembler compatibility)
// against the BSWAP64 mask kept resident in xmm12 for the whole kernel.
// Reference: OpenSSL CRYPTOGAMS sha512-x86_64.pl (AVX single-block kernel).
// Expects MS x64 ABI (after HlpSimdProc4Begin): rcx = state ptr, rdx = data ptr,
//   r8d = numblocks, r9 = doubled-K512 ptr (K512_Doubled: each 128-bit K512 pair
//   stored twice, read at a 32-byte stride; the BSWAP64 mask sits at +1280).
//
// MS x64 non-volatile saves: xmm6-xmm15 via the shared HlpSimdNonVolatileSave/Restore
// include (no-op on SysV); rbx, rbp, rdi, rsi, r12-r15 in the local frame.

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileSave_x86_64.inc}

  push   rbx
  push   rbp
  push   rsi
  push   rdi
  push   r12
  push   r13
  push   r14
  push   r15
  mov    rax, rsp
  sub    rsp, $100
  and    rsp, $FFFFFFFFFFFFFFC0
  mov    qword [rsp + $98], rax
  mov    qword [rsp + $A0], r9
  movdqu xmm12, oword [r9 + $500]  // BSWAP64 mask (K512_Doubled + 1280)
  mov    qword [rsp + $80], rcx
  mov    r11d, r8d
  shl    r11, $7
  lea    r11, [rdx + r11*1]
  mov    qword [rsp + $90], r11
  mov    rsi, rdx
  mov    rdi, qword [rsp + $80]
  mov    rax, qword [rdi]
  mov    rbx, qword [rdi + $8]
  mov    rcx, qword [rdi + $10]
  mov    rdx, qword [rdi + $18]
  mov    r8, qword [rdi + $20]
  mov    r9, qword [rdi + $28]
  mov    r10, qword [rdi + $30]
  mov    r11, qword [rdi + $38]

@block_loop:
  movdqu xmm0, oword [rsi]
  mov    rbp, qword [rsp + $A0]
  add    rbp, $80
  movdqu xmm1, oword [rsi + $10]
  movdqu xmm2, oword [rsi + $20]
  db $66, $41, $0F, $38, $00, $C4              // pshufb xmm0, xmm12
  movdqu xmm3, oword [rsi + $30]
  db $66, $41, $0F, $38, $00, $CC              // pshufb xmm1, xmm12
  movdqu xmm4, oword [rsi + $40]
  db $66, $41, $0F, $38, $00, $D4              // pshufb xmm2, xmm12
  movdqu xmm5, oword [rsi + $50]
  db $66, $41, $0F, $38, $00, $DC              // pshufb xmm3, xmm12
  movdqu xmm6, oword [rsi + $60]
  db $66, $41, $0F, $38, $00, $E4              // pshufb xmm4, xmm12
  movdqu xmm7, oword [rsi + $70]
  db $66, $41, $0F, $38, $00, $EC              // pshufb xmm5, xmm12
  movdqa xmm8, xmm0
  movdqu xmm13, oword [rbp - $80]
  paddq  xmm8, xmm13
  db $66, $41, $0F, $38, $00, $F4              // pshufb xmm6, xmm12
  movdqa xmm9, xmm1
  movdqu xmm13, oword [rbp - $60]
  paddq  xmm9, xmm13
  db $66, $41, $0F, $38, $00, $FC              // pshufb xmm7, xmm12
  movdqa xmm10, xmm2
  movdqu xmm13, oword [rbp - $40]
  paddq  xmm10, xmm13
  movdqa xmm11, xmm3
  movdqu xmm13, oword [rbp - $20]
  paddq  xmm11, xmm13
  movdqa oword [rsp], xmm8
  movdqa xmm8, xmm4
  movdqu xmm13, oword [rbp + $0]
  paddq  xmm8, xmm13
  movdqa oword [rsp + $10], xmm9
  movdqa xmm9, xmm5
  movdqu xmm13, oword [rbp + $20]
  paddq  xmm9, xmm13
  movdqa oword [rsp + $20], xmm10
  movdqa xmm10, xmm6
  movdqu xmm13, oword [rbp + $40]
  paddq  xmm10, xmm13
  movdqa oword [rsp + $30], xmm11
  movdqa xmm11, xmm7
  movdqu xmm13, oword [rbp + $60]
  paddq  xmm11, xmm13
  movdqa oword [rsp + $40], xmm8
  mov    r14, rax
  movdqa oword [rsp + $50], xmm9
  mov    rdi, rbx
  movdqa oword [rsp + $60], xmm10
  xor    rdi, rcx
  movdqa oword [rsp + $70], xmm11
  mov    r13, r8
  jmp @sched_loop

@sched_loop:
  add    rbp, $100
  movdqa xmm8, xmm0
  shufpd xmm8, xmm1, $1
  shrd   r13, r13, $17
  mov    rax, r14
  movdqa xmm11, xmm4
  shufpd xmm11, xmm5, $1
  mov    r12, r9
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, r8
  xor    r12, r10
  paddq  xmm0, xmm11
  shrd   r13, r13, $4
  xor    r14, rax
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, r8
  xor    r13, r8
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    r11, qword [rsp]
  mov    r15, rax
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, r10
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, rbx
  add    r11, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, rax
  add    r11, r13
  pxor   xmm8, xmm10
  xor    rdi, rbx
  shrd   r14, r14, $1C
  movdqa xmm11, xmm7
  psrlq  xmm11, $6
  add    rdx, r11
  add    r11, rdi
  pxor   xmm8, xmm9
  mov    r13, rdx
  add    r14, r11
  movdqa xmm10, xmm7
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    r11, r14
  paddq  xmm0, xmm8
  mov    r12, r8
  shrd   r14, r14, $5
  movdqa xmm9, xmm7
  psrlq  xmm9, $13
  xor    r13, rdx
  xor    r12, r9
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, r11
  psllq  xmm10, $2A
  and    r12, rdx
  xor    r13, rdx
  pxor   xmm11, xmm9
  add    r10, qword [rsp + $8]
  mov    rdi, r11
  psrlq  xmm9, $2A
  xor    r12, r9
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, rax
  add    r10, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm0, xmm11
  xor    r14, r11
  add    r10, r13
  movdqa xmm10, xmm0
  movdqu xmm13, oword [rbp - $80]
  paddq  xmm10, xmm13
  xor    r15, rax
  shrd   r14, r14, $1C
  add    rcx, r10
  add    r10, r15
  mov    r13, rcx
  add    r14, r10
  movdqa oword [rsp], xmm10
  movdqa xmm8, xmm1
  shufpd xmm8, xmm2, $1
  shrd   r13, r13, $17
  mov    r10, r14
  movdqa xmm11, xmm5
  shufpd xmm11, xmm6, $1
  mov    r12, rdx
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, rcx
  xor    r12, r8
  paddq  xmm1, xmm11
  shrd   r13, r13, $4
  xor    r14, r10
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, rcx
  xor    r13, rcx
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    r9, qword [rsp + $10]
  mov    r15, r10
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, r8
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, r11
  add    r9, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, r10
  add    r9, r13
  pxor   xmm8, xmm10
  xor    rdi, r11
  shrd   r14, r14, $1C
  movdqa xmm11, xmm0
  psrlq  xmm11, $6
  add    rbx, r9
  add    r9, rdi
  pxor   xmm8, xmm9
  mov    r13, rbx
  add    r14, r9
  movdqa xmm10, xmm0
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    r9, r14
  paddq  xmm1, xmm8
  mov    r12, rcx
  shrd   r14, r14, $5
  movdqa xmm9, xmm0
  psrlq  xmm9, $13
  xor    r13, rbx
  xor    r12, rdx
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, r9
  psllq  xmm10, $2A
  and    r12, rbx
  xor    r13, rbx
  pxor   xmm11, xmm9
  add    r8, qword [rsp + $18]
  mov    rdi, r9
  psrlq  xmm9, $2A
  xor    r12, rdx
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, r10
  add    r8, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm1, xmm11
  xor    r14, r9
  add    r8, r13
  movdqa xmm10, xmm1
  movdqu xmm13, oword [rbp - $60]
  paddq  xmm10, xmm13
  xor    r15, r10
  shrd   r14, r14, $1C
  add    rax, r8
  add    r8, r15
  mov    r13, rax
  add    r14, r8
  movdqa oword [rsp + $10], xmm10
  movdqa xmm8, xmm2
  shufpd xmm8, xmm3, $1
  shrd   r13, r13, $17
  mov    r8, r14
  movdqa xmm11, xmm6
  shufpd xmm11, xmm7, $1
  mov    r12, rbx
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, rax
  xor    r12, rcx
  paddq  xmm2, xmm11
  shrd   r13, r13, $4
  xor    r14, r8
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, rax
  xor    r13, rax
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    rdx, qword [rsp + $20]
  mov    r15, r8
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, rcx
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, r9
  add    rdx, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, r8
  add    rdx, r13
  pxor   xmm8, xmm10
  xor    rdi, r9
  shrd   r14, r14, $1C
  movdqa xmm11, xmm1
  psrlq  xmm11, $6
  add    r11, rdx
  add    rdx, rdi
  pxor   xmm8, xmm9
  mov    r13, r11
  add    r14, rdx
  movdqa xmm10, xmm1
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    rdx, r14
  paddq  xmm2, xmm8
  mov    r12, rax
  shrd   r14, r14, $5
  movdqa xmm9, xmm1
  psrlq  xmm9, $13
  xor    r13, r11
  xor    r12, rbx
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, rdx
  psllq  xmm10, $2A
  and    r12, r11
  xor    r13, r11
  pxor   xmm11, xmm9
  add    rcx, qword [rsp + $28]
  mov    rdi, rdx
  psrlq  xmm9, $2A
  xor    r12, rbx
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, r8
  add    rcx, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm2, xmm11
  xor    r14, rdx
  add    rcx, r13
  movdqa xmm10, xmm2
  movdqu xmm13, oword [rbp - $40]
  paddq  xmm10, xmm13
  xor    r15, r8
  shrd   r14, r14, $1C
  add    r10, rcx
  add    rcx, r15
  mov    r13, r10
  add    r14, rcx
  movdqa oword [rsp + $20], xmm10
  movdqa xmm8, xmm3
  shufpd xmm8, xmm4, $1
  shrd   r13, r13, $17
  mov    rcx, r14
  movdqa xmm11, xmm7
  shufpd xmm11, xmm0, $1
  mov    r12, r11
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, r10
  xor    r12, rax
  paddq  xmm3, xmm11
  shrd   r13, r13, $4
  xor    r14, rcx
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, r10
  xor    r13, r10
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    rbx, qword [rsp + $30]
  mov    r15, rcx
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, rax
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, rdx
  add    rbx, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, rcx
  add    rbx, r13
  pxor   xmm8, xmm10
  xor    rdi, rdx
  shrd   r14, r14, $1C
  movdqa xmm11, xmm2
  psrlq  xmm11, $6
  add    r9, rbx
  add    rbx, rdi
  pxor   xmm8, xmm9
  mov    r13, r9
  add    r14, rbx
  movdqa xmm10, xmm2
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    rbx, r14
  paddq  xmm3, xmm8
  mov    r12, r10
  shrd   r14, r14, $5
  movdqa xmm9, xmm2
  psrlq  xmm9, $13
  xor    r13, r9
  xor    r12, r11
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, rbx
  psllq  xmm10, $2A
  and    r12, r9
  xor    r13, r9
  pxor   xmm11, xmm9
  add    rax, qword [rsp + $38]
  mov    rdi, rbx
  psrlq  xmm9, $2A
  xor    r12, r11
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, rcx
  add    rax, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm3, xmm11
  xor    r14, rbx
  add    rax, r13
  movdqa xmm10, xmm3
  movdqu xmm13, oword [rbp - $20]
  paddq  xmm10, xmm13
  xor    r15, rcx
  shrd   r14, r14, $1C
  add    r8, rax
  add    rax, r15
  mov    r13, r8
  add    r14, rax
  movdqa oword [rsp + $30], xmm10
  movdqa xmm8, xmm4
  shufpd xmm8, xmm5, $1
  shrd   r13, r13, $17
  mov    rax, r14
  movdqa xmm11, xmm0
  shufpd xmm11, xmm1, $1
  mov    r12, r9
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, r8
  xor    r12, r10
  paddq  xmm4, xmm11
  shrd   r13, r13, $4
  xor    r14, rax
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, r8
  xor    r13, r8
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    r11, qword [rsp + $40]
  mov    r15, rax
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, r10
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, rbx
  add    r11, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, rax
  add    r11, r13
  pxor   xmm8, xmm10
  xor    rdi, rbx
  shrd   r14, r14, $1C
  movdqa xmm11, xmm3
  psrlq  xmm11, $6
  add    rdx, r11
  add    r11, rdi
  pxor   xmm8, xmm9
  mov    r13, rdx
  add    r14, r11
  movdqa xmm10, xmm3
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    r11, r14
  paddq  xmm4, xmm8
  mov    r12, r8
  shrd   r14, r14, $5
  movdqa xmm9, xmm3
  psrlq  xmm9, $13
  xor    r13, rdx
  xor    r12, r9
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, r11
  psllq  xmm10, $2A
  and    r12, rdx
  xor    r13, rdx
  pxor   xmm11, xmm9
  add    r10, qword [rsp + $48]
  mov    rdi, r11
  psrlq  xmm9, $2A
  xor    r12, r9
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, rax
  add    r10, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm4, xmm11
  xor    r14, r11
  add    r10, r13
  movdqa xmm10, xmm4
  movdqu xmm13, oword [rbp + $0]
  paddq  xmm10, xmm13
  xor    r15, rax
  shrd   r14, r14, $1C
  add    rcx, r10
  add    r10, r15
  mov    r13, rcx
  add    r14, r10
  movdqa oword [rsp + $40], xmm10
  movdqa xmm8, xmm5
  shufpd xmm8, xmm6, $1
  shrd   r13, r13, $17
  mov    r10, r14
  movdqa xmm11, xmm1
  shufpd xmm11, xmm2, $1
  mov    r12, rdx
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, rcx
  xor    r12, r8
  paddq  xmm5, xmm11
  shrd   r13, r13, $4
  xor    r14, r10
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, rcx
  xor    r13, rcx
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    r9, qword [rsp + $50]
  mov    r15, r10
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, r8
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, r11
  add    r9, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, r10
  add    r9, r13
  pxor   xmm8, xmm10
  xor    rdi, r11
  shrd   r14, r14, $1C
  movdqa xmm11, xmm4
  psrlq  xmm11, $6
  add    rbx, r9
  add    r9, rdi
  pxor   xmm8, xmm9
  mov    r13, rbx
  add    r14, r9
  movdqa xmm10, xmm4
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    r9, r14
  paddq  xmm5, xmm8
  mov    r12, rcx
  shrd   r14, r14, $5
  movdqa xmm9, xmm4
  psrlq  xmm9, $13
  xor    r13, rbx
  xor    r12, rdx
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, r9
  psllq  xmm10, $2A
  and    r12, rbx
  xor    r13, rbx
  pxor   xmm11, xmm9
  add    r8, qword [rsp + $58]
  mov    rdi, r9
  psrlq  xmm9, $2A
  xor    r12, rdx
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, r10
  add    r8, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm5, xmm11
  xor    r14, r9
  add    r8, r13
  movdqa xmm10, xmm5
  movdqu xmm13, oword [rbp + $20]
  paddq  xmm10, xmm13
  xor    r15, r10
  shrd   r14, r14, $1C
  add    rax, r8
  add    r8, r15
  mov    r13, rax
  add    r14, r8
  movdqa oword [rsp + $50], xmm10
  movdqa xmm8, xmm6
  shufpd xmm8, xmm7, $1
  shrd   r13, r13, $17
  mov    r8, r14
  movdqa xmm11, xmm2
  shufpd xmm11, xmm3, $1
  mov    r12, rbx
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, rax
  xor    r12, rcx
  paddq  xmm6, xmm11
  shrd   r13, r13, $4
  xor    r14, r8
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, rax
  xor    r13, rax
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    rdx, qword [rsp + $60]
  mov    r15, r8
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, rcx
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, r9
  add    rdx, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, r8
  add    rdx, r13
  pxor   xmm8, xmm10
  xor    rdi, r9
  shrd   r14, r14, $1C
  movdqa xmm11, xmm5
  psrlq  xmm11, $6
  add    r11, rdx
  add    rdx, rdi
  pxor   xmm8, xmm9
  mov    r13, r11
  add    r14, rdx
  movdqa xmm10, xmm5
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    rdx, r14
  paddq  xmm6, xmm8
  mov    r12, rax
  shrd   r14, r14, $5
  movdqa xmm9, xmm5
  psrlq  xmm9, $13
  xor    r13, r11
  xor    r12, rbx
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, rdx
  psllq  xmm10, $2A
  and    r12, r11
  xor    r13, r11
  pxor   xmm11, xmm9
  add    rcx, qword [rsp + $68]
  mov    rdi, rdx
  psrlq  xmm9, $2A
  xor    r12, rbx
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, r8
  add    rcx, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm6, xmm11
  xor    r14, rdx
  add    rcx, r13
  movdqa xmm10, xmm6
  movdqu xmm13, oword [rbp + $40]
  paddq  xmm10, xmm13
  xor    r15, r8
  shrd   r14, r14, $1C
  add    r10, rcx
  add    rcx, r15
  mov    r13, r10
  add    r14, rcx
  movdqa oword [rsp + $60], xmm10
  movdqa xmm8, xmm7
  shufpd xmm8, xmm0, $1
  shrd   r13, r13, $17
  mov    rcx, r14
  movdqa xmm11, xmm3
  shufpd xmm11, xmm4, $1
  mov    r12, r11
  shrd   r14, r14, $5
  movdqa xmm10, xmm8
  psrlq  xmm10, $1
  xor    r13, r10
  xor    r12, rax
  paddq  xmm7, xmm11
  shrd   r13, r13, $4
  xor    r14, rcx
  movdqa xmm11, xmm8
  psrlq  xmm11, $7
  and    r12, r10
  xor    r13, r10
  movdqa xmm9, xmm8
  psllq  xmm9, $38
  add    rbx, qword [rsp + $70]
  mov    r15, rcx
  movdqa xmm8, xmm11
  pxor   xmm8, xmm10
  xor    r12, rax
  shrd   r14, r14, $6
  psrlq  xmm10, $7
  xor    r15, rdx
  add    rbx, r12
  pxor   xmm8, xmm9
  shrd   r13, r13, $E
  and    rdi, r15
  psllq  xmm9, $7
  xor    r14, rcx
  add    rbx, r13
  pxor   xmm8, xmm10
  xor    rdi, rdx
  shrd   r14, r14, $1C
  movdqa xmm11, xmm6
  psrlq  xmm11, $6
  add    r9, rbx
  add    rbx, rdi
  pxor   xmm8, xmm9
  mov    r13, r9
  add    r14, rbx
  movdqa xmm10, xmm6
  psllq  xmm10, $3
  shrd   r13, r13, $17
  mov    rbx, r14
  paddq  xmm7, xmm8
  mov    r12, r10
  shrd   r14, r14, $5
  movdqa xmm9, xmm6
  psrlq  xmm9, $13
  xor    r13, r9
  xor    r12, r11
  pxor   xmm11, xmm10
  shrd   r13, r13, $4
  xor    r14, rbx
  psllq  xmm10, $2A
  and    r12, r9
  xor    r13, r9
  pxor   xmm11, xmm9
  add    rax, qword [rsp + $78]
  mov    rdi, rbx
  psrlq  xmm9, $2A
  xor    r12, r11
  shrd   r14, r14, $6
  pxor   xmm11, xmm10
  xor    rdi, rcx
  add    rax, r12
  pxor   xmm11, xmm9
  shrd   r13, r13, $E
  and    r15, rdi
  paddq  xmm7, xmm11
  xor    r14, rbx
  add    rax, r13
  movdqa xmm10, xmm7
  movdqu xmm13, oword [rbp + $60]
  paddq  xmm10, xmm13
  xor    r15, rcx
  shrd   r14, r14, $1C
  add    r8, rax
  add    rax, r15
  mov    r13, r8
  add    r14, rax
  movdqa oword [rsp + $70], xmm10
  cmp    byte [rbp + $87], $0
  jne @sched_loop
  shrd   r13, r13, $17
  mov    rax, r14
  mov    r12, r9
  shrd   r14, r14, $5
  xor    r13, r8
  xor    r12, r10
  shrd   r13, r13, $4
  xor    r14, rax
  and    r12, r8
  xor    r13, r8
  add    r11, qword [rsp]
  mov    r15, rax
  xor    r12, r10
  shrd   r14, r14, $6
  xor    r15, rbx
  add    r11, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, rax
  add    r11, r13
  xor    rdi, rbx
  shrd   r14, r14, $1C
  add    rdx, r11
  add    r11, rdi
  mov    r13, rdx
  add    r14, r11
  shrd   r13, r13, $17
  mov    r11, r14
  mov    r12, r8
  shrd   r14, r14, $5
  xor    r13, rdx
  xor    r12, r9
  shrd   r13, r13, $4
  xor    r14, r11
  and    r12, rdx
  xor    r13, rdx
  add    r10, qword [rsp + $8]
  mov    rdi, r11
  xor    r12, r9
  shrd   r14, r14, $6
  xor    rdi, rax
  add    r10, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, r11
  add    r10, r13
  xor    r15, rax
  shrd   r14, r14, $1C
  add    rcx, r10
  add    r10, r15
  mov    r13, rcx
  add    r14, r10
  shrd   r13, r13, $17
  mov    r10, r14
  mov    r12, rdx
  shrd   r14, r14, $5
  xor    r13, rcx
  xor    r12, r8
  shrd   r13, r13, $4
  xor    r14, r10
  and    r12, rcx
  xor    r13, rcx
  add    r9, qword [rsp + $10]
  mov    r15, r10
  xor    r12, r8
  shrd   r14, r14, $6
  xor    r15, r11
  add    r9, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, r10
  add    r9, r13
  xor    rdi, r11
  shrd   r14, r14, $1C
  add    rbx, r9
  add    r9, rdi
  mov    r13, rbx
  add    r14, r9
  shrd   r13, r13, $17
  mov    r9, r14
  mov    r12, rcx
  shrd   r14, r14, $5
  xor    r13, rbx
  xor    r12, rdx
  shrd   r13, r13, $4
  xor    r14, r9
  and    r12, rbx
  xor    r13, rbx
  add    r8, qword [rsp + $18]
  mov    rdi, r9
  xor    r12, rdx
  shrd   r14, r14, $6
  xor    rdi, r10
  add    r8, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, r9
  add    r8, r13
  xor    r15, r10
  shrd   r14, r14, $1C
  add    rax, r8
  add    r8, r15
  mov    r13, rax
  add    r14, r8
  shrd   r13, r13, $17
  mov    r8, r14
  mov    r12, rbx
  shrd   r14, r14, $5
  xor    r13, rax
  xor    r12, rcx
  shrd   r13, r13, $4
  xor    r14, r8
  and    r12, rax
  xor    r13, rax
  add    rdx, qword [rsp + $20]
  mov    r15, r8
  xor    r12, rcx
  shrd   r14, r14, $6
  xor    r15, r9
  add    rdx, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, r8
  add    rdx, r13
  xor    rdi, r9
  shrd   r14, r14, $1C
  add    r11, rdx
  add    rdx, rdi
  mov    r13, r11
  add    r14, rdx
  shrd   r13, r13, $17
  mov    rdx, r14
  mov    r12, rax
  shrd   r14, r14, $5
  xor    r13, r11
  xor    r12, rbx
  shrd   r13, r13, $4
  xor    r14, rdx
  and    r12, r11
  xor    r13, r11
  add    rcx, qword [rsp + $28]
  mov    rdi, rdx
  xor    r12, rbx
  shrd   r14, r14, $6
  xor    rdi, r8
  add    rcx, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, rdx
  add    rcx, r13
  xor    r15, r8
  shrd   r14, r14, $1C
  add    r10, rcx
  add    rcx, r15
  mov    r13, r10
  add    r14, rcx
  shrd   r13, r13, $17
  mov    rcx, r14
  mov    r12, r11
  shrd   r14, r14, $5
  xor    r13, r10
  xor    r12, rax
  shrd   r13, r13, $4
  xor    r14, rcx
  and    r12, r10
  xor    r13, r10
  add    rbx, qword [rsp + $30]
  mov    r15, rcx
  xor    r12, rax
  shrd   r14, r14, $6
  xor    r15, rdx
  add    rbx, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, rcx
  add    rbx, r13
  xor    rdi, rdx
  shrd   r14, r14, $1C
  add    r9, rbx
  add    rbx, rdi
  mov    r13, r9
  add    r14, rbx
  shrd   r13, r13, $17
  mov    rbx, r14
  mov    r12, r10
  shrd   r14, r14, $5
  xor    r13, r9
  xor    r12, r11
  shrd   r13, r13, $4
  xor    r14, rbx
  and    r12, r9
  xor    r13, r9
  add    rax, qword [rsp + $38]
  mov    rdi, rbx
  xor    r12, r11
  shrd   r14, r14, $6
  xor    rdi, rcx
  add    rax, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, rbx
  add    rax, r13
  xor    r15, rcx
  shrd   r14, r14, $1C
  add    r8, rax
  add    rax, r15
  mov    r13, r8
  add    r14, rax
  shrd   r13, r13, $17
  mov    rax, r14
  mov    r12, r9
  shrd   r14, r14, $5
  xor    r13, r8
  xor    r12, r10
  shrd   r13, r13, $4
  xor    r14, rax
  and    r12, r8
  xor    r13, r8
  add    r11, qword [rsp + $40]
  mov    r15, rax
  xor    r12, r10
  shrd   r14, r14, $6
  xor    r15, rbx
  add    r11, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, rax
  add    r11, r13
  xor    rdi, rbx
  shrd   r14, r14, $1C
  add    rdx, r11
  add    r11, rdi
  mov    r13, rdx
  add    r14, r11
  shrd   r13, r13, $17
  mov    r11, r14
  mov    r12, r8
  shrd   r14, r14, $5
  xor    r13, rdx
  xor    r12, r9
  shrd   r13, r13, $4
  xor    r14, r11
  and    r12, rdx
  xor    r13, rdx
  add    r10, qword [rsp + $48]
  mov    rdi, r11
  xor    r12, r9
  shrd   r14, r14, $6
  xor    rdi, rax
  add    r10, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, r11
  add    r10, r13
  xor    r15, rax
  shrd   r14, r14, $1C
  add    rcx, r10
  add    r10, r15
  mov    r13, rcx
  add    r14, r10
  shrd   r13, r13, $17
  mov    r10, r14
  mov    r12, rdx
  shrd   r14, r14, $5
  xor    r13, rcx
  xor    r12, r8
  shrd   r13, r13, $4
  xor    r14, r10
  and    r12, rcx
  xor    r13, rcx
  add    r9, qword [rsp + $50]
  mov    r15, r10
  xor    r12, r8
  shrd   r14, r14, $6
  xor    r15, r11
  add    r9, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, r10
  add    r9, r13
  xor    rdi, r11
  shrd   r14, r14, $1C
  add    rbx, r9
  add    r9, rdi
  mov    r13, rbx
  add    r14, r9
  shrd   r13, r13, $17
  mov    r9, r14
  mov    r12, rcx
  shrd   r14, r14, $5
  xor    r13, rbx
  xor    r12, rdx
  shrd   r13, r13, $4
  xor    r14, r9
  and    r12, rbx
  xor    r13, rbx
  add    r8, qword [rsp + $58]
  mov    rdi, r9
  xor    r12, rdx
  shrd   r14, r14, $6
  xor    rdi, r10
  add    r8, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, r9
  add    r8, r13
  xor    r15, r10
  shrd   r14, r14, $1C
  add    rax, r8
  add    r8, r15
  mov    r13, rax
  add    r14, r8
  shrd   r13, r13, $17
  mov    r8, r14
  mov    r12, rbx
  shrd   r14, r14, $5
  xor    r13, rax
  xor    r12, rcx
  shrd   r13, r13, $4
  xor    r14, r8
  and    r12, rax
  xor    r13, rax
  add    rdx, qword [rsp + $60]
  mov    r15, r8
  xor    r12, rcx
  shrd   r14, r14, $6
  xor    r15, r9
  add    rdx, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, r8
  add    rdx, r13
  xor    rdi, r9
  shrd   r14, r14, $1C
  add    r11, rdx
  add    rdx, rdi
  mov    r13, r11
  add    r14, rdx
  shrd   r13, r13, $17
  mov    rdx, r14
  mov    r12, rax
  shrd   r14, r14, $5
  xor    r13, r11
  xor    r12, rbx
  shrd   r13, r13, $4
  xor    r14, rdx
  and    r12, r11
  xor    r13, r11
  add    rcx, qword [rsp + $68]
  mov    rdi, rdx
  xor    r12, rbx
  shrd   r14, r14, $6
  xor    rdi, r8
  add    rcx, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, rdx
  add    rcx, r13
  xor    r15, r8
  shrd   r14, r14, $1C
  add    r10, rcx
  add    rcx, r15
  mov    r13, r10
  add    r14, rcx
  shrd   r13, r13, $17
  mov    rcx, r14
  mov    r12, r11
  shrd   r14, r14, $5
  xor    r13, r10
  xor    r12, rax
  shrd   r13, r13, $4
  xor    r14, rcx
  and    r12, r10
  xor    r13, r10
  add    rbx, qword [rsp + $70]
  mov    r15, rcx
  xor    r12, rax
  shrd   r14, r14, $6
  xor    r15, rdx
  add    rbx, r12
  shrd   r13, r13, $E
  and    rdi, r15
  xor    r14, rcx
  add    rbx, r13
  xor    rdi, rdx
  shrd   r14, r14, $1C
  add    r9, rbx
  add    rbx, rdi
  mov    r13, r9
  add    r14, rbx
  shrd   r13, r13, $17
  mov    rbx, r14
  mov    r12, r10
  shrd   r14, r14, $5
  xor    r13, r9
  xor    r12, r11
  shrd   r13, r13, $4
  xor    r14, rbx
  and    r12, r9
  xor    r13, r9
  add    rax, qword [rsp + $78]
  mov    rdi, rbx
  xor    r12, r11
  shrd   r14, r14, $6
  xor    rdi, rcx
  add    rax, r12
  shrd   r13, r13, $E
  and    r15, rdi
  xor    r14, rbx
  add    rax, r13
  xor    r15, rcx
  shrd   r14, r14, $1C
  add    r8, rax
  add    rax, r15
  mov    r13, r8
  add    r14, rax
  mov    rdi, qword [rsp + $80]
  mov    rax, r14
  add    rax, qword [rdi]
  lea    rsi, [rsi + $80]
  add    rbx, qword [rdi + $8]
  add    rcx, qword [rdi + $10]
  add    rdx, qword [rdi + $18]
  add    r8, qword [rdi + $20]
  add    r9, qword [rdi + $28]
  add    r10, qword [rdi + $30]
  add    r11, qword [rdi + $38]
  cmp    rsi, qword [rsp + $90]
  mov    qword [rdi], rax
  mov    qword [rdi + $8], rbx
  mov    qword [rdi + $10], rcx
  mov    qword [rdi + $18], rdx
  mov    qword [rdi + $20], r8
  mov    qword [rdi + $28], r9
  mov    qword [rdi + $30], r10
  mov    qword [rdi + $38], r11
  jb @block_loop
  mov    rsp, qword [rsp + $98]
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  pop    rdi
  pop    rsi
  pop    rbp
  pop    rbx

  {$I ..\..\Include\Simd\Common\HlpSimdNonVolatileRestore_x86_64.inc}
