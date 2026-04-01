// SHA-256 SSE2 implementation with SIMD message schedule.
// Based on SSSE3 implementation (see SHA256CompressSsse3_x86_64.inc).
// Same algorithm as SSSE3 version but replaces SSSE3-specific instructions:
//   pshufb  -> SSE2 byte-swap (pshuflw/pshufhw + psrlw/psllw/por)
//   palignr -> SSE2 emulation (movdqa/psrldq/pslldq/por)
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K256 ptr.
// K256 layout: 64 UInt32 round constants (256 bytes), then BSWAP mask (16 bytes) at offset 256.
// Uses xmm0-xmm7, all GPR.
//
// Two-phase per block:
//   Phase 1 (SIMD): Compute W+K[0..63] using SSE2 message schedule, store to stack
//   Phase 2 (GPR): Run 64 compression rounds reading W+K from stack
//
// Non-volatile register saves:
//   Windows: xmm6-xmm7, rbx, rbp, rdi, rsi, r12-r15
//   Unix: rbx, rbp, r12-r15
//
// Stack layout (sub rsp, 376): same as SSSE3 version

  sub rsp, 376

{$IFDEF MSWINDOWS}
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  mov [rsp + $30], rdi
  mov [rsp + $38], rsi
{$ENDIF}
  mov [rsp + $20], rbx
  mov [rsp + $28], rbp
  mov [rsp + $40], r12
  mov [rsp + $48], r13
  mov [rsp + $50], r14
  mov [rsp + $58], r15

  mov r12, rcx
  mov r13, rdx
  mov r14d, r8d
  mov [rsp + $60], r9

  test r14d, r14d
  jz @sse2_256_done

@sse2_256_block_loop:

  // ========== Phase 1: Message Schedule ==========

  mov rax, [rsp + $60]

  // SSE2 32-bit byte-swap for W[0..15]
  movdqu xmm0, oword [r13]
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4

  movdqu xmm1, oword [r13 + $10]
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqa xmm4, xmm1
  psrlw  xmm1, 8
  psllw  xmm4, 8
  por    xmm1, xmm4

  movdqu xmm2, oword [r13 + $20]
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  movdqa xmm4, xmm2
  psrlw  xmm2, 8
  psllw  xmm4, 8
  por    xmm2, xmm4

  movdqu xmm3, oword [r13 + $30]
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  movdqa xmm4, xmm3
  psrlw  xmm3, 8
  psllw  xmm4, 8
  por    xmm3, xmm4

  lea rbp, [rsp + $70]

  movdqa xmm4, xmm0
  movdqu xmm5, oword [rax]
  paddd  xmm4, xmm5
  movdqa oword [rbp], xmm4

  movdqa xmm4, xmm1
  movdqu xmm5, oword [rax + $10]
  paddd  xmm4, xmm5
  movdqa oword [rbp + $10], xmm4

  movdqa xmm4, xmm2
  movdqu xmm5, oword [rax + $20]
  paddd  xmm4, xmm5
  movdqa oword [rbp + $20], xmm4

  movdqa xmm4, xmm3
  movdqu xmm5, oword [rax + $30]
  paddd  xmm4, xmm5
  movdqa oword [rbp + $30], xmm4

  add rax, $40
  add rbp, $40
  mov ecx, 12

@sse2_256_expand_loop:

  // sigma0(W[t-15..t-12]) - replaces palignr xmm4, xmm0, 4
  movdqa xmm4, xmm0
  psrldq xmm4, 4
  movdqa xmm7, xmm1
  pslldq xmm7, 12
  por    xmm4, xmm7

  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 3
  psrld  xmm5, 7
  pslld  xmm6, 14
  pxor   xmm4, xmm5
  psrld  xmm5, 11
  pxor   xmm4, xmm6
  pslld  xmm6, 11
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6

  paddd  xmm0, xmm4

  // W[t-7..t-4] - replaces palignr xmm4, xmm2, 4
  movdqa xmm4, xmm2
  psrldq xmm4, 4
  movdqa xmm7, xmm3
  pslldq xmm7, 12
  por    xmm4, xmm7
  paddd  xmm0, xmm4

  // sigma1 phase 1: W[t-2..t-1]
  movdqa xmm4, xmm3
  psrldq xmm4, 8
  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 10
  psrld  xmm5, 17
  pslld  xmm6, 13
  pxor   xmm4, xmm5
  psrld  xmm5, 2
  pxor   xmm4, xmm6
  pslld  xmm6, 2
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6
  paddd  xmm0, xmm4

  // sigma1 phase 2: W[t..t+1]
  movdqa xmm4, xmm0
  pslldq xmm4, 8
  movdqa xmm5, xmm4
  movdqa xmm6, xmm4
  psrld  xmm4, 10
  psrld  xmm5, 17
  pslld  xmm6, 13
  pxor   xmm4, xmm5
  psrld  xmm5, 2
  pxor   xmm4, xmm6
  pslld  xmm6, 2
  pxor   xmm4, xmm5
  pxor   xmm4, xmm6
  paddd  xmm0, xmm4

  movdqu xmm4, oword [rax]
  paddd  xmm4, xmm0
  movdqa oword [rbp], xmm4

  movdqa xmm4, xmm0
  movdqa xmm0, xmm1
  movdqa xmm1, xmm2
  movdqa xmm2, xmm3
  movdqa xmm3, xmm4

  add rax, $10
  add rbp, $10
  dec ecx
  jnz @sse2_256_expand_loop

  // ========== Phase 2: 64 Compression Rounds ==========

  mov eax, [r12]
  mov ebx, [r12 + $04]
  mov ecx, [r12 + $08]
  mov edx, [r12 + $0C]
  mov r8d, [r12 + $10]
  mov r9d, [r12 + $14]
  mov r10d, [r12 + $18]
  mov r11d, [r12 + $1C]

  lea rbp, [rsp + $70]
  lea r15, [rsp + $70 + $100]

@sse2_256_round_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=r8d f=r9d g=r10d h=r11d
  mov esi, r8d
  mov edi, r8d
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, r9d
  xor edi, r10d
  and edi, r8d
  xor edi, r10d
  add esi, r11d
  add esi, edi
  add esi, [rbp]
  add edx, esi
  mov edi, eax
  mov r11d, eax
  ror edi, 2
  ror r11d, 13
  xor edi, r11d
  ror r11d, 9
  xor edi, r11d
  add esi, edi
  mov r11d, eax
  and r11d, ebx
  mov edi, eax
  xor edi, ebx
  and edi, ecx
  xor r11d, edi
  add r11d, esi

  // Round 1: a=r11d b=eax c=ebx d=ecx e=edx f=r8d g=r9d h=r10d
  mov esi, edx
  mov edi, edx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, r8d
  xor edi, r9d
  and edi, edx
  xor edi, r9d
  add esi, r10d
  add esi, edi
  add esi, [rbp + $04]
  add ecx, esi
  mov edi, r11d
  mov r10d, r11d
  ror edi, 2
  ror r10d, 13
  xor edi, r10d
  ror r10d, 9
  xor edi, r10d
  add esi, edi
  mov r10d, r11d
  and r10d, eax
  mov edi, r11d
  xor edi, eax
  and edi, ebx
  xor r10d, edi
  add r10d, esi

  // Round 2: a=r10d b=r11d c=eax d=ebx e=ecx f=edx g=r8d h=r9d
  mov esi, ecx
  mov edi, ecx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, edx
  xor edi, r8d
  and edi, ecx
  xor edi, r8d
  add esi, r9d
  add esi, edi
  add esi, [rbp + $08]
  add ebx, esi
  mov edi, r10d
  mov r9d, r10d
  ror edi, 2
  ror r9d, 13
  xor edi, r9d
  ror r9d, 9
  xor edi, r9d
  add esi, edi
  mov r9d, r10d
  and r9d, r11d
  mov edi, r10d
  xor edi, r11d
  and edi, eax
  xor r9d, edi
  add r9d, esi

  // Round 3: a=r9d b=r10d c=r11d d=eax e=ebx f=ecx g=edx h=r8d
  mov esi, ebx
  mov edi, ebx
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, ecx
  xor edi, edx
  and edi, ebx
  xor edi, edx
  add esi, r8d
  add esi, edi
  add esi, [rbp + $0C]
  add eax, esi
  mov edi, r9d
  mov r8d, r9d
  ror edi, 2
  ror r8d, 13
  xor edi, r8d
  ror r8d, 9
  xor edi, r8d
  add esi, edi
  mov r8d, r9d
  and r8d, r10d
  mov edi, r9d
  xor edi, r10d
  and edi, r11d
  xor r8d, edi
  add r8d, esi

  // Round 4: a=r8d b=r9d c=r10d d=r11d e=eax f=ebx g=ecx h=edx
  mov esi, eax
  mov edi, eax
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, ebx
  xor edi, ecx
  and edi, eax
  xor edi, ecx
  add esi, edx
  add esi, edi
  add esi, [rbp + $10]
  add r11d, esi
  mov edi, r8d
  mov edx, r8d
  ror edi, 2
  ror edx, 13
  xor edi, edx
  ror edx, 9
  xor edi, edx
  add esi, edi
  mov edx, r8d
  and edx, r9d
  mov edi, r8d
  xor edi, r9d
  and edi, r10d
  xor edx, edi
  add edx, esi

  // Round 5: a=edx b=r8d c=r9d d=r10d e=r11d f=eax g=ebx h=ecx
  mov esi, r11d
  mov edi, r11d
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, eax
  xor edi, ebx
  and edi, r11d
  xor edi, ebx
  add esi, ecx
  add esi, edi
  add esi, [rbp + $14]
  add r10d, esi
  mov edi, edx
  mov ecx, edx
  ror edi, 2
  ror ecx, 13
  xor edi, ecx
  ror ecx, 9
  xor edi, ecx
  add esi, edi
  mov ecx, edx
  and ecx, r8d
  mov edi, edx
  xor edi, r8d
  and edi, r9d
  xor ecx, edi
  add ecx, esi

  // Round 6: a=ecx b=edx c=r8d d=r9d e=r10d f=r11d g=eax h=ebx
  mov esi, r10d
  mov edi, r10d
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, r11d
  xor edi, eax
  and edi, r10d
  xor edi, eax
  add esi, ebx
  add esi, edi
  add esi, [rbp + $18]
  add r9d, esi
  mov edi, ecx
  mov ebx, ecx
  ror edi, 2
  ror ebx, 13
  xor edi, ebx
  ror ebx, 9
  xor edi, ebx
  add esi, edi
  mov ebx, ecx
  and ebx, edx
  mov edi, ecx
  xor edi, edx
  and edi, r8d
  xor ebx, edi
  add ebx, esi

  // Round 7: a=ebx b=ecx c=edx d=r8d e=r9d f=r10d g=r11d h=eax
  mov esi, r9d
  mov edi, r9d
  ror esi, 6
  ror edi, 11
  xor esi, edi
  ror edi, 14
  xor esi, edi
  mov edi, r10d
  xor edi, r11d
  and edi, r9d
  xor edi, r11d
  add esi, eax
  add esi, edi
  add esi, [rbp + $1C]
  add r8d, esi
  mov edi, ebx
  mov eax, ebx
  ror edi, 2
  ror eax, 13
  xor edi, eax
  ror eax, 9
  xor edi, eax
  add esi, edi
  mov eax, ebx
  and eax, ecx
  mov edi, ebx
  xor edi, ecx
  and edi, edx
  xor eax, edi
  add eax, esi

  add rbp, $20
  cmp rbp, r15
  jb @sse2_256_round_loop

  // Add round results to state
  add [r12], eax
  add [r12 + $04], ebx
  add [r12 + $08], ecx
  add [r12 + $0C], edx
  add [r12 + $10], r8d
  add [r12 + $14], r9d
  add [r12 + $18], r10d
  add [r12 + $1C], r11d

  add r13, $40
  dec r14d
  jnz @sse2_256_block_loop

@sse2_256_done:

  mov rbx, [rsp + $20]
  mov rbp, [rsp + $28]
  mov r12, [rsp + $40]
  mov r13, [rsp + $48]
  mov r14, [rsp + $50]
  mov r15, [rsp + $58]
{$IFDEF MSWINDOWS}
  mov rdi, [rsp + $30]
  mov rsi, [rsp + $38]
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
{$ENDIF}
  add rsp, 376
