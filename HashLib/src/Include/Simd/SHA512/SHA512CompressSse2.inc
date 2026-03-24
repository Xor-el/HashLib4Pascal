// SHA-512 SSE2 implementation.
// Based on SSSE3 implementation (see SHA512CompressSsse3.inc).
// Same as SSSE3 but byte-swap uses SSE2 emulation (pshuflw/pshufhw + psrlw/psllw/por)
// instead of SSSE3 pshufb. Message schedule expansion and compression use GPR only.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K512 ptr.
// K512 layout: 80 UInt64 round constants (640 bytes), BSWAP64 mask unused.
// Uses xmm0, xmm4, all GPR.
//
// Stack layout (sub rsp, 1016): same as SSSE3 version (xmm6-xmm7 save slots unused)

  sub rsp, 1016

{$IFDEF MSWINDOWS}
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
  jz @sse2_512_done

@sse2_512_block_loop:

  // ========== Phase 1: Load, byte-swap, expand message schedule ==========

  mov rax, [rsp + $60]

  lea rbp, [rsp + $70]
  lea r15, [rsp + $2F0]

  // SSE2 64-bit byte-swap: reverse bytes within each qword
  // pshuflw/pshufhw $1B reverses 16-bit words, then psrlw/psllw/por swaps bytes in words

  movdqu xmm0, oword [r13]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15], xmm0
  movdqu xmm4, oword [rax]
  paddq  xmm4, xmm0
  movdqa oword [rbp], xmm4

  movdqu xmm0, oword [r13 + $10]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $10], xmm0
  movdqu xmm4, oword [rax + $10]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $10], xmm4

  movdqu xmm0, oword [r13 + $20]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $20], xmm0
  movdqu xmm4, oword [rax + $20]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $20], xmm4

  movdqu xmm0, oword [r13 + $30]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $30], xmm0
  movdqu xmm4, oword [rax + $30]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $30], xmm4

  movdqu xmm0, oword [r13 + $40]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $40], xmm0
  movdqu xmm4, oword [rax + $40]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $40], xmm4

  movdqu xmm0, oword [r13 + $50]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $50], xmm0
  movdqu xmm4, oword [rax + $50]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $50], xmm4

  movdqu xmm0, oword [r13 + $60]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $60], xmm0
  movdqu xmm4, oword [rax + $60]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $60], xmm4

  movdqu xmm0, oword [r13 + $70]
  pshuflw xmm0, xmm0, $1B
  pshufhw xmm0, xmm0, $1B
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15 + $70], xmm0
  movdqu xmm4, oword [rax + $70]
  paddq  xmm4, xmm0
  movdqa oword [rbp + $70], xmm4

  // Expand W[16..79] using GPR with circular buffer (identical to SSSE3)

  mov ecx, 16

@sse2_512_expand_loop:
  mov edx, ecx
  sub edx, 2
  and edx, 15
  mov rsi, [r15 + rdx*8]
  mov rdi, rsi
  ror rdi, 19
  mov r8, rsi
  ror r8, 61
  xor rdi, r8
  shr rsi, 6
  xor rdi, rsi

  mov edx, ecx
  sub edx, 7
  and edx, 15
  add rdi, [r15 + rdx*8]

  mov edx, ecx
  sub edx, 15
  and edx, 15
  mov rsi, [r15 + rdx*8]
  mov r8, rsi
  ror r8, 1
  mov r9, rsi
  ror r9, 8
  xor r8, r9
  shr rsi, 7
  xor r8, rsi
  add rdi, r8

  mov edx, ecx
  sub edx, 16
  and edx, 15
  add rdi, [r15 + rdx*8]

  mov edx, ecx
  and edx, 15
  mov [r15 + rdx*8], rdi

  mov rsi, [rax + rcx*8]
  add rsi, rdi
  mov [rbp + rcx*8], rsi

  inc ecx
  cmp ecx, 80
  jb @sse2_512_expand_loop

  // ========== Phase 2: 80 Compression Rounds (identical to SSSE3) ==========

  mov rax, [r12]
  mov rbx, [r12 + $08]
  mov rcx, [r12 + $10]
  mov rdx, [r12 + $18]
  mov r8, [r12 + $20]
  mov r9, [r12 + $28]
  mov r10, [r12 + $30]
  mov r11, [r12 + $38]

  lea r15, [rbp + $280]

@sse2_512_round_loop:

  // Round 0: a=rax b=rbx c=rcx d=rdx e=r8 f=r9 g=r10 h=r11
  mov rsi, r8
  mov rdi, r8
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, r9
  xor rdi, r10
  and rdi, r8
  xor rdi, r10
  add rsi, r11
  add rsi, rdi
  add rsi, [rbp]
  add rdx, rsi
  mov rdi, rax
  mov r11, rax
  ror rdi, 28
  ror r11, 34
  xor rdi, r11
  ror r11, 5
  xor rdi, r11
  add rsi, rdi
  mov r11, rax
  and r11, rbx
  mov rdi, rax
  xor rdi, rbx
  and rdi, rcx
  xor r11, rdi
  add r11, rsi

  // Round 1: a=r11 b=rax c=rbx d=rcx e=rdx f=r8 g=r9 h=r10
  mov rsi, rdx
  mov rdi, rdx
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, r8
  xor rdi, r9
  and rdi, rdx
  xor rdi, r9
  add rsi, r10
  add rsi, rdi
  add rsi, [rbp + $08]
  add rcx, rsi
  mov rdi, r11
  mov r10, r11
  ror rdi, 28
  ror r10, 34
  xor rdi, r10
  ror r10, 5
  xor rdi, r10
  add rsi, rdi
  mov r10, r11
  and r10, rax
  mov rdi, r11
  xor rdi, rax
  and rdi, rbx
  xor r10, rdi
  add r10, rsi

  // Round 2: a=r10 b=r11 c=rax d=rbx e=rcx f=rdx g=r8 h=r9
  mov rsi, rcx
  mov rdi, rcx
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, rdx
  xor rdi, r8
  and rdi, rcx
  xor rdi, r8
  add rsi, r9
  add rsi, rdi
  add rsi, [rbp + $10]
  add rbx, rsi
  mov rdi, r10
  mov r9, r10
  ror rdi, 28
  ror r9, 34
  xor rdi, r9
  ror r9, 5
  xor rdi, r9
  add rsi, rdi
  mov r9, r10
  and r9, r11
  mov rdi, r10
  xor rdi, r11
  and rdi, rax
  xor r9, rdi
  add r9, rsi

  // Round 3: a=r9 b=r10 c=r11 d=rax e=rbx f=rcx g=rdx h=r8
  mov rsi, rbx
  mov rdi, rbx
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, rcx
  xor rdi, rdx
  and rdi, rbx
  xor rdi, rdx
  add rsi, r8
  add rsi, rdi
  add rsi, [rbp + $18]
  add rax, rsi
  mov rdi, r9
  mov r8, r9
  ror rdi, 28
  ror r8, 34
  xor rdi, r8
  ror r8, 5
  xor rdi, r8
  add rsi, rdi
  mov r8, r9
  and r8, r10
  mov rdi, r9
  xor rdi, r10
  and rdi, r11
  xor r8, rdi
  add r8, rsi

  // Round 4: a=r8 b=r9 c=r10 d=r11 e=rax f=rbx g=rcx h=rdx
  mov rsi, rax
  mov rdi, rax
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, rbx
  xor rdi, rcx
  and rdi, rax
  xor rdi, rcx
  add rsi, rdx
  add rsi, rdi
  add rsi, [rbp + $20]
  add r11, rsi
  mov rdi, r8
  mov rdx, r8
  ror rdi, 28
  ror rdx, 34
  xor rdi, rdx
  ror rdx, 5
  xor rdi, rdx
  add rsi, rdi
  mov rdx, r8
  and rdx, r9
  mov rdi, r8
  xor rdi, r9
  and rdi, r10
  xor rdx, rdi
  add rdx, rsi

  // Round 5: a=rdx b=r8 c=r9 d=r10 e=r11 f=rax g=rbx h=rcx
  mov rsi, r11
  mov rdi, r11
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, rax
  xor rdi, rbx
  and rdi, r11
  xor rdi, rbx
  add rsi, rcx
  add rsi, rdi
  add rsi, [rbp + $28]
  add r10, rsi
  mov rdi, rdx
  mov rcx, rdx
  ror rdi, 28
  ror rcx, 34
  xor rdi, rcx
  ror rcx, 5
  xor rdi, rcx
  add rsi, rdi
  mov rcx, rdx
  and rcx, r8
  mov rdi, rdx
  xor rdi, r8
  and rdi, r9
  xor rcx, rdi
  add rcx, rsi

  // Round 6: a=rcx b=rdx c=r8 d=r9 e=r10 f=r11 g=rax h=rbx
  mov rsi, r10
  mov rdi, r10
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, r11
  xor rdi, rax
  and rdi, r10
  xor rdi, rax
  add rsi, rbx
  add rsi, rdi
  add rsi, [rbp + $30]
  add r9, rsi
  mov rdi, rcx
  mov rbx, rcx
  ror rdi, 28
  ror rbx, 34
  xor rdi, rbx
  ror rbx, 5
  xor rdi, rbx
  add rsi, rdi
  mov rbx, rcx
  and rbx, rdx
  mov rdi, rcx
  xor rdi, rdx
  and rdi, r8
  xor rbx, rdi
  add rbx, rsi

  // Round 7: a=rbx b=rcx c=rdx d=r8 e=r9 f=r10 g=r11 h=rax
  mov rsi, r9
  mov rdi, r9
  ror rsi, 14
  ror rdi, 18
  xor rsi, rdi
  ror rdi, 23
  xor rsi, rdi
  mov rdi, r10
  xor rdi, r11
  and rdi, r9
  xor rdi, r11
  add rsi, rax
  add rsi, rdi
  add rsi, [rbp + $38]
  add r8, rsi
  mov rdi, rbx
  mov rax, rbx
  ror rdi, 28
  ror rax, 34
  xor rdi, rax
  ror rax, 5
  xor rdi, rax
  add rsi, rdi
  mov rax, rbx
  and rax, rcx
  mov rdi, rbx
  xor rdi, rcx
  and rdi, rdx
  xor rax, rdi
  add rax, rsi

  add rbp, $40
  cmp rbp, r15
  jb @sse2_512_round_loop

  // Add round results to state
  add [r12], rax
  add [r12 + $08], rbx
  add [r12 + $10], rcx
  add [r12 + $18], rdx
  add [r12 + $20], r8
  add [r12 + $28], r9
  add [r12 + $30], r10
  add [r12 + $38], r11

  add r13, $80
  dec r14d
  jnz @sse2_512_block_loop

@sse2_512_done:

  mov rbx, [rsp + $20]
  mov rbp, [rsp + $28]
  mov r12, [rsp + $40]
  mov r13, [rsp + $48]
  mov r14, [rsp + $50]
  mov r15, [rsp + $58]
{$IFDEF MSWINDOWS}
  mov rdi, [rsp + $30]
  mov rsi, [rsp + $38]
{$ENDIF}
  add rsp, 1016
