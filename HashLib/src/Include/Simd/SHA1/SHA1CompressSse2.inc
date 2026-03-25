// SHA-1 SSE2 implementation with SIMD message schedule.
// Based on SSSE3 implementation (see SHA1CompressSsse3.inc).
// Same algorithm as SSSE3 version but byte-swap uses SSE2 emulation
// (pshuflw/pshufhw + psrlw/psllw/por) instead of SSSE3 pshufb.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K_SHA1 ptr.
// K_SHA1 layout: K_00_19 (16 bytes) at offset 0, K_20_39 at 16, K_40_59 at 32,
//   K_60_79 at 48, BSWAP32 mask (16 bytes) at offset 64.
// Uses xmm0-xmm6, all GPR.
//
// Two phases per block:
//   Phase 1 (SIMD): SSE2 byte-swap W[0..15], then expand W[16..79]
//     using vectorized message schedule (same as SSSE3).
//   Phase 2 (GPR): 80 compression rounds with 5-round unrolling
//
// Non-volatile register saves:
//   Windows: xmm6, rbx, rbp, rdi, rsi, r12-r15
//   System V: rbx, rbp, r12-r15
//
// Stack layout (sub rsp, 424):
//   [rsp +   0.. 15]: xmm6 save (Windows only)
//   [rsp +  16.. 23]: rbx save
//   [rsp +  24.. 31]: rbp save
//   [rsp +  32.. 39]: rdi save (Windows only)
//   [rsp +  40.. 47]: rsi save (Windows only)
//   [rsp +  48.. 55]: r12 save
//   [rsp +  56.. 63]: r13 save
//   [rsp +  64.. 71]: r14 save
//   [rsp +  72.. 79]: r15 save
//   [rsp +  80.. 87]: padding
//   [rsp +  88.. 95]: padding
//   [rsp +  96..415]: W buffer (320 bytes = 80 x 4, 16-byte aligned)

  sub rsp, 424

{$IFDEF MSWINDOWS}
  movdqu oword [rsp], xmm6
  mov [rsp + $20], rdi
  mov [rsp + $28], rsi
{$ENDIF}
  mov [rsp + $10], rbx
  mov [rsp + $18], rbp
  mov [rsp + $30], r12
  mov [rsp + $38], r13
  mov [rsp + $40], r14
  mov [rsp + $48], r15

  mov r12, rcx
  mov r13, rdx
  mov r14d, r8d

  test r14d, r14d
  jz @sse2_sha1_done

@sse2_sha1_block_loop:

  // ========== Phase 1: SIMD message schedule ==========

  lea r15, [rsp + $60]

  // SSE2 32-bit byte-swap: pshuflw/pshufhw swap 16-bit words, then swap bytes within words
  movdqu xmm0, oword [r13]
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqa oword [r15], xmm0

  movdqu xmm1, oword [r13 + $10]
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqa xmm4, xmm1
  psrlw  xmm1, 8
  psllw  xmm4, 8
  por    xmm1, xmm4
  movdqa oword [r15 + $10], xmm1

  movdqu xmm2, oword [r13 + $20]
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  movdqa xmm4, xmm2
  psrlw  xmm2, 8
  psllw  xmm4, 8
  por    xmm2, xmm4
  movdqa oword [r15 + $20], xmm2

  movdqu xmm3, oword [r13 + $30]
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  movdqa xmm4, xmm3
  psrlw  xmm3, 8
  psllw  xmm4, 8
  por    xmm3, xmm4
  movdqa oword [r15 + $30], xmm3

  // --- W[16..31]: ROL1 formula with cross-lane fix ---

  lea rbp, [r15 + $40]
  lea r10, [r15 + $80]

@sse2_sha1_expand_16_31:
  movdqa xmm0, oword [rbp - $40]
  movdqa xmm1, oword [rbp - $30]
  movdqa xmm2, oword [rbp - $20]
  movdqa xmm3, oword [rbp - $10]

  pshufd xmm4, xmm0, $EE
  punpcklqdq xmm4, xmm1

  movdqa xmm5, xmm3
  psrldq xmm5, 4

  pxor xmm4, xmm0
  pxor xmm5, xmm2
  pxor xmm4, xmm5

  movdqa xmm6, xmm4
  movdqa xmm5, xmm4
  pslldq xmm6, 12
  paddd  xmm4, xmm4
  psrld  xmm5, 31
  por    xmm4, xmm5

  movdqa xmm5, xmm6
  psrld  xmm6, 30
  pslld  xmm5, 2
  pxor   xmm4, xmm6
  pxor   xmm4, xmm5

  movdqa oword [rbp], xmm4
  add rbp, $10
  cmp rbp, r10
  jb @sse2_sha1_expand_16_31

  // --- W[32..79]: ROL2 expanded recurrence ---

  lea r10, [r15 + $140]

@sse2_sha1_expand_32_79:
  movdqa xmm0, oword [rbp - $80]
  movdqa xmm1, oword [rbp - $40]
  movdqa xmm2, oword [rbp - $20]
  movdqa xmm3, oword [rbp - $10]
  movdqa xmm4, oword [rbp - $70]

  pxor xmm0, xmm1

  pshufd xmm5, xmm2, $EE
  punpcklqdq xmm5, xmm3

  pxor xmm0, xmm4
  pxor xmm0, xmm5

  movdqa xmm5, xmm0
  pslld  xmm0, 2
  psrld  xmm5, 30
  por    xmm0, xmm5

  movdqa oword [rbp], xmm0
  add rbp, $10
  cmp rbp, r10
  jb @sse2_sha1_expand_32_79

  // ========== Phase 2: 80 Compression Rounds ==========

  mov eax, [r12]
  mov ebx, [r12 + $04]
  mov ecx, [r12 + $08]
  mov edx, [r12 + $0C]
  mov r8d, [r12 + $10]

  lea rbp, [rsp + $60]

  // ---------- Rounds 0-19: Ch, K = $5A827999 ----------

  mov r9d, 4

@sse2_sha1_ch_loop:

  mov esi, ecx
  xor esi, edx
  and esi, ebx
  xor esi, edx
  mov edi, eax
  rol edi, 5
  add r8d, [rbp]
  add r8d, edi
  add r8d, esi
  add r8d, $5A827999
  rol ebx, 30

  mov esi, ebx
  xor esi, ecx
  and esi, eax
  xor esi, ecx
  mov edi, r8d
  rol edi, 5
  add edx, [rbp + $04]
  add edx, edi
  add edx, esi
  add edx, $5A827999
  rol eax, 30

  mov esi, eax
  xor esi, ebx
  and esi, r8d
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, [rbp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $5A827999
  rol r8d, 30

  mov esi, r8d
  xor esi, eax
  and esi, edx
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, [rbp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $5A827999
  rol edx, 30

  mov esi, edx
  xor esi, r8d
  and esi, ecx
  xor esi, r8d
  mov edi, ebx
  rol edi, 5
  add eax, [rbp + $10]
  add eax, edi
  add eax, esi
  add eax, $5A827999
  rol ecx, 30

  add rbp, $14
  dec r9d
  jnz @sse2_sha1_ch_loop

  // ---------- Rounds 20-39: Parity, K = $6ED9EBA1 ----------

  mov r9d, 4

@sse2_sha1_par1_loop:

  mov esi, ebx
  xor esi, ecx
  xor esi, edx
  mov edi, eax
  rol edi, 5
  add r8d, [rbp]
  add r8d, edi
  add r8d, esi
  add r8d, $6ED9EBA1
  rol ebx, 30

  mov esi, eax
  xor esi, ebx
  xor esi, ecx
  mov edi, r8d
  rol edi, 5
  add edx, [rbp + $04]
  add edx, edi
  add edx, esi
  add edx, $6ED9EBA1
  rol eax, 30

  mov esi, r8d
  xor esi, eax
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, [rbp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $6ED9EBA1
  rol r8d, 30

  mov esi, edx
  xor esi, r8d
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, [rbp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $6ED9EBA1
  rol edx, 30

  mov esi, ecx
  xor esi, edx
  xor esi, r8d
  mov edi, ebx
  rol edi, 5
  add eax, [rbp + $10]
  add eax, edi
  add eax, esi
  add eax, $6ED9EBA1
  rol ecx, 30

  add rbp, $14
  dec r9d
  jnz @sse2_sha1_par1_loop

  // ---------- Rounds 40-59: Maj, K = $8F1BBCDC ----------

  mov r9d, 4

@sse2_sha1_maj_loop:

  mov esi, ebx
  or  esi, ecx
  and esi, edx
  mov edi, ebx
  and edi, ecx
  or  esi, edi
  mov edi, eax
  rol edi, 5
  add r8d, [rbp]
  add r8d, edi
  add r8d, esi
  add r8d, $8F1BBCDC
  rol ebx, 30

  mov esi, eax
  or  esi, ebx
  and esi, ecx
  mov edi, eax
  and edi, ebx
  or  esi, edi
  mov edi, r8d
  rol edi, 5
  add edx, [rbp + $04]
  add edx, edi
  add edx, esi
  add edx, $8F1BBCDC
  rol eax, 30

  mov esi, r8d
  or  esi, eax
  and esi, ebx
  mov edi, r8d
  and edi, eax
  or  esi, edi
  mov edi, edx
  rol edi, 5
  add ecx, [rbp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $8F1BBCDC
  rol r8d, 30

  mov esi, edx
  or  esi, r8d
  and esi, eax
  mov edi, edx
  and edi, r8d
  or  esi, edi
  mov edi, ecx
  rol edi, 5
  add ebx, [rbp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $8F1BBCDC
  rol edx, 30

  mov esi, ecx
  or  esi, edx
  and esi, r8d
  mov edi, ecx
  and edi, edx
  or  esi, edi
  mov edi, ebx
  rol edi, 5
  add eax, [rbp + $10]
  add eax, edi
  add eax, esi
  add eax, $8F1BBCDC
  rol ecx, 30

  add rbp, $14
  dec r9d
  jnz @sse2_sha1_maj_loop

  // ---------- Rounds 60-79: Parity, K = $CA62C1D6 ----------

  mov r9d, 4

@sse2_sha1_par2_loop:

  mov esi, ebx
  xor esi, ecx
  xor esi, edx
  mov edi, eax
  rol edi, 5
  add r8d, [rbp]
  add r8d, edi
  add r8d, esi
  add r8d, $CA62C1D6
  rol ebx, 30

  mov esi, eax
  xor esi, ebx
  xor esi, ecx
  mov edi, r8d
  rol edi, 5
  add edx, [rbp + $04]
  add edx, edi
  add edx, esi
  add edx, $CA62C1D6
  rol eax, 30

  mov esi, r8d
  xor esi, eax
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, [rbp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $CA62C1D6
  rol r8d, 30

  mov esi, edx
  xor esi, r8d
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, [rbp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $CA62C1D6
  rol edx, 30

  mov esi, ecx
  xor esi, edx
  xor esi, r8d
  mov edi, ebx
  rol edi, 5
  add eax, [rbp + $10]
  add eax, edi
  add eax, esi
  add eax, $CA62C1D6
  rol ecx, 30

  add rbp, $14
  dec r9d
  jnz @sse2_sha1_par2_loop

  // Add round results to state
  add [r12], eax
  add [r12 + $04], ebx
  add [r12 + $08], ecx
  add [r12 + $0C], edx
  add [r12 + $10], r8d

  add r13, $40
  dec r14d
  jnz @sse2_sha1_block_loop

@sse2_sha1_done:

  mov rbx, [rsp + $10]
  mov rbp, [rsp + $18]
  mov r12, [rsp + $30]
  mov r13, [rsp + $38]
  mov r14, [rsp + $40]
  mov r15, [rsp + $48]
{$IFDEF MSWINDOWS}
  mov rdi, [rsp + $20]
  mov rsi, [rsp + $28]
  movdqu xmm6, oword [rsp]
{$ENDIF}
  add rsp, 424
