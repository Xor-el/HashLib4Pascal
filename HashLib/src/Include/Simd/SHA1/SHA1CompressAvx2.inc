// SHA-1 AVX2 (VEX-128) implementation.
// Same algorithm as SSSE3 but using VEX-encoded instructions for the SIMD byte-swap phase,
// avoiding SSE/AVX transition penalties.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K_SHA1 ptr.
// K_SHA1 layout: BSWAP32 mask (16 bytes) at offset 0.
//
// Three phases per block:
//   Phase 1 (VEX-128 SIMD): Byte-swap W[0..15] using vpshufb, store to stack
//   Phase 2 (GPR): Expand W[16..79] using ROL1 expansion
//   Phase 3 (GPR): 80 compression rounds (identical to SSSE3)
//
// Stack layout (sub rsp, 440): same as SSSE3 version

  sub rsp, 440

{$IFDEF MSWINDOWS}
  db $C5, $FA, $7F, $34, $24                    // vmovdqu oword [rsp], xmm6
  db $C5, $FA, $7F, $7C, $24, $10               // vmovdqu oword [rsp + $10], xmm7
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
  jz @avx2_sha1_done

@avx2_sha1_block_loop:

  // ========== Phase 1: VEX-128 byte-swap W[0..15] ==========

  mov rax, [rsp + $60]
  db $C5, $FA, $6F, $38                         // vmovdqu xmm7, oword [rax]

  lea r15, [rsp + $70]

  db $C4, $C1, $7A, $6F, $45, $00               // vmovdqu xmm0, oword [r13]
  db $C4, $E2, $79, $00, $C7                    // vpshufb xmm0, xmm0, xmm7
  db $C4, $C1, $79, $7F, $07                    // vmovdqa oword [r15], xmm0

  db $C4, $C1, $7A, $6F, $45, $10               // vmovdqu xmm0, oword [r13 + $10]
  db $C4, $E2, $79, $00, $C7                    // vpshufb xmm0, xmm0, xmm7
  db $C4, $C1, $79, $7F, $47, $10               // vmovdqa oword [r15 + $10], xmm0

  db $C4, $C1, $7A, $6F, $45, $20               // vmovdqu xmm0, oword [r13 + $20]
  db $C4, $E2, $79, $00, $C7                    // vpshufb xmm0, xmm0, xmm7
  db $C4, $C1, $79, $7F, $47, $20               // vmovdqa oword [r15 + $20], xmm0

  db $C4, $C1, $7A, $6F, $45, $30               // vmovdqu xmm0, oword [r13 + $30]
  db $C4, $E2, $79, $00, $C7                    // vpshufb xmm0, xmm0, xmm7
  db $C4, $C1, $79, $7F, $47, $30               // vmovdqa oword [r15 + $30], xmm0

  // ========== Phase 2: GPR expand W[16..79] ==========

  lea rbp, [r15 + $40]
  lea r10, [r15 + $140]

@avx2_sha1_expand:
  mov eax, [rbp - 12]
  xor eax, [rbp - 32]
  xor eax, [rbp - 56]
  xor eax, [rbp - 64]
  rol eax, 1
  mov [rbp], eax
  add rbp, 4
  cmp rbp, r10
  jb @avx2_sha1_expand

  // ========== Phase 3: 80 Compression Rounds (GPR, identical to SSSE3) ==========

  mov eax, [r12]
  mov ebx, [r12 + $04]
  mov ecx, [r12 + $08]
  mov edx, [r12 + $0C]
  mov r8d, [r12 + $10]

  lea rbp, [rsp + $70]

  // ---------- Rounds 0-19: Ch, K = $5A827999 ----------

  mov r9d, 4

@avx2_sha1_ch_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=r8d
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

  // Round 1: a=r8d b=eax c=ebx d=ecx e=edx
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

  // Round 2: a=edx b=r8d c=eax d=ebx e=ecx
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

  // Round 3: a=ecx b=edx c=r8d d=eax e=ebx
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

  // Round 4: a=ebx b=ecx c=edx d=r8d e=eax
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
  jnz @avx2_sha1_ch_loop

  // ---------- Rounds 20-39: Parity, K = $6ED9EBA1 ----------

  mov r9d, 4

@avx2_sha1_par1_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=r8d
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

  // Round 1: a=r8d b=eax c=ebx d=ecx e=edx
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

  // Round 2: a=edx b=r8d c=eax d=ebx e=ecx
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

  // Round 3: a=ecx b=edx c=r8d d=eax e=ebx
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

  // Round 4: a=ebx b=ecx c=edx d=r8d e=eax
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
  jnz @avx2_sha1_par1_loop

  // ---------- Rounds 40-59: Maj, K = $8F1BBCDC ----------

  mov r9d, 4

@avx2_sha1_maj_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=r8d
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

  // Round 1: a=r8d b=eax c=ebx d=ecx e=edx
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

  // Round 2: a=edx b=r8d c=eax d=ebx e=ecx
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

  // Round 3: a=ecx b=edx c=r8d d=eax e=ebx
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

  // Round 4: a=ebx b=ecx c=edx d=r8d e=eax
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
  jnz @avx2_sha1_maj_loop

  // ---------- Rounds 60-79: Parity, K = $CA62C1D6 ----------

  mov r9d, 4

@avx2_sha1_par2_loop:

  // Round 0: a=eax b=ebx c=ecx d=edx e=r8d
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

  // Round 1: a=r8d b=eax c=ebx d=ecx e=edx
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

  // Round 2: a=edx b=r8d c=eax d=ebx e=ecx
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

  // Round 3: a=ecx b=edx c=r8d d=eax e=ebx
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

  // Round 4: a=ebx b=ecx c=edx d=r8d e=eax
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
  jnz @avx2_sha1_par2_loop

  // Add round results to state
  add [r12], eax
  add [r12 + $04], ebx
  add [r12 + $08], ecx
  add [r12 + $0C], edx
  add [r12 + $10], r8d

  add r13, $40
  dec r14d
  jnz @avx2_sha1_block_loop

@avx2_sha1_done:

  mov rbx, [rsp + $20]
  mov rbp, [rsp + $28]
  mov r12, [rsp + $40]
  mov r13, [rsp + $48]
  mov r14, [rsp + $50]
  mov r15, [rsp + $58]
{$IFDEF MSWINDOWS}
  mov rdi, [rsp + $30]
  mov rsi, [rsp + $38]
  db $C5, $FA, $6F, $34, $24                    // vmovdqu xmm6, oword [rsp]
  db $C5, $FA, $6F, $7C, $24, $10               // vmovdqu xmm7, oword [rsp + $10]
{$ENDIF}
  add rsp, 440

  db $C5, $F8, $77                              // vzeroupper
