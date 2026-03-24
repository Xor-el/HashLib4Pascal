// SHA-1 SSSE3 implementation.
// Expects MS x64 ABI: rcx = state ptr, rdx = data ptr, r8d = numblocks, r9 = K_SHA1 ptr.
// K_SHA1 layout: BSWAP32 mask (16 bytes) at offset 0.
// Uses xmm0, xmm7 (SIMD byte-swap only), all GPR.
//
// Three phases per block:
//   Phase 1 (SIMD): Byte-swap W[0..15] using SSSE3 pshufb, store to stack
//   Phase 2 (GPR): Expand W[16..79] using ROL1(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16])
//   Phase 3 (GPR): 80 compression rounds with 5-round unrolling and implicit register renaming
//
// Non-volatile register saves:
//   Windows: xmm6-xmm7, rbx, rbp, rdi, rsi, r12-r15
//   System V: rbx, rbp, r12-r15
//
// Stack layout (sub rsp, 440):
//   [rsp +   0.. 15]: xmm6 save (Windows only)
//   [rsp +  16.. 31]: xmm7 save (Windows only)
//   [rsp +  32.. 39]: rbx save
//   [rsp +  40.. 47]: rbp save
//   [rsp +  48.. 55]: rdi save (Windows only)
//   [rsp +  56.. 63]: rsi save (Windows only)
//   [rsp +  64.. 71]: r12 save
//   [rsp +  72.. 79]: r13 save
//   [rsp +  80.. 87]: r14 save
//   [rsp +  88.. 95]: r15 save
//   [rsp +  96..103]: K_SHA1 ptr save
//   [rsp + 104..111]: padding
//   [rsp + 112..431]: W buffer (320 bytes = 80 x 4, 16-byte aligned)

  sub rsp, 440

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
  jz @ssse3_sha1_done

@ssse3_sha1_block_loop:

  // ========== Phase 1: SSSE3 byte-swap W[0..15] ==========

  mov rax, [rsp + $60]
  movdqu xmm7, oword [rax]

  lea r15, [rsp + $70]

  movdqu xmm0, oword [r13]
  pshufb xmm0, xmm7
  movdqa oword [r15], xmm0

  movdqu xmm0, oword [r13 + $10]
  pshufb xmm0, xmm7
  movdqa oword [r15 + $10], xmm0

  movdqu xmm0, oword [r13 + $20]
  pshufb xmm0, xmm7
  movdqa oword [r15 + $20], xmm0

  movdqu xmm0, oword [r13 + $30]
  pshufb xmm0, xmm7
  movdqa oword [r15 + $30], xmm0

  // ========== Phase 2: GPR expand W[16..79] ==========

  lea rbp, [r15 + $40]
  lea r10, [r15 + $140]

@ssse3_sha1_expand:
  mov eax, [rbp - 12]
  xor eax, [rbp - 32]
  xor eax, [rbp - 56]
  xor eax, [rbp - 64]
  rol eax, 1
  mov [rbp], eax
  add rbp, 4
  cmp rbp, r10
  jb @ssse3_sha1_expand

  // ========== Phase 3: 80 Compression Rounds ==========

  mov eax, [r12]
  mov ebx, [r12 + $04]
  mov ecx, [r12 + $08]
  mov edx, [r12 + $0C]
  mov r8d, [r12 + $10]

  lea rbp, [rsp + $70]

  // ---------- Rounds 0-19: Ch, K = $5A827999 ----------
  // f(b,c,d) = d XOR (b AND (c XOR d))

  mov r9d, 4

@ssse3_sha1_ch_loop:

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

  // After 5 rounds: a=eax b=ebx c=ecx d=edx e=r8d (back to original assignment)
  add rbp, $14
  dec r9d
  jnz @ssse3_sha1_ch_loop

  // ---------- Rounds 20-39: Parity, K = $6ED9EBA1 ----------
  // f(b,c,d) = b XOR c XOR d

  mov r9d, 4

@ssse3_sha1_par1_loop:

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
  jnz @ssse3_sha1_par1_loop

  // ---------- Rounds 40-59: Maj, K = $8F1BBCDC ----------
  // f(b,c,d) = (b AND c) OR (d AND (b OR c))

  mov r9d, 4

@ssse3_sha1_maj_loop:

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
  jnz @ssse3_sha1_maj_loop

  // ---------- Rounds 60-79: Parity, K = $CA62C1D6 ----------
  // f(b,c,d) = b XOR c XOR d

  mov r9d, 4

@ssse3_sha1_par2_loop:

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
  jnz @ssse3_sha1_par2_loop

  // Add round results to state
  add [r12], eax
  add [r12 + $04], ebx
  add [r12 + $08], ecx
  add [r12 + $0C], edx
  add [r12 + $10], r8d

  add r13, $40
  dec r14d
  jnz @ssse3_sha1_block_loop

@ssse3_sha1_done:

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
  add rsp, 440
