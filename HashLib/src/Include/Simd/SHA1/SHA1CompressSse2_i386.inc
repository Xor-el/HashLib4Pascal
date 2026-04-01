// SHA-1 SSE2 implementation with SIMD message schedule.
// Based on SSSE3 implementation (see SHA1CompressSsse3_x86_64.inc).
// Same algorithm as SSSE3 version but byte-swap uses SSE2 emulation
//   (pshuflw/pshufhw + psrlw/psllw/por) instead of SSSE3 pshufb.
// IA-32: after SimdProc3Begin_i386 — ebx = state, esi = data, edi = numblocks
//   (parallel to MS x64 ABI: rcx, rdx, r8d; K constants are inlined here — x64 SSE2 passes K_SHA1 via r9).
// Uses xmm0–xmm6. Non-volatile xmm6 saved/restored on Windows (MSWINDOWS).
//
// Two phases per block:
//   Phase 1 (SIMD): SSE2 byte-swap W[0..15], then expand W[16..79] (same as SSSE3 schedule).
//   Phase 2 (GPR): 80 compression rounds with 5-round unrolling
//
// Saved GPR / stack (sub esp, 424): [esp+$10] state, +$14 data, +$18 numblocks, +$1C E, +$20 loop ctr,
//   +$38 saved ebp; W buffer at +$60.
// W-buffer uses movdqu (not movdqa): this frame does not keep ESP 16-byte aligned.

  sub esp, 424

{$IFDEF MSWINDOWS}
  movdqu oword ptr [esp], xmm6
{$ENDIF}
  mov [esp + $10], ebx
  mov [esp + $14], esi
  mov [esp + $18], edi
  mov [esp + $38], ebp

  test edi, edi
  jz @sse2_sha1_done

@sse2_sha1_block_loop:

  // ========== Phase 1: SIMD message schedule ==========

  mov esi, [esp + $14]
  lea ebx, [esp + $60]

  // SSE2 32-bit byte-swap: pshuflw/pshufhw swap 16-bit words, then swap bytes within words
  movdqu xmm0, oword ptr [esi]
  pshuflw xmm0, xmm0, $B1
  pshufhw xmm0, xmm0, $B1
  movdqa xmm4, xmm0
  psrlw  xmm0, 8
  psllw  xmm4, 8
  por    xmm0, xmm4
  movdqu oword ptr [ebx], xmm0

  movdqu xmm1, oword ptr [esi + $10]
  pshuflw xmm1, xmm1, $B1
  pshufhw xmm1, xmm1, $B1
  movdqa xmm4, xmm1
  psrlw  xmm1, 8
  psllw  xmm4, 8
  por    xmm1, xmm4
  movdqu oword ptr [ebx + $10], xmm1

  movdqu xmm2, oword ptr [esi + $20]
  pshuflw xmm2, xmm2, $B1
  pshufhw xmm2, xmm2, $B1
  movdqa xmm4, xmm2
  psrlw  xmm2, 8
  psllw  xmm4, 8
  por    xmm2, xmm4
  movdqu oword ptr [ebx + $20], xmm2

  movdqu xmm3, oword ptr [esi + $30]
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  movdqa xmm4, xmm3
  psrlw  xmm3, 8
  psllw  xmm4, 8
  por    xmm3, xmm4
  movdqu oword ptr [ebx + $30], xmm3

  // --- W[16..31]: ROL1 formula with cross-lane fix ---

  lea edi, [ebx + $40]
  lea ecx, [ebx + $80]

@sse2_sha1_expand_16_31:
  movdqu xmm0, oword ptr [edi - $40]
  movdqu xmm1, oword ptr [edi - $30]
  movdqu xmm2, oword ptr [edi - $20]
  movdqu xmm3, oword ptr [edi - $10]

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

  movdqu oword ptr [edi], xmm4
  add edi, $10
  cmp edi, ecx
  jb @sse2_sha1_expand_16_31

  // --- W[32..79]: ROL2 expanded recurrence ---

  lea ecx, [ebx + $140]

@sse2_sha1_expand_32_79:
  movdqu xmm0, oword ptr [edi - $80]
  movdqu xmm1, oword ptr [edi - $40]
  movdqu xmm2, oword ptr [edi - $20]
  movdqu xmm3, oword ptr [edi - $10]
  movdqu xmm4, oword ptr [edi - $70]

  pxor xmm0, xmm1

  pshufd xmm5, xmm2, $EE
  punpcklqdq xmm5, xmm3

  pxor xmm0, xmm4
  pxor xmm0, xmm5

  movdqa xmm5, xmm0
  pslld  xmm0, 2
  psrld  xmm5, 30
  por    xmm0, xmm5

  movdqu oword ptr [edi], xmm0
  add edi, $10
  cmp edi, ecx
  jb @sse2_sha1_expand_32_79

  // ========== Phase 2: 80 Compression Rounds ==========

  mov esi, [esp + $10]
  mov eax, [esi]
  mov ebx, [esi + $04]
  mov ecx, [esi + $08]
  mov edx, [esi + $0C]
  mov edi, [esi + $10]
  mov [esp + $1C], edi

  lea ebp, [esp + $60]

  // ---------- Rounds 0-19: Ch, K = $5A827999 ----------

  mov dword ptr [esp + $20], 4

@sse2_sha1_ch_loop:

  mov esi, ecx
  xor esi, edx
  and esi, ebx
  xor esi, edx
  mov edi, dword ptr [ebp]
  add dword ptr [esp + $1C], edi
  mov edi, eax
  rol edi, 5
  add dword ptr [esp + $1C], edi
  add dword ptr [esp + $1C], esi
  add dword ptr [esp + $1C], $5A827999
  rol ebx, 30

  mov esi, ebx
  xor esi, ecx
  and esi, eax
  xor esi, ecx
  mov edi, dword ptr [esp + $1C]
  rol edi, 5
  add edx, dword ptr [ebp + $04]
  add edx, edi
  add edx, esi
  add edx, $5A827999
  rol eax, 30

  mov esi, eax
  xor esi, ebx
  and esi, dword ptr [esp + $1C]
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, dword ptr [ebp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $5A827999
  mov edi, dword ptr [esp + $1C]
  rol edi, 30
  mov dword ptr [esp + $1C], edi
  mov esi, edi
  xor esi, eax
  and esi, edx
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, dword ptr [ebp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $5A827999
  rol edx, 30

  mov esi, edx
  xor esi, dword ptr [esp + $1C]
  and esi, ecx
  xor esi, dword ptr [esp + $1C]
  mov edi, ebx
  rol edi, 5
  add eax, dword ptr [ebp + $10]
  add eax, edi
  add eax, esi
  add eax, $5A827999
  rol ecx, 30

  add ebp, $14
  dec dword ptr [esp + $20]
  jnz @sse2_sha1_ch_loop

  // ---------- Rounds 20-39: Parity, K = $6ED9EBA1 ----------

  mov dword ptr [esp + $20], 4

@sse2_sha1_par1_loop:

  mov esi, ebx
  xor esi, ecx
  xor esi, edx
  mov edi, dword ptr [ebp]
  add dword ptr [esp + $1C], edi
  mov edi, eax
  rol edi, 5
  add dword ptr [esp + $1C], edi
  add dword ptr [esp + $1C], esi
  add dword ptr [esp + $1C], $6ED9EBA1
  rol ebx, 30

  mov esi, eax
  xor esi, ebx
  xor esi, ecx
  mov edi, dword ptr [esp + $1C]
  rol edi, 5
  add edx, dword ptr [ebp + $04]
  add edx, edi
  add edx, esi
  add edx, $6ED9EBA1
  rol eax, 30

  mov esi, dword ptr [esp + $1C]
  xor esi, eax
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, dword ptr [ebp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $6ED9EBA1
  mov edi, dword ptr [esp + $1C]
  rol edi, 30
  mov dword ptr [esp + $1C], edi

  mov esi, edx
  xor esi, dword ptr [esp + $1C]
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, dword ptr [ebp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $6ED9EBA1
  rol edx, 30

  mov esi, ecx
  xor esi, edx
  xor esi, dword ptr [esp + $1C]
  mov edi, ebx
  rol edi, 5
  add eax, dword ptr [ebp + $10]
  add eax, edi
  add eax, esi
  add eax, $6ED9EBA1
  rol ecx, 30

  add ebp, $14
  dec dword ptr [esp + $20]
  jnz @sse2_sha1_par1_loop

  // ---------- Rounds 40-59: Maj, K = $8F1BBCDC ----------

  mov dword ptr [esp + $20], 4

@sse2_sha1_maj_loop:

  mov esi, ebx
  or  esi, ecx
  and esi, edx
  mov edi, ebx
  and edi, ecx
  or  esi, edi
  mov edi, dword ptr [ebp]
  add dword ptr [esp + $1C], edi
  mov edi, eax
  rol edi, 5
  add dword ptr [esp + $1C], edi
  add dword ptr [esp + $1C], esi
  add dword ptr [esp + $1C], $8F1BBCDC
  rol ebx, 30

  mov esi, eax
  or  esi, ebx
  and esi, ecx
  mov edi, eax
  and edi, ebx
  or  esi, edi
  mov edi, dword ptr [esp + $1C]
  rol edi, 5
  add edx, dword ptr [ebp + $04]
  add edx, edi
  add edx, esi
  add edx, $8F1BBCDC
  rol eax, 30

  mov esi, dword ptr [esp + $1C]
  or  esi, eax
  and esi, ebx
  mov edi, dword ptr [esp + $1C]
  and edi, eax
  or  esi, edi
  mov edi, edx
  rol edi, 5
  add ecx, dword ptr [ebp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $8F1BBCDC
  mov edi, dword ptr [esp + $1C]
  rol edi, 30
  mov dword ptr [esp + $1C], edi

  mov esi, edx
  or  esi, dword ptr [esp + $1C]
  and esi, eax
  mov edi, edx
  and edi, dword ptr [esp + $1C]
  or  esi, edi
  mov edi, ecx
  rol edi, 5
  add ebx, dword ptr [ebp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $8F1BBCDC
  rol edx, 30

  mov esi, ecx
  or  esi, edx
  and esi, dword ptr [esp + $1C]
  mov edi, ecx
  and edi, edx
  or  esi, edi
  mov edi, ebx
  rol edi, 5
  add eax, dword ptr [ebp + $10]
  add eax, edi
  add eax, esi
  add eax, $8F1BBCDC
  rol ecx, 30

  add ebp, $14
  dec dword ptr [esp + $20]
  jnz @sse2_sha1_maj_loop

  // ---------- Rounds 60-79: Parity, K = $CA62C1D6 ----------

  mov dword ptr [esp + $20], 4

@sse2_sha1_par2_loop:

  mov esi, ebx
  xor esi, ecx
  xor esi, edx
  mov edi, dword ptr [ebp]
  add dword ptr [esp + $1C], edi
  mov edi, eax
  rol edi, 5
  add dword ptr [esp + $1C], edi
  add dword ptr [esp + $1C], esi
  add dword ptr [esp + $1C], $CA62C1D6
  rol ebx, 30

  mov esi, eax
  xor esi, ebx
  xor esi, ecx
  mov edi, dword ptr [esp + $1C]
  rol edi, 5
  add edx, dword ptr [ebp + $04]
  add edx, edi
  add edx, esi
  add edx, $CA62C1D6
  rol eax, 30

  mov esi, dword ptr [esp + $1C]
  xor esi, eax
  xor esi, ebx
  mov edi, edx
  rol edi, 5
  add ecx, dword ptr [ebp + $08]
  add ecx, edi
  add ecx, esi
  add ecx, $CA62C1D6
  mov edi, dword ptr [esp + $1C]
  rol edi, 30
  mov dword ptr [esp + $1C], edi

  mov esi, edx
  xor esi, dword ptr [esp + $1C]
  xor esi, eax
  mov edi, ecx
  rol edi, 5
  add ebx, dword ptr [ebp + $0C]
  add ebx, edi
  add ebx, esi
  add ebx, $CA62C1D6
  rol edx, 30

  mov esi, ecx
  xor esi, edx
  xor esi, dword ptr [esp + $1C]
  mov edi, ebx
  rol edi, 5
  add eax, dword ptr [ebp + $10]
  add eax, edi
  add eax, esi
  add eax, $CA62C1D6
  rol ecx, 30

  add ebp, $14
  dec dword ptr [esp + $20]
  jnz @sse2_sha1_par2_loop

  // Add round results to state
  mov esi, [esp + $10]
  add dword ptr [esi], eax
  add dword ptr [esi + $04], ebx
  add dword ptr [esi + $08], ecx
  add dword ptr [esi + $0C], edx
  mov eax, dword ptr [esp + $1C]
  add dword ptr [esi + $10], eax

  mov esi, [esp + $14]
  add esi, $40
  mov [esp + $14], esi
  dec dword ptr [esp + $18]
  jnz @sse2_sha1_block_loop

@sse2_sha1_done:

  mov ebp, [esp + $38]
{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
{$ENDIF}
  add esp, 424
  pop edi
  pop esi
  pop ebx
