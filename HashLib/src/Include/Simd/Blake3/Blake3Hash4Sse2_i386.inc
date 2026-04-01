// SSE2 i386 implementation of BLAKE3 hash4: processes up to 4 chunks sequentially.
// Reference: BLAKE3-team/BLAKE3 official SSE2 implementation (blake3_sse2.c / hash_one).
// i386 has only xmm0-xmm7 (8 registers), so inter-chunk parallelism is not possible;
//   each chunk is processed one at a time with the inline SSE2 compress kernel.
// Register map during rounds: xmm0=a(v0-3), xmm1=b(v4-7), xmm2=c(v8-11), xmm3=d(v12-15);
//   xmm4={m0,m2,m4,m6}, xmm5={m1,m3,m5,m7}, xmm6={m14,m8,m10,m12}, xmm7={m15,m9,m11,m13}.
// After SimdProc6Begin_i386: ebx=P1 (input), esi=P2 (key), edi=P3 (out), eax=P4 (num chunks),
//   ecx=P5_lo, edx=P5_hi (chunk counter). Prologue pushed ebx/esi/edi — epilogue pops them.
// Block index (0..15) is kept at [esp+$90] so ebp is never used as a temp (frame-friendly).
// Stack layout (148 bytes, esp-relative after sub esp,148):
//   [esp+$00..0F] xmm6 save      [esp+$10..1F] xmm7 save
//   [esp+$20..2F] TEMP_A (xmm0 spill during rounds)
//   [esp+$30..3F] TEMP_B (xmm1 spill during msg permutation — also D_VEC build slot)
//   [esp+$40..4F] TEMP_C (xmm2 spill during msg permutation)
//   [esp+$50..5F] IV_VEC {$6A09E667,$BB67AE85,$3C6EF372,$A54FF53A}
//   [esp+$60..6F] CV_LO (running chaining value low 16 bytes)
//   [esp+$70..7F] CV_HI (running chaining value high 16 bytes)
//   [esp+$80]     CTR_LO  [esp+$84] CTR_HI  [esp+$88] BASE_FLAGS  [esp+$8C] SAVE_NC
//   [esp+$90]     BLOCK_IDX (current block within chunk, 0..15)
// P6 (flags): FPC i386 [esp+$A4] (16+148 after sub esp,148). Delphi [ebp+8].

  sub esp, 148

  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7

  // Save parameters before clobbering registers
  mov dword ptr [esp + $8C], eax          // SAVE_NC = ANumChunks
  mov dword ptr [esp + $80], ecx          // CTR_LO
  mov dword ptr [esp + $84], edx          // CTR_HI

  // Store BLAKE3 IV constant at [esp+$50]
  mov eax, $6A09E667
  mov dword ptr [esp + $50], eax
  mov eax, $BB67AE85
  mov dword ptr [esp + $54], eax
  mov eax, $3C6EF372
  mov dword ptr [esp + $58], eax
  mov eax, $A54FF53A
  mov dword ptr [esp + $5C], eax

  {$IFDEF FPC}
  mov eax, dword ptr [esp + $A4]
  {$ELSE}
  mov eax, dword ptr [ebp + 8]
  {$ENDIF}
  mov dword ptr [esp + $88], eax          // BASE_FLAGS

  // Check if there is work to do
  mov eax, dword ptr [esp + $8C]
  test eax, eax
  jle @h4_done

@h4_chunk_loop:
  // Initialize CV from key (esi = AKey, 8 x UInt32 = 32 bytes)
  movdqu xmm0, oword ptr [esi]
  movdqu xmm1, oword ptr [esi + $10]
  movdqu oword ptr [esp + $60], xmm0
  movdqu oword ptr [esp + $70], xmm1

  // Process 16 blocks of 64 bytes each (= one 1024-byte chunk)
  mov dword ptr [esp + $90], 0            // BLOCK_IDX := 0

@h4_block_loop:
  // Build D_VEC = {CTR_LO, CTR_HI, BLKLEN=64, flags} at TEMP_B slot [esp+$30]
  // (TEMP_B will be overwritten by msg permutation later — that is expected)
  mov ecx, dword ptr [esp + $80]          // CTR_LO
  mov edx, dword ptr [esp + $84]          // CTR_HI
  mov eax, dword ptr [esp + $88]          // BASE_FLAGS
  cmp dword ptr [esp + $90], 0
  jne @h4_not_first
  or eax, 1                               // CHUNK_START = bit 0
@h4_not_first:
  cmp dword ptr [esp + $90], 15
  jne @h4_not_last
  or eax, 2                               // CHUNK_END = bit 1
@h4_not_last:
  mov dword ptr [esp + $30], ecx
  mov dword ptr [esp + $34], edx
  mov dword ptr [esp + $38], 64           // BLKLEN
  mov dword ptr [esp + $3C], eax
  movdqu xmm3, oword ptr [esp + $30]     // xmm3 = d = {CTR_LO,CTR_HI,64,flags}

  // Load IV into xmm2 = c
  movdqu xmm2, oword ptr [esp + $50]

  // Load CV into xmm0 = a, xmm1 = b
  movdqu xmm0, oword ptr [esp + $60]
  movdqu xmm1, oword ptr [esp + $70]

  // Load and reorder 64-byte message block from [ebx].
  // After reorder: xmm4={m0,m2,m4,m6}, xmm5={m1,m3,m5,m7},
  //   xmm6={m14,m8,m10,m12}, xmm7={m15,m9,m11,m13}.
  movdqu oword ptr [esp + $20], xmm0
  movdqu xmm4, oword ptr [ebx]
  movdqu xmm5, oword ptr [ebx + $10]
  movdqa xmm0, xmm4
  shufps xmm4, xmm5, $88
  shufps xmm0, xmm5, $DD
  movdqa xmm5, xmm0
  movdqu xmm6, oword ptr [ebx + $20]
  movdqu xmm7, oword ptr [ebx + $30]
  movdqa xmm0, xmm6
  shufps xmm6, xmm7, $88
  pshufd xmm6, xmm6, $93
  shufps xmm0, xmm7, $DD
  pshufd xmm7, xmm0, $93
  movdqu xmm0, oword ptr [esp + $20]

  // ===== Round 0 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 0->1 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 1 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 1->2 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 2 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 2->3 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 3 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 3->4 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 4 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 4->5 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 5 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Message Permutation 5->6 =====
  movdqu oword ptr [esp + $20], xmm0
  movdqu oword ptr [esp + $30], xmm1
  movdqu oword ptr [esp + $40], xmm2
  movdqa xmm0, xmm4
  shufps xmm0, xmm5, $D6
  pshufd xmm1, xmm4, $0F
  pshufd xmm4, xmm0, $39
  movdqa xmm0, xmm6
  shufps xmm0, xmm7, $FA
  shufps xmm1, xmm0, $D8
  pshufd xmm1, xmm1, $D8
  movdqa xmm0, xmm7
  punpcklqdq xmm0, xmm5
  movdqa xmm2, xmm0
  punpckhdq xmm2, xmm6
  shufps xmm0, xmm2, $C4
  pshufd xmm0, xmm0, $78
  punpckhdq xmm5, xmm7
  punpckldq xmm6, xmm5
  pshufd xmm7, xmm6, $1E
  movdqa xmm5, xmm1
  movdqa xmm6, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  movdqu xmm1, oword ptr [esp + $30]
  movdqu xmm2, oword ptr [esp + $40]

  // ===== Round 6 =====

  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm5
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  paddd xmm0, xmm6
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  pshuflw xmm3, xmm3, $B1
  pshufhw xmm3, xmm3, $B1
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 20
  psrld xmm0, 12
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  paddd xmm0, xmm7
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm3
  psrld xmm3, 8
  pslld xmm0, 24
  pxor xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $20]
  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqu oword ptr [esp + $20], xmm0
  movdqa xmm0, xmm1
  pslld xmm1, 25
  psrld xmm0, 7
  por xmm1, xmm0
  movdqu xmm0, oword ptr [esp + $20]

  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // === Block finalize: new CV = {a ^ c, b ^ d} ===
  pxor xmm0, xmm2
  pxor xmm1, xmm3
  movdqu oword ptr [esp + $60], xmm0
  movdqu oword ptr [esp + $70], xmm1

  // Advance block message pointer and block index
  add ebx, 64
  inc dword ptr [esp + $90]
  cmp dword ptr [esp + $90], 16
  jl @h4_block_loop

  // Write 32-byte chunk chaining value to AOut
  movdqu oword ptr [edi], xmm0
  movdqu oword ptr [edi + $10], xmm1
  add edi, 32

  // Increment 64-bit chunk counter
  add dword ptr [esp + $80], 1
  adc dword ptr [esp + $84], 0

  // Outer chunk loop
  dec dword ptr [esp + $8C]
  jg @h4_chunk_loop

@h4_done:
  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 148
  pop edi
  pop esi
  pop ebx
