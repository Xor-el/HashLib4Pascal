// SSSE3 implementation of BLAKE2s compress (fully unrolled 10 rounds; IA-32);
// SSE2 sibling: Blake2SCompressSse2_i386.inc. Rotations: rot16 via pshufb
// against the resident xmm7 mask; rot8 via a per-site mask reload into the
// xmm5 temp + pshufb (only xmm7 is free); rot12/7 via psrld/pslld/por (not
// byte-aligned). Diagonalize/Undiagonalize via pshufd. Message loads via
// movd + punpcklqdq + shufps.
// ABI (after HlpSimdProc5Begin_i386.inc): ebx = state ptr, esi = msg ptr,
//   edi = counter+flags ptr, eax = IV ptr, ecx = byte-rotation masks ptr
//   (BLAKE2S_ROT_MASKS: rot16 at +0, rot8 at +16; read unaligned, so the
//   Pascal const needs no special alignment).
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11),
//   xmm3 = d (v12-15), xmm4 = message buffer, xmm5 = temp,
//   xmm6 = temp (msg load), xmm7 = rot16 mask.
// Saves: xmm6-xmm7 saved/restored defensively (volatile on IA-32).
// pshufb instructions are db-encoded for broad assembler compatibility.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

  sub esp, 32
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7

  // Load the rot16 mask (resident; rot8 reloads the xmm5 temp per site)
  movdqu xmm7, oword ptr [ecx]

  // Initialize working vector
  movdqu xmm0, oword ptr [ebx]
  movdqu xmm1, oword ptr [ebx + $10]
  movdqu xmm2, oword ptr [eax]
  movdqu xmm3, oword ptr [eax + $10]

  // XOR d with counter and flags
  movdqu xmm4, oword ptr [edi]
  pxor xmm3, xmm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  movd xmm4, dword ptr [esi]
  movd xmm5, dword ptr [esi + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $10]
  movd xmm6, dword ptr [esi + $18]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m1,m3,m5,m7)
  movd xmm4, dword ptr [esi + $04]
  movd xmm5, dword ptr [esi + $0C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $14]
  movd xmm6, dword ptr [esi + $1C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  movd xmm4, dword ptr [esi + $38]
  movd xmm5, dword ptr [esi + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $28]
  movd xmm6, dword ptr [esi + $30]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m15,m9,m11,m13)
  movd xmm4, dword ptr [esi + $3C]
  movd xmm5, dword ptr [esi + $24]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $2C]
  movd xmm6, dword ptr [esi + $34]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4,m9,m13)
  movd xmm4, dword ptr [esi + $38]
  movd xmm5, dword ptr [esi + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $24]
  movd xmm6, dword ptr [esi + $34]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m10,m8,m15,m6)
  movd xmm4, dword ptr [esi + $28]
  movd xmm5, dword ptr [esi + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $3C]
  movd xmm6, dword ptr [esi + $18]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  movd xmm4, dword ptr [esi + $14]
  movd xmm5, dword ptr [esi + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi]
  movd xmm6, dword ptr [esi + $2C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m3,m12,m2,m7)
  movd xmm4, dword ptr [esi + $0C]
  movd xmm5, dword ptr [esi + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $08]
  movd xmm6, dword ptr [esi + $1C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12,m5,m15)
  movd xmm4, dword ptr [esi + $2C]
  movd xmm5, dword ptr [esi + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $14]
  movd xmm6, dword ptr [esi + $3C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m8,m0,m2,m13)
  movd xmm4, dword ptr [esi + $20]
  movd xmm5, dword ptr [esi]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $08]
  movd xmm6, dword ptr [esi + $34]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m9,m10,m3,m7)
  movd xmm4, dword ptr [esi + $24]
  movd xmm5, dword ptr [esi + $28]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $0C]
  movd xmm6, dword ptr [esi + $1C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m4,m14,m6,m1)
  movd xmm4, dword ptr [esi + $10]
  movd xmm5, dword ptr [esi + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $18]
  movd xmm6, dword ptr [esi + $04]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3,m13,m11)
  movd xmm4, dword ptr [esi + $1C]
  movd xmm5, dword ptr [esi + $0C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $34]
  movd xmm6, dword ptr [esi + $2C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m9,m1,m12,m14)
  movd xmm4, dword ptr [esi + $24]
  movd xmm5, dword ptr [esi + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $30]
  movd xmm6, dword ptr [esi + $38]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m15,m2,m5,m4)
  movd xmm4, dword ptr [esi + $3C]
  movd xmm5, dword ptr [esi + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $14]
  movd xmm6, dword ptr [esi + $10]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m8,m6,m10,m0)
  movd xmm4, dword ptr [esi + $20]
  movd xmm5, dword ptr [esi + $18]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $28]
  movd xmm6, dword ptr [esi]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5,m2,m10)
  movd xmm4, dword ptr [esi + $24]
  movd xmm5, dword ptr [esi + $14]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $08]
  movd xmm6, dword ptr [esi + $28]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m0,m7,m4,m15)
  movd xmm4, dword ptr [esi]
  movd xmm5, dword ptr [esi + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $10]
  movd xmm6, dword ptr [esi + $3C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m3,m14,m11,m6)
  movd xmm4, dword ptr [esi + $0C]
  movd xmm5, dword ptr [esi + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $2C]
  movd xmm6, dword ptr [esi + $18]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m13,m1,m12,m8)
  movd xmm4, dword ptr [esi + $34]
  movd xmm5, dword ptr [esi + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $30]
  movd xmm6, dword ptr [esi + $20]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6,m0,m8)
  movd xmm4, dword ptr [esi + $08]
  movd xmm5, dword ptr [esi + $18]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi]
  movd xmm6, dword ptr [esi + $20]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m12,m10,m11,m3)
  movd xmm4, dword ptr [esi + $30]
  movd xmm5, dword ptr [esi + $28]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $2C]
  movd xmm6, dword ptr [esi + $0C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m1,m4,m7,m15)
  movd xmm4, dword ptr [esi + $04]
  movd xmm5, dword ptr [esi + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $1C]
  movd xmm6, dword ptr [esi + $3C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m9,m13,m5,m14)
  movd xmm4, dword ptr [esi + $24]
  movd xmm5, dword ptr [esi + $34]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $14]
  movd xmm6, dword ptr [esi + $38]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1,m14,m4)
  movd xmm4, dword ptr [esi + $30]
  movd xmm5, dword ptr [esi + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $38]
  movd xmm6, dword ptr [esi + $10]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m5,m15,m13,m10)
  movd xmm4, dword ptr [esi + $14]
  movd xmm5, dword ptr [esi + $3C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $34]
  movd xmm6, dword ptr [esi + $28]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m8,m0,m6,m9)
  movd xmm4, dword ptr [esi + $20]
  movd xmm5, dword ptr [esi]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $18]
  movd xmm6, dword ptr [esi + $24]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m11,m7,m3,m2)
  movd xmm4, dword ptr [esi + $2C]
  movd xmm5, dword ptr [esi + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $0C]
  movd xmm6, dword ptr [esi + $08]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7,m12,m3)
  movd xmm4, dword ptr [esi + $34]
  movd xmm5, dword ptr [esi + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $30]
  movd xmm6, dword ptr [esi + $0C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m11,m14,m1,m9)
  movd xmm4, dword ptr [esi + $2C]
  movd xmm5, dword ptr [esi + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $04]
  movd xmm6, dword ptr [esi + $24]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m2,m5,m15,m8)
  movd xmm4, dword ptr [esi + $08]
  movd xmm5, dword ptr [esi + $14]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $3C]
  movd xmm6, dword ptr [esi + $20]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m10,m0,m4,m6)
  movd xmm4, dword ptr [esi + $28]
  movd xmm5, dword ptr [esi]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $10]
  movd xmm6, dword ptr [esi + $18]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14,m11,m0)
  movd xmm4, dword ptr [esi + $18]
  movd xmm5, dword ptr [esi + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $2C]
  movd xmm6, dword ptr [esi]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m15,m9,m3,m8)
  movd xmm4, dword ptr [esi + $3C]
  movd xmm5, dword ptr [esi + $24]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $0C]
  movd xmm6, dword ptr [esi + $20]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m10,m12,m13,m1)
  movd xmm4, dword ptr [esi + $28]
  movd xmm5, dword ptr [esi + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $34]
  movd xmm6, dword ptr [esi + $04]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m5,m2,m7,m4)
  movd xmm4, dword ptr [esi + $14]
  movd xmm5, dword ptr [esi + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $1C]
  movd xmm6, dword ptr [esi + $10]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8,m7,m1)
  movd xmm4, dword ptr [esi + $28]
  movd xmm5, dword ptr [esi + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $1C]
  movd xmm6, dword ptr [esi + $04]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 columns (msg: m2,m4,m6,m5)
  movd xmm4, dword ptr [esi + $08]
  movd xmm5, dword ptr [esi + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $18]
  movd xmm6, dword ptr [esi + $14]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Diagonalize
  pshufd xmm0, xmm0, $93
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m13,m15,m9,m3)
  movd xmm4, dword ptr [esi + $34]
  movd xmm5, dword ptr [esi + $3C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $24]
  movd xmm6, dword ptr [esi + $0C]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  db $66, $0F, $38, $00, $DF                    // pshufb xmm3, xmm7

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 12
  pslld xmm5, 20
  por xmm1, xmm5

  // G2 diagonals (msg: m0,m11,m14,m12)
  movd xmm4, dword ptr [esi]
  movd xmm5, dword ptr [esi + $2C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword ptr [esi + $38]
  movd xmm6, dword ptr [esi + $30]
  punpcklqdq xmm5, xmm6
  shufps xmm4, xmm5, $88
  paddd xmm0, xmm4
  paddd xmm0, xmm1
  pxor xmm3, xmm0
  movdqu xmm5, oword ptr [ecx + $10]
  db $66, $0F, $38, $00, $DD                    // pshufb xmm3, xmm5

  paddd xmm2, xmm3
  pxor xmm1, xmm2
  movdqa xmm5, xmm1
  psrld xmm1, 7
  pslld xmm5, 25
  por xmm1, xmm5

  // Undiagonalize
  pshufd xmm0, xmm0, $39
  pshufd xmm3, xmm3, $4E
  pshufd xmm2, xmm2, $93

  // Finalization: state[i] ^= v[i] ^ v[i+8]
  pxor xmm0, xmm2
  pxor xmm1, xmm3
  movdqu xmm4, oword ptr [ebx]
  pxor xmm0, xmm4
  movdqu xmm4, oword ptr [ebx + $10]
  pxor xmm1, xmm4

  // Store result
  movdqu oword ptr [ebx], xmm0
  movdqu oword ptr [ebx + $10], xmm1

  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 32
  pop edi
  pop esi
  pop ebx
