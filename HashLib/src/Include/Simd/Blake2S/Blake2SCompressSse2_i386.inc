// SSE2 implementation of BLAKE2s compress (fully unrolled 10 rounds).
// IA-32: after SimdProc4Begin_i386 — ebx = state, esi = msg, edi = counter+flags, eax = IV
//   (parallel to MS x64 ABI: rcx, rdx, r8, r9).
// Uses xmm0–xmm6. Non-volatile xmm6 saved/restored on Windows (MSWINDOWS).
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15),
//   xmm4 = message buffer, xmm5 = temp, xmm6 = temp (msg load).
// Rotations: ROT16/12/8/7 via psrld/pslld/por.
// Diagonalize/Undiagonalize via pshufd.
// Message loads via movd + punpcklqdq + shufps.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

{$IFDEF MSWINDOWS}
  sub esp, 16
  movdqu oword ptr [esp], xmm6
{$ENDIF}

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 16
  pslld xmm5, 16
  por xmm3, xmm5

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
  movdqa xmm5, xmm3
  psrld xmm3, 8
  pslld xmm5, 24
  por xmm3, xmm5

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

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword ptr [esp]
  add esp, 16
{$ENDIF}
  pop edi
  pop esi
  pop ebx
