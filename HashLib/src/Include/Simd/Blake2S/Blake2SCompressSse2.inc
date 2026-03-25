// SSE2 implementation of BLAKE2s compress (fully unrolled 10 rounds).
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = counter+flags ptr, r9 = IV ptr.
// Uses xmm0-xmm6. Non-volatile xmm6 saved/restored on Windows.
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15),
//   xmm4 = message buffer, xmm5 = temp, xmm6 = temp (msg load).
// Rotations: ROT16/12/8/7 via psrld/pslld/por.
// Diagonalize/Undiagonalize via pshufd.
// Message loads via movd + punpcklqdq + shufps.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

{$IFDEF MSWINDOWS}
  sub rsp, 16
  movdqu oword [rsp], xmm6
{$ENDIF}

  // Initialize working vector
  movdqu xmm0, oword [rcx]
  movdqu xmm1, oword [rcx + $10]
  movdqu xmm2, oword [r9]
  movdqu xmm3, oword [r9 + $10]

  // XOR d with counter and flags
  movdqu xmm4, oword [r8]
  pxor xmm3, xmm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  movd xmm4, dword [rdx]
  movd xmm5, dword [rdx + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $10]
  movd xmm6, dword [rdx + $18]
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
  movd xmm4, dword [rdx + $04]
  movd xmm5, dword [rdx + $0C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $14]
  movd xmm6, dword [rdx + $1C]
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
  movd xmm4, dword [rdx + $38]
  movd xmm5, dword [rdx + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $28]
  movd xmm6, dword [rdx + $30]
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
  movd xmm4, dword [rdx + $3C]
  movd xmm5, dword [rdx + $24]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $2C]
  movd xmm6, dword [rdx + $34]
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
  movd xmm4, dword [rdx + $38]
  movd xmm5, dword [rdx + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $24]
  movd xmm6, dword [rdx + $34]
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
  movd xmm4, dword [rdx + $28]
  movd xmm5, dword [rdx + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $3C]
  movd xmm6, dword [rdx + $18]
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
  movd xmm4, dword [rdx + $14]
  movd xmm5, dword [rdx + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx]
  movd xmm6, dword [rdx + $2C]
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
  movd xmm4, dword [rdx + $0C]
  movd xmm5, dword [rdx + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $08]
  movd xmm6, dword [rdx + $1C]
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
  movd xmm4, dword [rdx + $2C]
  movd xmm5, dword [rdx + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $14]
  movd xmm6, dword [rdx + $3C]
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
  movd xmm4, dword [rdx + $20]
  movd xmm5, dword [rdx]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $08]
  movd xmm6, dword [rdx + $34]
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
  movd xmm4, dword [rdx + $24]
  movd xmm5, dword [rdx + $28]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $0C]
  movd xmm6, dword [rdx + $1C]
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
  movd xmm4, dword [rdx + $10]
  movd xmm5, dword [rdx + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $18]
  movd xmm6, dword [rdx + $04]
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
  movd xmm4, dword [rdx + $1C]
  movd xmm5, dword [rdx + $0C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $34]
  movd xmm6, dword [rdx + $2C]
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
  movd xmm4, dword [rdx + $24]
  movd xmm5, dword [rdx + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $30]
  movd xmm6, dword [rdx + $38]
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
  movd xmm4, dword [rdx + $3C]
  movd xmm5, dword [rdx + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $14]
  movd xmm6, dword [rdx + $10]
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
  movd xmm4, dword [rdx + $20]
  movd xmm5, dword [rdx + $18]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $28]
  movd xmm6, dword [rdx]
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
  movd xmm4, dword [rdx + $24]
  movd xmm5, dword [rdx + $14]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $08]
  movd xmm6, dword [rdx + $28]
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
  movd xmm4, dword [rdx]
  movd xmm5, dword [rdx + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $10]
  movd xmm6, dword [rdx + $3C]
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
  movd xmm4, dword [rdx + $0C]
  movd xmm5, dword [rdx + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $2C]
  movd xmm6, dword [rdx + $18]
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
  movd xmm4, dword [rdx + $34]
  movd xmm5, dword [rdx + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $30]
  movd xmm6, dword [rdx + $20]
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
  movd xmm4, dword [rdx + $08]
  movd xmm5, dword [rdx + $18]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx]
  movd xmm6, dword [rdx + $20]
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
  movd xmm4, dword [rdx + $30]
  movd xmm5, dword [rdx + $28]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $2C]
  movd xmm6, dword [rdx + $0C]
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
  movd xmm4, dword [rdx + $04]
  movd xmm5, dword [rdx + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $1C]
  movd xmm6, dword [rdx + $3C]
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
  movd xmm4, dword [rdx + $24]
  movd xmm5, dword [rdx + $34]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $14]
  movd xmm6, dword [rdx + $38]
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
  movd xmm4, dword [rdx + $30]
  movd xmm5, dword [rdx + $04]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $38]
  movd xmm6, dword [rdx + $10]
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
  movd xmm4, dword [rdx + $14]
  movd xmm5, dword [rdx + $3C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $34]
  movd xmm6, dword [rdx + $28]
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
  movd xmm4, dword [rdx + $20]
  movd xmm5, dword [rdx]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $18]
  movd xmm6, dword [rdx + $24]
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
  movd xmm4, dword [rdx + $2C]
  movd xmm5, dword [rdx + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $0C]
  movd xmm6, dword [rdx + $08]
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
  movd xmm4, dword [rdx + $34]
  movd xmm5, dword [rdx + $1C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $30]
  movd xmm6, dword [rdx + $0C]
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
  movd xmm4, dword [rdx + $2C]
  movd xmm5, dword [rdx + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $04]
  movd xmm6, dword [rdx + $24]
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
  movd xmm4, dword [rdx + $08]
  movd xmm5, dword [rdx + $14]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $3C]
  movd xmm6, dword [rdx + $20]
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
  movd xmm4, dword [rdx + $28]
  movd xmm5, dword [rdx]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $10]
  movd xmm6, dword [rdx + $18]
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
  movd xmm4, dword [rdx + $18]
  movd xmm5, dword [rdx + $38]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $2C]
  movd xmm6, dword [rdx]
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
  movd xmm4, dword [rdx + $3C]
  movd xmm5, dword [rdx + $24]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $0C]
  movd xmm6, dword [rdx + $20]
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
  movd xmm4, dword [rdx + $28]
  movd xmm5, dword [rdx + $30]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $34]
  movd xmm6, dword [rdx + $04]
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
  movd xmm4, dword [rdx + $14]
  movd xmm5, dword [rdx + $08]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $1C]
  movd xmm6, dword [rdx + $10]
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
  movd xmm4, dword [rdx + $28]
  movd xmm5, dword [rdx + $20]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $1C]
  movd xmm6, dword [rdx + $04]
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
  movd xmm4, dword [rdx + $08]
  movd xmm5, dword [rdx + $10]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $18]
  movd xmm6, dword [rdx + $14]
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
  movd xmm4, dword [rdx + $34]
  movd xmm5, dword [rdx + $3C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $24]
  movd xmm6, dword [rdx + $0C]
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
  movd xmm4, dword [rdx]
  movd xmm5, dword [rdx + $2C]
  punpcklqdq xmm4, xmm5
  movd xmm5, dword [rdx + $38]
  movd xmm6, dword [rdx + $30]
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
  movdqu xmm4, oword [rcx]
  pxor xmm0, xmm4
  movdqu xmm4, oword [rcx + $10]
  pxor xmm1, xmm4

  // Store result
  movdqu oword [rcx], xmm0
  movdqu oword [rcx + $10], xmm1

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  add rsp, 16
{$ENDIF}
