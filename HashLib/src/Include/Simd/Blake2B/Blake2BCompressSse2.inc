// SSE2 implementation of BLAKE2b compress (fully unrolled 12 rounds).
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = counter+flags ptr, r9 = IV ptr.
// Uses xmm0-xmm9. Non-volatile xmm6-xmm9 saved/restored on Windows.
// Register map: xmm0-1 = row1 (v0-3), xmm2-3 = row2 (v4-7),
//   xmm4-5 = row3 (v8-11), xmm6-7 = row4 (v12-15), xmm8-9 = temps.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

{$IFDEF MSWINDOWS}
  sub rsp, 64
  movdqu oword [rsp], xmm6
  movdqu oword [rsp + $10], xmm7
  movdqu oword [rsp + $20], xmm8
  movdqu oword [rsp + $30], xmm9
{$ENDIF}

  // Initialize working vector
  movdqu xmm0, oword [rcx]
  movdqu xmm1, oword [rcx + $10]
  movdqu xmm2, oword [rcx + $20]
  movdqu xmm3, oword [rcx + $30]
  movdqu xmm4, oword [r9]
  movdqu xmm5, oword [r9 + $10]
  movdqu xmm6, oword [r9 + $20]
  movdqu xmm7, oword [r9 + $30]

  // XOR row4 with counter and flags
  movdqu xmm8, oword [r8]
  movdqu xmm9, oword [r8 + $10]
  pxor xmm6, xmm8
  pxor xmm7, xmm9

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2 / m4,m6)
  movq xmm8, qword [rdx]
  movhpd xmm8, qword [rdx + $10]
  movq xmm9, qword [rdx + $20]
  movhpd xmm9, qword [rdx + $30]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m1,m3 / m5,m7)
  movq xmm8, qword [rdx + $08]
  movhpd xmm8, qword [rdx + $18]
  movq xmm9, qword [rdx + $28]
  movhpd xmm9, qword [rdx + $38]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m8,m10 / m12,m14)
  movq xmm8, qword [rdx + $40]
  movhpd xmm8, qword [rdx + $50]
  movq xmm9, qword [rdx + $60]
  movhpd xmm9, qword [rdx + $70]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m9,m11 / m13,m15)
  movq xmm8, qword [rdx + $48]
  movhpd xmm8, qword [rdx + $58]
  movq xmm9, qword [rdx + $68]
  movhpd xmm9, qword [rdx + $78]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4 / m9,m13)
  movq xmm8, qword [rdx + $70]
  movhpd xmm8, qword [rdx + $20]
  movq xmm9, qword [rdx + $48]
  movhpd xmm9, qword [rdx + $68]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m10,m8 / m15,m6)
  movq xmm8, qword [rdx + $50]
  movhpd xmm8, qword [rdx + $40]
  movq xmm9, qword [rdx + $78]
  movhpd xmm9, qword [rdx + $30]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m1,m0 / m11,m5)
  movq xmm8, qword [rdx + $08]
  movhpd xmm8, qword [rdx]
  movq xmm9, qword [rdx + $58]
  movhpd xmm9, qword [rdx + $28]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m12,m2 / m7,m3)
  movq xmm8, qword [rdx + $60]
  movhpd xmm8, qword [rdx + $10]
  movq xmm9, qword [rdx + $38]
  movhpd xmm9, qword [rdx + $18]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12 / m5,m15)
  movq xmm8, qword [rdx + $58]
  movhpd xmm8, qword [rdx + $60]
  movq xmm9, qword [rdx + $28]
  movhpd xmm9, qword [rdx + $78]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m8,m0 / m2,m13)
  movq xmm8, qword [rdx + $40]
  movhpd xmm8, qword [rdx]
  movq xmm9, qword [rdx + $10]
  movhpd xmm9, qword [rdx + $68]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m10,m3 / m7,m9)
  movq xmm8, qword [rdx + $50]
  movhpd xmm8, qword [rdx + $18]
  movq xmm9, qword [rdx + $38]
  movhpd xmm9, qword [rdx + $48]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m14,m6 / m1,m4)
  movq xmm8, qword [rdx + $70]
  movhpd xmm8, qword [rdx + $30]
  movq xmm9, qword [rdx + $08]
  movhpd xmm9, qword [rdx + $20]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3 / m13,m11)
  movq xmm8, qword [rdx + $38]
  movhpd xmm8, qword [rdx + $18]
  movq xmm9, qword [rdx + $68]
  movhpd xmm9, qword [rdx + $58]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m9,m1 / m12,m14)
  movq xmm8, qword [rdx + $48]
  movhpd xmm8, qword [rdx + $08]
  movq xmm9, qword [rdx + $60]
  movhpd xmm9, qword [rdx + $70]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m2,m5 / m4,m15)
  movq xmm8, qword [rdx + $10]
  movhpd xmm8, qword [rdx + $28]
  movq xmm9, qword [rdx + $20]
  movhpd xmm9, qword [rdx + $78]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m6,m10 / m0,m8)
  movq xmm8, qword [rdx + $30]
  movhpd xmm8, qword [rdx + $50]
  movq xmm9, qword [rdx]
  movhpd xmm9, qword [rdx + $40]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5 / m2,m10)
  movq xmm8, qword [rdx + $48]
  movhpd xmm8, qword [rdx + $28]
  movq xmm9, qword [rdx + $10]
  movhpd xmm9, qword [rdx + $50]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m0,m7 / m4,m15)
  movq xmm8, qword [rdx]
  movhpd xmm8, qword [rdx + $38]
  movq xmm9, qword [rdx + $20]
  movhpd xmm9, qword [rdx + $78]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m14,m11 / m6,m3)
  movq xmm8, qword [rdx + $70]
  movhpd xmm8, qword [rdx + $58]
  movq xmm9, qword [rdx + $30]
  movhpd xmm9, qword [rdx + $18]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m1,m12 / m8,m13)
  movq xmm8, qword [rdx + $08]
  movhpd xmm8, qword [rdx + $60]
  movq xmm9, qword [rdx + $40]
  movhpd xmm9, qword [rdx + $68]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6 / m0,m8)
  movq xmm8, qword [rdx + $10]
  movhpd xmm8, qword [rdx + $30]
  movq xmm9, qword [rdx]
  movhpd xmm9, qword [rdx + $40]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m12,m10 / m11,m3)
  movq xmm8, qword [rdx + $60]
  movhpd xmm8, qword [rdx + $50]
  movq xmm9, qword [rdx + $58]
  movhpd xmm9, qword [rdx + $18]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m4,m7 / m15,m1)
  movq xmm8, qword [rdx + $20]
  movhpd xmm8, qword [rdx + $38]
  movq xmm9, qword [rdx + $78]
  movhpd xmm9, qword [rdx + $08]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m13,m5 / m14,m9)
  movq xmm8, qword [rdx + $68]
  movhpd xmm8, qword [rdx + $28]
  movq xmm9, qword [rdx + $70]
  movhpd xmm9, qword [rdx + $48]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1 / m14,m4)
  movq xmm8, qword [rdx + $60]
  movhpd xmm8, qword [rdx + $08]
  movq xmm9, qword [rdx + $70]
  movhpd xmm9, qword [rdx + $20]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m5,m15 / m13,m10)
  movq xmm8, qword [rdx + $28]
  movhpd xmm8, qword [rdx + $78]
  movq xmm9, qword [rdx + $68]
  movhpd xmm9, qword [rdx + $50]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m0,m6 / m9,m8)
  movq xmm8, qword [rdx]
  movhpd xmm8, qword [rdx + $30]
  movq xmm9, qword [rdx + $48]
  movhpd xmm9, qword [rdx + $40]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m7,m3 / m2,m11)
  movq xmm8, qword [rdx + $38]
  movhpd xmm8, qword [rdx + $18]
  movq xmm9, qword [rdx + $10]
  movhpd xmm9, qword [rdx + $58]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7 / m12,m3)
  movq xmm8, qword [rdx + $68]
  movhpd xmm8, qword [rdx + $38]
  movq xmm9, qword [rdx + $60]
  movhpd xmm9, qword [rdx + $18]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m11,m14 / m1,m9)
  movq xmm8, qword [rdx + $58]
  movhpd xmm8, qword [rdx + $70]
  movq xmm9, qword [rdx + $08]
  movhpd xmm9, qword [rdx + $48]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m5,m15 / m8,m2)
  movq xmm8, qword [rdx + $28]
  movhpd xmm8, qword [rdx + $78]
  movq xmm9, qword [rdx + $40]
  movhpd xmm9, qword [rdx + $10]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m0,m4 / m6,m10)
  movq xmm8, qword [rdx]
  movhpd xmm8, qword [rdx + $20]
  movq xmm9, qword [rdx + $30]
  movhpd xmm9, qword [rdx + $50]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14 / m11,m0)
  movq xmm8, qword [rdx + $30]
  movhpd xmm8, qword [rdx + $70]
  movq xmm9, qword [rdx + $58]
  movhpd xmm9, qword [rdx]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m15,m9 / m3,m8)
  movq xmm8, qword [rdx + $78]
  movhpd xmm8, qword [rdx + $48]
  movq xmm9, qword [rdx + $18]
  movhpd xmm9, qword [rdx + $40]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m12,m13 / m1,m10)
  movq xmm8, qword [rdx + $60]
  movhpd xmm8, qword [rdx + $68]
  movq xmm9, qword [rdx + $08]
  movhpd xmm9, qword [rdx + $50]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m2,m7 / m4,m5)
  movq xmm8, qword [rdx + $10]
  movhpd xmm8, qword [rdx + $38]
  movq xmm9, qword [rdx + $20]
  movhpd xmm9, qword [rdx + $28]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8 / m7,m1)
  movq xmm8, qword [rdx + $50]
  movhpd xmm8, qword [rdx + $40]
  movq xmm9, qword [rdx + $38]
  movhpd xmm9, qword [rdx + $08]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m2,m4 / m6,m5)
  movq xmm8, qword [rdx + $10]
  movhpd xmm8, qword [rdx + $20]
  movq xmm9, qword [rdx + $30]
  movhpd xmm9, qword [rdx + $28]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m15,m9 / m3,m13)
  movq xmm8, qword [rdx + $78]
  movhpd xmm8, qword [rdx + $48]
  movq xmm9, qword [rdx + $18]
  movhpd xmm9, qword [rdx + $68]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m11,m14 / m12,m0)
  movq xmm8, qword [rdx + $58]
  movhpd xmm8, qword [rdx + $70]
  movq xmm9, qword [rdx + $60]
  movhpd xmm9, qword [rdx]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 10 =====

  // G1 columns (msg: m0,m2 / m4,m6)
  movq xmm8, qword [rdx]
  movhpd xmm8, qword [rdx + $10]
  movq xmm9, qword [rdx + $20]
  movhpd xmm9, qword [rdx + $30]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m1,m3 / m5,m7)
  movq xmm8, qword [rdx + $08]
  movhpd xmm8, qword [rdx + $18]
  movq xmm9, qword [rdx + $28]
  movhpd xmm9, qword [rdx + $38]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m8,m10 / m12,m14)
  movq xmm8, qword [rdx + $40]
  movhpd xmm8, qword [rdx + $50]
  movq xmm9, qword [rdx + $60]
  movhpd xmm9, qword [rdx + $70]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m9,m11 / m13,m15)
  movq xmm8, qword [rdx + $48]
  movhpd xmm8, qword [rdx + $58]
  movq xmm9, qword [rdx + $68]
  movhpd xmm9, qword [rdx + $78]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // ===== Round 11 =====

  // G1 columns (msg: m14,m4 / m9,m13)
  movq xmm8, qword [rdx + $70]
  movhpd xmm8, qword [rdx + $20]
  movq xmm9, qword [rdx + $48]
  movhpd xmm9, qword [rdx + $68]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 columns (msg: m10,m8 / m15,m6)
  movq xmm8, qword [rdx + $50]
  movhpd xmm8, qword [rdx + $40]
  movq xmm9, qword [rdx + $78]
  movhpd xmm9, qword [rdx + $30]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Diagonalize
  movdqa xmm8, xmm6
  movdqa xmm9, xmm2

  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6

  movdqa xmm6, xmm7
  shufpd xmm7, xmm8, $01
  shufpd xmm8, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm8

  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm9, $01

  // G1 diagonals (msg: m1,m0 / m11,m5)
  movq xmm8, qword [rdx + $08]
  movhpd xmm8, qword [rdx]
  movq xmm9, qword [rdx + $58]
  movhpd xmm9, qword [rdx + $28]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 24
  psllq xmm2, 40
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 24
  psllq xmm3, 40
  por xmm3, xmm9

  // G2 diagonals (msg: m12,m2 / m7,m3)
  movq xmm8, qword [rdx + $60]
  movhpd xmm8, qword [rdx + $10]
  movq xmm9, qword [rdx + $38]
  movhpd xmm9, qword [rdx + $18]
  paddq xmm0, xmm8
  paddq xmm0, xmm2
  paddq xmm1, xmm9
  paddq xmm1, xmm3

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqa xmm8, xmm6
  psrlq xmm8, 16
  psllq xmm6, 48
  por xmm6, xmm8
  movdqa xmm9, xmm7
  psrlq xmm9, 16
  psllq xmm7, 48
  por xmm7, xmm9

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqa xmm8, xmm2
  psrlq xmm8, 63
  paddq xmm2, xmm2
  por xmm2, xmm8
  movdqa xmm9, xmm3
  psrlq xmm9, 63
  paddq xmm3, xmm3
  por xmm3, xmm9

  // Undiagonalize
  movdqa xmm8, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm8

  movdqa xmm8, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm8, $01

  movdqa xmm8, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm8, $01
  shufpd xmm8, xmm3, $01
  movdqa xmm3, xmm8

  // Finalization
  pxor xmm0, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm6
  pxor xmm3, xmm7

  // XOR with original state (re-read from memory via movdqu for safe unaligned access)
  movdqu xmm8, oword [rcx]
  pxor xmm0, xmm8
  movdqu xmm9, oword [rcx + $10]
  pxor xmm1, xmm9
  movdqu xmm8, oword [rcx + $20]
  pxor xmm2, xmm8
  movdqu xmm9, oword [rcx + $30]
  pxor xmm3, xmm9

  // Store result
  movdqu oword [rcx], xmm0
  movdqu oword [rcx + $10], xmm1
  movdqu oword [rcx + $20], xmm2
  movdqu oword [rcx + $30], xmm3

{$IFDEF MSWINDOWS}
  movdqu xmm6, oword [rsp]
  movdqu xmm7, oword [rsp + $10]
  movdqu xmm8, oword [rsp + $20]
  movdqu xmm9, oword [rsp + $30]
  add rsp, 64
{$ENDIF}
