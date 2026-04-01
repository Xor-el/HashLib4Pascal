// SSE2 implementation of BLAKE2b compress (fully unrolled 12 rounds).
// IA-32: after SimdProc4Begin_i386 — ebx = state, esi = msg, edi = counter+flags, eax = IV
//   (parallel to MS x64 ABI: rcx, rdx, r8, r9).
// XMM8+ from x64 eliminated: xmm4 scratch + stack, xmm0/1 for diagonal work; uses xmm0–xmm7.
// Non-volatile xmm6–xmm7 saved in stack frame (sub esp, 128).
// Register map: xmm0-1 = row1 (v0-3), xmm2-3 = row2 (v4-7), xmm4-5 = row3 (v8-11), xmm6-7 = row4 (v12-15)
//   with temps folded per IA-32 constraints.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

  sub esp, 128
  movdqu oword ptr [esp], xmm6
  movdqu oword ptr [esp + $10], xmm7

  // Initialize working vector
  movdqu xmm0, oword ptr [ebx]
  movdqu xmm1, oword ptr [ebx + $10]
  movdqu xmm2, oword ptr [ebx + $20]
  movdqu xmm3, oword ptr [ebx + $30]
  movdqu xmm4, oword ptr [eax]
  movdqu xmm5, oword ptr [eax + $10]
  movdqu xmm6, oword ptr [eax + $20]
  movdqu xmm7, oword ptr [eax + $30]

  // XOR row4 with counter and flags
  movdqu oword ptr [esp + $20], xmm4
  movdqu xmm4, oword ptr [edi]
  pxor xmm6, xmm4
  movdqu xmm4, oword ptr [edi + $10]
  pxor xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2 / m4,m6)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $10]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m1,m3 / m5,m7)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $28]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m8,m10 / m12,m14)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $40]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m9,m11 / m13,m15)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $58]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4 / m9,m13)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m10,m8 / m15,m6)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $50]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $78]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m1,m0 / m11,m5)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m12,m2 / m7,m3)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $10]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12 / m5,m15)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $60]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $28]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m8,m0 / m2,m13)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $40]
  movhpd xmm4, qword ptr [esi]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m10,m3 / m7,m9)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $50]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $48]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m14,m6 / m1,m4)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3 / m13,m11)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $58]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m9,m1 / m12,m14)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $08]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m2,m5 / m4,m15)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m6,m10 / m0,m8)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $30]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5 / m2,m10)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m0,m7 / m4,m15)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m14,m11 / m6,m3)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $58]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $30]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m1,m12 / m8,m13)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $60]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $40]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6 / m0,m8)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m12,m10 / m11,m3)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m4,m7 / m15,m1)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $78]
  movhpd xmm4, qword ptr [esi + $08]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m13,m5 / m14,m9)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $48]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1 / m14,m4)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $08]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m5,m15 / m13,m10)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $28]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m0,m6 / m9,m8)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m7,m3 / m2,m11)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $58]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7 / m12,m3)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m11,m14 / m1,m9)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $48]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m5,m15 / m8,m2)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $28]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $40]
  movhpd xmm4, qword ptr [esi + $10]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m0,m4 / m6,m10)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $30]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14 / m11,m0)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $30]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m15,m9 / m3,m8)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $78]
  movhpd xmm4, qword ptr [esi + $48]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $18]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m12,m13 / m1,m10)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m2,m7 / m4,m5)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8 / m7,m1)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $50]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $08]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m2,m4 / m6,m5)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $10]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $30]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m15,m9 / m3,m13)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $78]
  movhpd xmm4, qword ptr [esi + $48]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $18]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m11,m14 / m12,m0)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 10 =====

  // G1 columns (msg: m0,m2 / m4,m6)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi]
  movhpd xmm4, qword ptr [esi + $10]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $20]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m1,m3 / m5,m7)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $28]
  movhpd xmm4, qword ptr [esi + $38]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m8,m10 / m12,m14)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $40]
  movhpd xmm4, qword ptr [esi + $50]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $70]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m9,m11 / m13,m15)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $58]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $68]
  movhpd xmm4, qword ptr [esi + $78]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // ===== Round 11 =====

  // G1 columns (msg: m14,m4 / m9,m13)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $70]
  movhpd xmm4, qword ptr [esi + $20]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $48]
  movhpd xmm4, qword ptr [esi + $68]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 columns (msg: m10,m8 / m15,m6)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $50]
  movhpd xmm4, qword ptr [esi + $40]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $78]
  movhpd xmm4, qword ptr [esi + $30]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Diagonalize (i386: xmm0/1 scratch; no XMM8+)
  movdqu oword ptr [esp + $40], xmm0
  movdqu oword ptr [esp + $50], xmm1
  movdqa xmm0, xmm6
  movdqa xmm1, xmm2
  movdqa xmm6, xmm4
  movdqa xmm4, xmm5
  movdqa xmm5, xmm6
  movdqa xmm6, xmm7
  shufpd xmm7, xmm0, $01
  shufpd xmm0, xmm6, $01
  movdqa xmm6, xmm7
  movdqa xmm7, xmm0
  shufpd xmm2, xmm3, $01
  shufpd xmm3, xmm1, $01
  movdqu xmm0, oword ptr [esp + $40]
  movdqu xmm1, oword ptr [esp + $50]

  // G1 diagonals (msg: m1,m0 / m11,m5)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $08]
  movhpd xmm4, qword ptr [esi]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $58]
  movhpd xmm4, qword ptr [esi + $28]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  pshufd xmm6, xmm6, $B1
  pshufd xmm7, xmm7, $B1

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 24
  psllq xmm2, 40
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 24
  psllq xmm3, 40
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // G2 diagonals (msg: m12,m2 / m7,m3)
  movdqu oword ptr [esp + $20], xmm4
  movq xmm4, qword ptr [esi + $60]
  movhpd xmm4, qword ptr [esi + $10]
  paddq xmm0, xmm4
  paddq xmm0, xmm2
  movq xmm4, qword ptr [esi + $38]
  movhpd xmm4, qword ptr [esi + $18]
  paddq xmm1, xmm4
  paddq xmm1, xmm3
  movdqu xmm4, oword ptr [esp + $20]

  pxor xmm6, xmm0
  pxor xmm7, xmm1
  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm6
  psrlq xmm4, 16
  psllq xmm6, 48
  por xmm6, xmm4
  movdqa xmm4, xmm7
  psrlq xmm4, 16
  psllq xmm7, 48
  por xmm7, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  paddq xmm4, xmm6
  paddq xmm5, xmm7
  pxor xmm2, xmm4
  pxor xmm3, xmm5

  movdqu oword ptr [esp + $20], xmm4
  movdqa xmm4, xmm2
  psrlq xmm4, 63
  paddq xmm2, xmm2
  por xmm2, xmm4
  movdqa xmm4, xmm3
  psrlq xmm4, 63
  paddq xmm3, xmm3
  por xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Undiagonalize (i386: memory swap + xmm0 scratch)
  movdqu oword ptr [esp + $70], xmm4
  movdqa xmm4, xmm5
  movdqu xmm5, oword ptr [esp + $70]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm6
  shufpd xmm6, xmm7, $01
  shufpd xmm7, xmm0, $01
  movdqu xmm0, oword ptr [esp + $40]

  movdqu oword ptr [esp + $40], xmm0
  movdqa xmm0, xmm2
  movdqa xmm2, xmm3
  shufpd xmm2, xmm0, $01
  shufpd xmm0, xmm3, $01
  movdqa xmm3, xmm0
  movdqu xmm0, oword ptr [esp + $40]

  // Finalization
  pxor xmm0, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm6
  pxor xmm3, xmm7

  // XOR with original state (re-read from memory via movdqu for safe unaligned access)
  movdqu oword ptr [esp + $20], xmm4
  movdqu xmm4, oword ptr [ebx]
  pxor xmm0, xmm4
  movdqu xmm4, oword ptr [ebx + $10]
  pxor xmm1, xmm4
  movdqu xmm4, oword ptr [ebx + $20]
  pxor xmm2, xmm4
  movdqu xmm4, oword ptr [ebx + $30]
  pxor xmm3, xmm4
  movdqu xmm4, oword ptr [esp + $20]

  // Store result
  movdqu oword ptr [ebx], xmm0
  movdqu oword ptr [ebx + $10], xmm1
  movdqu oword ptr [ebx + $20], xmm2
  movdqu oword ptr [ebx + $30], xmm3

  movdqu xmm6, oword ptr [esp]
  movdqu xmm7, oword ptr [esp + $10]
  add esp, 128
  pop edi
  pop esi
  pop ebx
