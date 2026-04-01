// AVX2 implementation of BLAKE2s compress (VEX-encoded 128-bit, fully unrolled 10 rounds).
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = counter+flags ptr, r9 = IV ptr.
// Uses xmm0-xmm6. Non-volatile xmm6 saved/restored on Windows.
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15),
//   xmm4 = message buffer, xmm5 = temp, xmm6 = temp (msg load).
// 3-operand VEX form eliminates movdqa copies needed in SSE2 rotations.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves.

{$IFDEF MSWINDOWS}
  sub rsp, 16
  db $C5, $FA, $7F, $34, $24                    // vmovdqu oword [rsp], xmm6
{$ENDIF}

  // Initialize working vector
  db $C5, $FA, $6F, $01                         // vmovdqu xmm0, oword [rcx]
  db $C5, $FA, $6F, $49, $10                    // vmovdqu xmm1, oword [rcx + $10]
  db $C4, $C1, $7A, $6F, $11                    // vmovdqu xmm2, oword [r9]
  db $C4, $C1, $7A, $6F, $59, $10               // vmovdqu xmm3, oword [r9 + $10]

  // XOR d with counter and flags
  db $C4, $C1, $7A, $6F, $20                    // vmovdqu xmm4, oword [r8]
  db $C5, $E1, $EF, $DC                         // vpxor xmm3, xmm3, xmm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C4, $E1, $79, $6E, $22                    // vmovd xmm4, dword [rdx]
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C4, $E1, $79, $6E, $72, $18               // vmovd xmm6, dword [rdx + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m1,m3,m5,m7)
  db $C4, $E1, $79, $6E, $62, $04               // vmovd xmm4, dword [rdx + $04]
  db $C4, $E1, $79, $6E, $6A, $0C               // vmovd xmm5, dword [rdx + $0C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $72, $1C               // vmovd xmm6, dword [rdx + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C4, $E1, $79, $6E, $62, $38               // vmovd xmm4, dword [rdx + $38]
  db $C4, $E1, $79, $6E, $6A, $20               // vmovd xmm5, dword [rdx + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $28               // vmovd xmm5, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $72, $30               // vmovd xmm6, dword [rdx + $30]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C4, $E1, $79, $6E, $62, $3C               // vmovd xmm4, dword [rdx + $3C]
  db $C4, $E1, $79, $6E, $6A, $24               // vmovd xmm5, dword [rdx + $24]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $2C               // vmovd xmm5, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $72, $34               // vmovd xmm6, dword [rdx + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C4, $E1, $79, $6E, $62, $38               // vmovd xmm4, dword [rdx + $38]
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $24               // vmovd xmm5, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $72, $34               // vmovd xmm6, dword [rdx + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m10,m8,m15,m6)
  db $C4, $E1, $79, $6E, $62, $28               // vmovd xmm4, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $6A, $20               // vmovd xmm5, dword [rdx + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $3C               // vmovd xmm5, dword [rdx + $3C]
  db $C4, $E1, $79, $6E, $72, $18               // vmovd xmm6, dword [rdx + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C4, $E1, $79, $6E, $62, $14               // vmovd xmm4, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $6A, $04               // vmovd xmm5, dword [rdx + $04]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $2A                    // vmovd xmm5, dword [rdx]
  db $C4, $E1, $79, $6E, $72, $2C               // vmovd xmm6, dword [rdx + $2C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C4, $E1, $79, $6E, $62, $0C               // vmovd xmm4, dword [rdx + $0C]
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $72, $1C               // vmovd xmm6, dword [rdx + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12,m5,m15)
  db $C4, $E1, $79, $6E, $62, $2C               // vmovd xmm4, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $72, $3C               // vmovd xmm6, dword [rdx + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m8,m0,m2,m13)
  db $C4, $E1, $79, $6E, $62, $20               // vmovd xmm4, dword [rdx + $20]
  db $C4, $E1, $79, $6E, $2A                    // vmovd xmm5, dword [rdx]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $72, $34               // vmovd xmm6, dword [rdx + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m9,m10,m3,m7)
  db $C4, $E1, $79, $6E, $62, $24               // vmovd xmm4, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $6A, $28               // vmovd xmm5, dword [rdx + $28]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $0C               // vmovd xmm5, dword [rdx + $0C]
  db $C4, $E1, $79, $6E, $72, $1C               // vmovd xmm6, dword [rdx + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m4,m14,m6,m1)
  db $C4, $E1, $79, $6E, $62, $10               // vmovd xmm4, dword [rdx + $10]
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $18               // vmovd xmm5, dword [rdx + $18]
  db $C4, $E1, $79, $6E, $72, $04               // vmovd xmm6, dword [rdx + $04]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3,m13,m11)
  db $C4, $E1, $79, $6E, $62, $1C               // vmovd xmm4, dword [rdx + $1C]
  db $C4, $E1, $79, $6E, $6A, $0C               // vmovd xmm5, dword [rdx + $0C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $34               // vmovd xmm5, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $72, $2C               // vmovd xmm6, dword [rdx + $2C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m9,m1,m12,m14)
  db $C4, $E1, $79, $6E, $62, $24               // vmovd xmm4, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $6A, $04               // vmovd xmm5, dword [rdx + $04]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C4, $E1, $79, $6E, $72, $38               // vmovd xmm6, dword [rdx + $38]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m15,m2,m5,m4)
  db $C4, $E1, $79, $6E, $62, $3C               // vmovd xmm4, dword [rdx + $3C]
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $72, $10               // vmovd xmm6, dword [rdx + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m8,m6,m10,m0)
  db $C4, $E1, $79, $6E, $62, $20               // vmovd xmm4, dword [rdx + $20]
  db $C4, $E1, $79, $6E, $6A, $18               // vmovd xmm5, dword [rdx + $18]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $28               // vmovd xmm5, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $32                    // vmovd xmm6, dword [rdx]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5,m2,m10)
  db $C4, $E1, $79, $6E, $62, $24               // vmovd xmm4, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $72, $28               // vmovd xmm6, dword [rdx + $28]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m0,m7,m4,m15)
  db $C4, $E1, $79, $6E, $22                    // vmovd xmm4, dword [rdx]
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C4, $E1, $79, $6E, $72, $3C               // vmovd xmm6, dword [rdx + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m3,m14,m11,m6)
  db $C4, $E1, $79, $6E, $62, $0C               // vmovd xmm4, dword [rdx + $0C]
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $2C               // vmovd xmm5, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $72, $18               // vmovd xmm6, dword [rdx + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m13,m1,m12,m8)
  db $C4, $E1, $79, $6E, $62, $34               // vmovd xmm4, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $6A, $04               // vmovd xmm5, dword [rdx + $04]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C4, $E1, $79, $6E, $72, $20               // vmovd xmm6, dword [rdx + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6,m0,m8)
  db $C4, $E1, $79, $6E, $62, $08               // vmovd xmm4, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $6A, $18               // vmovd xmm5, dword [rdx + $18]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $2A                    // vmovd xmm5, dword [rdx]
  db $C4, $E1, $79, $6E, $72, $20               // vmovd xmm6, dword [rdx + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m12,m10,m11,m3)
  db $C4, $E1, $79, $6E, $62, $30               // vmovd xmm4, dword [rdx + $30]
  db $C4, $E1, $79, $6E, $6A, $28               // vmovd xmm5, dword [rdx + $28]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $2C               // vmovd xmm5, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $72, $0C               // vmovd xmm6, dword [rdx + $0C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m1,m4,m7,m15)
  db $C4, $E1, $79, $6E, $62, $04               // vmovd xmm4, dword [rdx + $04]
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C4, $E1, $79, $6E, $72, $3C               // vmovd xmm6, dword [rdx + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m9,m13,m5,m14)
  db $C4, $E1, $79, $6E, $62, $24               // vmovd xmm4, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $6A, $34               // vmovd xmm5, dword [rdx + $34]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $72, $38               // vmovd xmm6, dword [rdx + $38]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1,m14,m4)
  db $C4, $E1, $79, $6E, $62, $30               // vmovd xmm4, dword [rdx + $30]
  db $C4, $E1, $79, $6E, $6A, $04               // vmovd xmm5, dword [rdx + $04]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C4, $E1, $79, $6E, $72, $10               // vmovd xmm6, dword [rdx + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m5,m15,m13,m10)
  db $C4, $E1, $79, $6E, $62, $14               // vmovd xmm4, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $6A, $3C               // vmovd xmm5, dword [rdx + $3C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $34               // vmovd xmm5, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $72, $28               // vmovd xmm6, dword [rdx + $28]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m8,m0,m6,m9)
  db $C4, $E1, $79, $6E, $62, $20               // vmovd xmm4, dword [rdx + $20]
  db $C4, $E1, $79, $6E, $2A                    // vmovd xmm5, dword [rdx]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $18               // vmovd xmm5, dword [rdx + $18]
  db $C4, $E1, $79, $6E, $72, $24               // vmovd xmm6, dword [rdx + $24]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m11,m7,m3,m2)
  db $C4, $E1, $79, $6E, $62, $2C               // vmovd xmm4, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $0C               // vmovd xmm5, dword [rdx + $0C]
  db $C4, $E1, $79, $6E, $72, $08               // vmovd xmm6, dword [rdx + $08]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7,m12,m3)
  db $C4, $E1, $79, $6E, $62, $34               // vmovd xmm4, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C4, $E1, $79, $6E, $72, $0C               // vmovd xmm6, dword [rdx + $0C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m11,m14,m1,m9)
  db $C4, $E1, $79, $6E, $62, $2C               // vmovd xmm4, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $04               // vmovd xmm5, dword [rdx + $04]
  db $C4, $E1, $79, $6E, $72, $24               // vmovd xmm6, dword [rdx + $24]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m2,m5,m15,m8)
  db $C4, $E1, $79, $6E, $62, $08               // vmovd xmm4, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $6A, $14               // vmovd xmm5, dword [rdx + $14]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $3C               // vmovd xmm5, dword [rdx + $3C]
  db $C4, $E1, $79, $6E, $72, $20               // vmovd xmm6, dword [rdx + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m10,m0,m4,m6)
  db $C4, $E1, $79, $6E, $62, $28               // vmovd xmm4, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $2A                    // vmovd xmm5, dword [rdx]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C4, $E1, $79, $6E, $72, $18               // vmovd xmm6, dword [rdx + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14,m11,m0)
  db $C4, $E1, $79, $6E, $62, $18               // vmovd xmm4, dword [rdx + $18]
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $2C               // vmovd xmm5, dword [rdx + $2C]
  db $C4, $E1, $79, $6E, $32                    // vmovd xmm6, dword [rdx]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m15,m9,m3,m8)
  db $C4, $E1, $79, $6E, $62, $3C               // vmovd xmm4, dword [rdx + $3C]
  db $C4, $E1, $79, $6E, $6A, $24               // vmovd xmm5, dword [rdx + $24]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $0C               // vmovd xmm5, dword [rdx + $0C]
  db $C4, $E1, $79, $6E, $72, $20               // vmovd xmm6, dword [rdx + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m10,m12,m13,m1)
  db $C4, $E1, $79, $6E, $62, $28               // vmovd xmm4, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $6A, $30               // vmovd xmm5, dword [rdx + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $34               // vmovd xmm5, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $72, $04               // vmovd xmm6, dword [rdx + $04]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m5,m2,m7,m4)
  db $C4, $E1, $79, $6E, $62, $14               // vmovd xmm4, dword [rdx + $14]
  db $C4, $E1, $79, $6E, $6A, $08               // vmovd xmm5, dword [rdx + $08]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C4, $E1, $79, $6E, $72, $10               // vmovd xmm6, dword [rdx + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8,m7,m1)
  db $C4, $E1, $79, $6E, $62, $28               // vmovd xmm4, dword [rdx + $28]
  db $C4, $E1, $79, $6E, $6A, $20               // vmovd xmm5, dword [rdx + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $1C               // vmovd xmm5, dword [rdx + $1C]
  db $C4, $E1, $79, $6E, $72, $04               // vmovd xmm6, dword [rdx + $04]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 columns (msg: m2,m4,m6,m5)
  db $C4, $E1, $79, $6E, $62, $08               // vmovd xmm4, dword [rdx + $08]
  db $C4, $E1, $79, $6E, $6A, $10               // vmovd xmm5, dword [rdx + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $18               // vmovd xmm5, dword [rdx + $18]
  db $C4, $E1, $79, $6E, $72, $14               // vmovd xmm6, dword [rdx + $14]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m13,m15,m9,m3)
  db $C4, $E1, $79, $6E, $62, $34               // vmovd xmm4, dword [rdx + $34]
  db $C4, $E1, $79, $6E, $6A, $3C               // vmovd xmm5, dword [rdx + $3C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $24               // vmovd xmm5, dword [rdx + $24]
  db $C4, $E1, $79, $6E, $72, $0C               // vmovd xmm6, dword [rdx + $0C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $10                    // vpsrld xmm5, xmm3, 16
  db $C5, $E1, $72, $F3, $10                    // vpslld xmm3, xmm3, 16
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, 12
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, 20
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // G2 diagonals (msg: m0,m11,m14,m12)
  db $C4, $E1, $79, $6E, $22                    // vmovd xmm4, dword [rdx]
  db $C4, $E1, $79, $6E, $6A, $2C               // vmovd xmm5, dword [rdx + $2C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C4, $E1, $79, $6E, $6A, $38               // vmovd xmm5, dword [rdx + $38]
  db $C4, $E1, $79, $6E, $72, $30               // vmovd xmm6, dword [rdx + $30]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor xmm3, xmm3, xmm0
  db $C5, $D1, $72, $D3, $08                    // vpsrld xmm5, xmm3, 8
  db $C5, $E1, $72, $F3, $18                    // vpslld xmm3, xmm3, 24
  db $C5, $E1, $EB, $DD                         // vpor xmm3, xmm3, xmm5

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, 7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, 25
  db $C5, $F1, $EB, $CD                         // vpor xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // Finalization: state[i] ^= v[i] ^ v[i+8]
  db $C5, $F9, $EF, $C2                         // vpxor xmm0, xmm0, xmm2
  db $C5, $F1, $EF, $CB                         // vpxor xmm1, xmm1, xmm3
  db $C5, $FA, $6F, $21                         // vmovdqu xmm4, oword [rcx]
  db $C5, $F9, $EF, $C4                         // vpxor xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $61, $10                    // vmovdqu xmm4, oword [rcx + $10]
  db $C5, $F1, $EF, $CC                         // vpxor xmm1, xmm1, xmm4

  // Store result
  db $C5, $FA, $7F, $01                         // vmovdqu oword [rcx], xmm0
  db $C5, $FA, $7F, $49, $10                    // vmovdqu oword [rcx + $10], xmm1

{$IFDEF MSWINDOWS}
  db $C5, $FA, $6F, $34, $24                    // vmovdqu xmm6, oword [rsp]
  add rsp, 16
{$ENDIF}

  db $C5, $F8, $77                              // vzeroupper
