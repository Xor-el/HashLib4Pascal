// AVX (VEX-128) implementation of BLAKE2s compress (IA-32; fully unrolled
// 10 rounds). Same structure as Blake2SCompressAvx_x86_64.inc,
// with the rot8 mask read as a VEX memory operand per site (IA-32 has only
// xmm0-7, so no register is free to keep it resident; VEX memory operands
// are read unaligned, so the Pascal const needs no special alignment).
// IA-32: after HlpSimdProc5Begin_i386 - ebx = state ptr, esi = msg ptr,
//   edi = counter+flags ptr, eax = IV ptr, ecx = byte-rotation masks ptr
//   (see BLAKE2S_ROT_MASKS: rot16 at +0, rot8 at +16).
// Uses xmm0-xmm7; xmm6/xmm7 saved/restored defensively (volatile on IA-32).
// Register map: xmm0 = a (v0-3), xmm1 = b (v4-7), xmm2 = c (v8-11), xmm3 = d (v12-15),
//   xmm4 = message buffer, xmm5 = temp, xmm6 = temp (msg load), xmm7 = rot16 mask.
// Rotations: ROT16 via vpshufb against the resident xmm7 mask, ROT8 via
//   vpshufb against the [ecx+$10] memory operand, ROT12/7 via shift+or
//   (not byte-aligned; shifts are the known-best form).
// 3-operand VEX form eliminates movdqa copies needed in SSE2 rotations.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: BLAKE2/BLAKE2 sse/ by Samuel Neves, HashLib
// Blake2SCompressAvx2_x86_64.inc.

  // Defensive save of xmm6/xmm7 (volatile on IA-32; saved like the
  // SSE2 sibling to be safe under every RTL)
  sub    esp, $20
  db $C5, $FA, $7F, $34, $24                    // vmovdqu oword [esp], xmm6
  db $C5, $FA, $7F, $7C, $24, $10               // vmovdqu oword [esp + $10], xmm7


  // Load byte-rotation masks (resident for the whole kernel)
  db $C5, $FA, $6F, $39                         // vmovdqu xmm7, oword [ecx]

  // Initialize working vector
  db $C5, $FA, $6F, $03                         // vmovdqu xmm0, oword [ebx]
  db $C5, $FA, $6F, $4B, $10                    // vmovdqu xmm1, oword [ebx + $10]
  db $C5, $FA, $6F, $10                         // vmovdqu xmm2, oword [eax]
  db $C5, $FA, $6F, $58, $10                    // vmovdqu xmm3, oword [eax + $10]

  // XOR d with counter and flags
  db $C5, $FA, $6F, $27                         // vmovdqu xmm4, oword [edi]
  db $C5, $E1, $EF, $DC                         // vpxor  xmm3, xmm3, xmm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C5, $F9, $6E, $26                         // vmovd  xmm4, dword [esi]
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $F9, $6E, $76, $18                    // vmovd  xmm6, dword [esi + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m1,m3,m5,m7)
  db $C5, $F9, $6E, $66, $04                    // vmovd  xmm4, dword [esi + $4]
  db $C5, $F9, $6E, $6E, $0C                    // vmovd  xmm5, dword [esi + $C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $F9, $6E, $76, $1C                    // vmovd  xmm6, dword [esi + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C5, $F9, $6E, $66, $38                    // vmovd  xmm4, dword [esi + $38]
  db $C5, $F9, $6E, $6E, $20                    // vmovd  xmm5, dword [esi + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $28                    // vmovd  xmm5, dword [esi + $28]
  db $C5, $F9, $6E, $76, $30                    // vmovd  xmm6, dword [esi + $30]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C5, $F9, $6E, $66, $3C                    // vmovd  xmm4, dword [esi + $3C]
  db $C5, $F9, $6E, $6E, $24                    // vmovd  xmm5, dword [esi + $24]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $2C                    // vmovd  xmm5, dword [esi + $2C]
  db $C5, $F9, $6E, $76, $34                    // vmovd  xmm6, dword [esi + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C5, $F9, $6E, $66, $38                    // vmovd  xmm4, dword [esi + $38]
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $24                    // vmovd  xmm5, dword [esi + $24]
  db $C5, $F9, $6E, $76, $34                    // vmovd  xmm6, dword [esi + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m10,m8,m15,m6)
  db $C5, $F9, $6E, $66, $28                    // vmovd  xmm4, dword [esi + $28]
  db $C5, $F9, $6E, $6E, $20                    // vmovd  xmm5, dword [esi + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $3C                    // vmovd  xmm5, dword [esi + $3C]
  db $C5, $F9, $6E, $76, $18                    // vmovd  xmm6, dword [esi + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C5, $F9, $6E, $66, $14                    // vmovd  xmm4, dword [esi + $14]
  db $C5, $F9, $6E, $6E, $04                    // vmovd  xmm5, dword [esi + $4]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $2E                         // vmovd  xmm5, dword [esi]
  db $C5, $F9, $6E, $76, $2C                    // vmovd  xmm6, dword [esi + $2C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C5, $F9, $6E, $66, $0C                    // vmovd  xmm4, dword [esi + $C]
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $F9, $6E, $76, $1C                    // vmovd  xmm6, dword [esi + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12,m5,m15)
  db $C5, $F9, $6E, $66, $2C                    // vmovd  xmm4, dword [esi + $2C]
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $F9, $6E, $76, $3C                    // vmovd  xmm6, dword [esi + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m8,m0,m2,m13)
  db $C5, $F9, $6E, $66, $20                    // vmovd  xmm4, dword [esi + $20]
  db $C5, $F9, $6E, $2E                         // vmovd  xmm5, dword [esi]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $F9, $6E, $76, $34                    // vmovd  xmm6, dword [esi + $34]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m9,m10,m3,m7)
  db $C5, $F9, $6E, $66, $24                    // vmovd  xmm4, dword [esi + $24]
  db $C5, $F9, $6E, $6E, $28                    // vmovd  xmm5, dword [esi + $28]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $0C                    // vmovd  xmm5, dword [esi + $C]
  db $C5, $F9, $6E, $76, $1C                    // vmovd  xmm6, dword [esi + $1C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m4,m14,m6,m1)
  db $C5, $F9, $6E, $66, $10                    // vmovd  xmm4, dword [esi + $10]
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $18                    // vmovd  xmm5, dword [esi + $18]
  db $C5, $F9, $6E, $76, $04                    // vmovd  xmm6, dword [esi + $4]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3,m13,m11)
  db $C5, $F9, $6E, $66, $1C                    // vmovd  xmm4, dword [esi + $1C]
  db $C5, $F9, $6E, $6E, $0C                    // vmovd  xmm5, dword [esi + $C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $34                    // vmovd  xmm5, dword [esi + $34]
  db $C5, $F9, $6E, $76, $2C                    // vmovd  xmm6, dword [esi + $2C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m9,m1,m12,m14)
  db $C5, $F9, $6E, $66, $24                    // vmovd  xmm4, dword [esi + $24]
  db $C5, $F9, $6E, $6E, $04                    // vmovd  xmm5, dword [esi + $4]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $F9, $6E, $76, $38                    // vmovd  xmm6, dword [esi + $38]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m15,m2,m5,m4)
  db $C5, $F9, $6E, $66, $3C                    // vmovd  xmm4, dword [esi + $3C]
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $F9, $6E, $76, $10                    // vmovd  xmm6, dword [esi + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m8,m6,m10,m0)
  db $C5, $F9, $6E, $66, $20                    // vmovd  xmm4, dword [esi + $20]
  db $C5, $F9, $6E, $6E, $18                    // vmovd  xmm5, dword [esi + $18]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $28                    // vmovd  xmm5, dword [esi + $28]
  db $C5, $F9, $6E, $36                         // vmovd  xmm6, dword [esi]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5,m2,m10)
  db $C5, $F9, $6E, $66, $24                    // vmovd  xmm4, dword [esi + $24]
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $F9, $6E, $76, $28                    // vmovd  xmm6, dword [esi + $28]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m0,m7,m4,m15)
  db $C5, $F9, $6E, $26                         // vmovd  xmm4, dword [esi]
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $F9, $6E, $76, $3C                    // vmovd  xmm6, dword [esi + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m3,m14,m11,m6)
  db $C5, $F9, $6E, $66, $0C                    // vmovd  xmm4, dword [esi + $C]
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $2C                    // vmovd  xmm5, dword [esi + $2C]
  db $C5, $F9, $6E, $76, $18                    // vmovd  xmm6, dword [esi + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m13,m1,m12,m8)
  db $C5, $F9, $6E, $66, $34                    // vmovd  xmm4, dword [esi + $34]
  db $C5, $F9, $6E, $6E, $04                    // vmovd  xmm5, dword [esi + $4]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $F9, $6E, $76, $20                    // vmovd  xmm6, dword [esi + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6,m0,m8)
  db $C5, $F9, $6E, $66, $08                    // vmovd  xmm4, dword [esi + $8]
  db $C5, $F9, $6E, $6E, $18                    // vmovd  xmm5, dword [esi + $18]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $2E                         // vmovd  xmm5, dword [esi]
  db $C5, $F9, $6E, $76, $20                    // vmovd  xmm6, dword [esi + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m12,m10,m11,m3)
  db $C5, $F9, $6E, $66, $30                    // vmovd  xmm4, dword [esi + $30]
  db $C5, $F9, $6E, $6E, $28                    // vmovd  xmm5, dword [esi + $28]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $2C                    // vmovd  xmm5, dword [esi + $2C]
  db $C5, $F9, $6E, $76, $0C                    // vmovd  xmm6, dword [esi + $C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m1,m4,m7,m15)
  db $C5, $F9, $6E, $66, $04                    // vmovd  xmm4, dword [esi + $4]
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $F9, $6E, $76, $3C                    // vmovd  xmm6, dword [esi + $3C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m9,m13,m5,m14)
  db $C5, $F9, $6E, $66, $24                    // vmovd  xmm4, dword [esi + $24]
  db $C5, $F9, $6E, $6E, $34                    // vmovd  xmm5, dword [esi + $34]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $F9, $6E, $76, $38                    // vmovd  xmm6, dword [esi + $38]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1,m14,m4)
  db $C5, $F9, $6E, $66, $30                    // vmovd  xmm4, dword [esi + $30]
  db $C5, $F9, $6E, $6E, $04                    // vmovd  xmm5, dword [esi + $4]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $F9, $6E, $76, $10                    // vmovd  xmm6, dword [esi + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m5,m15,m13,m10)
  db $C5, $F9, $6E, $66, $14                    // vmovd  xmm4, dword [esi + $14]
  db $C5, $F9, $6E, $6E, $3C                    // vmovd  xmm5, dword [esi + $3C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $34                    // vmovd  xmm5, dword [esi + $34]
  db $C5, $F9, $6E, $76, $28                    // vmovd  xmm6, dword [esi + $28]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m8,m0,m6,m9)
  db $C5, $F9, $6E, $66, $20                    // vmovd  xmm4, dword [esi + $20]
  db $C5, $F9, $6E, $2E                         // vmovd  xmm5, dword [esi]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $18                    // vmovd  xmm5, dword [esi + $18]
  db $C5, $F9, $6E, $76, $24                    // vmovd  xmm6, dword [esi + $24]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m11,m7,m3,m2)
  db $C5, $F9, $6E, $66, $2C                    // vmovd  xmm4, dword [esi + $2C]
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $0C                    // vmovd  xmm5, dword [esi + $C]
  db $C5, $F9, $6E, $76, $08                    // vmovd  xmm6, dword [esi + $8]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7,m12,m3)
  db $C5, $F9, $6E, $66, $34                    // vmovd  xmm4, dword [esi + $34]
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $F9, $6E, $76, $0C                    // vmovd  xmm6, dword [esi + $C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m11,m14,m1,m9)
  db $C5, $F9, $6E, $66, $2C                    // vmovd  xmm4, dword [esi + $2C]
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $04                    // vmovd  xmm5, dword [esi + $4]
  db $C5, $F9, $6E, $76, $24                    // vmovd  xmm6, dword [esi + $24]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m2,m5,m15,m8)
  db $C5, $F9, $6E, $66, $08                    // vmovd  xmm4, dword [esi + $8]
  db $C5, $F9, $6E, $6E, $14                    // vmovd  xmm5, dword [esi + $14]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $3C                    // vmovd  xmm5, dword [esi + $3C]
  db $C5, $F9, $6E, $76, $20                    // vmovd  xmm6, dword [esi + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m10,m0,m4,m6)
  db $C5, $F9, $6E, $66, $28                    // vmovd  xmm4, dword [esi + $28]
  db $C5, $F9, $6E, $2E                         // vmovd  xmm5, dword [esi]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $F9, $6E, $76, $18                    // vmovd  xmm6, dword [esi + $18]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14,m11,m0)
  db $C5, $F9, $6E, $66, $18                    // vmovd  xmm4, dword [esi + $18]
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $2C                    // vmovd  xmm5, dword [esi + $2C]
  db $C5, $F9, $6E, $36                         // vmovd  xmm6, dword [esi]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m15,m9,m3,m8)
  db $C5, $F9, $6E, $66, $3C                    // vmovd  xmm4, dword [esi + $3C]
  db $C5, $F9, $6E, $6E, $24                    // vmovd  xmm5, dword [esi + $24]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $0C                    // vmovd  xmm5, dword [esi + $C]
  db $C5, $F9, $6E, $76, $20                    // vmovd  xmm6, dword [esi + $20]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m10,m12,m13,m1)
  db $C5, $F9, $6E, $66, $28                    // vmovd  xmm4, dword [esi + $28]
  db $C5, $F9, $6E, $6E, $30                    // vmovd  xmm5, dword [esi + $30]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $34                    // vmovd  xmm5, dword [esi + $34]
  db $C5, $F9, $6E, $76, $04                    // vmovd  xmm6, dword [esi + $4]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m5,m2,m7,m4)
  db $C5, $F9, $6E, $66, $14                    // vmovd  xmm4, dword [esi + $14]
  db $C5, $F9, $6E, $6E, $08                    // vmovd  xmm5, dword [esi + $8]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $F9, $6E, $76, $10                    // vmovd  xmm6, dword [esi + $10]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8,m7,m1)
  db $C5, $F9, $6E, $66, $28                    // vmovd  xmm4, dword [esi + $28]
  db $C5, $F9, $6E, $6E, $20                    // vmovd  xmm5, dword [esi + $20]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $1C                    // vmovd  xmm5, dword [esi + $1C]
  db $C5, $F9, $6E, $76, $04                    // vmovd  xmm6, dword [esi + $4]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 columns (msg: m2,m4,m6,m5)
  db $C5, $F9, $6E, $66, $08                    // vmovd  xmm4, dword [esi + $8]
  db $C5, $F9, $6E, $6E, $10                    // vmovd  xmm5, dword [esi + $10]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $18                    // vmovd  xmm5, dword [esi + $18]
  db $C5, $F9, $6E, $76, $14                    // vmovd  xmm6, dword [esi + $14]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Diagonalize
  db $C5, $F9, $70, $C0, $93                    // vpshufd xmm0, xmm0, $93
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $39                    // vpshufd xmm2, xmm2, $39

  // G1 diagonals (msg: m13,m15,m9,m3)
  db $C5, $F9, $6E, $66, $34                    // vmovd  xmm4, dword [esi + $34]
  db $C5, $F9, $6E, $6E, $3C                    // vmovd  xmm5, dword [esi + $3C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $24                    // vmovd  xmm5, dword [esi + $24]
  db $C5, $F9, $6E, $76, $0C                    // vmovd  xmm6, dword [esi + $C]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $DF                    // vpshufb xmm3, xmm3, xmm7

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $0C                    // vpsrld xmm5, xmm1, $C
  db $C5, $F1, $72, $F1, $14                    // vpslld xmm1, xmm1, $14
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // G2 diagonals (msg: m0,m11,m14,m12)
  db $C5, $F9, $6E, $26                         // vmovd  xmm4, dword [esi]
  db $C5, $F9, $6E, $6E, $2C                    // vmovd  xmm5, dword [esi + $2C]
  db $C5, $D9, $6C, $E5                         // vpunpcklqdq xmm4, xmm4, xmm5
  db $C5, $F9, $6E, $6E, $38                    // vmovd  xmm5, dword [esi + $38]
  db $C5, $F9, $6E, $76, $30                    // vmovd  xmm6, dword [esi + $30]
  db $C5, $D1, $6C, $EE                         // vpunpcklqdq xmm5, xmm5, xmm6
  db $C5, $D8, $C6, $E5, $88                    // vshufps xmm4, xmm4, xmm5, $88
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $F9, $FE, $C1                         // vpaddd xmm0, xmm0, xmm1
  db $C5, $E1, $EF, $D8                         // vpxor  xmm3, xmm3, xmm0
  db $C4, $E2, $61, $00, $59, $10               // vpshufb xmm3, xmm3, oword [ecx + $10]

  db $C5, $E9, $FE, $D3                         // vpaddd xmm2, xmm2, xmm3
  db $C5, $F1, $EF, $CA                         // vpxor  xmm1, xmm1, xmm2
  db $C5, $D1, $72, $D1, $07                    // vpsrld xmm5, xmm1, $7
  db $C5, $F1, $72, $F1, $19                    // vpslld xmm1, xmm1, $19
  db $C5, $F1, $EB, $CD                         // vpor   xmm1, xmm1, xmm5

  // Undiagonalize
  db $C5, $F9, $70, $C0, $39                    // vpshufd xmm0, xmm0, $39
  db $C5, $F9, $70, $DB, $4E                    // vpshufd xmm3, xmm3, $4E
  db $C5, $F9, $70, $D2, $93                    // vpshufd xmm2, xmm2, $93

  // Finalization: state[i] ^= v[i] ^ v[i+8]
  db $C5, $F9, $EF, $C2                         // vpxor  xmm0, xmm0, xmm2
  db $C5, $F1, $EF, $CB                         // vpxor  xmm1, xmm1, xmm3
  db $C5, $FA, $6F, $23                         // vmovdqu xmm4, oword [ebx]
  db $C5, $F9, $EF, $C4                         // vpxor  xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $63, $10                    // vmovdqu xmm4, oword [ebx + $10]
  db $C5, $F1, $EF, $CC                         // vpxor  xmm1, xmm1, xmm4

  // Store result
  db $C5, $FA, $7F, $03                         // vmovdqu oword [ebx], xmm0
  db $C5, $FA, $7F, $4B, $10                    // vmovdqu oword [ebx + $10], xmm1

  db $C5, $F8, $77                              // vzeroupper



  db $C5, $FA, $6F, $34, $24                    // vmovdqu xmm6, oword [esp]
  db $C5, $FA, $6F, $7C, $24, $10               // vmovdqu xmm7, oword [esp + $10]
  add    esp, $20
  pop    edi
  pop    esi
  pop    ebx
