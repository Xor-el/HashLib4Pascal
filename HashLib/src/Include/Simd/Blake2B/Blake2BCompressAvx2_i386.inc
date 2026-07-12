// AVX2 implementation of BLAKE2b compress (IA-32; fully unrolled 12 rounds).
// 256-bit ymm integer ops work in 32-bit mode; the kernel fits IA-32's
// ymm0-7 exactly. Same structure as Blake2BCompressAvx2_x86_64.inc, with the
// x86_64 version's memory-source vpinsrq message loads (not encodable in
// 32-bit mode) replaced 1:1 by vmovhps (same load-high-qword semantics).
// IA-32: after HlpSimdProc5Begin_i386 - ebx = state ptr, esi = msg ptr,
//   edi = counter+flags ptr, eax = IV ptr, ecx = byte-rotation masks ptr
//   (see BLAKE2B_ROT_MASKS: rot24 at +0, rot16 at +32; read unaligned, so the
//   Pascal const needs no special alignment).
// Register map: ymm0 = a (v0-3), ymm1 = b (v4-7), ymm2 = c (v8-11), ymm3 = d (v12-15),
//   ymm4 = message temp, ymm5 = computation temp, ymm6 = rot24 mask, ymm7 = rot16 mask.
// Rotations: ROT32 via vpshufd, ROT16/24 via vpshufb against the resident
//   masks, ROT63 via shift+or (not byte-aligned; shifts are the known-best form).
// Diagonalize/Undiagonalize via vpermq.
// Uses ymm0-ymm7; xmm6/xmm7 saved/restored defensively (volatile on IA-32).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: sneves/blake2-avx2 by Samuel Neves, HashLib
// Blake2BCompressAvx2_x86_64.inc.

  // Defensive save of xmm6/xmm7 (volatile on IA-32; saved like the
  // SSE2 sibling to be safe under every RTL). Only the low 128 bits
  // matter - the ymm uppers are dead after the trailing vzeroupper.
  sub    esp, $20
  db $C5, $FA, $7F, $34, $24                    // vmovdqu oword [esp], xmm6
  db $C5, $FA, $7F, $7C, $24, $10               // vmovdqu oword [esp + $10], xmm7


  // Initialize working vector
  db $C5, $FE, $6F, $03                         // vmovdqu ymm0, yword [ebx]
  db $C5, $FE, $6F, $4B, $20                    // vmovdqu ymm1, yword [ebx + $20]
  db $C5, $FE, $6F, $10                         // vmovdqu ymm2, yword [eax]
  db $C5, $FE, $6F, $58, $20                    // vmovdqu ymm3, yword [eax + $20]

  // Load byte-rotation masks (resident for the whole kernel)
  db $C5, $FE, $6F, $31                         // vmovdqu ymm6, yword [ecx]
  db $C5, $FE, $6F, $79, $20                    // vmovdqu ymm7, yword [ecx + $20]

  // XOR d with counter and flags
  db $C5, $FE, $6F, $27                         // vmovdqu ymm4, yword [edi]
  db $C5, $E5, $EF, $DC                         // vpxor  ymm3, ymm3, ymm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C5, $FA, $7E, $26                         // vmovq  xmm4, qword [esi]
  db $C5, $D8, $16, $66, $10                    // vmovhps xmm4, xmm4, qword [esi + $10]
  db $C5, $FA, $7E, $6E, $20                    // vmovq  xmm5, qword [esi + $20]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m1,m3,m5,m7)
  db $C5, $FA, $7E, $66, $08                    // vmovq  xmm4, qword [esi + $8]
  db $C5, $D8, $16, $66, $18                    // vmovhps xmm4, xmm4, qword [esi + $18]
  db $C5, $FA, $7E, $6E, $28                    // vmovq  xmm5, qword [esi + $28]
  db $C5, $D0, $16, $6E, $38                    // vmovhps xmm5, xmm5, qword [esi + $38]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C5, $FA, $7E, $66, $70                    // vmovq  xmm4, qword [esi + $70]
  db $C5, $D8, $16, $66, $40                    // vmovhps xmm4, xmm4, qword [esi + $40]
  db $C5, $FA, $7E, $6E, $50                    // vmovq  xmm5, qword [esi + $50]
  db $C5, $D0, $16, $6E, $60                    // vmovhps xmm5, xmm5, qword [esi + $60]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C5, $FA, $7E, $66, $78                    // vmovq  xmm4, qword [esi + $78]
  db $C5, $D8, $16, $66, $48                    // vmovhps xmm4, xmm4, qword [esi + $48]
  db $C5, $FA, $7E, $6E, $58                    // vmovq  xmm5, qword [esi + $58]
  db $C5, $D0, $16, $6E, $68                    // vmovhps xmm5, xmm5, qword [esi + $68]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C5, $FA, $7E, $66, $70                    // vmovq  xmm4, qword [esi + $70]
  db $C5, $D8, $16, $66, $20                    // vmovhps xmm4, xmm4, qword [esi + $20]
  db $C5, $FA, $7E, $6E, $48                    // vmovq  xmm5, qword [esi + $48]
  db $C5, $D0, $16, $6E, $68                    // vmovhps xmm5, xmm5, qword [esi + $68]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m10,m8,m15,m6)
  db $C5, $FA, $7E, $66, $50                    // vmovq  xmm4, qword [esi + $50]
  db $C5, $D8, $16, $66, $40                    // vmovhps xmm4, xmm4, qword [esi + $40]
  db $C5, $FA, $7E, $6E, $78                    // vmovq  xmm5, qword [esi + $78]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C5, $FA, $7E, $66, $28                    // vmovq  xmm4, qword [esi + $28]
  db $C5, $D8, $16, $66, $08                    // vmovhps xmm4, xmm4, qword [esi + $8]
  db $C5, $FA, $7E, $2E                         // vmovq  xmm5, qword [esi]
  db $C5, $D0, $16, $6E, $58                    // vmovhps xmm5, xmm5, qword [esi + $58]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C5, $FA, $7E, $66, $18                    // vmovq  xmm4, qword [esi + $18]
  db $C5, $D8, $16, $66, $60                    // vmovhps xmm4, xmm4, qword [esi + $60]
  db $C5, $FA, $7E, $6E, $10                    // vmovq  xmm5, qword [esi + $10]
  db $C5, $D0, $16, $6E, $38                    // vmovhps xmm5, xmm5, qword [esi + $38]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12,m5,m15)
  db $C5, $FA, $7E, $66, $58                    // vmovq  xmm4, qword [esi + $58]
  db $C5, $D8, $16, $66, $60                    // vmovhps xmm4, xmm4, qword [esi + $60]
  db $C5, $FA, $7E, $6E, $28                    // vmovq  xmm5, qword [esi + $28]
  db $C5, $D0, $16, $6E, $78                    // vmovhps xmm5, xmm5, qword [esi + $78]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m8,m0,m2,m13)
  db $C5, $FA, $7E, $66, $40                    // vmovq  xmm4, qword [esi + $40]
  db $C5, $D8, $16, $26                         // vmovhps xmm4, xmm4, qword [esi]
  db $C5, $FA, $7E, $6E, $10                    // vmovq  xmm5, qword [esi + $10]
  db $C5, $D0, $16, $6E, $68                    // vmovhps xmm5, xmm5, qword [esi + $68]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m9,m10,m3,m7)
  db $C5, $FA, $7E, $66, $48                    // vmovq  xmm4, qword [esi + $48]
  db $C5, $D8, $16, $66, $50                    // vmovhps xmm4, xmm4, qword [esi + $50]
  db $C5, $FA, $7E, $6E, $18                    // vmovq  xmm5, qword [esi + $18]
  db $C5, $D0, $16, $6E, $38                    // vmovhps xmm5, xmm5, qword [esi + $38]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m4,m14,m6,m1)
  db $C5, $FA, $7E, $66, $20                    // vmovq  xmm4, qword [esi + $20]
  db $C5, $D8, $16, $66, $70                    // vmovhps xmm4, xmm4, qword [esi + $70]
  db $C5, $FA, $7E, $6E, $30                    // vmovq  xmm5, qword [esi + $30]
  db $C5, $D0, $16, $6E, $08                    // vmovhps xmm5, xmm5, qword [esi + $8]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3,m13,m11)
  db $C5, $FA, $7E, $66, $38                    // vmovq  xmm4, qword [esi + $38]
  db $C5, $D8, $16, $66, $18                    // vmovhps xmm4, xmm4, qword [esi + $18]
  db $C5, $FA, $7E, $6E, $68                    // vmovq  xmm5, qword [esi + $68]
  db $C5, $D0, $16, $6E, $58                    // vmovhps xmm5, xmm5, qword [esi + $58]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m9,m1,m12,m14)
  db $C5, $FA, $7E, $66, $48                    // vmovq  xmm4, qword [esi + $48]
  db $C5, $D8, $16, $66, $08                    // vmovhps xmm4, xmm4, qword [esi + $8]
  db $C5, $FA, $7E, $6E, $60                    // vmovq  xmm5, qword [esi + $60]
  db $C5, $D0, $16, $6E, $70                    // vmovhps xmm5, xmm5, qword [esi + $70]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m15,m2,m5,m4)
  db $C5, $FA, $7E, $66, $78                    // vmovq  xmm4, qword [esi + $78]
  db $C5, $D8, $16, $66, $10                    // vmovhps xmm4, xmm4, qword [esi + $10]
  db $C5, $FA, $7E, $6E, $28                    // vmovq  xmm5, qword [esi + $28]
  db $C5, $D0, $16, $6E, $20                    // vmovhps xmm5, xmm5, qword [esi + $20]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m8,m6,m10,m0)
  db $C5, $FA, $7E, $66, $40                    // vmovq  xmm4, qword [esi + $40]
  db $C5, $D8, $16, $66, $30                    // vmovhps xmm4, xmm4, qword [esi + $30]
  db $C5, $FA, $7E, $6E, $50                    // vmovq  xmm5, qword [esi + $50]
  db $C5, $D0, $16, $2E                         // vmovhps xmm5, xmm5, qword [esi]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5,m2,m10)
  db $C5, $FA, $7E, $66, $48                    // vmovq  xmm4, qword [esi + $48]
  db $C5, $D8, $16, $66, $28                    // vmovhps xmm4, xmm4, qword [esi + $28]
  db $C5, $FA, $7E, $6E, $10                    // vmovq  xmm5, qword [esi + $10]
  db $C5, $D0, $16, $6E, $50                    // vmovhps xmm5, xmm5, qword [esi + $50]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m0,m7,m4,m15)
  db $C5, $FA, $7E, $26                         // vmovq  xmm4, qword [esi]
  db $C5, $D8, $16, $66, $38                    // vmovhps xmm4, xmm4, qword [esi + $38]
  db $C5, $FA, $7E, $6E, $20                    // vmovq  xmm5, qword [esi + $20]
  db $C5, $D0, $16, $6E, $78                    // vmovhps xmm5, xmm5, qword [esi + $78]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m3,m14,m11,m6)
  db $C5, $FA, $7E, $66, $18                    // vmovq  xmm4, qword [esi + $18]
  db $C5, $D8, $16, $66, $70                    // vmovhps xmm4, xmm4, qword [esi + $70]
  db $C5, $FA, $7E, $6E, $58                    // vmovq  xmm5, qword [esi + $58]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m13,m1,m12,m8)
  db $C5, $FA, $7E, $66, $68                    // vmovq  xmm4, qword [esi + $68]
  db $C5, $D8, $16, $66, $08                    // vmovhps xmm4, xmm4, qword [esi + $8]
  db $C5, $FA, $7E, $6E, $60                    // vmovq  xmm5, qword [esi + $60]
  db $C5, $D0, $16, $6E, $40                    // vmovhps xmm5, xmm5, qword [esi + $40]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6,m0,m8)
  db $C5, $FA, $7E, $66, $10                    // vmovq  xmm4, qword [esi + $10]
  db $C5, $D8, $16, $66, $30                    // vmovhps xmm4, xmm4, qword [esi + $30]
  db $C5, $FA, $7E, $2E                         // vmovq  xmm5, qword [esi]
  db $C5, $D0, $16, $6E, $40                    // vmovhps xmm5, xmm5, qword [esi + $40]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m12,m10,m11,m3)
  db $C5, $FA, $7E, $66, $60                    // vmovq  xmm4, qword [esi + $60]
  db $C5, $D8, $16, $66, $50                    // vmovhps xmm4, xmm4, qword [esi + $50]
  db $C5, $FA, $7E, $6E, $58                    // vmovq  xmm5, qword [esi + $58]
  db $C5, $D0, $16, $6E, $18                    // vmovhps xmm5, xmm5, qword [esi + $18]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m1,m4,m7,m15)
  db $C5, $FA, $7E, $66, $08                    // vmovq  xmm4, qword [esi + $8]
  db $C5, $D8, $16, $66, $20                    // vmovhps xmm4, xmm4, qword [esi + $20]
  db $C5, $FA, $7E, $6E, $38                    // vmovq  xmm5, qword [esi + $38]
  db $C5, $D0, $16, $6E, $78                    // vmovhps xmm5, xmm5, qword [esi + $78]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m9,m13,m5,m14)
  db $C5, $FA, $7E, $66, $48                    // vmovq  xmm4, qword [esi + $48]
  db $C5, $D8, $16, $66, $68                    // vmovhps xmm4, xmm4, qword [esi + $68]
  db $C5, $FA, $7E, $6E, $28                    // vmovq  xmm5, qword [esi + $28]
  db $C5, $D0, $16, $6E, $70                    // vmovhps xmm5, xmm5, qword [esi + $70]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1,m14,m4)
  db $C5, $FA, $7E, $66, $60                    // vmovq  xmm4, qword [esi + $60]
  db $C5, $D8, $16, $66, $08                    // vmovhps xmm4, xmm4, qword [esi + $8]
  db $C5, $FA, $7E, $6E, $70                    // vmovq  xmm5, qword [esi + $70]
  db $C5, $D0, $16, $6E, $20                    // vmovhps xmm5, xmm5, qword [esi + $20]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m5,m15,m13,m10)
  db $C5, $FA, $7E, $66, $28                    // vmovq  xmm4, qword [esi + $28]
  db $C5, $D8, $16, $66, $78                    // vmovhps xmm4, xmm4, qword [esi + $78]
  db $C5, $FA, $7E, $6E, $68                    // vmovq  xmm5, qword [esi + $68]
  db $C5, $D0, $16, $6E, $50                    // vmovhps xmm5, xmm5, qword [esi + $50]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m8,m0,m6,m9)
  db $C5, $FA, $7E, $66, $40                    // vmovq  xmm4, qword [esi + $40]
  db $C5, $D8, $16, $26                         // vmovhps xmm4, xmm4, qword [esi]
  db $C5, $FA, $7E, $6E, $30                    // vmovq  xmm5, qword [esi + $30]
  db $C5, $D0, $16, $6E, $48                    // vmovhps xmm5, xmm5, qword [esi + $48]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m11,m7,m3,m2)
  db $C5, $FA, $7E, $66, $58                    // vmovq  xmm4, qword [esi + $58]
  db $C5, $D8, $16, $66, $38                    // vmovhps xmm4, xmm4, qword [esi + $38]
  db $C5, $FA, $7E, $6E, $18                    // vmovq  xmm5, qword [esi + $18]
  db $C5, $D0, $16, $6E, $10                    // vmovhps xmm5, xmm5, qword [esi + $10]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7,m12,m3)
  db $C5, $FA, $7E, $66, $68                    // vmovq  xmm4, qword [esi + $68]
  db $C5, $D8, $16, $66, $38                    // vmovhps xmm4, xmm4, qword [esi + $38]
  db $C5, $FA, $7E, $6E, $60                    // vmovq  xmm5, qword [esi + $60]
  db $C5, $D0, $16, $6E, $18                    // vmovhps xmm5, xmm5, qword [esi + $18]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m11,m14,m1,m9)
  db $C5, $FA, $7E, $66, $58                    // vmovq  xmm4, qword [esi + $58]
  db $C5, $D8, $16, $66, $70                    // vmovhps xmm4, xmm4, qword [esi + $70]
  db $C5, $FA, $7E, $6E, $08                    // vmovq  xmm5, qword [esi + $8]
  db $C5, $D0, $16, $6E, $48                    // vmovhps xmm5, xmm5, qword [esi + $48]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m2,m5,m15,m8)
  db $C5, $FA, $7E, $66, $10                    // vmovq  xmm4, qword [esi + $10]
  db $C5, $D8, $16, $66, $28                    // vmovhps xmm4, xmm4, qword [esi + $28]
  db $C5, $FA, $7E, $6E, $78                    // vmovq  xmm5, qword [esi + $78]
  db $C5, $D0, $16, $6E, $40                    // vmovhps xmm5, xmm5, qword [esi + $40]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m10,m0,m4,m6)
  db $C5, $FA, $7E, $66, $50                    // vmovq  xmm4, qword [esi + $50]
  db $C5, $D8, $16, $26                         // vmovhps xmm4, xmm4, qword [esi]
  db $C5, $FA, $7E, $6E, $20                    // vmovq  xmm5, qword [esi + $20]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14,m11,m0)
  db $C5, $FA, $7E, $66, $30                    // vmovq  xmm4, qword [esi + $30]
  db $C5, $D8, $16, $66, $70                    // vmovhps xmm4, xmm4, qword [esi + $70]
  db $C5, $FA, $7E, $6E, $58                    // vmovq  xmm5, qword [esi + $58]
  db $C5, $D0, $16, $2E                         // vmovhps xmm5, xmm5, qword [esi]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m15,m9,m3,m8)
  db $C5, $FA, $7E, $66, $78                    // vmovq  xmm4, qword [esi + $78]
  db $C5, $D8, $16, $66, $48                    // vmovhps xmm4, xmm4, qword [esi + $48]
  db $C5, $FA, $7E, $6E, $18                    // vmovq  xmm5, qword [esi + $18]
  db $C5, $D0, $16, $6E, $40                    // vmovhps xmm5, xmm5, qword [esi + $40]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m10,m12,m13,m1)
  db $C5, $FA, $7E, $66, $50                    // vmovq  xmm4, qword [esi + $50]
  db $C5, $D8, $16, $66, $60                    // vmovhps xmm4, xmm4, qword [esi + $60]
  db $C5, $FA, $7E, $6E, $68                    // vmovq  xmm5, qword [esi + $68]
  db $C5, $D0, $16, $6E, $08                    // vmovhps xmm5, xmm5, qword [esi + $8]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m5,m2,m7,m4)
  db $C5, $FA, $7E, $66, $28                    // vmovq  xmm4, qword [esi + $28]
  db $C5, $D8, $16, $66, $10                    // vmovhps xmm4, xmm4, qword [esi + $10]
  db $C5, $FA, $7E, $6E, $38                    // vmovq  xmm5, qword [esi + $38]
  db $C5, $D0, $16, $6E, $20                    // vmovhps xmm5, xmm5, qword [esi + $20]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8,m7,m1)
  db $C5, $FA, $7E, $66, $50                    // vmovq  xmm4, qword [esi + $50]
  db $C5, $D8, $16, $66, $40                    // vmovhps xmm4, xmm4, qword [esi + $40]
  db $C5, $FA, $7E, $6E, $38                    // vmovq  xmm5, qword [esi + $38]
  db $C5, $D0, $16, $6E, $08                    // vmovhps xmm5, xmm5, qword [esi + $8]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m2,m4,m6,m5)
  db $C5, $FA, $7E, $66, $10                    // vmovq  xmm4, qword [esi + $10]
  db $C5, $D8, $16, $66, $20                    // vmovhps xmm4, xmm4, qword [esi + $20]
  db $C5, $FA, $7E, $6E, $30                    // vmovq  xmm5, qword [esi + $30]
  db $C5, $D0, $16, $6E, $28                    // vmovhps xmm5, xmm5, qword [esi + $28]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m13,m15,m9,m3)
  db $C5, $FA, $7E, $66, $68                    // vmovq  xmm4, qword [esi + $68]
  db $C5, $D8, $16, $66, $78                    // vmovhps xmm4, xmm4, qword [esi + $78]
  db $C5, $FA, $7E, $6E, $48                    // vmovq  xmm5, qword [esi + $48]
  db $C5, $D0, $16, $6E, $18                    // vmovhps xmm5, xmm5, qword [esi + $18]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m0,m11,m14,m12)
  db $C5, $FA, $7E, $26                         // vmovq  xmm4, qword [esi]
  db $C5, $D8, $16, $66, $58                    // vmovhps xmm4, xmm4, qword [esi + $58]
  db $C5, $FA, $7E, $6E, $70                    // vmovq  xmm5, qword [esi + $70]
  db $C5, $D0, $16, $6E, $60                    // vmovhps xmm5, xmm5, qword [esi + $60]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 10 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C5, $FA, $7E, $26                         // vmovq  xmm4, qword [esi]
  db $C5, $D8, $16, $66, $10                    // vmovhps xmm4, xmm4, qword [esi + $10]
  db $C5, $FA, $7E, $6E, $20                    // vmovq  xmm5, qword [esi + $20]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m1,m3,m5,m7)
  db $C5, $FA, $7E, $66, $08                    // vmovq  xmm4, qword [esi + $8]
  db $C5, $D8, $16, $66, $18                    // vmovhps xmm4, xmm4, qword [esi + $18]
  db $C5, $FA, $7E, $6E, $28                    // vmovq  xmm5, qword [esi + $28]
  db $C5, $D0, $16, $6E, $38                    // vmovhps xmm5, xmm5, qword [esi + $38]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C5, $FA, $7E, $66, $70                    // vmovq  xmm4, qword [esi + $70]
  db $C5, $D8, $16, $66, $40                    // vmovhps xmm4, xmm4, qword [esi + $40]
  db $C5, $FA, $7E, $6E, $50                    // vmovq  xmm5, qword [esi + $50]
  db $C5, $D0, $16, $6E, $60                    // vmovhps xmm5, xmm5, qword [esi + $60]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C5, $FA, $7E, $66, $78                    // vmovq  xmm4, qword [esi + $78]
  db $C5, $D8, $16, $66, $48                    // vmovhps xmm4, xmm4, qword [esi + $48]
  db $C5, $FA, $7E, $6E, $58                    // vmovq  xmm5, qword [esi + $58]
  db $C5, $D0, $16, $6E, $68                    // vmovhps xmm5, xmm5, qword [esi + $68]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 11 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C5, $FA, $7E, $66, $70                    // vmovq  xmm4, qword [esi + $70]
  db $C5, $D8, $16, $66, $20                    // vmovhps xmm4, xmm4, qword [esi + $20]
  db $C5, $FA, $7E, $6E, $48                    // vmovq  xmm5, qword [esi + $48]
  db $C5, $D0, $16, $6E, $68                    // vmovhps xmm5, xmm5, qword [esi + $68]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 columns (msg: m10,m8,m15,m6)
  db $C5, $FA, $7E, $66, $50                    // vmovq  xmm4, qword [esi + $50]
  db $C5, $D8, $16, $66, $40                    // vmovhps xmm4, xmm4, qword [esi + $40]
  db $C5, $FA, $7E, $6E, $78                    // vmovq  xmm5, qword [esi + $78]
  db $C5, $D0, $16, $6E, $30                    // vmovhps xmm5, xmm5, qword [esi + $30]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C5, $FA, $7E, $66, $28                    // vmovq  xmm4, qword [esi + $28]
  db $C5, $D8, $16, $66, $08                    // vmovhps xmm4, xmm4, qword [esi + $8]
  db $C5, $FA, $7E, $2E                         // vmovq  xmm5, qword [esi]
  db $C5, $D0, $16, $6E, $58                    // vmovhps xmm5, xmm5, qword [esi + $58]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $CE                    // vpshufb ymm1, ymm1, ymm6

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C5, $FA, $7E, $66, $18                    // vmovq  xmm4, qword [esi + $18]
  db $C5, $D8, $16, $66, $60                    // vmovhps xmm4, xmm4, qword [esi + $60]
  db $C5, $FA, $7E, $6E, $10                    // vmovq  xmm5, qword [esi + $10]
  db $C5, $D0, $16, $6E, $38                    // vmovhps xmm5, xmm5, qword [esi + $38]
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, $1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                    // vpshufb ymm3, ymm3, ymm7

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor   ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // Finalization
  db $C5, $FD, $EF, $C2                         // vpxor  ymm0, ymm0, ymm2
  db $C5, $F5, $EF, $CB                         // vpxor  ymm1, ymm1, ymm3

  // XOR with original state (re-read from memory)
  db $C5, $FD, $EF, $03                         // vpxor  ymm0, ymm0, yword [ebx]
  db $C5, $F5, $EF, $4B, $20                    // vpxor  ymm1, ymm1, yword [ebx + $20]

  // Store result
  db $C5, $FE, $7F, $03                         // vmovdqu yword [ebx], ymm0
  db $C5, $FE, $7F, $4B, $20                    // vmovdqu yword [ebx + $20], ymm1

  db $C5, $F8, $77                              // vzeroupper



  db $C5, $FA, $6F, $34, $24                    // vmovdqu xmm6, oword [esp]
  db $C5, $FA, $6F, $7C, $24, $10               // vmovdqu xmm7, oword [esp + $10]
  add    esp, $20
  pop    edi
  pop    esi
  pop    ebx
