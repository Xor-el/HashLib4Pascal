// AVX2 implementation of BLAKE2b compress (fully unrolled 12 rounds).
// Expects MS x64 ABI: rcx = state ptr, rdx = msg ptr, r8 = counter+flags ptr, r9 = IV ptr.
// Uses ymm0-ymm5 only (all volatile on Windows x64).
// Register map: ymm0 = a (v0-3), ymm1 = b (v4-7), ymm2 = c (v8-11), ymm3 = d (v12-15),
//   ymm4 = message temp, ymm5 = computation temp.
// Rotations: ROT32 via vpshufd, ROT16/24/63 via shift+or.
// Diagonalize/Undiagonalize via vpermq.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: sneves/blake2-avx2 by Samuel Neves.

  // Initialize working vector
  db $C5, $FE, $6F, $01                         // vmovdqu ymm0, yword [rcx]
  db $C5, $FE, $6F, $49, $20                    // vmovdqu ymm1, yword [rcx + $20]
  db $C4, $C1, $7E, $6F, $11                    // vmovdqu ymm2, yword [r9]
  db $C4, $C1, $7E, $6F, $59, $20               // vmovdqu ymm3, yword [r9 + $20]

  // XOR d with counter and flags
  db $C4, $C1, $7E, $6F, $20                    // vmovdqu ymm4, yword [r8]
  db $C5, $E5, $EF, $DC                         // vpxor ymm3, ymm3, ymm4

  // ===== Round 0 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C4, $E1, $F9, $6E, $22                    // vmovq xmm4, qword [rdx]
  db $C4, $E3, $D9, $22, $62, $10, $01          // vpinsrq xmm4, xmm4, qword [rdx + $10], 1
  db $C4, $E1, $F9, $6E, $6A, $20               // vmovq xmm5, qword [rdx + $20]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m1,m3,m5,m7)
  db $C4, $E1, $F9, $6E, $62, $08               // vmovq xmm4, qword [rdx + $08]
  db $C4, $E3, $D9, $22, $62, $18, $01          // vpinsrq xmm4, xmm4, qword [rdx + $18], 1
  db $C4, $E1, $F9, $6E, $6A, $28               // vmovq xmm5, qword [rdx + $28]
  db $C4, $E3, $D1, $22, $6A, $38, $01          // vpinsrq xmm5, xmm5, qword [rdx + $38], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C4, $E1, $F9, $6E, $62, $70               // vmovq xmm4, qword [rdx + $70]
  db $C4, $E3, $D9, $22, $62, $40, $01          // vpinsrq xmm4, xmm4, qword [rdx + $40], 1
  db $C4, $E1, $F9, $6E, $6A, $50               // vmovq xmm5, qword [rdx + $50]
  db $C4, $E3, $D1, $22, $6A, $60, $01          // vpinsrq xmm5, xmm5, qword [rdx + $60], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C4, $E1, $F9, $6E, $62, $78               // vmovq xmm4, qword [rdx + $78]
  db $C4, $E3, $D9, $22, $62, $48, $01          // vpinsrq xmm4, xmm4, qword [rdx + $48], 1
  db $C4, $E1, $F9, $6E, $6A, $58               // vmovq xmm5, qword [rdx + $58]
  db $C4, $E3, $D1, $22, $6A, $68, $01          // vpinsrq xmm5, xmm5, qword [rdx + $68], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 1 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C4, $E1, $F9, $6E, $62, $70               // vmovq xmm4, qword [rdx + $70]
  db $C4, $E3, $D9, $22, $62, $20, $01          // vpinsrq xmm4, xmm4, qword [rdx + $20], 1
  db $C4, $E1, $F9, $6E, $6A, $48               // vmovq xmm5, qword [rdx + $48]
  db $C4, $E3, $D1, $22, $6A, $68, $01          // vpinsrq xmm5, xmm5, qword [rdx + $68], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m10,m8,m15,m6)
  db $C4, $E1, $F9, $6E, $62, $50               // vmovq xmm4, qword [rdx + $50]
  db $C4, $E3, $D9, $22, $62, $40, $01          // vpinsrq xmm4, xmm4, qword [rdx + $40], 1
  db $C4, $E1, $F9, $6E, $6A, $78               // vmovq xmm5, qword [rdx + $78]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C4, $E1, $F9, $6E, $62, $28               // vmovq xmm4, qword [rdx + $28]
  db $C4, $E3, $D9, $22, $62, $08, $01          // vpinsrq xmm4, xmm4, qword [rdx + $08], 1
  db $C4, $E1, $F9, $6E, $2A                    // vmovq xmm5, qword [rdx]
  db $C4, $E3, $D1, $22, $6A, $58, $01          // vpinsrq xmm5, xmm5, qword [rdx + $58], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C4, $E1, $F9, $6E, $62, $18               // vmovq xmm4, qword [rdx + $18]
  db $C4, $E3, $D9, $22, $62, $60, $01          // vpinsrq xmm4, xmm4, qword [rdx + $60], 1
  db $C4, $E1, $F9, $6E, $6A, $10               // vmovq xmm5, qword [rdx + $10]
  db $C4, $E3, $D1, $22, $6A, $38, $01          // vpinsrq xmm5, xmm5, qword [rdx + $38], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 2 =====

  // G1 columns (msg: m11,m12,m5,m15)
  db $C4, $E1, $F9, $6E, $62, $58               // vmovq xmm4, qword [rdx + $58]
  db $C4, $E3, $D9, $22, $62, $60, $01          // vpinsrq xmm4, xmm4, qword [rdx + $60], 1
  db $C4, $E1, $F9, $6E, $6A, $28               // vmovq xmm5, qword [rdx + $28]
  db $C4, $E3, $D1, $22, $6A, $78, $01          // vpinsrq xmm5, xmm5, qword [rdx + $78], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m8,m0,m2,m13)
  db $C4, $E1, $F9, $6E, $62, $40               // vmovq xmm4, qword [rdx + $40]
  db $C4, $E3, $D9, $22, $22, $01               // vpinsrq xmm4, xmm4, qword [rdx], 1
  db $C4, $E1, $F9, $6E, $6A, $10               // vmovq xmm5, qword [rdx + $10]
  db $C4, $E3, $D1, $22, $6A, $68, $01          // vpinsrq xmm5, xmm5, qword [rdx + $68], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m9,m10,m3,m7)
  db $C4, $E1, $F9, $6E, $62, $48               // vmovq xmm4, qword [rdx + $48]
  db $C4, $E3, $D9, $22, $62, $50, $01          // vpinsrq xmm4, xmm4, qword [rdx + $50], 1
  db $C4, $E1, $F9, $6E, $6A, $18               // vmovq xmm5, qword [rdx + $18]
  db $C4, $E3, $D1, $22, $6A, $38, $01          // vpinsrq xmm5, xmm5, qword [rdx + $38], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m4,m14,m6,m1)
  db $C4, $E1, $F9, $6E, $62, $20               // vmovq xmm4, qword [rdx + $20]
  db $C4, $E3, $D9, $22, $62, $70, $01          // vpinsrq xmm4, xmm4, qword [rdx + $70], 1
  db $C4, $E1, $F9, $6E, $6A, $30               // vmovq xmm5, qword [rdx + $30]
  db $C4, $E3, $D1, $22, $6A, $08, $01          // vpinsrq xmm5, xmm5, qword [rdx + $08], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 3 =====

  // G1 columns (msg: m7,m3,m13,m11)
  db $C4, $E1, $F9, $6E, $62, $38               // vmovq xmm4, qword [rdx + $38]
  db $C4, $E3, $D9, $22, $62, $18, $01          // vpinsrq xmm4, xmm4, qword [rdx + $18], 1
  db $C4, $E1, $F9, $6E, $6A, $68               // vmovq xmm5, qword [rdx + $68]
  db $C4, $E3, $D1, $22, $6A, $58, $01          // vpinsrq xmm5, xmm5, qword [rdx + $58], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m9,m1,m12,m14)
  db $C4, $E1, $F9, $6E, $62, $48               // vmovq xmm4, qword [rdx + $48]
  db $C4, $E3, $D9, $22, $62, $08, $01          // vpinsrq xmm4, xmm4, qword [rdx + $08], 1
  db $C4, $E1, $F9, $6E, $6A, $60               // vmovq xmm5, qword [rdx + $60]
  db $C4, $E3, $D1, $22, $6A, $70, $01          // vpinsrq xmm5, xmm5, qword [rdx + $70], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m15,m2,m5,m4)
  db $C4, $E1, $F9, $6E, $62, $78               // vmovq xmm4, qword [rdx + $78]
  db $C4, $E3, $D9, $22, $62, $10, $01          // vpinsrq xmm4, xmm4, qword [rdx + $10], 1
  db $C4, $E1, $F9, $6E, $6A, $28               // vmovq xmm5, qword [rdx + $28]
  db $C4, $E3, $D1, $22, $6A, $20, $01          // vpinsrq xmm5, xmm5, qword [rdx + $20], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m8,m6,m10,m0)
  db $C4, $E1, $F9, $6E, $62, $40               // vmovq xmm4, qword [rdx + $40]
  db $C4, $E3, $D9, $22, $62, $30, $01          // vpinsrq xmm4, xmm4, qword [rdx + $30], 1
  db $C4, $E1, $F9, $6E, $6A, $50               // vmovq xmm5, qword [rdx + $50]
  db $C4, $E3, $D1, $22, $2A, $01               // vpinsrq xmm5, xmm5, qword [rdx], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 4 =====

  // G1 columns (msg: m9,m5,m2,m10)
  db $C4, $E1, $F9, $6E, $62, $48               // vmovq xmm4, qword [rdx + $48]
  db $C4, $E3, $D9, $22, $62, $28, $01          // vpinsrq xmm4, xmm4, qword [rdx + $28], 1
  db $C4, $E1, $F9, $6E, $6A, $10               // vmovq xmm5, qword [rdx + $10]
  db $C4, $E3, $D1, $22, $6A, $50, $01          // vpinsrq xmm5, xmm5, qword [rdx + $50], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m0,m7,m4,m15)
  db $C4, $E1, $F9, $6E, $22                    // vmovq xmm4, qword [rdx]
  db $C4, $E3, $D9, $22, $62, $38, $01          // vpinsrq xmm4, xmm4, qword [rdx + $38], 1
  db $C4, $E1, $F9, $6E, $6A, $20               // vmovq xmm5, qword [rdx + $20]
  db $C4, $E3, $D1, $22, $6A, $78, $01          // vpinsrq xmm5, xmm5, qword [rdx + $78], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m3,m14,m11,m6)
  db $C4, $E1, $F9, $6E, $62, $18               // vmovq xmm4, qword [rdx + $18]
  db $C4, $E3, $D9, $22, $62, $70, $01          // vpinsrq xmm4, xmm4, qword [rdx + $70], 1
  db $C4, $E1, $F9, $6E, $6A, $58               // vmovq xmm5, qword [rdx + $58]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m13,m1,m12,m8)
  db $C4, $E1, $F9, $6E, $62, $68               // vmovq xmm4, qword [rdx + $68]
  db $C4, $E3, $D9, $22, $62, $08, $01          // vpinsrq xmm4, xmm4, qword [rdx + $08], 1
  db $C4, $E1, $F9, $6E, $6A, $60               // vmovq xmm5, qword [rdx + $60]
  db $C4, $E3, $D1, $22, $6A, $40, $01          // vpinsrq xmm5, xmm5, qword [rdx + $40], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 5 =====

  // G1 columns (msg: m2,m6,m0,m8)
  db $C4, $E1, $F9, $6E, $62, $10               // vmovq xmm4, qword [rdx + $10]
  db $C4, $E3, $D9, $22, $62, $30, $01          // vpinsrq xmm4, xmm4, qword [rdx + $30], 1
  db $C4, $E1, $F9, $6E, $2A                    // vmovq xmm5, qword [rdx]
  db $C4, $E3, $D1, $22, $6A, $40, $01          // vpinsrq xmm5, xmm5, qword [rdx + $40], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m12,m10,m11,m3)
  db $C4, $E1, $F9, $6E, $62, $60               // vmovq xmm4, qword [rdx + $60]
  db $C4, $E3, $D9, $22, $62, $50, $01          // vpinsrq xmm4, xmm4, qword [rdx + $50], 1
  db $C4, $E1, $F9, $6E, $6A, $58               // vmovq xmm5, qword [rdx + $58]
  db $C4, $E3, $D1, $22, $6A, $18, $01          // vpinsrq xmm5, xmm5, qword [rdx + $18], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m1,m4,m7,m15)
  db $C4, $E1, $F9, $6E, $62, $08               // vmovq xmm4, qword [rdx + $08]
  db $C4, $E3, $D9, $22, $62, $20, $01          // vpinsrq xmm4, xmm4, qword [rdx + $20], 1
  db $C4, $E1, $F9, $6E, $6A, $38               // vmovq xmm5, qword [rdx + $38]
  db $C4, $E3, $D1, $22, $6A, $78, $01          // vpinsrq xmm5, xmm5, qword [rdx + $78], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m9,m13,m5,m14)
  db $C4, $E1, $F9, $6E, $62, $48               // vmovq xmm4, qword [rdx + $48]
  db $C4, $E3, $D9, $22, $62, $68, $01          // vpinsrq xmm4, xmm4, qword [rdx + $68], 1
  db $C4, $E1, $F9, $6E, $6A, $28               // vmovq xmm5, qword [rdx + $28]
  db $C4, $E3, $D1, $22, $6A, $70, $01          // vpinsrq xmm5, xmm5, qword [rdx + $70], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 6 =====

  // G1 columns (msg: m12,m1,m14,m4)
  db $C4, $E1, $F9, $6E, $62, $60               // vmovq xmm4, qword [rdx + $60]
  db $C4, $E3, $D9, $22, $62, $08, $01          // vpinsrq xmm4, xmm4, qword [rdx + $08], 1
  db $C4, $E1, $F9, $6E, $6A, $70               // vmovq xmm5, qword [rdx + $70]
  db $C4, $E3, $D1, $22, $6A, $20, $01          // vpinsrq xmm5, xmm5, qword [rdx + $20], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m5,m15,m13,m10)
  db $C4, $E1, $F9, $6E, $62, $28               // vmovq xmm4, qword [rdx + $28]
  db $C4, $E3, $D9, $22, $62, $78, $01          // vpinsrq xmm4, xmm4, qword [rdx + $78], 1
  db $C4, $E1, $F9, $6E, $6A, $68               // vmovq xmm5, qword [rdx + $68]
  db $C4, $E3, $D1, $22, $6A, $50, $01          // vpinsrq xmm5, xmm5, qword [rdx + $50], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m8,m0,m6,m9)
  db $C4, $E1, $F9, $6E, $62, $40               // vmovq xmm4, qword [rdx + $40]
  db $C4, $E3, $D9, $22, $22, $01               // vpinsrq xmm4, xmm4, qword [rdx], 1
  db $C4, $E1, $F9, $6E, $6A, $30               // vmovq xmm5, qword [rdx + $30]
  db $C4, $E3, $D1, $22, $6A, $48, $01          // vpinsrq xmm5, xmm5, qword [rdx + $48], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m11,m7,m3,m2)
  db $C4, $E1, $F9, $6E, $62, $58               // vmovq xmm4, qword [rdx + $58]
  db $C4, $E3, $D9, $22, $62, $38, $01          // vpinsrq xmm4, xmm4, qword [rdx + $38], 1
  db $C4, $E1, $F9, $6E, $6A, $18               // vmovq xmm5, qword [rdx + $18]
  db $C4, $E3, $D1, $22, $6A, $10, $01          // vpinsrq xmm5, xmm5, qword [rdx + $10], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 7 =====

  // G1 columns (msg: m13,m7,m12,m3)
  db $C4, $E1, $F9, $6E, $62, $68               // vmovq xmm4, qword [rdx + $68]
  db $C4, $E3, $D9, $22, $62, $38, $01          // vpinsrq xmm4, xmm4, qword [rdx + $38], 1
  db $C4, $E1, $F9, $6E, $6A, $60               // vmovq xmm5, qword [rdx + $60]
  db $C4, $E3, $D1, $22, $6A, $18, $01          // vpinsrq xmm5, xmm5, qword [rdx + $18], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m11,m14,m1,m9)
  db $C4, $E1, $F9, $6E, $62, $58               // vmovq xmm4, qword [rdx + $58]
  db $C4, $E3, $D9, $22, $62, $70, $01          // vpinsrq xmm4, xmm4, qword [rdx + $70], 1
  db $C4, $E1, $F9, $6E, $6A, $08               // vmovq xmm5, qword [rdx + $08]
  db $C4, $E3, $D1, $22, $6A, $48, $01          // vpinsrq xmm5, xmm5, qword [rdx + $48], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m2,m5,m15,m8)
  db $C4, $E1, $F9, $6E, $62, $10               // vmovq xmm4, qword [rdx + $10]
  db $C4, $E3, $D9, $22, $62, $28, $01          // vpinsrq xmm4, xmm4, qword [rdx + $28], 1
  db $C4, $E1, $F9, $6E, $6A, $78               // vmovq xmm5, qword [rdx + $78]
  db $C4, $E3, $D1, $22, $6A, $40, $01          // vpinsrq xmm5, xmm5, qword [rdx + $40], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m10,m0,m4,m6)
  db $C4, $E1, $F9, $6E, $62, $50               // vmovq xmm4, qword [rdx + $50]
  db $C4, $E3, $D9, $22, $22, $01               // vpinsrq xmm4, xmm4, qword [rdx], 1
  db $C4, $E1, $F9, $6E, $6A, $20               // vmovq xmm5, qword [rdx + $20]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 8 =====

  // G1 columns (msg: m6,m14,m11,m0)
  db $C4, $E1, $F9, $6E, $62, $30               // vmovq xmm4, qword [rdx + $30]
  db $C4, $E3, $D9, $22, $62, $70, $01          // vpinsrq xmm4, xmm4, qword [rdx + $70], 1
  db $C4, $E1, $F9, $6E, $6A, $58               // vmovq xmm5, qword [rdx + $58]
  db $C4, $E3, $D1, $22, $2A, $01               // vpinsrq xmm5, xmm5, qword [rdx], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m15,m9,m3,m8)
  db $C4, $E1, $F9, $6E, $62, $78               // vmovq xmm4, qword [rdx + $78]
  db $C4, $E3, $D9, $22, $62, $48, $01          // vpinsrq xmm4, xmm4, qword [rdx + $48], 1
  db $C4, $E1, $F9, $6E, $6A, $18               // vmovq xmm5, qword [rdx + $18]
  db $C4, $E3, $D1, $22, $6A, $40, $01          // vpinsrq xmm5, xmm5, qword [rdx + $40], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m10,m12,m13,m1)
  db $C4, $E1, $F9, $6E, $62, $50               // vmovq xmm4, qword [rdx + $50]
  db $C4, $E3, $D9, $22, $62, $60, $01          // vpinsrq xmm4, xmm4, qword [rdx + $60], 1
  db $C4, $E1, $F9, $6E, $6A, $68               // vmovq xmm5, qword [rdx + $68]
  db $C4, $E3, $D1, $22, $6A, $08, $01          // vpinsrq xmm5, xmm5, qword [rdx + $08], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m5,m2,m7,m4)
  db $C4, $E1, $F9, $6E, $62, $28               // vmovq xmm4, qword [rdx + $28]
  db $C4, $E3, $D9, $22, $62, $10, $01          // vpinsrq xmm4, xmm4, qword [rdx + $10], 1
  db $C4, $E1, $F9, $6E, $6A, $38               // vmovq xmm5, qword [rdx + $38]
  db $C4, $E3, $D1, $22, $6A, $20, $01          // vpinsrq xmm5, xmm5, qword [rdx + $20], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 9 =====

  // G1 columns (msg: m10,m8,m7,m1)
  db $C4, $E1, $F9, $6E, $62, $50               // vmovq xmm4, qword [rdx + $50]
  db $C4, $E3, $D9, $22, $62, $40, $01          // vpinsrq xmm4, xmm4, qword [rdx + $40], 1
  db $C4, $E1, $F9, $6E, $6A, $38               // vmovq xmm5, qword [rdx + $38]
  db $C4, $E3, $D1, $22, $6A, $08, $01          // vpinsrq xmm5, xmm5, qword [rdx + $08], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m2,m4,m6,m5)
  db $C4, $E1, $F9, $6E, $62, $10               // vmovq xmm4, qword [rdx + $10]
  db $C4, $E3, $D9, $22, $62, $20, $01          // vpinsrq xmm4, xmm4, qword [rdx + $20], 1
  db $C4, $E1, $F9, $6E, $6A, $30               // vmovq xmm5, qword [rdx + $30]
  db $C4, $E3, $D1, $22, $6A, $28, $01          // vpinsrq xmm5, xmm5, qword [rdx + $28], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m13,m15,m9,m3)
  db $C4, $E1, $F9, $6E, $62, $68               // vmovq xmm4, qword [rdx + $68]
  db $C4, $E3, $D9, $22, $62, $78, $01          // vpinsrq xmm4, xmm4, qword [rdx + $78], 1
  db $C4, $E1, $F9, $6E, $6A, $48               // vmovq xmm5, qword [rdx + $48]
  db $C4, $E3, $D1, $22, $6A, $18, $01          // vpinsrq xmm5, xmm5, qword [rdx + $18], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m0,m11,m14,m12)
  db $C4, $E1, $F9, $6E, $22                    // vmovq xmm4, qword [rdx]
  db $C4, $E3, $D9, $22, $62, $58, $01          // vpinsrq xmm4, xmm4, qword [rdx + $58], 1
  db $C4, $E1, $F9, $6E, $6A, $70               // vmovq xmm5, qword [rdx + $70]
  db $C4, $E3, $D1, $22, $6A, $60, $01          // vpinsrq xmm5, xmm5, qword [rdx + $60], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 10 =====

  // G1 columns (msg: m0,m2,m4,m6)
  db $C4, $E1, $F9, $6E, $22                    // vmovq xmm4, qword [rdx]
  db $C4, $E3, $D9, $22, $62, $10, $01          // vpinsrq xmm4, xmm4, qword [rdx + $10], 1
  db $C4, $E1, $F9, $6E, $6A, $20               // vmovq xmm5, qword [rdx + $20]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m1,m3,m5,m7)
  db $C4, $E1, $F9, $6E, $62, $08               // vmovq xmm4, qword [rdx + $08]
  db $C4, $E3, $D9, $22, $62, $18, $01          // vpinsrq xmm4, xmm4, qword [rdx + $18], 1
  db $C4, $E1, $F9, $6E, $6A, $28               // vmovq xmm5, qword [rdx + $28]
  db $C4, $E3, $D1, $22, $6A, $38, $01          // vpinsrq xmm5, xmm5, qword [rdx + $38], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m14,m8,m10,m12)
  db $C4, $E1, $F9, $6E, $62, $70               // vmovq xmm4, qword [rdx + $70]
  db $C4, $E3, $D9, $22, $62, $40, $01          // vpinsrq xmm4, xmm4, qword [rdx + $40], 1
  db $C4, $E1, $F9, $6E, $6A, $50               // vmovq xmm5, qword [rdx + $50]
  db $C4, $E3, $D1, $22, $6A, $60, $01          // vpinsrq xmm5, xmm5, qword [rdx + $60], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m15,m9,m11,m13)
  db $C4, $E1, $F9, $6E, $62, $78               // vmovq xmm4, qword [rdx + $78]
  db $C4, $E3, $D9, $22, $62, $48, $01          // vpinsrq xmm4, xmm4, qword [rdx + $48], 1
  db $C4, $E1, $F9, $6E, $6A, $58               // vmovq xmm5, qword [rdx + $58]
  db $C4, $E3, $D1, $22, $6A, $68, $01          // vpinsrq xmm5, xmm5, qword [rdx + $68], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // ===== Round 11 =====

  // G1 columns (msg: m14,m4,m9,m13)
  db $C4, $E1, $F9, $6E, $62, $70               // vmovq xmm4, qword [rdx + $70]
  db $C4, $E3, $D9, $22, $62, $20, $01          // vpinsrq xmm4, xmm4, qword [rdx + $20], 1
  db $C4, $E1, $F9, $6E, $6A, $48               // vmovq xmm5, qword [rdx + $48]
  db $C4, $E3, $D1, $22, $6A, $68, $01          // vpinsrq xmm5, xmm5, qword [rdx + $68], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 columns (msg: m10,m8,m15,m6)
  db $C4, $E1, $F9, $6E, $62, $50               // vmovq xmm4, qword [rdx + $50]
  db $C4, $E3, $D9, $22, $62, $40, $01          // vpinsrq xmm4, xmm4, qword [rdx + $40], 1
  db $C4, $E1, $F9, $6E, $6A, $78               // vmovq xmm5, qword [rdx + $78]
  db $C4, $E3, $D1, $22, $6A, $30, $01          // vpinsrq xmm5, xmm5, qword [rdx + $30], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Diagonalize
  db $C4, $E3, $FD, $00, $C0, $93               // vpermq ymm0, ymm0, $93
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $39               // vpermq ymm2, ymm2, $39

  // G1 diagonals (msg: m5,m1,m0,m11)
  db $C4, $E1, $F9, $6E, $62, $28               // vmovq xmm4, qword [rdx + $28]
  db $C4, $E3, $D9, $22, $62, $08, $01          // vpinsrq xmm4, xmm4, qword [rdx + $08], 1
  db $C4, $E1, $F9, $6E, $2A                    // vmovq xmm5, qword [rdx]
  db $C4, $E3, $D1, $22, $6A, $58, $01          // vpinsrq xmm5, xmm5, qword [rdx + $58], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $18                    // vpsrlq ymm5, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // G2 diagonals (msg: m3,m12,m2,m7)
  db $C4, $E1, $F9, $6E, $62, $18               // vmovq xmm4, qword [rdx + $18]
  db $C4, $E3, $D9, $22, $62, $60, $01          // vpinsrq xmm4, xmm4, qword [rdx + $60], 1
  db $C4, $E1, $F9, $6E, $6A, $10               // vmovq xmm5, qword [rdx + $10]
  db $C4, $E3, $D1, $22, $6A, $38, $01          // vpinsrq xmm5, xmm5, qword [rdx + $38], 1
  db $C4, $E3, $5D, $38, $E5, $01               // vinserti128 ymm4, ymm4, xmm5, 1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $D5, $73, $D3, $10                    // vpsrlq ymm5, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DD                         // vpor ymm3, ymm3, ymm5

  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $D5, $73, $D1, $3F                    // vpsrlq ymm5, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CD                         // vpor ymm1, ymm1, ymm5

  // Undiagonalize
  db $C4, $E3, $FD, $00, $C0, $39               // vpermq ymm0, ymm0, $39
  db $C4, $E3, $FD, $00, $DB, $4E               // vpermq ymm3, ymm3, $4E
  db $C4, $E3, $FD, $00, $D2, $93               // vpermq ymm2, ymm2, $93

  // Finalization
  db $C5, $FD, $EF, $C2                         // vpxor ymm0, ymm0, ymm2
  db $C5, $F5, $EF, $CB                         // vpxor ymm1, ymm1, ymm3

  // XOR with original state (re-read from memory)
  db $C5, $FD, $EF, $01                         // vpxor ymm0, ymm0, yword [rcx]
  db $C5, $F5, $EF, $49, $20                    // vpxor ymm1, ymm1, yword [rcx + $20]

  // Store result
  db $C5, $FE, $7F, $01                         // vmovdqu yword [rcx], ymm0
  db $C5, $FE, $7F, $49, $20                    // vmovdqu yword [rcx + $20], ymm1

  db $C5, $F8, $77                              // vzeroupper
