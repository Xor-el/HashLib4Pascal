// AVX2 implementation of Argon2 FillBlock.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = Left ptr, rdx = Right ptr, r8 = Current ptr, r9 = WithXor (0 or 1).
// Each pointer addresses 128 QWords (1024 bytes).
// Uses ymm0-ymm9. Non-volatile ymm6-ymm9 saved/restored on Windows.
// Register map during G rounds: ymm0 = A(v0..v3), ymm1 = B(v4..v7),
//   ymm2 = C(v8..v11), ymm3 = D(v12..v15), ymm4-ymm5 = temps.
// Stack layout (sub rsp, 2184):
//   [rsp+0..127]    ymm6-9 save area (Windows only, 4 * 32 = 128 bytes)
//   [rsp+128..1151] R_buf (1024 bytes)
//   [rsp+1152..2175] Z_buf (1024 bytes)
//   [rsp+2176..2183] alignment padding
// r8 (Current) and r9 (WithXor) survive all loops (not clobbered).
// ARight and ACurrent may alias; R_buf buffering handles this.
// Diagonalize/Undiagonalize via vpermq (cross-lane 64-bit permute).
// vzeroupper required before return.

  sub rsp, 2184

{$IFDEF MSWINDOWS}
  db $C5, $FE, $7F, $34, $24                    // vmovdqu yword [rsp], ymm6
  db $C5, $FE, $7F, $7C, $24, $20               // vmovdqu yword [rsp + $20], ymm7
  db $C5, $7E, $7F, $44, $24, $40               // vmovdqu yword [rsp + $40], ymm8
  db $C5, $7E, $7F, $4C, $24, $60               // vmovdqu yword [rsp + $60], ymm9
{$ENDIF}

  // =========================================================================
  // Step 1: Compute R_buf = Left XOR Right, store at [rsp+128]
  // =========================================================================
  lea rax, [rsp + 128]
  xor r10, r10
@xor_loop:
  db $C4, $A1, $7E, $6F, $04, $11               // vmovdqu ymm0, yword [rcx + r10]
  db $C4, $A1, $7D, $EF, $04, $12               // vpxor ymm0, ymm0, yword [rdx + r10]
  db $C4, $A1, $7E, $7F, $04, $10               // vmovdqu yword [rax + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @xor_loop

  // =========================================================================
  // Step 2: Copy R_buf to Z_buf at [rsp+1152]
  // =========================================================================
  lea r11, [rsp + 1152]
  xor r10, r10
@copy_loop:
  db $C4, $A1, $7E, $6F, $04, $10               // vmovdqu ymm0, yword [rax + r10]
  db $C4, $81, $7E, $7F, $04, $13               // vmovdqu yword [r11 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @copy_loop

  // =========================================================================
  // Step 3: Column rounds on Z_buf (8 iterations, 16 QWords = 128 bytes each)
  // =========================================================================
  // Each iteration: load 4 ywords (128 bytes) into ymm0-3 (A,B,C,D),
  // apply BLAKE2_ROUND_NOMSG (columns + diagonals), store back.
  xor r10, r10

@col_loop:
  db $C4, $81, $7E, $6F, $04, $13               // vmovdqu ymm0, yword [r11 + r10]
  db $C4, $81, $7E, $6F, $4C, $13, $20          // vmovdqu ymm1, yword [r11 + r10 + $20]
  db $C4, $81, $7E, $6F, $54, $13, $40          // vmovdqu ymm2, yword [r11 + r10 + $40]
  db $C4, $81, $7E, $6F, $5C, $13, $60          // vmovdqu ymm3, yword [r11 + r10 + $60]

  // ----- Column G: G(A,B,C,D) across all 4 lanes -----

  // fBlaMka(a, b): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  // d = rotr64(d ^ a, 32)
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  // fBlaMka(c, d)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  // b = rotr64(b ^ c, 24)
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $18                    // vpsrlq ymm4, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  // fBlaMka(a, b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  // d = rotr64(d ^ a, 16)
  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $DD, $73, $D3, $10                    // vpsrlq ymm4, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DC                         // vpor ymm3, ymm3, ymm4

  // fBlaMka(c, d)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  // b = rotr64(b ^ c, 63)
  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  // ----- Diagonalize -----
  // B: rotate left by 1 QWord position
  db $C4, $E3, $FD, $00, $C9, $39               // vpermq ymm1, ymm1, $39
  // C: swap halves (rotate by 2)
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  // D: rotate right by 1 QWord position
  db $C4, $E3, $FD, $00, $DB, $93               // vpermq ymm3, ymm3, $93

  // ----- Diagonal G -----

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $18                    // vpsrlq ymm4, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $DD, $73, $D3, $10                    // vpsrlq ymm4, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DC                         // vpor ymm3, ymm3, ymm4

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  // ----- Undiagonalize -----
  db $C4, $E3, $FD, $00, $C9, $93               // vpermq ymm1, ymm1, $93
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $39               // vpermq ymm3, ymm3, $39

  // ----- Store back to Z_buf -----
  db $C4, $81, $7E, $7F, $04, $13               // vmovdqu yword [r11 + r10], ymm0
  db $C4, $81, $7E, $7F, $4C, $13, $20          // vmovdqu yword [r11 + r10 + $20], ymm1
  db $C4, $81, $7E, $7F, $54, $13, $40          // vmovdqu yword [r11 + r10 + $40], ymm2
  db $C4, $81, $7E, $7F, $5C, $13, $60          // vmovdqu yword [r11 + r10 + $60], ymm3

  add r10, 128
  cmp r10, 1024
  jb @col_loop

  // =========================================================================
  // Step 4: Row rounds on Z_buf (8 iterations, stride-16 QWord access)
  // =========================================================================
  // Row i: Z[2i,2i+1, 2i+16,2i+17, 2i+32,2i+33, 2i+48,2i+49,
  //          2i+64,2i+65, 2i+80,2i+81, 2i+96,2i+97, 2i+112,2i+113]
  // Load via vmovdqu xmm + vinserti128 to gather non-contiguous pairs.
  // Stride between pairs = 128 bytes.
  // ymm0 = A = (Z[2i..2i+1], Z[2i+16..2i+17])
  // ymm1 = B = (Z[2i+32..2i+33], Z[2i+48..2i+49])
  // ymm2 = C = (Z[2i+64..2i+65], Z[2i+80..2i+81])
  // ymm3 = D = (Z[2i+96..2i+97], Z[2i+112..2i+113])
  xor r10, r10

@row_loop:
  db $C4, $81, $7A, $6F, $04, $13               // vmovdqu xmm0, oword [r11 + r10]
  db $C4, $83, $7D, $38, $84, $13, $80, $00, $00, $00, $01 // vinserti128 ymm0, ymm0, oword [r11 + r10 + 128], 1
  db $C4, $81, $7A, $6F, $8C, $13, $00, $01, $00, $00 // vmovdqu xmm1, oword [r11 + r10 + 256]
  db $C4, $83, $75, $38, $8C, $13, $80, $01, $00, $00, $01 // vinserti128 ymm1, ymm1, oword [r11 + r10 + 384], 1
  db $C4, $81, $7A, $6F, $94, $13, $00, $02, $00, $00 // vmovdqu xmm2, oword [r11 + r10 + 512]
  db $C4, $83, $6D, $38, $94, $13, $80, $02, $00, $00, $01 // vinserti128 ymm2, ymm2, oword [r11 + r10 + 640], 1
  db $C4, $81, $7A, $6F, $9C, $13, $00, $03, $00, $00 // vmovdqu xmm3, oword [r11 + r10 + 768]
  db $C4, $83, $65, $38, $9C, $13, $80, $03, $00, $00, $01 // vinserti128 ymm3, ymm3, oword [r11 + r10 + 896], 1

  // ----- Column G -----

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $18                    // vpsrlq ymm4, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $DD, $73, $D3, $10                    // vpsrlq ymm4, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DC                         // vpor ymm3, ymm3, ymm4

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  // ----- Diagonalize -----
  db $C4, $E3, $FD, $00, $C9, $39               // vpermq ymm1, ymm1, $39
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $93               // vpermq ymm3, ymm3, $93

  // ----- Diagonal G -----

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $18                    // vpsrlq ymm4, ymm1, 24
  db $C5, $F5, $73, $F1, $28                    // vpsllq ymm1, ymm1, 40
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4

  db $C5, $E5, $EF, $D8                         // vpxor ymm3, ymm3, ymm0
  db $C5, $DD, $73, $D3, $10                    // vpsrlq ymm4, ymm3, 16
  db $C5, $E5, $73, $F3, $30                    // vpsllq ymm3, ymm3, 48
  db $C5, $E5, $EB, $DC                         // vpor ymm3, ymm3, ymm4

  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, 1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4

  db $C5, $F5, $EF, $CA                         // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, 63
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor ymm1, ymm1, ymm4

  // ----- Undiagonalize -----
  db $C4, $E3, $FD, $00, $C9, $93               // vpermq ymm1, ymm1, $93
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $39               // vpermq ymm3, ymm3, $39

  // ----- Store back to Z_buf (scatter to stride offsets) -----
  db $C4, $81, $7A, $7F, $04, $13               // vmovdqu oword [r11 + r10], xmm0
  db $C4, $83, $7D, $39, $84, $13, $80, $00, $00, $00, $01 // vextracti128 oword [r11 + r10 + 128], ymm0, 1
  db $C4, $81, $7A, $7F, $8C, $13, $00, $01, $00, $00 // vmovdqu oword [r11 + r10 + 256], xmm1
  db $C4, $83, $7D, $39, $8C, $13, $80, $01, $00, $00, $01 // vextracti128 oword [r11 + r10 + 384], ymm1, 1
  db $C4, $81, $7A, $7F, $94, $13, $00, $02, $00, $00 // vmovdqu oword [r11 + r10 + 512], xmm2
  db $C4, $83, $7D, $39, $94, $13, $80, $02, $00, $00, $01 // vextracti128 oword [r11 + r10 + 640], ymm2, 1
  db $C4, $81, $7A, $7F, $9C, $13, $00, $03, $00, $00 // vmovdqu oword [r11 + r10 + 768], xmm3
  db $C4, $83, $7D, $39, $9C, $13, $80, $03, $00, $00, $01 // vextracti128 oword [r11 + r10 + 896], ymm3, 1

  add r10, 16
  cmp r10, 128
  jb @row_loop

  // =========================================================================
  // Step 5: Final XOR — Current = R_buf XOR Z_buf [XOR Current]
  // =========================================================================
  test r9, r9
  jnz @final_with_xor

  xor r10, r10
@final_noxor_loop:
  db $C4, $A1, $7E, $6F, $04, $10               // vmovdqu ymm0, yword [rax + r10]
  db $C4, $81, $7D, $EF, $04, $13               // vpxor ymm0, ymm0, yword [r11 + r10]
  db $C4, $81, $7E, $7F, $04, $10               // vmovdqu yword [r8 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @final_noxor_loop
  jmp @epilogue

@final_with_xor:
  xor r10, r10
@final_xor_loop:
  db $C4, $A1, $7E, $6F, $04, $10               // vmovdqu ymm0, yword [rax + r10]
  db $C4, $81, $7D, $EF, $04, $13               // vpxor ymm0, ymm0, yword [r11 + r10]
  db $C4, $81, $7D, $EF, $04, $10               // vpxor ymm0, ymm0, yword [r8 + r10]
  db $C4, $81, $7E, $7F, $04, $10               // vmovdqu yword [r8 + r10], ymm0
  add r10, 32
  cmp r10, 1024
  jb @final_xor_loop

@epilogue:
{$IFDEF MSWINDOWS}
  db $C5, $FE, $6F, $34, $24                    // vmovdqu ymm6, yword [rsp]
  db $C5, $FE, $6F, $7C, $24, $20               // vmovdqu ymm7, yword [rsp + $20]
  db $C5, $7E, $6F, $44, $24, $40               // vmovdqu ymm8, yword [rsp + $40]
  db $C5, $7E, $6F, $4C, $24, $60               // vmovdqu ymm9, yword [rsp + $60]
{$ENDIF}

  add rsp, 2184
  db $C5, $F8, $77                              // vzeroupper
