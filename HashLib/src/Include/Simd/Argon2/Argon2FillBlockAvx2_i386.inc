// AVX2 implementation of Argon2 FillBlock (BlaMka round function; IA-32).
// 256-bit ymm integer ops work in 32-bit mode; same algorithm and buffer
// layout as Argon2FillBlockAvx2_x86_64.inc, redesigned for the IA-32
// register budget:
//  - the byte-rotation masks are VEX memory operands (rot24 at [masks],
//    rot16 at [masks+$20]; read unaligned, so the Pascal const needs no
//    special alignment) - the kernel touches only ymm0-ymm4;
//  - R_buf/Z_buf sit at [esp]/[esp+1024] and are addressed [esp+edx+disp]
//    (edx = loop offset) - no buffer pointer registers are needed;
//  - Left/Right are dead after step 1's XOR.
// Diagonalize/Undiagonalize via vpermq. vzeroupper required before return.
// ABI (after HlpSimdProc5Begin_i386.inc): ebx = Left ptr, esi = Right ptr,
//   edi = Current ptr, eax = WithXor (0 or 1; live until the final step),
//   ecx = byte-rotation masks ptr (ARGON2_ROT_MASKS; live throughout).
//   Each pointer addresses 128 QWords (1024 bytes). ARight and ACurrent may
//   alias; R_buf buffering handles this.
// Frame (sub esp, 2048): [esp+0..1023] R_buf, [esp+1024..2047] Z_buf.
// Saves: none (uses ymm0-ymm4 only; all volatile on IA-32).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Reference: official Argon2 AVX2 (blamka-round-opt.h), HashLib
// Argon2FillBlockAvx2_x86_64.inc.

  sub    esp, $800

  // Step 1: R_buf = Left XOR Right at [esp] (Left/Right dead afterwards)
  xor    edx, edx

@xor_loop:
  db $C5, $FE, $6F, $04, $13                    // vmovdqu ymm0, yword [ebx + edx*1]
  db $C5, $FD, $EF, $04, $16                    // vpxor  ymm0, ymm0, yword [esi + edx*1]
  db $C5, $FE, $7F, $04, $14                    // vmovdqu yword [esp + edx*1], ymm0
  add    edx, $20
  cmp    edx, $400
  jb @xor_loop

  // Step 2: copy R_buf to Z_buf at [esp+1024]
  xor    edx, edx

@copy_loop:
  db $C5, $FE, $6F, $04, $14                    // vmovdqu ymm0, yword [esp + edx*1]
  db $C5, $FE, $7F, $84, $14, $00, $04, $00, $00// vmovdqu yword [esp + edx*1 + $400], ymm0
  add    edx, $20
  cmp    edx, $400
  jb @copy_loop

  // Step 3: column rounds on Z_buf (8 iterations, 128 bytes each)
  xor    edx, edx

@col_loop:
  db $C5, $FE, $6F, $84, $14, $00, $04, $00, $00// vmovdqu ymm0, yword [esp + edx*1 + $400]
  db $C5, $FE, $6F, $8C, $14, $20, $04, $00, $00// vmovdqu ymm1, yword [esp + edx*1 + $420]
  db $C5, $FE, $6F, $94, $14, $40, $04, $00, $00// vmovdqu ymm2, yword [esp + edx*1 + $440]
  db $C5, $FE, $6F, $9C, $14, $60, $04, $00, $00// vmovdqu ymm3, yword [esp + edx*1 + $460]
  // ----- Column G -----
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 32)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 24)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $09                    // vpshufb ymm1, ymm1, yword [ecx]
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 16)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $59, $20               // vpshufb ymm3, ymm3, yword [ecx + $20]
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 63)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor   ymm1, ymm1, ymm4
  // ----- Diagonalize -----
  db $C4, $E3, $FD, $00, $C9, $39               // vpermq ymm1, ymm1, $39
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $93               // vpermq ymm3, ymm3, $93
  // ----- Diagonal G -----
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 32)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 24)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $09                    // vpshufb ymm1, ymm1, yword [ecx]
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 16)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $59, $20               // vpshufb ymm3, ymm3, yword [ecx + $20]
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 63)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor   ymm1, ymm1, ymm4
  // ----- Undiagonalize -----
  db $C4, $E3, $FD, $00, $C9, $93               // vpermq ymm1, ymm1, $93
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $39               // vpermq ymm3, ymm3, $39
  db $C5, $FE, $7F, $84, $14, $00, $04, $00, $00// vmovdqu yword [esp + edx*1 + $400], ymm0
  db $C5, $FE, $7F, $8C, $14, $20, $04, $00, $00// vmovdqu yword [esp + edx*1 + $420], ymm1
  db $C5, $FE, $7F, $94, $14, $40, $04, $00, $00// vmovdqu yword [esp + edx*1 + $440], ymm2
  db $C5, $FE, $7F, $9C, $14, $60, $04, $00, $00// vmovdqu yword [esp + edx*1 + $460], ymm3
  add    edx, $80
  cmp    edx, $400
  jb @col_loop

  // Step 4: row rounds on Z_buf (8 iterations, stride-16-QWord gathers)
  xor    edx, edx

@row_loop:
  db $C5, $FA, $6F, $84, $14, $00, $04, $00, $00// vmovdqu xmm0, oword [esp + edx*1 + $400]
  db $C4, $E3, $7D, $38, $84, $14, $80, $04, $00, $00, $01// vinserti128 ymm0, ymm0, oword [esp + edx*1 + $480], $1
  db $C5, $FA, $6F, $8C, $14, $00, $05, $00, $00// vmovdqu xmm1, oword [esp + edx*1 + $500]
  db $C4, $E3, $75, $38, $8C, $14, $80, $05, $00, $00, $01// vinserti128 ymm1, ymm1, oword [esp + edx*1 + $580], $1
  db $C5, $FA, $6F, $94, $14, $00, $06, $00, $00// vmovdqu xmm2, oword [esp + edx*1 + $600]
  db $C4, $E3, $6D, $38, $94, $14, $80, $06, $00, $00, $01// vinserti128 ymm2, ymm2, oword [esp + edx*1 + $680], $1
  db $C5, $FA, $6F, $9C, $14, $00, $07, $00, $00// vmovdqu xmm3, oword [esp + edx*1 + $700]
  db $C4, $E3, $65, $38, $9C, $14, $80, $07, $00, $00, $01// vinserti128 ymm3, ymm3, oword [esp + edx*1 + $780], $1
  // ----- Column G -----
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 32)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 24)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $09                    // vpshufb ymm1, ymm1, yword [ecx]
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 16)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $59, $20               // vpshufb ymm3, ymm3, yword [ecx + $20]
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 63)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor   ymm1, ymm1, ymm4
  // ----- Diagonalize -----
  db $C4, $E3, $FD, $00, $C9, $39               // vpermq ymm1, ymm1, $39
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $93               // vpermq ymm3, ymm3, $93
  // ----- Diagonal G -----
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 32)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C5, $FD, $70, $DB, $B1                    // vpshufd ymm3, ymm3, $B1
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 24)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C4, $E2, $75, $00, $09                    // vpshufb ymm1, ymm1, yword [ecx]
  // fBlaMka(0, 1): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $FD, $F4, $E1                         // vpmuludq ymm4, ymm0, ymm1
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $FD, $D4, $C1                         // vpaddq ymm0, ymm0, ymm1
  db $C5, $FD, $D4, $C4                         // vpaddq ymm0, ymm0, ymm4
  // d = rotr64(d ^ a, 16)
  db $C5, $E5, $EF, $D8                         // vpxor  ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $59, $20               // vpshufb ymm3, ymm3, yword [ecx + $20]
  // fBlaMka(2, 3): a = a + b + 2*lo32(a)*lo32(b)
  db $C5, $ED, $F4, $E3                         // vpmuludq ymm4, ymm2, ymm3
  db $C5, $DD, $73, $F4, $01                    // vpsllq ymm4, ymm4, $1
  db $C5, $ED, $D4, $D3                         // vpaddq ymm2, ymm2, ymm3
  db $C5, $ED, $D4, $D4                         // vpaddq ymm2, ymm2, ymm4
  // b = rotr64(b ^ c, 63)
  db $C5, $F5, $EF, $CA                         // vpxor  ymm1, ymm1, ymm2
  db $C5, $DD, $73, $D1, $3F                    // vpsrlq ymm4, ymm1, $3F
  db $C5, $F5, $D4, $C9                         // vpaddq ymm1, ymm1, ymm1
  db $C5, $F5, $EB, $CC                         // vpor   ymm1, ymm1, ymm4
  // ----- Undiagonalize -----
  db $C4, $E3, $FD, $00, $C9, $93               // vpermq ymm1, ymm1, $93
  db $C4, $E3, $FD, $00, $D2, $4E               // vpermq ymm2, ymm2, $4E
  db $C4, $E3, $FD, $00, $DB, $39               // vpermq ymm3, ymm3, $39
  db $C5, $FA, $7F, $84, $14, $00, $04, $00, $00// vmovdqu oword [esp + edx*1 + $400], xmm0
  db $C4, $E3, $7D, $39, $84, $14, $80, $04, $00, $00, $01// vextracti128 oword [esp + edx*1 + $480], ymm0, $1
  db $C5, $FA, $7F, $8C, $14, $00, $05, $00, $00// vmovdqu oword [esp + edx*1 + $500], xmm1
  db $C4, $E3, $7D, $39, $8C, $14, $80, $05, $00, $00, $01// vextracti128 oword [esp + edx*1 + $580], ymm1, $1
  db $C5, $FA, $7F, $94, $14, $00, $06, $00, $00// vmovdqu oword [esp + edx*1 + $600], xmm2
  db $C4, $E3, $7D, $39, $94, $14, $80, $06, $00, $00, $01// vextracti128 oword [esp + edx*1 + $680], ymm2, $1
  db $C5, $FA, $7F, $9C, $14, $00, $07, $00, $00// vmovdqu oword [esp + edx*1 + $700], xmm3
  db $C4, $E3, $7D, $39, $9C, $14, $80, $07, $00, $00, $01// vextracti128 oword [esp + edx*1 + $780], ymm3, $1
  add    edx, $10
  cmp    edx, $80
  jb @row_loop

  // Step 5: Current = R_buf XOR Z_buf [XOR Current]
  test   eax, eax
  jnz @final_with_xor

  xor    edx, edx

@final_noxor_loop:
  db $C5, $FE, $6F, $04, $14                    // vmovdqu ymm0, yword [esp + edx*1]
  db $C5, $FD, $EF, $84, $14, $00, $04, $00, $00// vpxor  ymm0, ymm0, yword [esp + edx*1 + $400]
  db $C5, $FE, $7F, $04, $17                    // vmovdqu yword [edi + edx*1], ymm0
  add    edx, $20
  cmp    edx, $400
  jb @final_noxor_loop
  jmp @epilogue


@final_with_xor:
  xor    edx, edx

@final_xor_loop:
  db $C5, $FE, $6F, $04, $14                    // vmovdqu ymm0, yword [esp + edx*1]
  db $C5, $FD, $EF, $84, $14, $00, $04, $00, $00// vpxor  ymm0, ymm0, yword [esp + edx*1 + $400]
  db $C5, $FD, $EF, $04, $17                    // vpxor  ymm0, ymm0, yword [edi + edx*1]
  db $C5, $FE, $7F, $04, $17                    // vmovdqu yword [edi + edx*1], ymm0
  add    edx, $20
  cmp    edx, $400
  jb @final_xor_loop


@epilogue:
  add    esp, $800
  db $C5, $F8, $77                              // vzeroupper
  pop    edi
  pop    esi
  pop    ebx
