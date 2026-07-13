// AVX (VEX-128) implementation of fused XOR + Salsa20/8 on Percival-permuted
// data (IA-32). Same structure as ScryptSalsa8Avx_x86_64.inc; the state
// save/reload uses vmovdqu (IA-32 stacks are only 4-aligned), so the frame is
// 64 bytes with no alignment padding.
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
//
// Reference: Colin Percival, "Stronger Key Derivation via Sequential
// Memory-Hard Functions" (2009), and the Tarsnap scrypt reference
// implementation (crypto_scrypt-sse.c). The (i*5 mod 16) data permutation
// arranges each 16-word Salsa20 state into role-based diagonal order,
// enabling lane-parallel SIMD processing of column and row quarter-rounds
// with vpshufd-based diagonalize/undiagonalize between them.
//
// Identical algorithm to the SSE2 variant but uses VEX-128 3-operand
// encoding, eliminating movdqa register copies and reducing each QR step
// from 7 to 5 instructions.
//
// IA-32: after HlpSimdProc2Begin_i386 - ebx = State ptr, esi = Input ptr
//   (parallel to MS x64 ABI: rcx, rdx).
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   xmm0 = A = {w0,w5,w10,w15}, xmm1 = B = {w4,w9,w14,w3},
//   xmm2 = C = {w8,w13,w2,w7},  xmm3 = D = {w12,w1,w6,w11}.
// Operation: State = Salsa20/8(State XOR Input)
// Uses xmm0-xmm5 and eax (all volatile). No spills needed.

  sub    esp, $40

  // Load state, XOR with input, save for final addition
  db $C5, $FA, $6F, $03                         // vmovdqu xmm0, oword [ebx]
  db $C5, $FA, $6F, $26                         // vmovdqu xmm4, oword [esi]
  db $C5, $F9, $EF, $C4                         // vpxor  xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $4B, $10                    // vmovdqu xmm1, oword [ebx + $10]
  db $C5, $FA, $6F, $66, $10                    // vmovdqu xmm4, oword [esi + $10]
  db $C5, $F1, $EF, $CC                         // vpxor  xmm1, xmm1, xmm4
  db $C5, $FA, $6F, $53, $20                    // vmovdqu xmm2, oword [ebx + $20]
  db $C5, $FA, $6F, $66, $20                    // vmovdqu xmm4, oword [esi + $20]
  db $C5, $E9, $EF, $D4                         // vpxor  xmm2, xmm2, xmm4
  db $C5, $FA, $6F, $5B, $30                    // vmovdqu xmm3, oword [ebx + $30]
  db $C5, $FA, $6F, $66, $30                    // vmovdqu xmm4, oword [esi + $30]
  db $C5, $E1, $EF, $DC                         // vpxor  xmm3, xmm3, xmm4

  db $C5, $FA, $7F, $04, $24                    // vmovdqu oword [esp], xmm0
  db $C5, $FA, $7F, $4C, $24, $10               // vmovdqu oword [esp + $10], xmm1
  db $C5, $FA, $7F, $54, $24, $20               // vmovdqu oword [esp + $20], xmm2
  db $C5, $FA, $7F, $5C, $24, $30               // vmovdqu oword [esp + $30], xmm3

  // 4 double-rounds (= 8 rounds = Salsa20/8)
  mov    eax, $4
@double_round:
  // --- Column quarter-round ---
  // xmm1 ^= rotl(xmm0 + xmm3, 7)
  db $C5, $F9, $FE, $E3                         // vpaddd xmm4, xmm0, xmm3
  db $C5, $D1, $72, $F4, $07                    // vpslld xmm5, xmm4, $7
  db $C5, $D9, $72, $D4, $19                    // vpsrld xmm4, xmm4, $19
  db $C5, $F1, $EF, $CD                         // vpxor  xmm1, xmm1, xmm5
  db $C5, $F1, $EF, $CC                         // vpxor  xmm1, xmm1, xmm4
  // xmm2 ^= rotl(xmm1 + xmm0, 9)
  db $C5, $F1, $FE, $E0                         // vpaddd xmm4, xmm1, xmm0
  db $C5, $D1, $72, $F4, $09                    // vpslld xmm5, xmm4, $9
  db $C5, $D9, $72, $D4, $17                    // vpsrld xmm4, xmm4, $17
  db $C5, $E9, $EF, $D5                         // vpxor  xmm2, xmm2, xmm5
  db $C5, $E9, $EF, $D4                         // vpxor  xmm2, xmm2, xmm4
  // xmm3 ^= rotl(xmm2 + xmm1, 13)
  db $C5, $E9, $FE, $E1                         // vpaddd xmm4, xmm2, xmm1
  db $C5, $D1, $72, $F4, $0D                    // vpslld xmm5, xmm4, $D
  db $C5, $D9, $72, $D4, $13                    // vpsrld xmm4, xmm4, $13
  db $C5, $E1, $EF, $DD                         // vpxor  xmm3, xmm3, xmm5
  db $C5, $E1, $EF, $DC                         // vpxor  xmm3, xmm3, xmm4
  // xmm0 ^= rotl(xmm3 + xmm2, 18)
  db $C5, $E1, $FE, $E2                         // vpaddd xmm4, xmm3, xmm2
  db $C5, $D1, $72, $F4, $12                    // vpslld xmm5, xmm4, $12
  db $C5, $D9, $72, $D4, $0E                    // vpsrld xmm4, xmm4, $E
  db $C5, $F9, $EF, $C5                         // vpxor  xmm0, xmm0, xmm5
  db $C5, $F9, $EF, $C4                         // vpxor  xmm0, xmm0, xmm4
  // Diagonalize: rotate B right by 1, C by 2, D left by 1
  db $C5, $F9, $70, $C9, $93                    // vpshufd xmm1, xmm1, $93
  db $C5, $F9, $70, $D2, $4E                    // vpshufd xmm2, xmm2, $4E
  db $C5, $F9, $70, $DB, $39                    // vpshufd xmm3, xmm3, $39

  // --- Row quarter-round (B/D roles swapped after diagonal shuffle) ---
  // xmm3 ^= rotl(xmm0 + xmm1, 7)
  db $C5, $F9, $FE, $E1                         // vpaddd xmm4, xmm0, xmm1
  db $C5, $D1, $72, $F4, $07                    // vpslld xmm5, xmm4, $7
  db $C5, $D9, $72, $D4, $19                    // vpsrld xmm4, xmm4, $19
  db $C5, $E1, $EF, $DD                         // vpxor  xmm3, xmm3, xmm5
  db $C5, $E1, $EF, $DC                         // vpxor  xmm3, xmm3, xmm4
  // xmm2 ^= rotl(xmm3 + xmm0, 9)
  db $C5, $E1, $FE, $E0                         // vpaddd xmm4, xmm3, xmm0
  db $C5, $D1, $72, $F4, $09                    // vpslld xmm5, xmm4, $9
  db $C5, $D9, $72, $D4, $17                    // vpsrld xmm4, xmm4, $17
  db $C5, $E9, $EF, $D5                         // vpxor  xmm2, xmm2, xmm5
  db $C5, $E9, $EF, $D4                         // vpxor  xmm2, xmm2, xmm4
  // xmm1 ^= rotl(xmm2 + xmm3, 13)
  db $C5, $E9, $FE, $E3                         // vpaddd xmm4, xmm2, xmm3
  db $C5, $D1, $72, $F4, $0D                    // vpslld xmm5, xmm4, $D
  db $C5, $D9, $72, $D4, $13                    // vpsrld xmm4, xmm4, $13
  db $C5, $F1, $EF, $CD                         // vpxor  xmm1, xmm1, xmm5
  db $C5, $F1, $EF, $CC                         // vpxor  xmm1, xmm1, xmm4
  // xmm0 ^= rotl(xmm1 + xmm2, 18)
  db $C5, $F1, $FE, $E2                         // vpaddd xmm4, xmm1, xmm2
  db $C5, $D1, $72, $F4, $12                    // vpslld xmm5, xmm4, $12
  db $C5, $D9, $72, $D4, $0E                    // vpsrld xmm4, xmm4, $E
  db $C5, $F9, $EF, $C5                         // vpxor  xmm0, xmm0, xmm5
  db $C5, $F9, $EF, $C4                         // vpxor  xmm0, xmm0, xmm4
  // Undiagonalize: reverse the shuffles
  db $C5, $F9, $70, $C9, $39                    // vpshufd xmm1, xmm1, $39
  db $C5, $F9, $70, $D2, $4E                    // vpshufd xmm2, xmm2, $4E
  db $C5, $F9, $70, $DB, $93                    // vpshufd xmm3, xmm3, $93

  dec    eax
  jnz @double_round

  // Final addition and store
  db $C5, $FA, $6F, $24, $24                    // vmovdqu xmm4, oword [esp]
  db $C5, $F9, $FE, $C4                         // vpaddd xmm0, xmm0, xmm4
  db $C5, $FA, $6F, $64, $24, $10               // vmovdqu xmm4, oword [esp + $10]
  db $C5, $F1, $FE, $CC                         // vpaddd xmm1, xmm1, xmm4
  db $C5, $FA, $6F, $64, $24, $20               // vmovdqu xmm4, oword [esp + $20]
  db $C5, $E9, $FE, $D4                         // vpaddd xmm2, xmm2, xmm4
  db $C5, $FA, $6F, $64, $24, $30               // vmovdqu xmm4, oword [esp + $30]
  db $C5, $E1, $FE, $DC                         // vpaddd xmm3, xmm3, xmm4

  db $C5, $FA, $7F, $03                         // vmovdqu oword [ebx], xmm0
  db $C5, $FA, $7F, $4B, $10                    // vmovdqu oword [ebx + $10], xmm1
  db $C5, $FA, $7F, $53, $20                    // vmovdqu oword [ebx + $20], xmm2
  db $C5, $FA, $7F, $5B, $30                    // vmovdqu oword [ebx + $30], xmm3

  add    esp, $40
  pop    esi
  pop    ebx
