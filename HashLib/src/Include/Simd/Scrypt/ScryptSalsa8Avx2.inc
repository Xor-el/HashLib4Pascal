// AVX2 (VEX-128) implementation of fused XOR + Salsa20/8 on Percival-permuted data.
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
// Expects MS x64 ABI: rcx = State ptr, rdx = Input ptr.
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   xmm0 = A = {w0,w5,w10,w15}, xmm1 = B = {w4,w9,w14,w3},
//   xmm2 = C = {w8,w13,w2,w7},  xmm3 = D = {w12,w1,w6,w11}.
// Operation: State = Salsa20/8(State XOR Input)
// Uses xmm0-xmm5 (all volatile). No spills needed.
// Stack: 72 bytes (64 for saved XOR'd state + 8 alignment padding).

  sub rsp, 72

  // =========================================================================
  // Load state, XOR with input, save for final addition
  // =========================================================================
  vmovdqu xmm0, oword [rcx]
  vmovdqu xmm4, oword [rdx]
  vpxor xmm0, xmm0, xmm4
  vmovdqu xmm1, oword [rcx + $10]
  vmovdqu xmm4, oword [rdx + $10]
  vpxor xmm1, xmm1, xmm4
  vmovdqu xmm2, oword [rcx + $20]
  vmovdqu xmm4, oword [rdx + $20]
  vpxor xmm2, xmm2, xmm4
  vmovdqu xmm3, oword [rcx + $30]
  vmovdqu xmm4, oword [rdx + $30]
  vpxor xmm3, xmm3, xmm4

  vmovdqa oword [rsp], xmm0
  vmovdqa oword [rsp + $10], xmm1
  vmovdqa oword [rsp + $20], xmm2
  vmovdqa oword [rsp + $30], xmm3

  // =========================================================================
  // 4 double-rounds (= 8 rounds = Salsa20/8)
  // =========================================================================
  mov r10d, 4
@double_round:

  // --- Column quarter-round ---

  // xmm1 ^= rotl(xmm0 + xmm3, 7)
  vpaddd xmm4, xmm0, xmm3
  vpslld xmm5, xmm4, 7
  vpsrld xmm4, xmm4, 25
  vpxor xmm1, xmm1, xmm5
  vpxor xmm1, xmm1, xmm4

  // xmm2 ^= rotl(xmm1 + xmm0, 9)
  vpaddd xmm4, xmm1, xmm0
  vpslld xmm5, xmm4, 9
  vpsrld xmm4, xmm4, 23
  vpxor xmm2, xmm2, xmm5
  vpxor xmm2, xmm2, xmm4

  // xmm3 ^= rotl(xmm2 + xmm1, 13)
  vpaddd xmm4, xmm2, xmm1
  vpslld xmm5, xmm4, 13
  vpsrld xmm4, xmm4, 19
  vpxor xmm3, xmm3, xmm5
  vpxor xmm3, xmm3, xmm4

  // xmm0 ^= rotl(xmm3 + xmm2, 18)
  vpaddd xmm4, xmm3, xmm2
  vpslld xmm5, xmm4, 18
  vpsrld xmm4, xmm4, 14
  vpxor xmm0, xmm0, xmm5
  vpxor xmm0, xmm0, xmm4

  // Diagonalize: rotate B right by 1, C by 2, D left by 1
  vpshufd xmm1, xmm1, $93
  vpshufd xmm2, xmm2, $4E
  vpshufd xmm3, xmm3, $39

  // --- Row quarter-round (B/D roles swapped after diagonal shuffle) ---

  // xmm3 ^= rotl(xmm0 + xmm1, 7)
  vpaddd xmm4, xmm0, xmm1
  vpslld xmm5, xmm4, 7
  vpsrld xmm4, xmm4, 25
  vpxor xmm3, xmm3, xmm5
  vpxor xmm3, xmm3, xmm4

  // xmm2 ^= rotl(xmm3 + xmm0, 9)
  vpaddd xmm4, xmm3, xmm0
  vpslld xmm5, xmm4, 9
  vpsrld xmm4, xmm4, 23
  vpxor xmm2, xmm2, xmm5
  vpxor xmm2, xmm2, xmm4

  // xmm1 ^= rotl(xmm2 + xmm3, 13)
  vpaddd xmm4, xmm2, xmm3
  vpslld xmm5, xmm4, 13
  vpsrld xmm4, xmm4, 19
  vpxor xmm1, xmm1, xmm5
  vpxor xmm1, xmm1, xmm4

  // xmm0 ^= rotl(xmm1 + xmm2, 18)
  vpaddd xmm4, xmm1, xmm2
  vpslld xmm5, xmm4, 18
  vpsrld xmm4, xmm4, 14
  vpxor xmm0, xmm0, xmm5
  vpxor xmm0, xmm0, xmm4

  // Undiagonalize: reverse the shuffles
  vpshufd xmm1, xmm1, $39
  vpshufd xmm2, xmm2, $4E
  vpshufd xmm3, xmm3, $93

  dec r10d
  jnz @double_round

  // =========================================================================
  // Final addition and store
  // =========================================================================
  vmovdqa xmm4, oword [rsp]
  vpaddd xmm0, xmm0, xmm4
  vmovdqa xmm4, oword [rsp + $10]
  vpaddd xmm1, xmm1, xmm4
  vmovdqa xmm4, oword [rsp + $20]
  vpaddd xmm2, xmm2, xmm4
  vmovdqa xmm4, oword [rsp + $30]
  vpaddd xmm3, xmm3, xmm4

  vmovdqu oword [rcx], xmm0
  vmovdqu oword [rcx + $10], xmm1
  vmovdqu oword [rcx + $20], xmm2
  vmovdqu oword [rcx + $30], xmm3

  add rsp, 72
