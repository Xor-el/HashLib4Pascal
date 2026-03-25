// SSE2 implementation of fused XOR + Salsa20/8 on Percival-permuted data.
//
// Reference: Colin Percival, "Stronger Key Derivation via Sequential
// Memory-Hard Functions" (2009), and the Tarsnap scrypt reference
// implementation (crypto_scrypt-sse.c). The (i*5 mod 16) data permutation
// arranges each 16-word Salsa20 state into role-based diagonal order,
// enabling lane-parallel SIMD processing of column and row quarter-rounds
// with pshufd-based diagonalize/undiagonalize between them.
//
// Expects MS x64 ABI: rcx = State ptr, rdx = Input ptr.
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   xmm0 = A = {w0,w5,w10,w15}, xmm1 = B = {w4,w9,w14,w3},
//   xmm2 = C = {w8,w13,w2,w7},  xmm3 = D = {w12,w1,w6,w11}.
// Operation: State = Salsa20/8(State XOR Input)
// Uses xmm0-xmm5 (all volatile on Windows and System V). No spills needed.
// Stack: 72 bytes (64 for saved XOR'd state + 8 alignment padding).
//
// Column QR (lane-parallel):
//   B ^= rotl(A+D,7); C ^= rotl(B+A,9); D ^= rotl(C+B,13); A ^= rotl(D+C,18)
// Diag:   pshufd B,$93; pshufd C,$4E; pshufd D,$39
// Row QR (lane-parallel, swapped B/D roles):
//   D' ^= rotl(A+B',7); C' ^= rotl(D'+A,9); B' ^= rotl(C'+D',13); A ^= rotl(B'+C',18)
// Undiag: pshufd B,$39; pshufd C,$4E; pshufd D,$93

  sub rsp, 72

  // =========================================================================
  // Load state, XOR with input, save for final addition
  // =========================================================================
  movdqu xmm0, oword [rcx]
  movdqu xmm4, oword [rdx]
  pxor xmm0, xmm4
  movdqu xmm1, oword [rcx + $10]
  movdqu xmm4, oword [rdx + $10]
  pxor xmm1, xmm4
  movdqu xmm2, oword [rcx + $20]
  movdqu xmm4, oword [rdx + $20]
  pxor xmm2, xmm4
  movdqu xmm3, oword [rcx + $30]
  movdqu xmm4, oword [rdx + $30]
  pxor xmm3, xmm4

  movdqa oword [rsp], xmm0
  movdqa oword [rsp + $10], xmm1
  movdqa oword [rsp + $20], xmm2
  movdqa oword [rsp + $30], xmm3

  // =========================================================================
  // 4 double-rounds (= 8 rounds = Salsa20/8)
  // =========================================================================
  mov r10d, 4
@double_round:

  // --- Column quarter-round ---

  // xmm1 ^= rotl(xmm0 + xmm3, 7)
  movdqa xmm4, xmm0
  paddd xmm4, xmm3
  movdqa xmm5, xmm4
  pslld xmm5, 7
  psrld xmm4, 25
  pxor xmm1, xmm5
  pxor xmm1, xmm4

  // xmm2 ^= rotl(xmm1 + xmm0, 9)
  movdqa xmm4, xmm1
  paddd xmm4, xmm0
  movdqa xmm5, xmm4
  pslld xmm5, 9
  psrld xmm4, 23
  pxor xmm2, xmm5
  pxor xmm2, xmm4

  // xmm3 ^= rotl(xmm2 + xmm1, 13)
  movdqa xmm4, xmm2
  paddd xmm4, xmm1
  movdqa xmm5, xmm4
  pslld xmm5, 13
  psrld xmm4, 19
  pxor xmm3, xmm5
  pxor xmm3, xmm4

  // xmm0 ^= rotl(xmm3 + xmm2, 18)
  movdqa xmm4, xmm3
  paddd xmm4, xmm2
  movdqa xmm5, xmm4
  pslld xmm5, 18
  psrld xmm4, 14
  pxor xmm0, xmm5
  pxor xmm0, xmm4

  // Diagonalize: rotate B right by 1, C by 2, D left by 1
  pshufd xmm1, xmm1, $93
  pshufd xmm2, xmm2, $4E
  pshufd xmm3, xmm3, $39

  // --- Row quarter-round (B/D roles swapped after diagonal shuffle) ---

  // xmm3 ^= rotl(xmm0 + xmm1, 7)
  movdqa xmm4, xmm0
  paddd xmm4, xmm1
  movdqa xmm5, xmm4
  pslld xmm5, 7
  psrld xmm4, 25
  pxor xmm3, xmm5
  pxor xmm3, xmm4

  // xmm2 ^= rotl(xmm3 + xmm0, 9)
  movdqa xmm4, xmm3
  paddd xmm4, xmm0
  movdqa xmm5, xmm4
  pslld xmm5, 9
  psrld xmm4, 23
  pxor xmm2, xmm5
  pxor xmm2, xmm4

  // xmm1 ^= rotl(xmm2 + xmm3, 13)
  movdqa xmm4, xmm2
  paddd xmm4, xmm3
  movdqa xmm5, xmm4
  pslld xmm5, 13
  psrld xmm4, 19
  pxor xmm1, xmm5
  pxor xmm1, xmm4

  // xmm0 ^= rotl(xmm1 + xmm2, 18)
  movdqa xmm4, xmm1
  paddd xmm4, xmm2
  movdqa xmm5, xmm4
  pslld xmm5, 18
  psrld xmm4, 14
  pxor xmm0, xmm5
  pxor xmm0, xmm4

  // Undiagonalize: reverse the shuffles
  pshufd xmm1, xmm1, $39
  pshufd xmm2, xmm2, $4E
  pshufd xmm3, xmm3, $93

  dec r10d
  jnz @double_round

  // =========================================================================
  // Final addition and store
  // =========================================================================
  movdqa xmm4, oword [rsp]
  paddd xmm0, xmm4
  movdqa xmm4, oword [rsp + $10]
  paddd xmm1, xmm4
  movdqa xmm4, oword [rsp + $20]
  paddd xmm2, xmm4
  movdqa xmm4, oword [rsp + $30]
  paddd xmm3, xmm4

  movdqu oword [rcx], xmm0
  movdqu oword [rcx + $10], xmm1
  movdqu oword [rcx + $20], xmm2
  movdqu oword [rcx + $30], xmm3

  add rsp, 72
