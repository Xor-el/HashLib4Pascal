// SSE2 implementation of fused XOR + Salsa20/8 on Percival-permuted data.
//
// Reference: Colin Percival, "Stronger Key Derivation via Sequential
// Memory-Hard Functions" (2009), and the Tarsnap scrypt reference
// implementation (crypto_scrypt-sse.c). The (i*5 mod 16) data permutation
// arranges each 16-word Salsa20 state into role-based diagonal order,
// enabling lane-parallel SIMD processing of column and row quarter-rounds
// with pshufd-based diagonalize/undiagonalize between them.
//
// IA-32: after SimdProc2Begin_i386 — ebx = State ptr, esi = Input ptr
//   (parallel to MS x64 ABI: rcx, rdx).
// Each pointer addresses 16 UInt32 (64 bytes) in permuted order:
//   xmm0 = A = {w0,w5,w10,w15}, xmm1 = B = {w4,w9,w14,w3},
//   xmm2 = C = {w8,w13,w2,w7},  xmm3 = D = {w12,w1,w6,w11}.
// Operation: State = Salsa20/8(State XOR Input)
// Uses xmm0–xmm5. Stack: sub esp, 72 (64 for saved XOR'd state + 8 alignment padding).
//
// Column QR / diagonal / row QR: same structure as ScryptSalsa8Sse2.inc header on x86-64.

  sub esp, 72

  movdqu xmm0, oword ptr [ebx]
  movdqu xmm4, oword ptr [esi]
  pxor xmm0, xmm4
  movdqu xmm1, oword ptr [ebx + $10]
  movdqu xmm4, oword ptr [esi + $10]
  pxor xmm1, xmm4
  movdqu xmm2, oword ptr [ebx + $20]
  movdqu xmm4, oword ptr [esi + $20]
  pxor xmm2, xmm4
  movdqu xmm3, oword ptr [ebx + $30]
  movdqu xmm4, oword ptr [esi + $30]
  pxor xmm3, xmm4

  movdqu oword ptr [esp], xmm0
  movdqu oword ptr [esp + $10], xmm1
  movdqu oword ptr [esp + $20], xmm2
  movdqu oword ptr [esp + $30], xmm3

  mov ecx, 4
@double_round:

  movdqa xmm4, xmm0
  paddd xmm4, xmm3
  movdqa xmm5, xmm4
  pslld xmm5, 7
  psrld xmm4, 25
  pxor xmm1, xmm5
  pxor xmm1, xmm4

  movdqa xmm4, xmm1
  paddd xmm4, xmm0
  movdqa xmm5, xmm4
  pslld xmm5, 9
  psrld xmm4, 23
  pxor xmm2, xmm5
  pxor xmm2, xmm4

  movdqa xmm4, xmm2
  paddd xmm4, xmm1
  movdqa xmm5, xmm4
  pslld xmm5, 13
  psrld xmm4, 19
  pxor xmm3, xmm5
  pxor xmm3, xmm4

  movdqa xmm4, xmm3
  paddd xmm4, xmm2
  movdqa xmm5, xmm4
  pslld xmm5, 18
  psrld xmm4, 14
  pxor xmm0, xmm5
  pxor xmm0, xmm4

  pshufd xmm1, xmm1, $93
  pshufd xmm2, xmm2, $4E
  pshufd xmm3, xmm3, $39

  movdqa xmm4, xmm0
  paddd xmm4, xmm1
  movdqa xmm5, xmm4
  pslld xmm5, 7
  psrld xmm4, 25
  pxor xmm3, xmm5
  pxor xmm3, xmm4

  movdqa xmm4, xmm3
  paddd xmm4, xmm0
  movdqa xmm5, xmm4
  pslld xmm5, 9
  psrld xmm4, 23
  pxor xmm2, xmm5
  pxor xmm2, xmm4

  movdqa xmm4, xmm2
  paddd xmm4, xmm3
  movdqa xmm5, xmm4
  pslld xmm5, 13
  psrld xmm4, 19
  pxor xmm1, xmm5
  pxor xmm1, xmm4

  movdqa xmm4, xmm1
  paddd xmm4, xmm2
  movdqa xmm5, xmm4
  pslld xmm5, 18
  psrld xmm4, 14
  pxor xmm0, xmm5
  pxor xmm0, xmm4

  pshufd xmm1, xmm1, $39
  pshufd xmm2, xmm2, $4E
  pshufd xmm3, xmm3, $93

  dec ecx
  jnz @double_round

  movdqu xmm4, oword ptr [esp]
  paddd xmm0, xmm4
  movdqu xmm4, oword ptr [esp + $10]
  paddd xmm1, xmm4
  movdqu xmm4, oword ptr [esp + $20]
  paddd xmm2, xmm4
  movdqu xmm4, oword ptr [esp + $30]
  paddd xmm3, xmm4

  movdqu oword ptr [ebx], xmm0
  movdqu oword ptr [ebx + $10], xmm1
  movdqu oword ptr [ebx + $20], xmm2
  movdqu oword ptr [ebx + $30], xmm3

  add esp, 72
  pop esi
  pop ebx
