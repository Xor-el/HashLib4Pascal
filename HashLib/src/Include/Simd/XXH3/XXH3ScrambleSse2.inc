// SSE2 implementation of XXH3_scrambleAcc (fully unrolled, 4 x 16-byte chunks).
// Expects MS x64 ABI: rcx = acc ptr, rdx = secret ptr.
// Uses only volatile registers: xmm0-xmm5, eax.
// Algorithm per 128-bit chunk:
//   acc ^= (acc >> 47)
//   acc ^= secret
//   acc *= XXH_PRIME32_1
// Reference: official xxHash C - XXH3_scrambleAcc_sse2 in xxhash.h

  // Load XXH_PRIME32_1 ($9E3779B1) into xmm5 as broadcast dword
  mov eax, $9E3779B1
  movd xmm5, eax
  pshufd xmm5, xmm5, 0

  // --- Chunk 0: acc[0..1], secret[0..15] ---
  movdqu xmm0, oword [rcx]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [rdx]
  pxor xmm0, xmm1
  // Multiply 64-bit lanes by PRIME32_1 using two 32x32->64 multiplies
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [rcx], xmm0

  // --- Chunk 1: acc[2..3], secret[16..31] ---
  movdqu xmm0, oword [rcx + $10]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [rdx + $10]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [rcx + $10], xmm0

  // --- Chunk 2: acc[4..5], secret[32..47] ---
  movdqu xmm0, oword [rcx + $20]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [rdx + $20]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [rcx + $20], xmm0

  // --- Chunk 3: acc[6..7], secret[48..63] ---
  movdqu xmm0, oword [rcx + $30]
  movdqu xmm1, xmm0
  psrlq xmm1, 47
  pxor xmm0, xmm1
  movdqu xmm1, oword [rdx + $30]
  pxor xmm0, xmm1
  pshufd xmm1, xmm0, $31
  pmuludq xmm0, xmm5
  pmuludq xmm1, xmm5
  psllq xmm1, 32
  paddq xmm0, xmm1
  movdqu oword [rcx + $30], xmm0
