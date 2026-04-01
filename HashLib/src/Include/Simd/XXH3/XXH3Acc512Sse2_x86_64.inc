// SSE2 implementation of XXH3_accumulate_512 (fully unrolled, 4 x 16-byte chunks).
// Expects MS x64 ABI: rcx = acc ptr, rdx = input ptr, r8 = secret ptr.
// Uses only volatile registers: xmm0-xmm5.
// Reference: official xxHash C - XXH3_accumulate_512_sse2 in xxhash.h

  // --- Chunk 0: acc[0..1], input[0..15], secret[0..15] ---
  movdqu xmm0, oword [rcx]
  movdqu xmm1, oword [rdx]
  movdqu xmm2, oword [r8]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [rcx], xmm0

  // --- Chunk 1: acc[2..3], input[16..31], secret[16..31] ---
  movdqu xmm0, oword [rcx + $10]
  movdqu xmm1, oword [rdx + $10]
  movdqu xmm2, oword [r8 + $10]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [rcx + $10], xmm0

  // --- Chunk 2: acc[4..5], input[32..47], secret[32..47] ---
  movdqu xmm0, oword [rcx + $20]
  movdqu xmm1, oword [rdx + $20]
  movdqu xmm2, oword [r8 + $20]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [rcx + $20], xmm0

  // --- Chunk 3: acc[6..7], input[48..63], secret[48..63] ---
  movdqu xmm0, oword [rcx + $30]
  movdqu xmm1, oword [rdx + $30]
  movdqu xmm2, oword [r8 + $30]
  pxor xmm2, xmm1
  pshufd xmm3, xmm2, $31
  pmuludq xmm2, xmm3
  pshufd xmm1, xmm1, $4E
  paddq xmm0, xmm1
  paddq xmm0, xmm2
  movdqu oword [rcx + $30], xmm0
