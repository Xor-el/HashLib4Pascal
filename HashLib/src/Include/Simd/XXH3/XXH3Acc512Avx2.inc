// AVX2 implementation of XXH3_accumulate_512 (fully unrolled, 2 x 32-byte chunks).
// Expects MS x64 ABI: rcx = acc ptr, rdx = input ptr, r8 = secret ptr.
// Uses only volatile registers: ymm0-ymm4.
// Reference: official xxHash C - XXH3_accumulate_512_avx2 in xxhash.h

  // --- Chunk 0: acc[0..3], input[0..31], secret[0..31] ---
  vmovdqu ymm0, yword [rcx]
  vmovdqu ymm1, yword [rdx]
  vmovdqu ymm2, yword [r8]
  vpxor ymm2, ymm2, ymm1
  vpsrlq ymm3, ymm2, 32
  vpmuludq ymm2, ymm2, ymm3
  vpshufd ymm1, ymm1, $4E
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm2
  vmovdqu yword [rcx], ymm0

  // --- Chunk 1: acc[4..7], input[32..63], secret[32..63] ---
  vmovdqu ymm0, yword [rcx + $20]
  vmovdqu ymm1, yword [rdx + $20]
  vmovdqu ymm2, yword [r8 + $20]
  vpxor ymm2, ymm2, ymm1
  vpsrlq ymm3, ymm2, 32
  vpmuludq ymm2, ymm2, ymm3
  vpshufd ymm1, ymm1, $4E
  vpaddq ymm0, ymm0, ymm1
  vpaddq ymm0, ymm0, ymm2
  vmovdqu yword [rcx + $20], ymm0

  vzeroupper
