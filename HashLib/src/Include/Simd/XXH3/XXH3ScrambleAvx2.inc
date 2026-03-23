// AVX2 implementation of XXH3_scrambleAcc (fully unrolled, 2 x 32-byte chunks).
// Expects MS x64 ABI: rcx = acc ptr, rdx = secret ptr.
// Uses only volatile registers: ymm0-ymm4, eax.
// Reference: official xxHash C - XXH3_scrambleAcc_avx2 in xxhash.h

  // Broadcast XXH_PRIME32_1 ($9E3779B1) to all dword lanes of ymm4
  mov eax, $9E3779B1
  vmovd xmm4, eax
  vpbroadcastd ymm4, xmm4

  // --- Chunk 0: acc[0..3], secret[0..31] ---
  vmovdqu ymm0, yword [rcx]
  vpsrlq ymm1, ymm0, 47
  vpxor ymm0, ymm0, ymm1
  vmovdqu ymm1, yword [rdx]
  vpxor ymm0, ymm0, ymm1
  // Multiply 64-bit lanes by PRIME32_1
  vpsrlq ymm1, ymm0, 32
  vpmuludq ymm2, ymm0, ymm4
  vpmuludq ymm1, ymm1, ymm4
  vpsllq ymm1, ymm1, 32
  vpaddq ymm0, ymm2, ymm1
  vmovdqu yword [rcx], ymm0

  // --- Chunk 1: acc[4..7], secret[32..63] ---
  vmovdqu ymm0, yword [rcx + $20]
  vpsrlq ymm1, ymm0, 47
  vpxor ymm0, ymm0, ymm1
  vmovdqu ymm1, yword [rdx + $20]
  vpxor ymm0, ymm0, ymm1
  vpsrlq ymm1, ymm0, 32
  vpmuludq ymm2, ymm0, ymm4
  vpmuludq ymm1, ymm1, ymm4
  vpsllq ymm1, ymm1, 32
  vpaddq ymm0, ymm2, ymm1
  vmovdqu yword [rcx + $20], ymm0

  vzeroupper
