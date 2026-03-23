// AVX2 implementation of XXH3_initCustomSecret (fully unrolled, 6 x 32-byte chunks).
// Expects MS x64 ABI: rcx = customSecret ptr, rdx = defaultSecret ptr, r8 = seed (UInt64).
// Uses only volatile registers: ymm0-ymm2, rax.
// Reference: official xxHash C - XXH3_initCustomSecret_avx2 in xxhash.h

  // Build seed vector ymm0 = [seed, -seed, seed, -seed]
  vmovq xmm0, r8
  mov rax, r8
  neg rax
  vmovq xmm1, rax
  vpunpcklqdq xmm0, xmm0, xmm1
  vinserti128 ymm0, ymm0, xmm0, 1

  // Block 0
  vmovdqu ymm1, yword [rdx]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx], ymm1

  // Block 1
  vmovdqu ymm1, yword [rdx + $20]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx + $20], ymm1

  // Block 2
  vmovdqu ymm1, yword [rdx + $40]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx + $40], ymm1

  // Block 3
  vmovdqu ymm1, yword [rdx + $60]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx + $60], ymm1

  // Block 4
  vmovdqu ymm1, yword [rdx + $80]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx + $80], ymm1

  // Block 5
  vmovdqu ymm1, yword [rdx + $A0]
  vpaddq ymm1, ymm1, ymm0
  vmovdqu yword [rcx + $A0], ymm1

  vzeroupper
