// AVX2 implementation of XXH3_scrambleAcc (fully unrolled, 2 x 32-byte chunks).
// AVX/AVX2 instructions are db-encoded for broad assembler compatibility.
// Expects MS x64 ABI: rcx = acc ptr, rdx = secret ptr.
// Uses only volatile registers: ymm0-ymm4, eax.
// Reference: official xxHash C - XXH3_scrambleAcc_avx2 in xxhash.h

  // Broadcast XXH_PRIME32_1 ($9E3779B1) to all dword lanes of ymm4
  mov eax, $9E3779B1
  db $C5, $F9, $6E, $E0                         // vmovd xmm4, eax
  db $C4, $E2, $7D, $58, $E4                    // vpbroadcastd ymm4, xmm4

  // --- Chunk 0: acc[0..3], secret[0..31] ---
  db $C5, $FE, $6F, $01                         // vmovdqu ymm0, yword [rcx]
  db $C5, $F5, $73, $D0, $2F                    // vpsrlq ymm1, ymm0, 47
  db $C5, $FD, $EF, $C1                         // vpxor ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $0A                         // vmovdqu ymm1, yword [rdx]
  db $C5, $FD, $EF, $C1                         // vpxor ymm0, ymm0, ymm1
  // Multiply 64-bit lanes by PRIME32_1
  db $C5, $F5, $73, $D0, $20                    // vpsrlq ymm1, ymm0, 32
  db $C5, $FD, $F4, $D4                         // vpmuludq ymm2, ymm0, ymm4
  db $C5, $F5, $F4, $CC                         // vpmuludq ymm1, ymm1, ymm4
  db $C5, $F5, $73, $F1, $20                    // vpsllq ymm1, ymm1, 32
  db $C5, $ED, $D4, $C1                         // vpaddq ymm0, ymm2, ymm1
  db $C5, $FE, $7F, $01                         // vmovdqu yword [rcx], ymm0

  // --- Chunk 1: acc[4..7], secret[32..63] ---
  db $C5, $FE, $6F, $41, $20                    // vmovdqu ymm0, yword [rcx + $20]
  db $C5, $F5, $73, $D0, $2F                    // vpsrlq ymm1, ymm0, 47
  db $C5, $FD, $EF, $C1                         // vpxor ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $4A, $20                    // vmovdqu ymm1, yword [rdx + $20]
  db $C5, $FD, $EF, $C1                         // vpxor ymm0, ymm0, ymm1
  db $C5, $F5, $73, $D0, $20                    // vpsrlq ymm1, ymm0, 32
  db $C5, $FD, $F4, $D4                         // vpmuludq ymm2, ymm0, ymm4
  db $C5, $F5, $F4, $CC                         // vpmuludq ymm1, ymm1, ymm4
  db $C5, $F5, $73, $F1, $20                    // vpsllq ymm1, ymm1, 32
  db $C5, $ED, $D4, $C1                         // vpaddq ymm0, ymm2, ymm1
  db $C5, $FE, $7F, $41, $20                    // vmovdqu yword [rcx + $20], ymm0

  db $C5, $F8, $77                              // vzeroupper
